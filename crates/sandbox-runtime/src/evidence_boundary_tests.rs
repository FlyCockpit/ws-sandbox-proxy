//! Compile the actual production modules with an added sibling, rather than an
//! external-crate doctest that would only establish the public API boundary.
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

fn dependency_candidates(deps: &Path, name: &str) -> Vec<PathBuf> {
    let prefix = format!("lib{name}-");
    let mut paths = std::fs::read_dir(deps)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let file = path.file_name().unwrap().to_string_lossy();
            file.starts_with(&prefix) && file.ends_with(".rlib")
        })
        .collect::<Vec<_>>();
    paths.sort(); // Stable lexical order; timestamps and readdir order have no authority.
    paths
}

fn compile(
    deps: &Path,
    dir: &Path,
    source: &Path,
    externs: &HashMap<String, PathBuf>,
) -> std::process::Output {
    let mut command = Command::new("rustc");
    command
        .args([
            "--edition=2024",
            "--crate-type=lib",
            "--emit=metadata",
            "--crate-name",
            "evidence_probe",
        ])
        .arg(source)
        .arg("--out-dir")
        .arg(dir)
        .arg("-L")
        .arg(format!("dependency={}", deps.display()));
    let mut names: Vec<_> = externs.keys().collect();
    names.sort();
    for name in names {
        command
            .arg("--extern")
            .arg(format!("{name}={}", externs[name].display()));
    }
    command.output().unwrap()
}

fn resolve_dependencies(
    deps: &Path,
    fingerprints: &Path,
    binary_fingerprint: &serde_json::Value,
    dir: &Path,
    root: &str,
) -> HashMap<String, PathBuf> {
    // Resolve the exact graph Cargo linked into THIS test binary. Searching a
    // Cartesian product of stale artifacts is unbounded and cannot succeed if
    // a newly added production dependency is missing from a handwritten list.
    // Cargo's fingerprint evidence is test tooling only; still compile the
    // complete production module graph before any privacy probes below.
    let fingerprint_dirs: Vec<_> = std::fs::read_dir(fingerprints)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    let mut externs = HashMap::new();
    for dependency in binary_fingerprint["deps"].as_array().unwrap() {
        let name = dependency[1].as_str().unwrap();
        let expected = dependency[3].as_u64().unwrap();
        let candidates: Vec<_> = dependency_candidates(deps, name)
            .into_iter()
            .filter(|artifact| {
                let file = artifact.file_stem().unwrap().to_str().unwrap();
                let hash = file.rsplit_once('-').unwrap().1;
                fingerprint_dirs.iter().any(|directory| {
                    if !directory
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .ends_with(&format!("-{hash}"))
                    {
                        return false;
                    }
                    let Ok(record) = std::fs::read_to_string(directory.join(format!("lib-{name}")))
                    else {
                        return false;
                    };
                    // Cargo serializes the u64 fingerprint as little-endian hex.
                    u64::from_str_radix(record.trim(), 16)
                        .map(u64::swap_bytes)
                        .ok()
                        == Some(expected)
                })
            })
            .collect();
        assert_eq!(candidates.len(), 1, "exact Cargo artifact for {name}");
        externs.insert(name.to_owned(), candidates[0].clone());
    }
    let source = dir.join("resolve.rs");
    std::fs::write(&source, root).unwrap();
    let output = compile(deps, dir, &source, &externs);
    assert!(
        output.status.success(),
        "current production dependency graph: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    externs
}

#[test]
fn sibling_modules_cannot_forge_evidence_or_reuse_the_pre_issue_phase() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let dir = std::env::temp_dir().join(format!("wssp-evidence-probes-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    // Reproduce the reviewer experiment on every run: isolated exact dependency
    // files plus a lexically first synthetic incompatible getrandom API.
    // Never modify timestamps or artifacts in Cargo's shared target directory.
    let isolated = dir.join("deps");
    std::fs::create_dir_all(&isolated).unwrap();
    for entry in std::fs::read_dir(&deps).unwrap() {
        let path = entry.unwrap().path();
        if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("rlib" | "so")
        ) {
            let link = isolated.join(path.file_name().unwrap());
            if !link.exists() {
                std::os::unix::fs::symlink(&path, link).unwrap();
            }
        }
    }
    // Build the incompatible artifact ourselves: a crate-scoped clean build only
    // supplies the current getrandom API, independent of other workspace builds.
    let incompatible = dir.join("newer-getrandom.rs");
    std::fs::write(&incompatible, "pub fn getrandom(_: &mut [u8]) {}\n").unwrap();
    let stale = isolated.join("libgetrandom-000-newer-stale.rlib");
    let built = Command::new("rustc")
        .args([
            "--edition=2024",
            "--crate-type=rlib",
            "--crate-name=getrandom",
        ])
        .arg(&incompatible)
        .arg("-o")
        .arg(&stale)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "synthetic incompatible artifact: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    std::fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)),
        )
        .unwrap();
    let deps = isolated;
    let root = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    // Absolute module paths preserve their original module hierarchy and privacy.
    let root = root
        .lines()
        .map(|line| {
            // `pub mod` and `pub(crate) mod` declarations are file modules too.
            let declaration = ["pub(crate) ", "pub "]
                .iter()
                .find_map(|vis| line.strip_prefix(vis))
                .unwrap_or(line);
            if let Some(module) = declaration
                .strip_prefix("mod ")
                .and_then(|s| s.strip_suffix(';'))
            {
                let name = module.strip_prefix("r#").unwrap_or(module);
                let nested = src.join(name).join("mod.rs");
                let path = if nested.exists() {
                    nested
                } else {
                    src.join(format!("{name}.rs"))
                };
                format!("#[path = {:?}]\n{line}\n", path)
            } else {
                format!("{line}\n")
            }
        })
        .collect::<String>();
    let binary = std::env::current_exe().unwrap();
    let binary_hash = binary
        .file_stem()
        .unwrap()
        .to_str()
        .unwrap()
        .rsplit_once('-')
        .unwrap()
        .1;
    let fingerprints = binary
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".fingerprint");
    let binary_fingerprint: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fingerprints.join(format!(
            "sandbox-runtime-{binary_hash}/test-lib-sandbox_runtime.json"
        )))
        .unwrap(),
    )
    .unwrap();
    let externs = resolve_dependencies(&deps, &fingerprints, &binary_fingerprint, &dir, &root);
    assert_ne!(
        externs["getrandom"], stale,
        "newer incompatible API must be rejected"
    );
    let probes = [
        ("baseline", "", None),
        (
            "bound_constructor_private",
            r#"
            fn forge() { let _ = crate::BoundInstance {
                name: "wssp-sbx-sbx".into(), sandbox_id: "sbx".into(), fingerprint: "image".into(),
                create_key: None, binary: "incus".into(), project: "default".into(),
                observed: crate::HostInstance { name: "wssp-sbx-sbx".into(), status: "Running".into(), status_code: 103 },
            }; }
        "#,
            Some("E0451"),
        ),
        (
            "bound_delete_requires_token",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.delete_force("wssp-sbx-sbx"); }
        "#,
            Some("E0308"),
        ),
        (
            "bound_stop_requires_token",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.stop_force("wssp-sbx-sbx"); }
        "#,
            Some("E0308"),
        ),
        (
            "bound_exec_requires_token",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.exec_argv("wssp-sbx-sbx", &[]); }
        "#,
            Some("E0308"),
        ),
        (
            "bound_upload_requires_token",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.file_push("wssp-sbx-sbx", "/file", b"data"); }
        "#,
            Some("E0308"),
        ),
        (
            "bound_download_requires_token",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.file_pull("wssp-sbx-sbx", "/file"); }
        "#,
            Some("E0308"),
        ),
        (
            "bound_supervised_requires_token",
            r#"
            fn bypass(exec: &crate::ExecSupervisor, request: &crate::RunCommandRequest) { let _ = exec.run("wssp-sbx-sbx", request); }
        "#,
            Some("E0308"),
        ),
        (
            "bound_fields_private",
            r#"
            fn forge(mut bound: crate::BoundInstance) { bound.name = "wssp-sbx-foreign".into(); }
        "#,
            Some("E0616"),
        ),
        (
            "raw_name_query_private",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.query_instance_by_name("wssp-sbx-sbx"); }
        "#,
            Some("E0624"),
        ),
        (
            "raw_init_private",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.init_vm("image", "wssp-sbx-sbx", &[]); }
        "#,
            Some("E0624"),
        ),
        (
            "raw_effect_private",
            r#"
            fn bypass(client: &crate::IncusClient) { let _ = client.run_effect(&["delete", "wssp-sbx-sbx"], false); }
        "#,
            Some("E0624"),
        ),
        (
            "cancelled_constructor",
            r#"
            fn invent(response: crate::RunCommandResponse) {
                let _ = crate::incus::exec::CancelledCompletion { response, _guest: unreachable!(), _local: unreachable!() };
            }
            "#,
            Some("E0451"),
        ),
        (
            "sealed",
            r#"
            struct Invented;
            impl crate::effect::PositiveEvidence for Invented {
                type Value = ();
                fn value(self) {}
            }
        "#,
            Some("E0277"),
        ),
        (
            "completed_constructor",
            r#"
            fn invent<P: crate::effect::PositiveEvidence<Value = ()>>(proof: P) {
                let _ = crate::Completed::new(proof);
            }
        "#,
            Some("E0624"),
        ),
        (
            "not_issued_constructor",
            r#"
            fn invent(error: crate::RuntimeError) {
                let _ = crate::before_issue::NotIssuedProof::failed(error);
            }
        "#,
            Some("E0624"),
        ),
        (
            "capability_constructor",
            r#"
            fn invent() {
                let _ = crate::before_issue::BeforeIssue { _scope: std::marker::PhantomData };
            }
            "#,
            Some("E0451"),
        ),
        (
            "precondition_without_capability",
            r#"
            fn post_issue() -> crate::EffectOutcome<()> {
                crate::before_issue::incus::path("/", true)?;
                unreachable!()
            }
        "#,
            Some("E0061"),
        ),
        (
            "admission_without_capability",
            r#"
            fn post_issue() {
                let _ = crate::before_issue::incus::supervised_admission(|| {
                    Ok((std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)), ()))
                });
            }
        "#,
            Some("E0061"),
        ),
        (
            "consumed_capability",
            r#"
            fn post_issue() {
                let _ = crate::before_issue::phase(|before| {
                    let issued = before.issue(|| Ok(()))?;
                    crate::before_issue::incus::path(&before, "/", true)?;
                    Ok(issued)
                }, Ok);
            }
        "#,
            Some("E0382"),
        ),
        (
            "escaped_capability",
            r#"
            fn post_issue() {
                let mut leaked = None;
                let _ = crate::before_issue::phase::<(), ()>(|before| {
                    leaked = Some(before);
                    unreachable!()
                }, Ok);
            }
        "#,
            Some("E0521"),
        ),
        (
            "not_issued_in_post_callback",
            r#"
            fn post_issue(error: crate::EffectError) {
                let _ = crate::before_issue::phase(|before| before.issue(|| Ok(())), |()| {
                    Err::<(), _>(error)
                });
            }
        "#,
            Some("E0308"),
        ),
    ];
    for (name, probe, diagnostic) in probes {
        let file = dir.join(format!("{name}.rs"));
        std::fs::write(&file, format!("{root}\nmod sibling_probe {{ {probe} }}\n")).unwrap();
        let mut command = Command::new("rustc");
        command
            .args([
                "--edition=2024",
                "--crate-type=lib",
                "--emit=metadata",
                "--crate-name",
                "evidence_probe",
            ])
            .arg(&file)
            .arg("--out-dir")
            .arg(&dir)
            .arg("-L")
            .arg(format!("dependency={}", deps.display()));
        for (name, path) in &externs {
            command
                .arg("--extern")
                .arg(format!("{name}={}", path.display()));
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        std::fs::write(dir.join(format!("{name}.log")), stderr.as_bytes()).unwrap();
        match diagnostic {
            None => assert!(output.status.success(), "baseline: {stderr}"),
            Some(expected) => {
                assert!(!output.status.success(), "{name} unexpectedly compiled");
                assert!(
                    stderr.contains(expected),
                    "{name}: expected {expected}: {stderr}"
                );
            }
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
