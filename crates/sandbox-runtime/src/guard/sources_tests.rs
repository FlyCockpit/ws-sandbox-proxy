//! Security-critical: policy sources, provenance and last-valid (M13, M16).

use super::*;

fn cidrs(content: &PolicyContent) -> Vec<String> {
    content.cidrs.iter().map(ToString::to_string).collect()
}

#[test]
fn parses_cidrs_domains_comments_and_normalizes() {
    let content = parse_source(
        b"# operator list\n\n1.1.1.1\n203.0.113.0/24  # docs\n203.0.113.128/25\nBad.Example.\nexample.org\nexample.org\n",
    )
    .unwrap();
    assert_eq!(cidrs(&content), ["1.1.1.1/32", "203.0.113.0/24"]);
    assert_eq!(content.domains, ["bad.example", "example.org"]);
    assert!(content.digest().starts_with("sha256:"));
    assert_eq!(
        content.digest(),
        parse_source(b"example.org\nbad.example\n1.1.1.1/32\n203.0.113.0/24\n")
            .unwrap()
            .digest()
    );
}

#[test]
fn any_bad_line_rejects_the_whole_source_with_its_line() {
    for (body, line) in [
        (&b"1.1.1.1\n2.2.2.2\n\n\n\n\n2001:db8::/32\n"[..], Some(7)),
        (b"10.0.0.1/8\n", Some(1)),
        (b"10.0.0.0/33\n", Some(1)),
        (b"10.0.0.0/08\n", Some(1)),
        (b"1.1.1.1 trailing\n", Some(1)),
        (b"*.example.org\n", Some(1)),
        (b"ok.example\nnot_a_domain\n", Some(2)),
        (b"single\n", Some(1)),
    ] {
        let err = parse_source(body).unwrap_err();
        assert_eq!(err.line, line, "{}", String::from_utf8_lossy(body));
    }
    assert_eq!(parse_source(&[0xff, 0xfe]).unwrap_err().line, None);
}

#[test]
fn limits_are_enforced() {
    let big = vec![b'#'; MAX_SOURCE_BYTES + 1];
    assert!(parse_source(&big).is_err());

    let mut many = String::new();
    for i in 0..=MAX_CIDRS {
        many.push_str(&format!(
            "{}.{}.{}.0/24\n",
            1 + i / 65536,
            (i / 256) % 256,
            i % 256
        ));
    }
    assert_eq!(
        parse_source(many.as_bytes()).unwrap_err().line,
        Some(MAX_CIDRS + 1)
    );

    let mut domains = String::new();
    for i in 0..=MAX_DOMAINS {
        domains.push_str(&format!("d{i}.example\n"));
    }
    assert_eq!(
        parse_source(domains.as_bytes()).unwrap_err().line,
        Some(MAX_DOMAINS + 1)
    );

    // 2048 long names exceed the rendered 63 KiB bound.
    let mut long = String::new();
    for i in 0..MAX_DOMAINS {
        long.push_str(&format!("{}{i:04}.example\n", "a".repeat(40)));
    }
    assert!(parse_source(long.as_bytes()).is_err());

    let entries = vec!["1.1.1.1".to_string(); 2];
    assert!(parse_entries(&entries).is_ok());
    assert_eq!(
        parse_entries(&["1.1.1.1".into(), "a.example\n2.2.2.2".into()])
            .unwrap_err()
            .line,
        Some(2)
    );
}

#[test]
fn root_missing_after_install_keeps_last_valid_and_is_unhealthy() {
    let mut root = Source::starting(None);
    root.accept_root_file(parse_source(b"1.1.1.1\n").unwrap());
    assert!(matches!(root.state, SourceState::Valid { cidrs: 1, .. }));
    root.reject(root_state(RootRead::Missing).unwrap_err());
    assert_eq!(root.state, SourceState::Missing);
    assert!(!root.state.healthy());
    assert_eq!(cidrs(root.last_valid.as_ref().unwrap()), ["1.1.1.1/32"]);
    assert_eq!(deny4(&root, &Source::starting(None)).len(), 1);
}

#[test]
fn root_empty_file_is_not_configured_and_healthy() {
    let mut root = Source::starting(Some(parse_source(b"1.1.1.1\n").unwrap()));
    root.accept_root_file(root_state(RootRead::Content(b"# nothing\n".to_vec())).unwrap());
    assert!(matches!(root.state, SourceState::NotConfigured { .. }));
    assert!(root.state.healthy());
    // Clearing is explicit: the old entry is gone.
    assert!(deny4(&root, &Source::starting(None)).is_empty());
}

#[test]
fn root_invalid_line_keeps_last_valid() {
    let mut root = Source::starting(None);
    root.accept_root_file(parse_source(b"1.1.1.1\n").unwrap());
    let body = b"a.example\nb.example\nc.example\nd.example\ne.example\nf.example\n10.0.0.1/8\n";
    root.reject(root_state(RootRead::Content(body.to_vec())).unwrap_err());
    assert!(matches!(
        root.state,
        SourceState::Invalid { line: Some(7), .. }
    ));
    assert_eq!(cidrs(root.last_valid.as_ref().unwrap()), ["1.1.1.1/32"]);
}

#[test]
fn deployment_is_unknown_until_first_push_and_explicitly_cleared() {
    let persisted = parse_entries(&["9.9.9.0/24".into()]).unwrap();
    let mut deployment = Source::starting(Some(persisted));
    assert_eq!(deployment.state, SourceState::Unknown);
    assert!(!deployment.state.healthy());
    // Last valid stays enforced while unknown.
    assert_eq!(deny4(&Source::starting(None), &deployment).len(), 1);

    deployment.accept(PolicyContent::default(), false);
    assert!(matches!(
        deployment.state,
        SourceState::NotConfigured { .. }
    ));
    assert!(deployment.state.healthy());
    assert!(deny4(&Source::starting(None), &deployment).is_empty());

    deployment.accept(PolicyContent::default(), true);
    assert!(matches!(
        deployment.state,
        SourceState::Valid {
            cidrs: 0,
            domains: 0,
            ..
        }
    ));
}

/// Property (M16): whatever the deployment push says, every root entry
/// stays in `deny4`.
#[test]
fn a_deployment_push_never_removes_a_root_entry() {
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..300 {
        let mut root_lines = Vec::new();
        for _ in 0..(next() % 6) {
            let n = next();
            let prefix = 8 + (n % 25) as u8;
            let net =
                Ipv4Net::containing(std::net::Ipv4Addr::from((n >> 8) as u32), prefix).unwrap();
            root_lines.push(net.to_string());
        }
        let mut root = Source::starting(None);
        root.accept_root_file(parse_entries(&root_lines).unwrap());
        let mut deployment = Source::starting(None);
        let mut pushed = Vec::new();
        for _ in 0..(next() % 6) {
            let n = next();
            let net = Ipv4Net::containing(
                std::net::Ipv4Addr::from((n >> 16) as u32),
                8 + (n % 25) as u8,
            )
            .unwrap();
            pushed.push(net.to_string());
        }
        deployment.accept(parse_entries(&pushed).unwrap(), next() % 2 == 0);
        let union = deny4(&root, &deployment);
        for line in &root_lines {
            let net = Ipv4Net::parse_cidr(line).unwrap();
            assert!(union.iter().any(|cover| net.within(*cover)), "{line} lost");
        }
    }
}

#[test]
fn domain_union_must_fit_runtime_bounds() {
    let names = |prefix: &str, n: usize| -> Vec<String> {
        (0..n).map(|i| format!("{prefix}{i}.example")).collect()
    };
    let mut root = Source::starting(None);
    root.accept_root_file(parse_entries(&names("r", 1500)).unwrap());
    let mut deployment = Source::starting(None);
    deployment.accept(parse_entries(&names("d", 500)).unwrap(), true);
    assert!(domain_union_fits(&root, &deployment));
    deployment.accept(parse_entries(&names("d", 600)).unwrap(), true);
    assert!(!domain_union_fits(&root, &deployment));
}

#[test]
fn ownership_rules() {
    assert!(check_root_owned("f", 0, 0o100644, 0, true).is_ok());
    assert!(check_root_owned("f", 1000, 0o100644, 0, true).is_err());
    assert!(check_root_owned("f", 0, 0o100664, 0, true).is_err());
    assert!(check_root_owned("f", 0, 0o100646, 0, true).is_err());
    assert!(check_root_owned("f", 0, 0o100644, 0, false).is_err());
}

#[cfg(target_os = "linux")]
mod files {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn tempfile_dir() -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("wssp-guard-src-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    #[test]
    fn reads_owned_regular_file_and_refuses_the_rest() {
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile_dir();
        let me = std::fs::metadata(&dir).unwrap().uid();
        let file = dir.join("egress-blocklist");
        assert_eq!(read_root_file(&file, me), RootRead::Missing);

        std::fs::write(&file, b"1.1.1.1\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_root_file(&file, me),
            RootRead::Content(b"1.1.1.1\n".to_vec())
        );
        // Wrong owner (production expects root).
        assert!(matches!(
            read_root_file(&file, me + 1),
            RootRead::Refused(_)
        ));
        // Group-writable file.
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(matches!(read_root_file(&file, me), RootRead::Refused(_)));
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        // Symlink.
        let link = dir.join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(matches!(read_root_file(&link, me), RootRead::Refused(r) if r.contains("symlink")));
        // Writable directory.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(read_root_file(&file, me), RootRead::Refused(_)));
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        // Not a regular file.
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        assert!(matches!(read_root_file(&sub, me), RootRead::Refused(_)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// E6, security-critical: the deployment list the relay derives from
/// `SANDBOX_EGRESS_BLOCKLIST` (shared fixture with `apps/server`) is exactly
/// what this parser accepts; `deny4` is the union of the root list and that
/// list; an invalid list the relay refuses is refused here too, and a
/// refused push never removes the last valid deployment set.
#[test]
fn e6_deployment_list_parity_and_root_union() {
    let cases: serde_json::Value = serde_json::from_str(include_str!(
        "../../../sandbox-protocol/fixtures/egress_blocklist_cases.json"
    ))
    .unwrap();
    let tokens = |raw: &serde_json::Value| -> Vec<String> {
        raw.as_str()
            .unwrap_or("")
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .collect()
    };
    let mut root = Source::starting(None);
    root.accept_root_file(parse_source(b"# operator\n192.0.2.0/24\nroot.example\n").unwrap());
    for case in cases["env"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let raw = tokens(&case["raw"]);
        match case["state"].as_str().unwrap() {
            "invalid" => {
                let err = parse_entries(&raw).unwrap_err();
                assert_eq!(
                    err.line,
                    case["invalidEntry"].as_u64().map(|n| n as usize),
                    "{name}"
                );
            }
            state => {
                let entries: Vec<String> = case["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|e| e.as_str().unwrap().to_string())
                    .collect();
                // The relay's normalized entries mean what the raw tokens mean.
                let content = parse_entries(&entries).unwrap();
                assert_eq!(content, parse_entries(&raw).unwrap(), "{name}");
                let mut deployment = Source::starting(None);
                deployment.accept(content.clone(), state == "valid");
                assert!(deployment.state.healthy(), "{name}");
                let union = deny4(&root, &deployment);
                for net in root.cidrs().iter().chain(content.cidrs.iter()) {
                    assert!(
                        union.iter().any(|cover| net.within(*cover)),
                        "{name}: {net}"
                    );
                }
                for net in &union {
                    assert!(
                        root.cidrs()
                            .iter()
                            .chain(content.cidrs.iter())
                            .any(|source| net.within(*source)),
                        "{name}: {net} came from nowhere"
                    );
                }
                assert!(domain_union_fits(&root, &deployment));
            }
        }
    }

    // A valid deployment list, then a push the parser refuses: the guard
    // answers an error and leaves the source untouched (last valid stays).
    let mut deployment = Source::starting(None);
    deployment.accept(
        parse_entries(&["203.0.113.0/24".into(), "bad.example".into()]).unwrap(),
        true,
    );
    let before = deny4(&root, &deployment);
    assert!(parse_entries(&["203.0.113.1/24".into()]).is_err());
    assert_eq!(deny4(&root, &deployment), before);
    assert!(before.iter().any(|n| n.to_string() == "203.0.113.0/24"));
    assert!(before.iter().any(|n| n.to_string() == "192.0.2.0/24"));
    assert_eq!(deployment.domains(), ["bad.example"]);
    assert_eq!(root.domains(), ["root.example"]);
}
