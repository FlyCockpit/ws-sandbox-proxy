//! The notices the CLI release archives carry (`dist-workspace.toml`
//! `include`): every file named there exists, the Apache-2.0 text the
//! modified russh needs is one of them and is the standard text byte for
//! byte, and the russh notice names it.

use std::path::{Path, PathBuf};

/// SHA-256 of <https://www.apache.org/licenses/LICENSE-2.0.txt>.
const APACHE_2_0_SHA256: &str = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30";
const APACHE_2_0: &str = "licenses/Apache-2.0.txt";

fn cli_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn repo_root() -> PathBuf {
    cli_dir()
        .parent()
        .and_then(Path::parent)
        .expect("apps/cli sits two levels below the repository root")
        .to_owned()
}

/// The `[dist] include` list, resolved against `apps/cli` as cargo-dist
/// does.
fn dist_includes() -> Vec<PathBuf> {
    let text = std::fs::read_to_string(cli_dir().join("dist-workspace.toml")).unwrap();
    let config: toml::Table = text.parse().unwrap();
    let include = config["dist"]["include"]
        .as_array()
        .expect("[dist] include is a list");
    include
        .iter()
        .map(|entry| cli_dir().join(entry.as_str().expect("an include is a path")))
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn every_file_the_release_archives_include_exists() {
    let includes = dist_includes();
    assert!(!includes.is_empty());
    for path in &includes {
        let meta = std::fs::metadata(path).unwrap_or_else(|error| panic!("{path:?}: {error}"));
        assert!(meta.is_file() && meta.len() > 0, "{path:?}");
    }
    let canonical: Vec<PathBuf> = includes
        .iter()
        .map(|path| std::fs::canonicalize(path).unwrap())
        .collect();
    for wanted in ["THIRD-PARTY-LICENSES.md", APACHE_2_0] {
        let wanted = std::fs::canonicalize(repo_root().join(wanted)).unwrap();
        assert!(
            canonical.contains(&wanted),
            "{wanted:?} is not in {includes:?}"
        );
    }
    // Archives flatten includes by file name: no two may collide.
    let mut names: Vec<_> = includes.iter().map(|path| path.file_name()).collect();
    names.sort();
    names.dedup();
    assert_eq!(names.len(), includes.len(), "{includes:?}");
}

#[test]
fn the_bundled_apache_licence_is_the_standard_text() {
    let bytes = std::fs::read(repo_root().join(APACHE_2_0)).unwrap();
    let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
    assert_eq!(hex(digest.as_ref()), APACHE_2_0_SHA256);
}

#[test]
fn the_russh_notice_names_the_bundled_licence() {
    let notices = std::fs::read_to_string(repo_root().join("THIRD-PARTY-LICENSES.md")).unwrap();
    let section = notices
        .split("\n## ")
        .find(|section| section.starts_with("russh "))
        .expect("THIRD-PARTY-LICENSES.md has a russh section");
    assert!(section.contains("Apache License"), "{section}");
    // The source path and the name it has in the archives.
    assert!(section.contains(&format!("`{APACHE_2_0}`")), "{section}");
    let name = Path::new(APACHE_2_0).file_name().unwrap().to_string_lossy();
    assert!(section.contains(&format!("`{name}`")), "{section}");
}
