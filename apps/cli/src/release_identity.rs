//! Release-metadata identity checks. Compiled only under `cfg(test)`.

use serde::Deserialize;

const CANONICAL_REPO: &str = "https://github.com/FlyCockpit/ws-sandbox-proxy";
const CANONICAL_REPO_GIT: &str = "https://github.com/FlyCockpit/ws-sandbox-proxy.git";
const GHCR_IMAGE: &str = "ghcr.io/flycockpit/ws-sandbox-proxy";
const ADVISORY_URL: &str = "https://github.com/FlyCockpit/ws-sandbox-proxy/security/advisories/new";
/// The install command the docs give: the user's own server's installer.
const SERVER_INSTALLER: &str = "/install.sh | sh";
/// cargo-dist's installer, which the release no longer ships.
const SHELL_INSTALLER: &str =
    "https://github.com/FlyCockpit/ws-sandbox-proxy/releases/latest/download/wssp-installer.sh";
const POWERSHELL_INSTALLER: &str =
    "https://github.com/FlyCockpit/ws-sandbox-proxy/releases/latest/download/wssp-installer.ps1";

#[derive(Debug, Deserialize)]
struct CliPackageManifest {
    package: PackageSection,
    bin: Vec<BinSection>,
}

#[derive(Debug, Deserialize)]
struct PackageSection {
    name: String,
    authors: Vec<String>,
    license: String,
    repository: String,
    homepage: String,
    documentation: String,
}

#[derive(Debug, Deserialize)]
struct BinSection {
    name: String,
}

#[derive(Debug, Deserialize)]
struct DistWorkspaceManifest {
    dist: DistSection,
}

#[derive(Debug, Deserialize)]
struct DistSection {
    installers: Vec<String>,
    targets: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RootPackageJson {
    repository: RepositoryField,
    homepage: String,
}

#[derive(Debug, Deserialize)]
struct RepositoryField {
    #[serde(rename = "type")]
    kind: String,
    url: String,
}

#[test]
fn cargo_package_uses_product_identity() {
    let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
    let parsed: CliPackageManifest = toml::from_str(text).expect("apps/cli/Cargo.toml parses");

    assert_eq!(parsed.package.name, "wssp");
    assert_eq!(parsed.package.repository, CANONICAL_REPO);
    assert_eq!(parsed.package.homepage, CANONICAL_REPO);
    assert_eq!(
        parsed.package.documentation,
        "https://github.com/FlyCockpit/ws-sandbox-proxy#readme"
    );
    assert_eq!(parsed.bin.len(), 1);
    assert_eq!(parsed.bin[0].name, "wssp");
    assert_eq!(parsed.package.name, parsed.bin[0].name);
    assert_eq!(parsed.package.authors, ["FlyCockpit LLC"]);
    assert_eq!(parsed.package.license, "MIT");
}

#[test]
fn dist_workspace_ships_linux_archives_without_an_installer() {
    let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/dist-workspace.toml"));
    let parsed: DistWorkspaceManifest =
        toml::from_str(text).expect("apps/cli/dist-workspace.toml parses");

    // The server serves the only installer (`/install.sh`).
    assert!(parsed.dist.installers.is_empty());
    // The CLI and node daemon are Linux-only.
    assert_eq!(
        parsed.dist.targets,
        ["aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"]
    );
}

#[test]
fn root_package_json_points_at_canonical_repo() {
    let text = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../package.json"));
    let parsed: RootPackageJson = serde_json::from_str(text).expect("root package.json parses");

    assert_eq!(parsed.repository.kind, "git");
    assert_eq!(parsed.repository.url, CANONICAL_REPO_GIT);
    assert_eq!(parsed.homepage, CANONICAL_REPO);
}

#[test]
fn readme_documents_server_installer_from_canonical_repo() {
    let cli_readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"));
    let root_readme = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../README.md"));
    let releasing = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/releasing.md"));

    for text in [cli_readme, root_readme, releasing] {
        assert!(text.contains(CANONICAL_REPO));
        assert!(text.contains(SERVER_INSTALLER));
        assert!(
            !text.contains(SHELL_INSTALLER),
            "the unpublished cargo-dist installer is advertised"
        );
    }
    for text in [cli_readme, root_readme, releasing] {
        assert!(
            !text.contains("brew install"),
            "unsupported Homebrew install is advertised"
        );
        assert!(
            !text.contains(POWERSHELL_INSTALLER),
            "unsupported PowerShell install is advertised"
        );
    }
    for text in [cli_readme, root_readme] {
        assert!(text.contains("Linux-only") || text.contains("Linux only"));
    }
    assert!(cli_readme.contains("git clone https://github.com/FlyCockpit/ws-sandbox-proxy"));
    assert!(root_readme.contains(GHCR_IMAGE));
    assert!(releasing.contains(GHCR_IMAGE));
    assert!(releasing.contains("x86_64-unknown-linux-musl"));
    assert!(releasing.contains("aarch64-unknown-linux-musl"));
}

#[test]
fn security_advisories_use_canonical_repo() {
    let cli_security = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/SECURITY.md"));
    let root_security = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../SECURITY.md"));

    assert!(cli_security.contains(ADVISORY_URL));
    assert!(root_security.contains(ADVISORY_URL));
}

#[test]
fn release_configuration_uses_only_supported_destinations() {
    let workflow = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../.github/workflows/release.yml"
    ));
    let releasing = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/docs/releasing.md"));
    let config = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/dist-workspace.toml"));

    for text in [workflow, releasing, config] {
        assert!(!text.contains("homebrew-tap"));
        assert!(!text.contains("HOMEBREW_TAP_TOKEN"));
    }
    assert!(workflow.contains("ghcr.io/${GITHUB_REPOSITORY,,}"));
    assert!(workflow.contains(GHCR_IMAGE));
}
