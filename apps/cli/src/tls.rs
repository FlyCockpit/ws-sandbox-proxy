//! Extra, explicit CA trust shared by the control-plane HTTPS and WSS clients.
#[cfg(test)]
#[path = "../test-support/certificates.rs"]
pub(crate) mod certificates;

use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, pem::PemObject};

mod http;

/// Classify verification failures through the clients' typed wrappers. ureq's
/// Error and tungstenite's TLS wrapper do not expose their rustls source;
/// io::Error may carry rustls internally.
pub(crate) fn certificate_hint(
    server: &str,
    mut error: &(dyn std::error::Error + 'static),
) -> Option<String> {
    for _ in 0..16 {
        if let Some(tls) = error.downcast_ref::<rustls::Error>() {
            if matches!(
                tls,
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented
            ) {
                // Only the origin belongs in diagnostics, never URL credentials,
                // query strings, request paths or workload values.
                let origin = url::Url::parse(server).ok()?.origin().ascii_serialization();
                return Some(format!(
                    "server `{origin}` certificate is not trusted or failed verification; use `--ca-file <path>` or `WSSP_CA_FILE` with the server's CA bundle; also check the certificate hostname and validity"
                ));
            }
            return None;
        }
        let inner: Option<&(dyn std::error::Error + 'static)> =
            match error.downcast_ref::<tungstenite::error::TlsError>() {
                Some(tungstenite::error::TlsError::Rustls(tls)) => Some(tls.as_ref()),
                _ => match error.downcast_ref::<ureq::Error>() {
                    Some(ureq::Error::Rustls(tls)) => Some(tls),
                    Some(ureq::Error::Io(io)) => Some(io),
                    _ => error
                        .downcast_ref::<std::io::Error>()
                        .and_then(|io| io.get_ref())
                        .map(|inner| inner as _)
                        .or_else(|| error.source()),
                },
            };
        error = inner?;
    }
    None
}

pub(crate) fn control_plane_error(
    server: &str,
    error: impl std::error::Error + Send + Sync + 'static,
) -> anyhow::Error {
    let hint = certificate_hint(server, &error);
    let error = anyhow::Error::new(error);
    match hint {
        Some(hint) => error.context(hint),
        None => error,
    }
}

#[derive(Debug, Default, clap::Args)]
pub struct TlsArgs {
    /// Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file).
    #[arg(long, value_name = "PATH")]
    pub ca_file: Option<PathBuf>,
}

impl TlsArgs {
    pub fn load(&self, config: &crate::config::Config) -> Result<Trust, CaFileError> {
        let env_path = std::env::var_os("WSSP_CA_FILE").map(PathBuf::from);
        let selected = self
            .ca_file
            .as_deref()
            .or(env_path.as_deref())
            .or(config.ca_file.as_deref());
        Trust::load(selected)
    }
}

/// Failure categories deliberately omit PEM text, even for malformed input.
#[derive(Debug)]
pub enum CaFileError {
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    Untrusted {
        path: PathBuf,
    },
    Empty {
        path: PathBuf,
    },
    NoCertificates {
        path: PathBuf,
    },
    MalformedPem {
        path: PathBuf,
    },
    InvalidCertificate {
        path: PathBuf,
        certificate: usize,
    },
    CurrentUserUnavailable,
    Configuration,
}

impl fmt::Display for CaFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentUserUnavailable => {
                f.write_str("cannot determine the current user to verify CA file ownership")
            }
            Self::Configuration => f.write_str("cannot configure TLS protocol versions"),
            Self::Read { path, .. } => write!(f, "cannot read CA file `{}`", path.display()),
            Self::Untrusted { path } => write!(
                f,
                "untrusted CA path `{}`: the CA file and its parent directory must be owned by the current user or root, and neither may be group- or world-writable; fix ownership and run `chmod go-w` on the file and parent directory (or `chmod 644 <path>` for the CA file)",
                path.display()
            ),
            Self::Empty { path } => write!(f, "CA file `{}` is empty", path.display()),
            Self::NoCertificates { path } => write!(
                f,
                "CA file `{}` contains no PEM certificates",
                path.display()
            ),
            Self::MalformedPem { path } => write!(
                f,
                "CA file `{}` contains malformed PEM; expected only CERTIFICATE blocks and whitespace",
                path.display()
            ),
            Self::InvalidCertificate { path, certificate } => write!(
                f,
                "CA file `{}` contains invalid certificate {certificate}",
                path.display()
            ),
        }
    }
}
impl std::error::Error for CaFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Trust {
    /// Absolute path, so a saved login works from another working directory.
    pub ca_file: Option<PathBuf>,
    config: Option<Arc<rustls::ClientConfig>>,
}

impl Trust {
    pub fn load(path: Option<&Path>) -> Result<Self, CaFileError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let read_error = |source| CaFileError::Read {
            path: path.to_owned(),
            source,
        };
        // Preserve symlink support, checking the resolved target and its parent.
        let ca_file = std::fs::canonicalize(path).map_err(read_error)?;
        let mut file = std::fs::File::open(&ca_file).map_err(read_error)?;
        let metadata = file.metadata().map_err(read_error)?;
        if !metadata.is_file() {
            return Err(read_error(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "CA path is not a regular file",
            )));
        }
        #[cfg(unix)]
        check_ca_permissions(&ca_file, &metadata, current_uid()?)?;
        // The metadata above and these bytes come from the same opened handle.
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(read_error)?;
        let certificates = parse_certificates(path, &bytes)?;
        let roots = root_store(path, &certificates)?;
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        // The ring provider supports the default protocol versions.
        .map_err(|_| CaFileError::Configuration)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tracing::info!(path = %ca_file.display(), certificates = certificates.len(), "loaded extra CA certificates");
        Ok(Self {
            ca_file: Some(ca_file),
            config: Some(Arc::new(config)),
        })
    }

    pub(crate) fn client_config(&self) -> Option<Arc<rustls::ClientConfig>> {
        self.config.clone()
    }

    /// An agent for the relay's own TLS trust (connect passes the WSS config).
    /// Every read on its connections fails once `idle_read` passes without a
    /// byte arriving, independent of any total timeout in `config`.
    pub(crate) fn http_agent_from(
        tls: Option<Arc<rustls::ClientConfig>>,
        config: ureq::config::Config,
        idle_read: std::time::Duration,
    ) -> ureq::Agent {
        http::idle_read_agent(config, tls, idle_read)
    }

    pub(crate) fn http_agent(&self, config: ureq::config::Config) -> ureq::Agent {
        match &self.config {
            Some(tls) => http::agent(config, tls.clone()),
            None => config.into(),
        }
    }
}

#[cfg(unix)]
const ID_PATHS: [&str; 2] = ["/usr/bin/id", "/bin/id"];

#[cfg(unix)]
fn current_uid() -> Result<u32, CaFileError> {
    #[cfg(target_os = "linux")]
    {
        current_uid_from_proc(Path::new("/proc/self"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        uid_from_id(&ID_PATHS)
    }
}

#[cfg(target_os = "linux")]
fn current_uid_from_proc(probe_path: &Path) -> Result<u32, CaFileError> {
    use std::os::unix::fs::MetadataExt;

    // Linux procfs exposes the effective uid as the owner of /proc/self.
    // The private path parameter lets tests exercise unavailable procfs without
    // changing the environment; production always probes the fixed path above.
    match std::fs::metadata(probe_path) {
        Ok(metadata) => Ok(metadata.uid()),
        Err(_) => uid_from_id(&ID_PATHS),
    }
}

#[cfg(unix)]
fn uid_from_id(paths: &[&str]) -> Result<u32, CaFileError> {
    // On systems without procfs (including macOS and BSD), use fixed OS utility
    // paths. Never resolve an ownership-checking command through PATH.
    for path in paths {
        let output = sandbox_runtime::host_child_command(
            path,
            sandbox_runtime::HostChildEnvironment::PathOnly,
        )
        .arg("-u")
        .output();
        if let Ok(output) = output
            && output.status.success()
            && let Ok(text) = std::str::from_utf8(&output.stdout)
            && let Ok(uid) = text.trim().parse()
        {
            return Ok(uid);
        }
    }
    Err(CaFileError::CurrentUserUnavailable)
}

#[cfg(unix)]
fn check_ca_permissions(
    path: &Path,
    metadata: &std::fs::Metadata,
    uid: u32,
) -> Result<(), CaFileError> {
    check_ca_path_permissions(path, metadata, uid)?;
    // `path` is the canonical path used to open the CA, so inspect that
    // target's immediate parent, rather than the original symlink's parent.
    if let Some(parent) = path.parent() {
        let parent_metadata = std::fs::File::open(parent)
            .and_then(|directory| directory.metadata())
            .map_err(|source| CaFileError::Read {
                path: parent.to_owned(),
                source,
            })?;
        check_ca_path_permissions(parent, &parent_metadata, uid)?;
    }
    Ok(())
}

#[cfg(unix)]
fn check_ca_path_permissions(
    path: &Path,
    metadata: &std::fs::Metadata,
    uid: u32,
) -> Result<(), CaFileError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.mode() & 0o022 != 0 || (metadata.uid() != uid && metadata.uid() != 0) {
        return Err(CaFileError::Untrusted {
            path: path.to_owned(),
        });
    }
    Ok(())
}

fn root_store(
    path: &Path,
    certificates: &[CertificateDer<'static>],
) -> Result<RootCertStore, CaFileError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    for (index, cert) in certificates.iter().enumerate() {
        roots
            .add(cert.clone())
            .map_err(|_| CaFileError::InvalidCertificate {
                path: path.to_owned(),
                certificate: index + 1,
            })?;
    }
    Ok(roots)
}

fn parse_certificates(
    path: &Path,
    bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, CaFileError> {
    let malformed = || CaFileError::MalformedPem {
        path: path.to_owned(),
    };
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    if text.trim().is_empty() {
        return Err(CaFileError::Empty {
            path: path.to_owned(),
        });
    }
    if !text.contains("-----BEGIN CERTIFICATE-----") {
        return Err(CaFileError::NoCertificates {
            path: path.to_owned(),
        });
    }
    // The generic PEM iterator skips arbitrary text. Check the envelope too,
    // so a valid cert followed by garbage or a truncated block fails closed.
    let mut rest = text.trim();
    let mut certs = Vec::new();
    while !rest.is_empty() {
        let body = rest
            .strip_prefix("-----BEGIN CERTIFICATE-----")
            .ok_or_else(malformed)?;
        let (body, tail) = body
            .split_once("-----END CERTIFICATE-----")
            .ok_or_else(malformed)?;
        let pem = format!("-----BEGIN CERTIFICATE-----{body}-----END CERTIFICATE-----\n");
        let cert = CertificateDer::from_pem_slice(pem.as_bytes()).map_err(|_| malformed())?;
        certs.push(cert);
        rest = tail.trim_start();
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verification_hint_covers_certificate_failures_and_typed_client_wrappers() {
        for certificate in [
            rustls::CertificateError::UnknownIssuer,
            rustls::CertificateError::Expired,
            rustls::CertificateError::NotValidYet,
            rustls::CertificateError::NotValidForName,
            rustls::CertificateError::BadSignature,
        ] {
            let error = rustls::Error::InvalidCertificate(certificate);
            let wrappers: Vec<Box<dyn std::error::Error>> = vec![
                Box::new(error.clone()),
                Box::new(ureq::Error::Rustls(error.clone())),
                Box::new(ureq::Error::Io(std::io::Error::other(error.clone()))),
                Box::new(tungstenite::error::TlsError::Rustls(Box::new(
                    error.clone(),
                ))),
                Box::new(tungstenite::Error::Tls(
                    tungstenite::error::TlsError::Rustls(Box::new(error.clone())),
                )),
                Box::new(tungstenite::Error::Io(std::io::Error::other(error))),
            ];
            // Assembled at runtime so secret scanners do not flag a literal
            // credential-bearing URL in this redaction fixture.
            let origin = format!(
                "https://user:{}@example.test:9443/path?private=value",
                "password"
            );
            for error in wrappers {
                let hint = certificate_hint(&origin, error.as_ref()).unwrap();
                assert!(
                    hint.contains("server `https://example.test:9443` certificate is not trusted")
                );
                assert!(hint.contains("--ca-file <path>") && hint.contains("WSSP_CA_FILE"));
                for private in ["user", "password", "/path", "private=value"] {
                    assert!(!hint.contains(private));
                }
            }
        }
        assert!(
            certificate_hint(
                "https://example.test",
                &rustls::Error::NoCertificatesPresented
            )
            .is_some()
        );
        assert!(
            certificate_hint(
                "https://example.test",
                &rustls::Error::General("UnknownIssuer".into())
            )
            .is_none()
        );
        assert!(
            certificate_hint(
                "https://example.test",
                &tungstenite::Error::Tls(tungstenite::error::TlsError::Rustls(Box::new(
                    rustls::Error::General("UnknownIssuer".into())
                )))
            )
            .is_none()
        );
        assert!(
            certificate_hint(
                "https://example.test",
                &std::io::Error::from(std::io::ErrorKind::ConnectionRefused)
            )
            .is_none()
        );
    }
    static CERTIFICATES: std::sync::LazyLock<certificates::Certificates> =
        std::sync::LazyLock::new(certificates::generate);
    fn ca() -> &'static str {
        &CERTIFICATES.ca_pem
    }

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        dir
    }

    fn write_ca(path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn load(text: &str) -> Result<Trust, CaFileError> {
        let dir = private_dir();
        let path = dir.path().join("ca.pem");
        write_ca(&path, text);
        Trust::load(Some(&path))
    }

    #[cfg(unix)]
    #[test]
    fn current_uid_matches_a_fresh_file_owner() {
        use std::os::unix::fs::MetadataExt;

        let file = tempfile::tempfile().unwrap();
        assert_eq!(current_uid().unwrap(), file.metadata().unwrap().uid());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unavailable_proc_probe_falls_back_to_fixed_id_paths() {
        use std::os::unix::fs::MetadataExt;

        let dir = private_dir();
        let file = tempfile::tempfile().unwrap();
        assert_eq!(
            current_uid_from_proc(&dir.path().join("missing-proc-self")).unwrap(),
            file.metadata().unwrap().uid()
        );
    }

    #[cfg(unix)]
    #[test]
    fn id_lookup_tries_the_second_fixed_path() {
        use std::os::unix::fs::MetadataExt;

        let dir = private_dir();
        let missing = dir.path().join("missing-id");
        let file = tempfile::tempfile().unwrap();
        for path in ID_PATHS {
            if Path::new(path).exists() {
                assert_eq!(
                    uid_from_id(&[missing.to_str().unwrap(), path]).unwrap(),
                    file.metadata().unwrap().uid()
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unavailable_uid_has_a_distinct_error_without_a_ca_path() {
        let dir = private_dir();
        let missing = dir.path().join("missing-id");
        let error = uid_from_id(&[missing.to_str().unwrap()]).unwrap_err();
        assert!(matches!(error, CaFileError::CurrentUserUnavailable));
        assert_eq!(
            error.to_string(),
            "cannot determine the current user to verify CA file ownership"
        );
        assert!(std::error::Error::source(&error).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn ca_permissions_accept_private_and_public_readable_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("ca.pem");
        write_ca(&path, ca());
        for mode in [0o644, 0o600] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(Trust::load(Some(&path)).is_ok(), "mode {mode:o}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_permissions_refuse_group_and_world_writable_files_and_parents() {
        use std::os::unix::fs::PermissionsExt;
        let dir = private_dir();
        let path = dir.path().join("ca.pem");
        write_ca(&path, ca());
        for (target, modes) in [
            (path.as_path(), [0o620, 0o602]),
            (dir.path(), [0o720, 0o702]),
        ] {
            for mode in modes {
                std::fs::set_permissions(target, std::fs::Permissions::from_mode(mode)).unwrap();
                let error = Trust::load(Some(&path)).unwrap_err();
                assert!(matches!(&error, CaFileError::Untrusted { path } if path == target));
                assert!(error.to_string().contains(&target.display().to_string()));
                assert!(error.to_string().contains("chmod go-w"));
                assert!(error.to_string().contains("chmod 644 <path>"));
                assert!(!format!("{error:?}: {error}").contains(ca()));
            }
            std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_permissions_refuse_another_owner() {
        use std::os::unix::fs::MetadataExt;
        let dir = private_dir();
        let path = dir.path().join("ca.pem");
        write_ca(&path, ca());
        let metadata = std::fs::File::open(&path).unwrap().metadata().unwrap();
        assert_eq!(metadata.uid(), current_uid().unwrap());
        // Simulate a different caller without needing privileged chown.
        if metadata.uid() != 0 {
            assert!(matches!(
                check_ca_permissions(&path, &metadata, metadata.uid() + 1),
                Err(CaFileError::Untrusted { .. })
            ));
        } else {
            // Root-owned files remain trusted for non-root callers too.
            assert!(check_ca_permissions(&path, &metadata, 1000).is_ok());
            std::os::unix::fs::chown(&path, Some(1001), None).unwrap();
            assert!(matches!(
                Trust::load(Some(&path)),
                Err(CaFileError::Untrusted { .. })
            ));
        }
    }

    #[cfg(unix)]
    #[test]
    fn ca_parent_permissions_refuse_another_non_root_owner() {
        use std::os::unix::fs::MetadataExt;

        let dir = private_dir();
        let path = dir.path().join("ca.pem");
        write_ca(&path, ca());
        let mut metadata = std::fs::metadata(dir.path()).unwrap();
        let caller_uid = current_uid().unwrap();
        if caller_uid == 0 {
            // Root can also cover the complete loader with a foreign parent.
            std::os::unix::fs::chown(dir.path(), Some(1001), None).unwrap();
            metadata = std::fs::metadata(dir.path()).unwrap();
            assert!(
                matches!(Trust::load(Some(&path)), Err(CaFileError::Untrusted { path }) if path == dir.path())
            );
        }
        // Without privileged chown, exercise the shared file/parent validator
        // with the real directory metadata and a simulated different caller.
        assert_ne!(metadata.uid(), 0);
        let other_uid = metadata.uid().checked_add(1).unwrap();
        assert!(
            matches!(check_ca_path_permissions(dir.path(), &metadata, other_uid), Err(CaFileError::Untrusted { path }) if path == dir.path())
        );
        assert!(check_ca_path_permissions(dir.path(), &metadata, metadata.uid()).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn ca_symlinks_check_the_final_target_and_its_parent() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = private_dir();
        let target_dir = private_dir();
        let target = target_dir.path().join("ca.pem");
        let link = dir.path().join("link.pem");
        write_ca(&target, ca());
        symlink(&target, &link).unwrap();
        assert!(Trust::load(Some(&link)).is_ok());
        // Only the resolved target's parent is inspected, not the link's parent.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Trust::load(Some(&link)).is_ok());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(
            matches!(Trust::load(Some(&link)), Err(CaFileError::Untrusted { path }) if path == target)
        );
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(target_dir.path(), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(
            matches!(Trust::load(Some(&link)), Err(CaFileError::Untrusted { path }) if path == target_dir.path())
        );
    }

    #[test]
    fn single_and_multiple_certificates_add_to_default_roots() {
        for (text, count) in [(ca().to_owned(), 1), (format!("{}\n{}", ca(), ca()), 2)] {
            let certs = parse_certificates(Path::new("ca.pem"), text.as_bytes()).unwrap();
            assert_eq!(certs.len(), count);
            let trust = load(&text).unwrap();
            assert!(trust.ca_file.as_ref().unwrap().is_absolute());
            assert!(trust.client_config().is_some());
            let roots = root_store(Path::new("ca.pem"), &certs).unwrap();
            assert_eq!(roots.len(), webpki_roots::TLS_SERVER_ROOTS.len() + count);
        }
        assert!(Trust::load(None).unwrap().client_config().is_none());
        assert!(!CERTIFICATES.leaf.is_empty());
        assert!(!CERTIFICATES.leaf_key.is_empty());
    }

    #[test]
    fn empty_garbage_missing_and_unreadable_files_fail_closed() {
        for text in ["", " \n\t"] {
            assert!(matches!(load(text), Err(CaFileError::Empty { .. })));
        }
        for text in [
            "garbage",
            // Split so the template secret-pattern scan never sees a key header.
            concat!(
                "-----BEGIN PRIV",
                "ATE KEY-----\nAA==\n-----END PRIV",
                "ATE KEY-----"
            ),
        ] {
            assert!(matches!(
                load(text),
                Err(CaFileError::NoCertificates { .. })
            ));
        }
        let dir = private_dir();
        assert!(
            matches!(Trust::load(Some(&dir.path().join("missing"))), Err(CaFileError::Read { source, .. }) if source.kind() == std::io::ErrorKind::NotFound)
        );
        // A directory is unreadable as a certificate file, even as root.
        assert!(matches!(
            Trust::load(Some(dir.path())),
            Err(CaFileError::Read { .. })
        ));
    }

    #[test]
    fn malformed_pem_and_invalid_der_fail_without_echoing_contents() {
        for text in [
            "-----BEGIN CERTIFICATE-----\nPRIVATE-CONTENT",
            "-----BEGIN CERTIFICATE-----\n%%%PRIVATE-CONTENT\n-----END CERTIFICATE-----",
            &format!("{}PRIVATE-CONTENT", ca()),
            &format!("{}-----BEGIN CERTIFICATE-----\nPRIVATE-CONTENT", ca()),
        ] {
            let error = load(text).unwrap_err();
            assert!(matches!(error, CaFileError::MalformedPem { .. }));
            assert!(!format!("{error:?}: {error}").contains("PRIVATE-CONTENT"));
        }
        assert!(matches!(
            load("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n"),
            Err(CaFileError::InvalidCertificate { certificate: 1, .. })
        ));
    }
}
