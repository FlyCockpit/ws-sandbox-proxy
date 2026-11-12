//! Guest-side credential steps over [`SandboxRuntime`]:
//! install (intent → restore → env in memory → installed), capture
//! (pack → seal → envelope durable, under the key barrier) and scrub.
//! Lifecycle sequencing (install-before-READY, teardown attempts, expiry)
//! is wired by the daemon service on top of these steps.

use anyhow::{Result, bail};
use login_definition::{BundleFileKind, decode_bundle};
use sandbox_protocol::{CredentialInstalledV11, SpecLeaseV11};
use sandbox_runtime::{
    CredentialGuest, CredentialPackRequest, CredentialPathSet, CredentialRestoreFile,
    CredentialRestoreRequest, CredentialScrubRequest, SandboxRuntime,
};

use super::SecretBytes;
use super::journal::InstallIntent;
use super::outbox::OutboxEntry;
use super::store::{CaptureContext, CredentialStore};
use super::transfer::{ReceivedBundle, definition_for, digest_bytes};

pub fn path_set(lease: &SpecLeaseV11) -> CredentialPathSet {
    CredentialPathSet {
        required: lease.files.required.clone(),
        optional: lease.files.optional.clone(),
        exclude: lease.files.exclude.clone(),
    }
}

/// Env values of one installed lease, memory only (never journaled).
#[derive(Debug, Default)]
pub struct InstalledEnv {
    pub values: Vec<(String, SecretBytes)>,
}

/// Installs a received bundle for `lease` on the guest: the install intent
/// is fsynced before the first guest write; files go through the helper
/// (scrub-then-write); env stays in daemon memory.
pub fn install_bundle(
    store: &CredentialStore,
    runtime: &dyn SandboxRuntime,
    guest: &CredentialGuest,
    lease: &SpecLeaseV11,
    request_id: &str,
    received: &ReceivedBundle,
) -> Result<(CredentialInstalledV11, InstalledEnv)> {
    let view = received.view()?;
    let binding = store
        .journal()
        .binding(&received.binding_id)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("bundle for an unrecorded binding"))?;
    if binding.lease_id != lease.lease_id || binding.sandbox_id != guest.sandbox_id {
        bail!("bundle binding does not match the lease");
    }
    store.journal().set_install_intent(
        &received.binding_id,
        InstallIntent {
            request_id: request_id.to_owned(),
            storage_seq: received.storage_seq,
        },
    )?;
    let files: Vec<CredentialRestoreFile<'_>> = view
        .files
        .iter()
        .map(|f| CredentialRestoreFile {
            kind: f.kind,
            path: f.path,
            mode: f.mode,
            data: if f.kind == BundleFileKind::Dir {
                b""
            } else {
                f.data
            },
        })
        .collect();
    if !lease.files.is_empty() {
        runtime
            .credential_restore(&CredentialRestoreRequest {
                guest: guest.clone(),
                declared: path_set(lease),
                files,
            })
            .map_err(|e| anyhow::anyhow!("credential restore failed: {}", e.message))?;
    }
    let env = InstalledEnv {
        values: view
            .env
            .iter()
            .map(|e| (e.name.to_owned(), SecretBytes::copy_from(e.value)))
            .collect(),
    };
    store
        .journal()
        .mark_installed(&received.binding_id, received.storage_seq)?;
    Ok((
        CredentialInstalledV11 {
            lease_id: lease.lease_id.clone(),
            binding_id: received.binding_id.clone(),
            storage_seq: received.storage_seq,
            file_count: view.files.len() as u32,
            env_count: view.env.len() as u32,
        },
        env,
    ))
}

/// Packs the binding's files and seals them durable. The key barrier's read
/// guard spans pack → seal → durable; the packed bundle is
/// re-validated against the spec entry before it is sealed.
pub fn capture_binding(
    store: &CredentialStore,
    runtime: &dyn SandboxRuntime,
    guest: &CredentialGuest,
    lease: &SpecLeaseV11,
    ctx: &CaptureContext,
    now_ms: u64,
) -> Result<OutboxEntry> {
    capture_binding_if(store, runtime, guest, lease, ctx, now_ms, |_| true)?
        .ok_or_else(|| anyhow::anyhow!("capture declined"))
}

/// [`capture_binding`] that seals only when `accept(packed)` holds (a
/// checkpoint whose bytes did not change since the last one). A declined
/// capture allocates no sequence and writes nothing: `Ok(None)`.
pub fn capture_binding_if(
    store: &CredentialStore,
    runtime: &dyn SandboxRuntime,
    guest: &CredentialGuest,
    lease: &SpecLeaseV11,
    ctx: &CaptureContext,
    now_ms: u64,
    accept: impl FnOnce(&[u8]) -> bool,
) -> Result<Option<OutboxEntry>> {
    let definition = definition_for(lease)?;
    let digest = digest_bytes(&lease.definition_digest)?;
    let mut declined = false;
    let sealed = store.seal_capture_with(ctx, now_ms, || {
        let packed = runtime
            .credential_pack(&CredentialPackRequest {
                guest: guest.clone(),
                paths: path_set(lease),
                definition_digest: digest,
                max_bytes: usize::try_from(lease.max_bytes)?,
            })
            .map_err(|e| anyhow::anyhow!("credential pack failed: {}", e.message))?;
        let bundle = SecretBytes::from_zeroizing(packed.bundle.into_zeroizing());
        let view = decode_bundle(bundle.expose(), &definition, &digest)
            .map_err(|e| anyhow::anyhow!("packed bundle invalid: {}", e.reason.as_str()))?;
        if !view.env.is_empty() {
            bail!("a capture carries files only");
        }
        drop(view);
        if !accept(bundle.expose()) {
            declined = true;
            bail!("capture declined");
        }
        Ok(bundle)
    });
    match sealed {
        Ok(entry) => Ok(Some(entry)),
        Err(_) if declined => Ok(None),
        Err(error) => Err(error),
    }
}

/// Scrubs `paths` and reports whether absence was verified.
pub fn scrub_paths(
    runtime: &dyn SandboxRuntime,
    guest: &CredentialGuest,
    paths: Vec<String>,
) -> Result<bool> {
    if paths.is_empty() {
        return Ok(true);
    }
    let out = runtime
        .credential_scrub(&CredentialScrubRequest {
            guest: guest.clone(),
            paths,
        })
        .map_err(|e| anyhow::anyhow!("credential scrub failed: {}", e.message))?;
    Ok(out.verified_absent)
}

/// Included paths of a lease (scrub list for its binding).
pub fn included_paths(lease: &SpecLeaseV11) -> Vec<String> {
    path_set(lease).included()
}

#[cfg(test)]
mod tests;
