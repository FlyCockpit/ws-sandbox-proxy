//! Stopped-sandbox disk offload: the runtime-side names,
//! types and the parsing of Incus JSON the daemon relies on.
//!
//! Every Incus field read here is [unverified] against a live Incus (C9 live
//! check): `last_used_at` on the instance, `volatile.cloud-init.instance-id`
//! in its config, `disk.root.usage` in its state, the alias list shape and
//! the operation resources. The parsers are isolated in this file so the live
//! check can correct one function without touching the callers. A field
//! that is absent parses as `None`; a document of the wrong shape is an
//! error, never a guess.

use sandbox_protocol::SandboxErrorCode;

use crate::RuntimeError;

/// Alias prefix of a published offload image (`wssp-off-<ownerTag>-<offloadId>`;
/// unmarked `wssp-off-<offloadId>` aliases predate the owner tag).
/// The image cache never manages such an image: it is aliased (so never
/// evicted) and never recorded in the cache journal (S6).
pub const OFFLOAD_ALIAS_PREFIX: &str = "wssp-off-";

/// Bound of every disk image IO step (`incus publish`, export, import):
/// four hours. A reconnect waits at most this long for an in-flight publish
/// (F13).
pub const IMAGE_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4 * 3600);

/// Length of the owner tag in an offload alias (hex characters).
pub const OFFLOAD_OWNER_TAG_LEN: usize = 12;

/// The alias of offload `offload_id` published by the daemon whose owner
/// tag is `owner_tag` (`wssp-off-<tag>-<offloadId>`). Images (and their
/// aliases) live in the default Incus image store shared by every daemon on
/// the machine, so the tag scopes each daemon's startup sweep to its own
/// images. The tag is [`OFFLOAD_OWNER_TAG_LEN`] lowercase hex characters;
/// the id is the server's offload row id (`[A-Za-z0-9_-]`); the whole alias
/// must be a valid Incus name (at most 63 bytes, starting alphanumeric).
pub fn offload_alias(owner_tag: &str, offload_id: &str) -> Result<String, RuntimeError> {
    if !valid_owner_tag(owner_tag) || offload_id.is_empty() {
        return Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid offload owner tag or id",
        ));
    }
    let alias = format!("{OFFLOAD_ALIAS_PREFIX}{owner_tag}-{offload_id}");
    validate_offload_alias(&alias)?;
    Ok(alias)
}

fn valid_owner_tag(tag: &str) -> bool {
    tag.len() == OFFLOAD_OWNER_TAG_LEN
        && tag
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Whether `alias` was published by the daemon tagged `owner_tag`. An alias
/// of another daemon, or an unmarked (pre-tag) one, is never owned.
pub fn offload_alias_owned_by(alias: &str, owner_tag: &str) -> bool {
    valid_owner_tag(owner_tag)
        && validate_offload_alias(alias).is_ok()
        && alias
            .strip_prefix(OFFLOAD_ALIAS_PREFIX)
            .and_then(|rest| rest.strip_prefix(owner_tag))
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|id| !id.is_empty())
}

/// `wssp-off-` + `[A-Za-z0-9_-]{1,54}`.
pub fn validate_offload_alias(alias: &str) -> Result<(), RuntimeError> {
    let valid = alias.len() <= 63
        && alias.strip_prefix(OFFLOAD_ALIAS_PREFIX).is_some_and(|id| {
            !id.is_empty()
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if valid {
        Ok(())
    } else {
        Err(RuntimeError::new(
            SandboxErrorCode::ProtocolError,
            "invalid offload image alias",
        ))
    }
}

/// The image `publish_stopped_instance` produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedDisk {
    /// `sha256:<hex>`; a unified image, so also the export's SHA-256.
    pub fingerprint: String,
    /// The image's stored (compressed) size when Incus reports it.
    pub size_bytes: Option<u64>,
}

/// One `wssp-off-*` alias of the host image store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffloadAlias {
    pub alias: String,
    /// `sha256:<hex>`.
    pub fingerprint: String,
}

fn shape(what: &str) -> RuntimeError {
    RuntimeError::new(
        SandboxErrorCode::ProtocolError,
        format!("incus {what} JSON has an unexpected shape"),
    )
}

/// `last_used_at` of an instance document (`GET /1.0/instances/<name>`):
/// the RFC 3339 text as Incus wrote it, compared only for equality (§8.1).
/// The zero time Incus reports for a never-started instance is kept as is.
pub fn parse_last_used(instance: &serde_json::Value) -> Result<Option<String>, RuntimeError> {
    let object = instance.as_object().ok_or_else(|| shape("instance"))?;
    match object.get("last_used_at") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(text)) if text.len() <= 64 => Ok(Some(text.clone())),
        Some(_) => Err(shape("instance last_used_at")),
    }
}

/// `volatile.cloud-init.instance-id` from an instance document's `config`.
pub fn parse_cloud_init_instance_id(
    instance: &serde_json::Value,
) -> Result<Option<String>, RuntimeError> {
    let object = instance.as_object().ok_or_else(|| shape("instance"))?;
    let Some(config) = object.get("config") else {
        return Ok(None);
    };
    let config = config.as_object().ok_or_else(|| shape("instance config"))?;
    match config.get("volatile.cloud-init.instance-id") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(id)) if id.len() <= 128 => Ok(Some(id.clone())),
        Some(_) => Err(shape("instance cloud-init id")),
    }
}

/// `disk.root.usage` (bytes) from an instance state document
/// (`GET /1.0/instances/<name>/state`). Incus may omit it for a stopped VM;
/// the caller then charges the configured root size.
pub fn parse_root_usage(state: &serde_json::Value) -> Result<Option<u64>, RuntimeError> {
    let object = state.as_object().ok_or_else(|| shape("instance state"))?;
    let Some(disk) = object.get("disk") else {
        return Ok(None);
    };
    if disk.is_null() {
        return Ok(None);
    }
    let disk = disk
        .as_object()
        .ok_or_else(|| shape("instance state disk"))?;
    let Some(root) = disk.get("root") else {
        return Ok(None);
    };
    match root.get("usage") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| shape("instance root usage")),
    }
}

/// At most this many aliases in one read; more is an error.
const ALIAS_INVENTORY_MAX: usize = 8192;

/// `wssp-off-*` entries of `GET /1.0/images/aliases?recursion=1`
/// (`[{name, target, ...}]`). Other aliases are ignored; a malformed entry
/// fails the whole read (the sweep never acts on a partial view).
pub fn parse_offload_aliases(list: &serde_json::Value) -> Result<Vec<OffloadAlias>, RuntimeError> {
    let entries = list.as_array().ok_or_else(|| shape("image aliases"))?;
    if entries.len() > ALIAS_INVENTORY_MAX {
        return Err(shape("image aliases (too many)"));
    }
    let mut out = Vec::new();
    for entry in entries {
        let name = entry
            .get("name")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| shape("image alias"))?;
        if !name.starts_with(OFFLOAD_ALIAS_PREFIX) {
            continue;
        }
        let target = entry
            .get("target")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| shape("image alias target"))?;
        // Incus names the target by its bare hex fingerprint.
        let fingerprint = crate::normalize_incus_fingerprint(&format!("sha256:{target}"))
            .map_err(|_| shape("image alias target"))?;
        // A name that is not a valid offload alias was not written by us;
        // never delete it.
        if validate_offload_alias(name).is_ok() {
            out.push(OffloadAlias {
                alias: name.to_owned(),
                fingerprint,
            });
        }
    }
    Ok(out)
}

/// An image-from-instance pack (`incus publish`) by its progress stage.
fn publish_in_progress(operation: &serde_json::Value) -> bool {
    const STAGE: &str = "create_image_from_container_pack";
    let Some(metadata) = operation
        .get("metadata")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    metadata.contains_key(&format!("{STAGE}_progress"))
        || metadata
            .get("progress")
            .and_then(|progress| progress.get("stage"))
            .and_then(serde_json::Value::as_str)
            == Some(STAGE)
}

/// Whether `GET /1.0/operations?recursion=1` lists a running (or pending)
/// operation whose resources name instance `instance` (R13: an interrupted
/// publish may still be running inside Incus after a daemon restart).
pub fn parse_instance_operation_running(
    operations: &serde_json::Value,
    instance: &str,
) -> Result<bool, RuntimeError> {
    let object = operations.as_object().ok_or_else(|| shape("operations"))?;
    let wanted = format!("/1.0/instances/{instance}");
    for class in ["running", "pending"] {
        let Some(list) = object.get(class) else {
            continue;
        };
        if list.is_null() {
            continue;
        }
        let list = list.as_array().ok_or_else(|| shape("operations list"))?;
        for operation in list {
            // C9 live (Incus 6): a running `incus publish` names NO resource
            // (`"resources": {}`, description "Downloading image"); only its
            // progress stage tells it apart. It cannot be attributed to an
            // instance, so any such operation in this project counts as a
            // publish that may still be ours (R13 waits, bounded).
            if publish_in_progress(operation) {
                return Ok(true);
            }
            let Some(resources) = operation.get("resources") else {
                continue;
            };
            if resources.is_null() {
                continue;
            }
            let resources = resources
                .as_object()
                .ok_or_else(|| shape("operation resources"))?;
            for key in ["instances", "containers", "virtual-machines"] {
                let Some(urls) = resources.get(key).and_then(serde_json::Value::as_array) else {
                    continue;
                };
                if urls
                    .iter()
                    .filter_map(serde_json::Value::as_str)
                    .any(|url| {
                        let path = url.split_once('?').map_or(url, |(path, _)| path);
                        path == wanted || path.starts_with(&format!("{wanted}/"))
                    })
                {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn aliases_are_bounded_and_offload_only() {
        const TAG: &str = "0123456789ab";
        assert_eq!(
            offload_alias(TAG, "off_1-a").unwrap(),
            "wssp-off-0123456789ab-off_1-a"
        );
        for bad in ["", "a/b", "a b", &"x".repeat(42)] {
            assert!(offload_alias(TAG, bad).is_err(), "{bad}");
        }
        for tag in [
            "",
            "0123456789a",
            "0123456789abc",
            "0123456789AB",
            "0123456789-x",
        ] {
            assert!(offload_alias(tag, "off_1").is_err(), "{tag}");
        }
        assert!(validate_offload_alias("wssp-sbx-1").is_err());
    }

    #[test]
    fn ownership_is_the_exact_tag_only() {
        const TAG: &str = "0123456789ab";
        let own = offload_alias(TAG, "o1").unwrap();
        assert!(offload_alias_owned_by(&own, TAG));
        // Another daemon's tag, an unmarked legacy alias, a bare tag.
        assert!(!offload_alias_owned_by(&own, "fe9876543210"));
        assert!(!offload_alias_owned_by("wssp-off-o1", TAG));
        assert!(!offload_alias_owned_by("wssp-off-0123456789ab", TAG));
        assert!(!offload_alias_owned_by("wssp-off-0123456789ab-", TAG));
        assert!(!offload_alias_owned_by("wssp-off-0123456789abc-o1", TAG));
        assert!(!offload_alias_owned_by(&own, ""));
    }

    #[test]
    fn instance_fields_parse_or_fail_closed() {
        let instance = json!({
            "last_used_at": "2026-11-06T10:00:00.123Z",
            "config": {"volatile.cloud-init.instance-id": "abc-123"}
        });
        assert_eq!(
            parse_last_used(&instance).unwrap().as_deref(),
            Some("2026-11-06T10:00:00.123Z")
        );
        assert_eq!(
            parse_cloud_init_instance_id(&instance).unwrap().as_deref(),
            Some("abc-123")
        );
        assert_eq!(parse_last_used(&json!({})).unwrap(), None);
        assert_eq!(
            parse_cloud_init_instance_id(&json!({"config": {}})).unwrap(),
            None
        );
        assert!(parse_last_used(&json!({"last_used_at": 7})).is_err());
        assert!(parse_cloud_init_instance_id(&json!({"config": []})).is_err());
        assert!(parse_last_used(&json!([])).is_err());
    }

    #[test]
    fn root_usage_parses_or_is_absent() {
        assert_eq!(
            parse_root_usage(&json!({"disk": {"root": {"usage": 4096}}})).unwrap(),
            Some(4096)
        );
        assert_eq!(parse_root_usage(&json!({"disk": null})).unwrap(), None);
        assert_eq!(parse_root_usage(&json!({"disk": {}})).unwrap(), None);
        assert!(parse_root_usage(&json!({"disk": {"root": {"usage": "x"}}})).is_err());
    }

    #[test]
    fn alias_list_keeps_only_valid_offload_aliases() {
        let hex = "ab".repeat(32);
        let list = json!([
            {"name": "wssp-off-o1", "target": hex},
            {"name": "ubuntu", "target": hex},
            {"name": "wssp-off-bad/name", "target": hex},
        ]);
        assert_eq!(
            parse_offload_aliases(&list).unwrap(),
            [OffloadAlias {
                alias: "wssp-off-o1".into(),
                fingerprint: format!("sha256:{hex}"),
            }]
        );
        assert!(parse_offload_aliases(&json!([{"name": "wssp-off-o1"}])).is_err());
        assert!(parse_offload_aliases(&json!({})).is_err());
    }

    #[test]
    fn running_operations_name_the_instance() {
        let ops = json!({
            "running": [{"status": "Running", "resources": {"instances": ["/1.0/instances/wssp-sbx-a?project=p"]}}],
            "success": [{"resources": {"instances": ["/1.0/instances/wssp-sbx-b"]}}]
        });
        assert!(parse_instance_operation_running(&ops, "wssp-sbx-a").unwrap());
        assert!(!parse_instance_operation_running(&ops, "wssp-sbx-b").unwrap());
        assert!(!parse_instance_operation_running(&ops, "wssp-sbx-ab").unwrap());
        assert!(!parse_instance_operation_running(&json!({}), "wssp-sbx-a").unwrap());
        assert!(parse_instance_operation_running(&json!([]), "wssp-sbx-a").is_err());
    }

    /// C9 live: the shape Incus 6 reports for a running `incus publish`.
    #[test]
    fn a_running_publish_without_resources_counts_as_running() {
        let ops = json!({"running": [{
            "class": "task", "description": "Downloading image", "status": "Running",
            "metadata": {
                "create_image_from_container_pack_progress": "Exporting: 40%",
                "progress": {"percent": "40", "speed": "0", "stage": "create_image_from_container_pack"}
            },
            "resources": {}
        }]});
        assert!(parse_instance_operation_running(&ops, "wssp-sbx-a").unwrap());
        // A download of another image (no pack stage) is not a publish.
        let other = json!({"running": [{"description": "Downloading image", "resources": {},
            "metadata": {"download_progress": "rootfs: 10%"}}]});
        assert!(!parse_instance_operation_running(&other, "wssp-sbx-a").unwrap());
    }
}
