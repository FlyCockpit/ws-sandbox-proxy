//! Image cache journal: a file separate from the operation journal (0600,
//! atomic rename). It records only images this daemon imported itself (absent
//! before the import) or published by capture; operator images are never
//! managed, so never evicted.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};

pub const CACHE_JOURNAL_FILE: &str = "image-cache.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    Fetched,
    Captured,
    Replica,
}

impl From<Origin> for sandbox_protocol::ImageOrigin {
    fn from(origin: Origin) -> Self {
        match origin {
            Origin::Fetched => Self::Fetched,
            Origin::Captured => Self::Captured,
            Origin::Replica => Self::Replica,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheEntry {
    pub fingerprint: String,
    pub owners: BTreeSet<String>,
    pub compressed_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpacked_bytes: Option<u64>,
    pub origin: Origin,
    /// Origin pin: the only copy until the server says it is durable elsewhere.
    pub pinned: bool,
    pub last_used_unix_ms: u64,
    /// When the last foreign use ended (foreign grace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_since_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheJournalFile {
    pub version: u32,
    pub entries: BTreeMap<String, CacheEntry>,
}

#[derive(Debug)]
pub struct CacheJournal {
    path: PathBuf,
    pub file: CacheJournalFile,
}

impl CacheJournal {
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir).with_context(|| format!("creating `{}`", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("securing `{}`", dir.display()))?;
        }
        let path = dir.join(CACHE_JOURNAL_FILE);
        let file = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing `{}`", path.display()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => CacheJournalFile {
                version: 1,
                entries: BTreeMap::new(),
            },
            Err(error) => {
                return Err(error).with_context(|| format!("reading `{}`", path.display()));
            }
        };
        anyhow::ensure!(file.version == 1, "unsupported image cache journal version");
        Ok(Self { path, file })
    }

    /// Best-effort save for bookkeeping that the next write or reconcile
    /// repairs: a failure is logged instead of failing the caller.
    pub fn save_or_warn(&self) {
        if let Err(error) = self.save() {
            tracing::warn!(reason = %format!("{error:#}"), "image cache journal save failed");
        }
    }

    pub fn save(&self) -> Result<()> {
        let dir = self
            .path
            .parent()
            .context("image cache journal has no directory")?;
        let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tmp.as_file()
                .set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        tmp.write_all(&serde_json::to_vec(&self.file)?)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    pub fn used_bytes(&self) -> u64 {
        self.file.entries.values().map(|e| e.compressed_bytes).sum()
    }

    /// Bytes of images none of whose owners is the host owner.
    pub fn foreign_bytes(&self, host_owner: Option<&str>) -> u64 {
        self.file
            .entries
            .values()
            .filter(|e| host_owner.is_none_or(|owner| !e.owners.contains(owner)))
            .map(|e| e.compressed_bytes)
            .sum()
    }

    pub fn totals(&self, host_owner: Option<&str>) -> sandbox_protocol::ImageCacheTotals {
        let used = self.used_bytes();
        sandbox_protocol::ImageCacheTotals {
            used_bytes: used,
            foreign_bytes: self.foreign_bytes(host_owner).min(used),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_round_trips_atomically_with_private_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let mut journal = CacheJournal::open(dir.path()).unwrap();
        journal.file.entries.insert(
            "sha256:aa".into(),
            CacheEntry {
                fingerprint: "sha256:aa".into(),
                owners: ["owner".to_owned()].into(),
                compressed_bytes: 10,
                unpacked_bytes: None,
                origin: Origin::Captured,
                pinned: true,
                last_used_unix_ms: 1,
                idle_since_unix_ms: None,
            },
        );
        journal.save().unwrap();
        let reopened = CacheJournal::open(dir.path()).unwrap();
        assert_eq!(reopened.file, journal.file);
        assert_eq!(reopened.totals(Some("owner")).foreign_bytes, 0);
        assert_eq!(reopened.totals(Some("other")).foreign_bytes, 10);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join(CACHE_JOURNAL_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
