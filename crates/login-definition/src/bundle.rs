//! Bundle v1 codec (same layout, rules and check order as `bundle.ts`).
//! All integers are big-endian.
//!
//! ```text
//! header     : "WSCB"(4) | u8 version=1 | definitionDigest[32] | u16 fileCount | u16 envCount  = 41 bytes
//! file entry : u8 kind(1=file,2=dir) | u16 mode | u16 pathLen | path | u32 dataLen | data     = 9 + pathLen + dataLen
//! env entry  : u8 nameLen | name | u16 valueLen | value                                        = 3 + nameLen + valueLen
//! ```
//!
//! The encoding is canonical: files in strictly ascending path byte order,
//! env entries in strictly ascending name order, file modes exactly 0600 or
//! 0700, directory modes exactly 0700. The decoder refuses anything else.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;

use crate::definition::LoginDefinition;
use crate::limits::{
    BUNDLE_ENV_COUNT_MAX, BUNDLE_FILE_COUNT_MAX, BUNDLE_HEADER_BYTES, BUNDLE_PATH_MAX_BYTES,
    BUNDLE_PATH_TOTAL_MAX_BYTES, ENV_NAME_MAX_BYTES, ENV_VALUE_MAX_BYTES,
};
use crate::paths::{path_problem, path_within};
use crate::secret::SecretBuf;

pub const BUNDLE_MAGIC: &[u8; 4] = b"WSCB";
pub const BUNDLE_VERSION: u8 = 1;
pub const BUNDLE_KIND_FILE: u8 = 1;
pub const BUNDLE_KIND_DIR: u8 = 2;
pub const BUNDLE_FILE_MODES: [u16; 2] = [0o600, 0o700];
pub const BUNDLE_DIR_MODE: u16 = 0o700;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFileKind {
    File,
    Dir,
}

/// One file or directory, borrowed from the caller's plaintext buffer (the
/// decoder's input or the capture's own storage); this crate never copies
/// `data`. `Debug` never prints `data`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleFile<'a> {
    pub kind: BundleFileKind,
    pub path: &'a str,
    pub mode: u16,
    /// Always empty for a directory.
    pub data: &'a [u8],
}

impl fmt::Debug for BundleFile<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleFile")
            .field("kind", &self.kind)
            .field("path", &self.path)
            .field("mode", &format_args!("{:o}", self.mode))
            .field(
                "data",
                &format_args!("<{} bytes redacted>", self.data.len()),
            )
            .finish()
    }
}

/// One env value, borrowed like [`BundleFile`]. `Debug` never prints `value`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BundleEnv<'a> {
    pub name: &'a str,
    pub value: &'a [u8],
}

impl fmt::Debug for BundleEnv<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleEnv")
            .field("name", &self.name)
            .field(
                "value",
                &format_args!("<{} bytes redacted>", self.value.len()),
            )
            .finish()
    }
}

/// A view of a bundle's entries. The plaintext stays in the buffer it
/// borrows from, so wiping that one buffer wipes the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle<'a> {
    pub definition_digest: [u8; 32],
    pub files: Vec<BundleFile<'a>>,
    pub env: Vec<BundleEnv<'a>>,
}

macro_rules! reasons {
    ($($variant:ident => $text:literal,)*) => {
        /// The failed rule. Never carries bytes, paths or values.
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum BundleErrorReason { $($variant,)* }

        impl BundleErrorReason {
            pub const ALL: &[Self] = &[$(Self::$variant,)*];

            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text,)* }
            }
        }
    };
}

reasons! {
    Truncated => "truncated",
    BadMagic => "bad_magic",
    UnsupportedVersion => "unsupported_version",
    DigestMismatch => "digest_mismatch",
    FileCount => "file_count",
    EnvCount => "env_count",
    BadKind => "bad_kind",
    BadMode => "bad_mode",
    PathLength => "path_length",
    PathTotal => "path_total",
    InvalidPath => "invalid_path",
    UnsortedPath => "unsorted_path",
    DuplicatePath => "duplicate_path",
    UndeclaredPath => "undeclared_path",
    ExcludedPath => "excluded_path",
    UnderFile => "under_file",
    DirHasData => "dir_has_data",
    DataTotal => "data_total",
    EnvNameLength => "env_name_length",
    UnsortedEnv => "unsorted_env",
    DuplicateEnv => "duplicate_env",
    UndeclaredEnv => "undeclared_env",
    EnvValueLength => "env_value_length",
    EnvValueNul => "env_value_nul",
    TrailingBytes => "trailing_bytes",
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid credential bundle: {}", reason.as_str())]
pub struct BundleError {
    pub reason: BundleErrorReason,
}

impl From<BundleErrorReason> for BundleError {
    fn from(reason: BundleErrorReason) -> Self {
        Self { reason }
    }
}

/// File modes keep only the owner execute bit; directories are always 0700.
#[must_use]
pub const fn normalize_mode(kind: BundleFileKind, mode: u16) -> u16 {
    match kind {
        BundleFileKind::Dir => BUNDLE_DIR_MODE,
        BundleFileKind::File if mode & 0o100 != 0 => 0o700,
        BundleFileKind::File => 0o600,
    }
}

fn len16(n: usize) -> [u8; 2] {
    u16::try_from(n).unwrap_or(u16::MAX).to_be_bytes()
}

fn kind_byte(kind: BundleFileKind) -> u8 {
    match kind {
        BundleFileKind::File => BUNDLE_KIND_FILE,
        BundleFileKind::Dir => BUNDLE_KIND_DIR,
    }
}

/// Writes entries in the given order into one exactly sized zeroizing buffer.
/// A length that does not fit its field saturates.
fn write_bundle<'b, 'a: 'b>(
    digest: &[u8; 32],
    files: &[&'b BundleFile<'a>],
    env: &[&'b BundleEnv<'a>],
    mode_of: impl Fn(&BundleFile<'_>) -> u16,
) -> SecretBuf {
    let size = BUNDLE_HEADER_BYTES
        + files
            .iter()
            .map(|f| 9 + f.path.len() + f.data.len())
            .sum::<usize>()
        + env
            .iter()
            .map(|e| 3 + e.name.len() + e.value.len())
            .sum::<usize>();
    let mut out = SecretBuf::with_capacity(size);
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(BUNDLE_VERSION);
    out.extend_from_slice(digest);
    out.extend_from_slice(&len16(files.len()));
    out.extend_from_slice(&len16(env.len()));
    for file in files {
        out.push(kind_byte(file.kind));
        out.extend_from_slice(&mode_of(file).to_be_bytes());
        out.extend_from_slice(&len16(file.path.len()));
        out.extend_from_slice(file.path.as_bytes());
        out.extend_from_slice(
            &u32::try_from(file.data.len())
                .unwrap_or(u32::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(file.data);
    }
    for entry in env {
        out.push(u8::try_from(entry.name.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&len16(entry.value.len()));
        out.extend_from_slice(entry.value);
    }
    out
}

/// Serializes entries exactly as given, without validation (vectors and
/// tests). A length that does not fit its field saturates.
#[must_use]
pub fn serialize_bundle_unchecked(bundle: &Bundle<'_>) -> SecretBuf {
    let files: Vec<&BundleFile<'_>> = bundle.files.iter().collect();
    let env: Vec<&BundleEnv<'_>> = bundle.env.iter().collect();
    write_bundle(&bundle.definition_digest, &files, &env, |f| f.mode)
}

/// Encodes canonically (sorted, modes normalized). Entries are checked by the
/// same rules, in the same order, as [`decode_bundle`] applies to the bytes,
/// so every encoded bundle decodes; the plaintext is copied once, into the
/// returned buffer.
pub fn encode_bundle(
    bundle: &Bundle<'_>,
    definition: &LoginDefinition,
) -> Result<SecretBuf, BundleError> {
    let mut files: Vec<&BundleFile<'_>> = bundle.files.iter().collect();
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let mut env: Vec<&BundleEnv<'_>> = bundle.env.iter().collect();
    env.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let mut rules = Rules::new(definition, files.len(), env.len())?;
    for file in &files {
        rules.file_head(
            file.kind,
            normalize_mode(file.kind, file.mode),
            file.path.len(),
        )?;
        rules.file_path(file.kind, file.path.as_bytes())?;
        rules.file_data(file.kind, file.data.len())?;
    }
    for entry in &env {
        rules.env_name(entry.name.as_bytes())?;
        rules.env_value(entry.value)?;
    }
    Ok(write_bundle(&bundle.definition_digest, &files, &env, |f| {
        normalize_mode(f.kind, f.mode)
    }))
}

/// Every per-entry rule of bundle v1, applied in wire order. The decoder runs
/// it over bytes, the encoder over sorted references.
struct Rules<'d, 'a> {
    declared: Vec<&'d str>,
    excluded: Vec<&'d str>,
    names: BTreeSet<&'d str>,
    max_data: usize,
    file_paths: BTreeSet<&'a str>,
    path_total: usize,
    data_total: usize,
    previous_path: Option<&'a [u8]>,
    previous_name: Option<&'a [u8]>,
}

impl<'d, 'a> Rules<'d, 'a> {
    fn new(
        definition: &'d LoginDefinition,
        file_count: usize,
        env_count: usize,
    ) -> Result<Self, BundleError> {
        if file_count > BUNDLE_FILE_COUNT_MAX {
            return Err(BundleErrorReason::FileCount.into());
        }
        if env_count > BUNDLE_ENV_COUNT_MAX {
            return Err(BundleErrorReason::EnvCount.into());
        }
        let creds = &definition.credentials;
        Ok(Self {
            declared: creds.included_paths().collect(),
            excluded: creds.excluded_paths().collect(),
            names: creds
                .env_entries()
                .iter()
                .map(|e| e.name.as_str())
                .collect(),
            max_data: creds.max_bytes(),
            file_paths: BTreeSet::new(),
            path_total: 0,
            data_total: 0,
            previous_path: None,
            previous_name: None,
        })
    }

    fn file_head(
        &mut self,
        kind: BundleFileKind,
        mode: u16,
        path_len: usize,
    ) -> Result<(), BundleError> {
        use BundleErrorReason as R;
        let mode_ok = match kind {
            BundleFileKind::File => BUNDLE_FILE_MODES.contains(&mode),
            BundleFileKind::Dir => mode == BUNDLE_DIR_MODE,
        };
        if !mode_ok {
            return Err(R::BadMode.into());
        }
        if path_len > BUNDLE_PATH_MAX_BYTES {
            return Err(R::PathLength.into());
        }
        self.path_total += path_len;
        if self.path_total > BUNDLE_PATH_TOTAL_MAX_BYTES {
            return Err(R::PathTotal.into());
        }
        Ok(())
    }

    fn file_path(&mut self, kind: BundleFileKind, raw: &'a [u8]) -> Result<&'a str, BundleError> {
        use BundleErrorReason as R;
        let path = std::str::from_utf8(raw).map_err(|_| R::InvalidPath)?;
        if path_problem(path, BUNDLE_PATH_MAX_BYTES).is_some() {
            return Err(R::InvalidPath.into());
        }
        if let Some(previous) = self.previous_path {
            match previous.cmp(raw) {
                Ordering::Equal => return Err(R::DuplicatePath.into()),
                Ordering::Greater => return Err(R::UnsortedPath.into()),
                Ordering::Less => {}
            }
        }
        self.previous_path = Some(raw);
        if !self.declared.iter().any(|d| path_within(path, d)) {
            return Err(R::UndeclaredPath.into());
        }
        if self.excluded.iter().any(|e| path_within(path, e)) {
            return Err(R::ExcludedPath.into());
        }
        if path
            .match_indices('/')
            .any(|(slash, _)| self.file_paths.contains(&path[..slash]))
        {
            return Err(R::UnderFile.into());
        }
        if kind == BundleFileKind::File {
            self.file_paths.insert(path);
        }
        Ok(path)
    }

    fn file_data(&mut self, kind: BundleFileKind, data_len: usize) -> Result<(), BundleError> {
        use BundleErrorReason as R;
        if kind == BundleFileKind::Dir && data_len != 0 {
            return Err(R::DirHasData.into());
        }
        self.data_total = self.data_total.saturating_add(data_len);
        if self.data_total > self.max_data {
            return Err(R::DataTotal.into());
        }
        Ok(())
    }

    fn env_name_len(name_len: usize) -> Result<(), BundleError> {
        if name_len > ENV_NAME_MAX_BYTES {
            return Err(BundleErrorReason::EnvNameLength.into());
        }
        Ok(())
    }

    fn env_name(&mut self, raw: &'a [u8]) -> Result<&'a str, BundleError> {
        use BundleErrorReason as R;
        Self::env_name_len(raw.len())?;
        if let Some(previous) = self.previous_name {
            match previous.cmp(raw) {
                Ordering::Equal => return Err(R::DuplicateEnv.into()),
                Ordering::Greater => return Err(R::UnsortedEnv.into()),
                Ordering::Less => {}
            }
        }
        self.previous_name = Some(raw);
        let name = std::str::from_utf8(raw).map_err(|_| R::UndeclaredEnv)?;
        if !self.names.contains(name) {
            return Err(R::UndeclaredEnv.into());
        }
        Ok(name)
    }

    fn env_value_len(value_len: usize) -> Result<(), BundleError> {
        if value_len > ENV_VALUE_MAX_BYTES {
            return Err(BundleErrorReason::EnvValueLength.into());
        }
        Ok(())
    }

    fn env_value(&self, value: &[u8]) -> Result<(), BundleError> {
        Self::env_value_len(value.len())?;
        if value.contains(&0) {
            return Err(BundleErrorReason::EnvValueNul.into());
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BundleError> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len());
        let end = end.ok_or(BundleErrorReason::Truncated)?;
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }
    fn need(&self, n: usize) -> Result<(), BundleError> {
        if self.bytes.len() - self.at < n {
            return Err(BundleErrorReason::Truncated.into());
        }
        Ok(())
    }
    fn u8(&mut self) -> Result<u8, BundleError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BundleError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, BundleError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
}

/// Decodes and validates a bundle against its verified definition. The
/// result borrows paths and values from `bytes`; nothing is copied.
pub fn decode_bundle<'a>(
    bytes: &'a [u8],
    definition: &LoginDefinition,
    expected_digest: &[u8; 32],
) -> Result<Bundle<'a>, BundleError> {
    use BundleErrorReason as R;
    let mut r = Reader { bytes, at: 0 };
    r.need(BUNDLE_HEADER_BYTES)?;
    if r.take(4)? != BUNDLE_MAGIC {
        return Err(R::BadMagic.into());
    }
    if r.u8()? != BUNDLE_VERSION {
        return Err(R::UnsupportedVersion.into());
    }
    let digest: [u8; 32] = r.take(32)?.try_into().map_err(|_| R::Truncated)?;
    if &digest != expected_digest {
        return Err(R::DigestMismatch.into());
    }
    let file_count = usize::from(r.u16()?);
    let env_count = usize::from(r.u16()?);
    let mut rules = Rules::new(definition, file_count, env_count)?;

    let mut files = Vec::with_capacity(file_count);
    for _ in 0..file_count {
        r.need(5)?;
        let kind = match r.u8()? {
            BUNDLE_KIND_FILE => BundleFileKind::File,
            BUNDLE_KIND_DIR => BundleFileKind::Dir,
            _ => return Err(R::BadKind.into()),
        };
        let mode = r.u16()?;
        let path_len = usize::from(r.u16()?);
        rules.file_head(kind, mode, path_len)?;
        let path = rules.file_path(kind, r.take(path_len)?)?;
        let data_len = usize::try_from(r.u32()?).map_err(|_| R::DataTotal)?;
        rules.file_data(kind, data_len)?;
        let data = r.take(data_len)?;
        files.push(BundleFile {
            kind,
            path,
            mode,
            data,
        });
    }

    let mut env = Vec::with_capacity(env_count);
    for _ in 0..env_count {
        let name_len = usize::from(r.u8()?);
        Rules::env_name_len(name_len)?;
        let name = rules.env_name(r.take(name_len)?)?;
        let value_len = usize::from(r.u16()?);
        Rules::env_value_len(value_len)?;
        let value = r.take(value_len)?;
        rules.env_value(value)?;
        env.push(BundleEnv { name, value });
    }
    if r.at != bytes.len() {
        return Err(R::TrailingBytes.into());
    }
    Ok(Bundle {
        definition_digest: digest,
        files,
        env,
    })
}

/// Required paths with no entry at or below them (a capture missing them is incomplete).
#[must_use]
pub fn missing_required_paths<'d>(
    bundle: &Bundle<'_>,
    definition: &'d LoginDefinition,
) -> Vec<&'d str> {
    definition
        .credentials
        .required_paths()
        .filter(|required| !bundle.files.iter().any(|f| path_within(f.path, required)))
        .collect()
}
