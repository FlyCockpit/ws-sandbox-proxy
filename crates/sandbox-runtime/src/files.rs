//! Private, immutable file captures. Paths are generated here, never supplied by peers.
use crate::RuntimeError;
use sandbox_protocol::SandboxErrorCode;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// One relay frame. Equal to the server's fixed transfer chunk (C27), so every
/// non-final relay chunk lands on a durable 1 MiB spool offset.
pub const FILE_CHUNK_BYTES: usize = 1024 * 1024;
/// One transfer cap end to end: equals the server's `TRANSFER_MAX_BYTES`
/// ceiling (`@wssp/sandbox-contracts`), which `TRANSFER_MAX_BYTES` env values may
/// lower but never exceed. A server test pins this literal.
pub const FILE_MAX_BYTES: u64 = 1024 * 1024 * 1024;
const DISK_BYTES: u64 = 10 * FILE_MAX_BYTES;
/// Active transfer slots of this host.
const ACTIVE_SLOTS: usize = 4;
const CREATOR_ACTIVE_SLOTS: usize = ACTIVE_SLOTS - 1;
// A creator cannot reserve more bytes than its three maximum-size captures.
const CREATOR_DISK_BYTES: u64 = CREATOR_ACTIVE_SLOTS as u64 * FILE_MAX_BYTES;
type StagingUsage = (u64, usize, BTreeMap<String, (u64, usize)>);
/// `(reserved bytes, active slots)` of *charged* host staging. Guest-disk models
/// (FakeRuntime) hold uncharged storage and never consume these slots.
#[cfg(not(test))]
static RESERVED: Mutex<StagingUsage> = Mutex::new((0, 0, BTreeMap::new()));
#[cfg(not(test))]
fn ledger() -> &'static Mutex<StagingUsage> {
    &RESERVED
}
fn release(used: &mut StagingUsage, creator: &str, reserved: u64) {
    used.0 -= reserved;
    used.1 -= 1;
    if let Some(local) = used.2.get_mut(creator) {
        local.0 -= reserved;
        local.1 -= 1;
        if local.1 == 0 {
            used.2.remove(creator);
        }
    }
}
fn io(error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::new(SandboxErrorCode::Internal, format!("file staging: {error}"))
}
#[derive(Debug)]
struct Storage {
    /// `None` only inside `Drop`: the descriptor closes before the charge is
    /// released, so released quota never still pins unlinked disk blocks.
    file: Option<File>,
    reserved: u64,
    creator: String,
    /// The ledger this storage charged, if any.
    charged: Option<&'static Mutex<StagingUsage>>,
}
impl Storage {
    fn file(&self) -> &File {
        self.file
            .as_ref()
            .expect("storage file is present until drop")
    }
}
impl Drop for Storage {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Some(ledger) = self.charged {
            let mut used = ledger.lock().unwrap_or_else(|e| e.into_inner());
            release(&mut used, &self.creator, self.reserved);
        }
    }
}
struct ContentReader {
    storage: Arc<Storage>,
    offset: u64,
}
impl Read for ContentReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        #[cfg(unix)]
        let n = {
            use std::os::unix::fs::FileExt;
            self.storage.file().read_at(bytes, self.offset)?
        };
        #[cfg(windows)]
        let n = {
            use std::os::windows::fs::FileExt;
            self.storage.file().seek_read(bytes, self.offset)?
        };
        self.offset += n as u64;
        Ok(n)
    }
}
#[derive(Debug, Clone)]
pub struct FileContent {
    storage: Arc<Storage>,
    length: u64,
    digest: String,
}
impl PartialEq for FileContent {
    fn eq(&self, other: &Self) -> bool {
        self.length == other.length && self.digest == other.digest
    }
}
impl Eq for FileContent {}
impl FileContent {
    pub fn len(&self) -> usize {
        self.length as usize
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }
    pub fn reader(&self) -> impl Read + Send + 'static {
        ContentReader {
            storage: self.storage.clone(),
            offset: 0,
        }
    }
    /// Bounded convenience adapter for tests and small caller-owned buffers.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RuntimeError> {
        let mut writer = FileStaging::new(bytes.len() as u64)?;
        writer.write_all(bytes).map_err(io)?;
        writer.seal(None)
    }
    pub fn read_chunk(&self, offset: u64, size: usize) -> Result<Vec<u8>, RuntimeError> {
        if size > FILE_CHUNK_BYTES || offset > self.length {
            return Err(io("invalid read range"));
        }
        let mut reader = ContentReader {
            storage: self.storage.clone(),
            offset,
        };
        let mut bytes = vec![0; size.min((self.length - offset) as usize)];
        reader.read_exact(&mut bytes).map_err(io)?;
        Ok(bytes)
    }
    /// Whether this content still holds an active host staging slot.
    pub fn is_charged(&self) -> bool {
        self.storage.charged.is_some()
    }
    /// Copy into a runtime-owned model of guest disk. Guest storage is not host
    /// transfer staging, so the copy holds no staging slot; the source's slot
    /// is released when the transfer drops it.
    pub(crate) fn guest_disk_copy(&self) -> Result<Self, RuntimeError> {
        let mut writer = FileStaging::create(self.length, false, &self.storage.creator)?;
        std::io::copy(&mut self.reader(), &mut writer).map_err(io)?;
        writer.seal(Some((self.length, &self.digest)))
    }
    /// A fresh, charged transfer capture of these bytes (what a guest read does).
    pub(crate) fn staged_copy(&self, creator: &str) -> Result<Self, RuntimeError> {
        let mut writer = FileStaging::for_creator(self.length, creator)?;
        std::io::copy(&mut self.reader(), &mut writer).map_err(io)?;
        writer.seal(Some((self.length, &self.digest)))
    }
}

/// A generated private directory and file, unlinked before any payload byte.
fn private_file() -> Result<(File, File), RuntimeError> {
    let mut nonce = [0u8; 16];
    getrandom::fill(&mut nonce).map_err(io)?;
    let id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let directory = std::env::temp_dir().join(format!("wssp-transfer-{id}"));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory).map_err(io)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let path = directory.join("content");
    let opened = (|| {
        let file = options.open(&path).map_err(io)?;
        let reader = file.try_clone().map_err(io)?;
        // Unlink before writing any payload. Crashes release the disk space
        // with the last fd; there is no attacker-selected cleanup path.
        fs::remove_file(&path).map_err(io)?;
        fs::remove_dir(&directory).map_err(io)?;
        Ok::<_, RuntimeError>((file, reader))
    })();
    if opened.is_err() {
        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&directory);
    }
    opened
}

pub struct FileStaging {
    // Field order is drop order: the writer closes before the shared storage
    // (and with it the charged slot) is released.
    file: File,
    storage: Arc<Storage>,
    length: u64,
    hash: ring::digest::Context,
}
impl FileStaging {
    /// Charged host transfer staging. Reservation precedes every allocation.
    pub fn new(reserved: u64) -> Result<Self, RuntimeError> {
        Self::for_creator(reserved, "local")
    }
    /// Relay callers must resolve this identity from verified journal lineage.
    /// Both uploads and runtime captures retain the charge through the last reader.
    pub fn for_creator(reserved: u64, creator: &str) -> Result<Self, RuntimeError> {
        Self::create(reserved, true, creator)
    }
    fn create(reserved: u64, charged: bool, creator: &str) -> Result<Self, RuntimeError> {
        if reserved > FILE_MAX_BYTES {
            return Err(RuntimeError::new(
                SandboxErrorCode::HostCapacity,
                "file staging quota exceeded",
            ));
        }
        let charged = charged.then(ledger);
        if let Some(ledger) = charged {
            // Reserve before allocating; no filesystem work runs under this lock.
            let mut used = ledger.lock().unwrap_or_else(|e| e.into_inner());
            let local = used.2.get(creator).copied().unwrap_or_default();
            if used.0 + reserved > DISK_BYTES
                || used.1 >= ACTIVE_SLOTS
                || local.0 + reserved > CREATOR_DISK_BYTES
                || local.1 >= CREATOR_ACTIVE_SLOTS
            {
                return Err(RuntimeError::new(
                    SandboxErrorCode::HostCapacity,
                    "file staging quota exceeded",
                ));
            }
            used.0 += reserved;
            used.1 += 1;
            let local = used.2.entry(creator.to_owned()).or_default();
            local.0 += reserved;
            local.1 += 1;
        }
        // From here the charge is owned by `Storage`; its Drop releases it
        // exactly once, including when allocation below fails.
        let (file, reader) = match private_file() {
            Ok(files) => files,
            Err(error) => {
                if let Some(ledger) = charged {
                    let mut used = ledger.lock().unwrap_or_else(|e| e.into_inner());
                    release(&mut used, creator, reserved);
                }
                return Err(error);
            }
        };
        let storage = Arc::new(Storage {
            file: Some(reader),
            reserved,
            creator: creator.to_owned(),
            charged,
        });
        Ok(Self {
            file,
            storage,
            length: 0,
            hash: ring::digest::Context::new(&ring::digest::SHA256),
        })
    }
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn is_empty(&self) -> bool {
        self.length == 0
    }
    pub fn seal(self, expected: Option<(u64, &str)>) -> Result<FileContent, RuntimeError> {
        let digest: String = self
            .hash
            .finish()
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if expected.is_some_and(|(length, hash)| length != self.length || hash != digest) {
            return Err(RuntimeError::new(
                SandboxErrorCode::ProtocolError,
                "file length or hash mismatch",
            ));
        }
        self.file.sync_all().map_err(io)?;
        Ok(FileContent {
            storage: self.storage,
            length: self.length,
            digest,
        })
    }
}
impl Write for FileStaging {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.length + bytes.len() as u64 > self.storage.reserved {
            return Err(std::io::Error::other("file staging byte limit"));
        }
        let written = self.file.write(bytes)?;
        self.hash.update(&bytes[..written]);
        self.length += written as u64;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

// libtest runs tests concurrently on separate threads, and many tests hold
// charged captures; a process-wide ledger would let them exhaust each other's
// slots and break exact slot accounting. Each test thread gets its own ledger,
// and `Storage` remembers which ledger it charged so a capture dropped on
// another thread still releases the right one. This stays below all production
// code: a source-inventory test reads this file up to the first `cfg(test)`.
#[cfg(test)]
fn ledger() -> &'static Mutex<StagingUsage> {
    thread_local! {
        static RESERVED: &'static Mutex<StagingUsage> =
            Box::leak(Box::new(Mutex::new((0, 0, BTreeMap::new()))));
    }
    RESERVED.with(|ledger| *ledger)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn creator_flood_leaves_a_slot_and_bytes_until_the_last_reader_drops() {
        let a: Vec<_> = (0..CREATOR_ACTIVE_SLOTS)
            .map(|_| {
                FileStaging::for_creator(FILE_MAX_BYTES, "a")
                    .unwrap()
                    .seal(None)
                    .unwrap()
            })
            .collect();
        assert!(FileStaging::for_creator(0, "a").is_err());
        let b = FileStaging::for_creator(FILE_MAX_BYTES, "b").unwrap();
        assert!(FileStaging::for_creator(0, "c").is_err());
        {
            let used = ledger().lock().unwrap();
            assert_eq!((used.0, used.1), (4 * FILE_MAX_BYTES, 4));
            assert_eq!(used.2["a"], (3 * FILE_MAX_BYTES, 3));
            assert_eq!(used.2["b"], (FILE_MAX_BYTES, 1));
        }
        let reader = a[0].reader();
        drop(a);
        assert_eq!(ledger().lock().unwrap().2["a"], (FILE_MAX_BYTES, 1));
        // A capture can outlive its producer or be dropped on another thread.
        std::thread::spawn(move || drop(reader)).join().unwrap();
        assert!(!ledger().lock().unwrap().2.contains_key("a"));
        drop(b);
        let used = ledger().lock().unwrap();
        assert_eq!((used.0, used.1), (0, 0));
        assert!(used.2.is_empty());
    }
    #[test]
    fn creator_charge_releases_on_bad_manifest_and_guest_copies_are_uncharged() {
        let source = FileStaging::for_creator(10, "a")
            .unwrap()
            .seal(None)
            .unwrap();
        let disk = source.guest_disk_copy().unwrap();
        let read = disk.staged_copy("b").unwrap();
        assert_eq!(ledger().lock().unwrap().2["b"], (0, 1));
        assert!(
            FileStaging::for_creator(10, "a")
                .unwrap()
                .seal(Some((1, "bad")))
                .is_err()
        );
        assert_eq!(ledger().lock().unwrap().2["a"], (10, 1));
        drop((source, read, disk));
        assert!(ledger().lock().unwrap().2.is_empty());
    }
    #[test]
    fn binary_empty_and_partial_capture_are_immutable_and_bounded() {
        let mut staging = FileStaging::new(65539).unwrap();
        let chunk = [0xff; 65536];
        staging.write_all(&chunk).unwrap();
        staging.write_all(&[0, 128, 7]).unwrap();
        assert!(staging.write_all(&[8]).is_err());
        let content = staging.seal(None).unwrap();
        assert_eq!(content.len(), 65539);
        assert_eq!(content.read_chunk(65536, 3).unwrap(), [0, 128, 7]);
        assert!(content.read_chunk(0, FILE_CHUNK_BYTES + 1).is_err());
        assert_eq!(content.storage.file().metadata().unwrap().len(), 65539);
        let empty = FileContent::from_bytes(&[]).unwrap();
        assert!(empty.is_empty());
        assert_eq!(
            empty.digest(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn length_and_hash_mismatch_delete_only_the_private_staging_file() {
        for expected in [(4, "wrong"), (3, "wrong")] {
            let mut staging = FileStaging::new(4).unwrap();
            let before = ledger().lock().unwrap().1;
            staging.write_all(b"data").unwrap();
            assert_eq!(
                staging.seal(Some(expected)).unwrap_err().code,
                SandboxErrorCode::ProtocolError
            );
            assert_eq!(ledger().lock().unwrap().1, before - 1);
        }
        assert!(FileStaging::new(FILE_MAX_BYTES + 1).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn disk_full_does_not_publish_a_capture_or_advance_its_length() {
        let mut staging = FileStaging::new(4).unwrap();
        staging.file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        assert_eq!(staging.write(b"data").unwrap_err().raw_os_error(), Some(28));
        assert_eq!(staging.len(), 0);
    }
    /// G6: a write fault after accepted bytes neither advances the length nor
    /// lets the capture seal against its manifest; the slot is released.
    #[cfg(target_os = "linux")]
    #[test]
    fn partial_write_fault_never_seals_and_releases_the_slot() {
        let bytes = [7u8; 8];
        let manifest = FileContent::from_bytes(&bytes).unwrap();
        let before = ledger().lock().unwrap().1;
        let mut staging = FileStaging::new(8).unwrap();
        staging.write_all(&bytes[..4]).unwrap();
        staging.file = OpenOptions::new().write(true).open("/dev/full").unwrap();
        assert_eq!(
            staging.write_all(&bytes[4..]).unwrap_err().raw_os_error(),
            Some(28)
        );
        assert_eq!(staging.len(), 4);
        assert_eq!(ledger().lock().unwrap().1, before + 1);
        assert_eq!(
            staging.seal(Some((8, manifest.digest()))).unwrap_err().code,
            SandboxErrorCode::ProtocolError
        );
        assert_eq!(ledger().lock().unwrap().1, before);
    }
    /// G4: guest-disk copies hold no staging slot; reading them back produces a
    /// fresh charged capture with identical bytes.
    #[test]
    fn guest_disk_copies_hold_no_slot_and_reads_are_charged_again() {
        let source = FileContent::from_bytes(b"\0guest\xff").unwrap();
        assert!(source.is_charged());
        let before = ledger().lock().unwrap().1;
        let disk: Vec<_> = (0..ACTIVE_SLOTS + 2)
            .map(|_| source.guest_disk_copy().unwrap())
            .collect();
        assert_eq!(ledger().lock().unwrap().1, before);
        assert!(
            disk.iter()
                .all(|copy| !copy.is_charged() && copy == &source)
        );
        drop(source);
        assert_eq!(ledger().lock().unwrap().1, before - 1);
        let read = disk[0].staged_copy("creator").unwrap();
        assert!(read.is_charged());
        assert_eq!(read.read_chunk(0, 16).unwrap(), b"\0guest\xff");
        drop(read);
        assert_eq!(ledger().lock().unwrap().1, before - 1);
    }
}
