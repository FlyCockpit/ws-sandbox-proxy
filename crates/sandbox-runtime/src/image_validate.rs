//! Pre-import validation of a unified VM image tarball (B2/B3).
//!
//! `incus image import` (at least 7.5.1) accepts crafted images: a qcow2
//! `rootfs.img` whose backing file names a host path, a `rootfs.img` that is
//! a symlink or a device node, and so on. Every image the daemon imports is
//! checked here first, whoever owns it, and refused unless it has exactly the
//! layout wssp produces and Incus exports for a VM:
//!
//! - one regular `metadata.yaml` (at most 1 MiB);
//! - one regular `rootfs.img` holding a qcow2 image (version 2 or 3) with no
//!   backing file, no external data file, no encryption and no backing-format
//!   or data-file header extension;
//! - optionally a `templates` directory with regular files directly in it.
//!
//! Any other entry is refused: symlinks, hard links, device nodes, FIFOs,
//! sparse or unknown entry types, absolute paths, `..` components, duplicate
//! names, and global PAX path overrides. The tarball may be uncompressed or
//! gzip, zstd, xz or bzip2 compressed; a fixed system decompressor streams it
//! (no new dependency, no extraction to disk) with a scrubbed environment and
//! is killed if validation stops early.
//!
//! An upstream split image (community bases) is a metadata tarball plus a
//! bare qcow2 disk; [`validate_split_image`] applies the same rules to both
//! halves, with tighter bounds and the metadata property audit.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Child, ChildStdout, Stdio};

use sandbox_protocol::SandboxErrorCode;

use crate::error::RuntimeError;

const BLOCK: usize = 512;
const METADATA_MAX_BYTES: u64 = 1 << 20;
const PAX_MAX_BYTES: u64 = 1 << 20;
const GNU_LONGNAME_MAX_BYTES: u64 = 4096;
/// The qcow2 header and its extensions live in the first cluster; at most
/// 2 MiB (cluster_bits 21) is ever read.
const QCOW2_WINDOW_MAX: usize = 2 << 20;
/// Decompression bound: the larger of 64 GiB and 64x the compressed size.
const UNPACKED_FLOOR: u64 = 64 << 30;
const UNPACKED_RATIO: u64 = 64;
/// Decompression bound of an upstream split image's metadata tarball.
pub const SPLIT_METADATA_UNPACKED_MAX: u64 = 4 << 20;
/// Largest virtual disk an upstream split image may declare.
pub const SPLIT_VIRTUAL_SIZE_MAX: u64 = 32 << 30;

/// Image property prefixes the allocation audit refuses
/// (`verify_template_launch_config`): Incus copies image properties into
/// `image.*` and some of these name launch configuration. The audit exempts
/// wssp's own `user.flycockpit.*`, `limits.cpu` and `limits.memory`; an
/// upstream split image's metadata gets no exemption at all.
pub const REFUSED_PROPERTY_PREFIXES: &[&str] = &[
    "boot.",
    "cloud-init.",
    "environment.",
    "limits.",
    "linux.",
    "migration.",
    "nvidia.",
    "raw.",
    "security.",
    "snapshots.",
    "user.",
    "volatile.",
];

/// Why an image was refused: a fixed token, safe to log and to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageRefusal(pub &'static str);

impl From<ImageRefusal> for RuntimeError {
    fn from(value: ImageRefusal) -> Self {
        RuntimeError::new(
            SandboxErrorCode::ImageRejected,
            format!("image refused: {}", value.0),
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Compression {
    None,
    Gzip,
    Zstd,
    Xz,
    Bzip2,
}

impl Compression {
    fn detect(head: &[u8]) -> Option<Self> {
        if head.starts_with(&[0x1f, 0x8b]) {
            Some(Self::Gzip)
        } else if head.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
            Some(Self::Zstd)
        } else if head.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
            Some(Self::Xz)
        } else if head.starts_with(b"BZh") {
            Some(Self::Bzip2)
        } else if head.len() >= 262 && &head[257..262] == b"ustar" {
            Some(Self::None)
        } else {
            None
        }
    }
    fn program(self) -> Option<(&'static str, &'static [&'static str])> {
        match self {
            Self::None => None,
            Self::Gzip => Some(("gzip", &["-d", "-c"])),
            Self::Zstd => Some(("zstd", &["-d", "-c", "-q"])),
            Self::Xz => Some(("xz", &["-d", "-c"])),
            Self::Bzip2 => Some(("bzip2", &["-d", "-c"])),
        }
    }
}

/// The decompressor child, killed and reaped unless it finished cleanly.
struct Decompressor {
    child: Option<Child>,
}

impl Drop for Decompressor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

enum Source {
    File(File),
    Child(ChildStdout),
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(file) => file.read(buf),
            Self::Child(stdout) => stdout.read(buf),
        }
    }
}

/// A byte-counted stream with a hard unpacked-size bound.
struct Stream {
    source: Source,
    read: u64,
    limit: u64,
}

impl Stream {
    fn exact(&mut self, buf: &mut [u8]) -> Result<(), ImageRefusal> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = match self.source.read(&mut buf[filled..]) {
                Ok(0) => return Err(ImageRefusal("archive_truncated")),
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return Err(ImageRefusal("archive_unreadable")),
            };
            filled += n;
            self.read += n as u64;
            if self.read > self.limit {
                return Err(ImageRefusal("unpacked_too_large"));
            }
        }
        Ok(())
    }
    fn skip(&mut self, mut n: u64) -> Result<(), ImageRefusal> {
        let mut buf = vec![0u8; 64 * 1024];
        while n > 0 {
            let take = n.min(buf.len() as u64) as usize;
            self.exact(&mut buf[..take])?;
            n -= take as u64;
        }
        Ok(())
    }
    /// Consume what follows the end-of-archive marker (record padding).
    fn drain(&mut self) -> Result<(), ImageRefusal> {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match self.source.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    if buf[..n].iter().any(|b| *b != 0) {
                        return Err(ImageRefusal("data_after_archive_end"));
                    }
                    self.read += n as u64;
                    if self.read > self.limit {
                        return Err(ImageRefusal("unpacked_too_large"));
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Err(ImageRefusal("archive_unreadable")),
            }
        }
    }
}

fn padded(size: u64) -> u64 {
    size.div_ceil(BLOCK as u64) * BLOCK as u64
}

fn octal(field: &[u8]) -> Result<u64, ImageRefusal> {
    // GNU base-256 for large sizes.
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut value: u64 = u64::from(field[0] & 0x7f);
        for b in &field[1..] {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(u64::from(*b)))
                .ok_or(ImageRefusal("bad_header_number"))?;
        }
        return Ok(value);
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|b| *b != 0)
        .filter(|b| *b != b' ')
        .collect();
    if text.is_empty() {
        return Ok(0);
    }
    let mut value: u64 = 0;
    for b in text {
        if !(b'0'..=b'7').contains(&b) {
            return Err(ImageRefusal("bad_header_number"));
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u64::from(b - b'0')))
            .ok_or(ImageRefusal("bad_header_number"))?;
    }
    Ok(value)
}

fn cstr(field: &[u8]) -> &[u8] {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    &field[..end]
}

fn checksum_ok(header: &[u8; BLOCK]) -> bool {
    let Ok(expected) = octal(&header[148..156]) else {
        return false;
    };
    let sum: u64 = header
        .iter()
        .enumerate()
        .map(|(i, b)| {
            if (148..156).contains(&i) {
                u64::from(b' ')
            } else {
                u64::from(*b)
            }
        })
        .sum();
    sum == expected
}

/// PAX records `"<len> <key>=<value>\n"`.
fn pax_records(data: &[u8]) -> Result<Vec<(String, Vec<u8>)>, ImageRefusal> {
    let bad = ImageRefusal("bad_pax_header");
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        if rest.iter().all(|b| *b == 0) {
            break;
        }
        let space = rest.iter().position(|b| *b == b' ').ok_or(bad)?;
        let len: usize = std::str::from_utf8(&rest[..space])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or(bad)?;
        if len <= space + 1 || len > rest.len() || rest[len - 1] != b'\n' {
            return Err(bad);
        }
        let record = &rest[space + 1..len - 1];
        let eq = record.iter().position(|b| *b == b'=').ok_or(bad)?;
        let key = std::str::from_utf8(&record[..eq]).map_err(|_| bad)?;
        out.push((key.to_owned(), record[eq + 1..].to_vec()));
        rest = &rest[len..];
    }
    Ok(out)
}

/// The archive path as a relative, normalized `a/b` (empty for `.`).
fn normalize(raw: &[u8]) -> Result<String, ImageRefusal> {
    if raw.is_empty() {
        return Err(ImageRefusal("empty_path"));
    }
    if raw.contains(&0) || raw.contains(&b'\\') {
        return Err(ImageRefusal("bad_path"));
    }
    let text = std::str::from_utf8(raw).map_err(|_| ImageRefusal("bad_path"))?;
    if text.starts_with('/') {
        return Err(ImageRefusal("absolute_path"));
    }
    let mut parts = Vec::new();
    for part in text.split('/') {
        match part {
            "" | "." => {}
            ".." => return Err(ImageRefusal("path_traversal")),
            other => parts.push(other),
        }
    }
    Ok(parts.join("/"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    File,
    Dir,
}

/// Which tarball is being validated.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Layout {
    /// A unified VM image: metadata, `rootfs.img` and templates.
    Unified,
    /// An upstream split image's metadata tarball: metadata and templates,
    /// no disk (it is the separate `disk.qcow2`).
    SplitMetadata,
}

/// What `layout` allows at `path`.
fn allowed(path: &str, kind: Kind, layout: Layout) -> bool {
    match (path, kind) {
        ("", Kind::Dir) | ("templates", Kind::Dir) => true,
        ("metadata.yaml", Kind::File) => true,
        ("rootfs.img", Kind::File) => layout == Layout::Unified,
        (other, Kind::File) => other
            .strip_prefix("templates/")
            .is_some_and(|name| !name.is_empty() && !name.contains('/')),
        _ => false,
    }
}

/// A refused property prefix anywhere a YAML key (or flow entry) can start
/// in `metadata`: at a line start, or after whitespace, a flow bracket, a
/// comma, a colon or a quote. Deliberately broader than YAML: a value that
/// merely looks like such a key is refused too (fail closed, no parser).
pub(crate) fn metadata_names_refused_property(metadata: &str) -> bool {
    metadata.lines().any(|line| {
        let bytes = line.as_bytes();
        (0..bytes.len()).any(|at| {
            (at == 0
                || matches!(
                    bytes[at - 1],
                    b' ' | b'\t' | b'{' | b'[' | b',' | b':' | b'"' | b'\''
                ))
                && REFUSED_PROPERTY_PREFIXES
                    .iter()
                    .any(|prefix| bytes[at..].starts_with(prefix.as_bytes()))
        })
    })
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn be64(b: &[u8], at: usize) -> u64 {
    (u64::from(be32(b, at)) << 32) | u64::from(be32(b, at + 4))
}

const QCOW2_EXT_END: u32 = 0;
const QCOW2_EXT_BACKING_FORMAT: u32 = 0xe279_2aca;
const QCOW2_EXT_DATA_FILE: u32 = 0x4441_5441;
const QCOW2_INCOMPAT_CORRUPT: u64 = 1 << 1;
const QCOW2_INCOMPAT_DATA_FILE: u64 = 1 << 2;

/// Check a qcow2 header (spec: qemu `docs/interop/qcow2.txt`). `head` is
/// the start of the image, `total` its full size.
pub fn validate_qcow2_header(head: &[u8], total: u64) -> Result<(), ImageRefusal> {
    if head.len() < 72 || &head[..4] != b"QFI\xfb" {
        return Err(ImageRefusal("rootfs_not_qcow2"));
    }
    let version = be32(head, 4);
    if version != 2 && version != 3 {
        return Err(ImageRefusal("qcow2_unsupported_version"));
    }
    if be64(head, 8) != 0 || be32(head, 16) != 0 {
        return Err(ImageRefusal("qcow2_backing_file"));
    }
    let cluster_bits = be32(head, 20);
    if !(9..=21).contains(&cluster_bits) {
        return Err(ImageRefusal("qcow2_bad_cluster_size"));
    }
    if be32(head, 32) != 0 {
        return Err(ImageRefusal("qcow2_encrypted"));
    }
    let header_length = if version == 2 {
        72
    } else {
        if head.len() < 104 {
            return Err(ImageRefusal("qcow2_header_truncated"));
        }
        let incompatible = be64(head, 72);
        if incompatible & QCOW2_INCOMPAT_DATA_FILE != 0 {
            return Err(ImageRefusal("qcow2_external_data_file"));
        }
        if incompatible & QCOW2_INCOMPAT_CORRUPT != 0 {
            return Err(ImageRefusal("qcow2_corrupt"));
        }
        let length = be32(head, 100) as usize;
        if !(104..=head.len()).contains(&length) || !length.is_multiple_of(8) {
            return Err(ImageRefusal("qcow2_header_truncated"));
        }
        length
    };
    // Header extensions follow the header, up to the end marker, inside the
    // first cluster.
    let cluster = 1usize << cluster_bits;
    let area = head.len().min(cluster);
    let truncated = (area as u64) < total.min(cluster as u64);
    let mut at = header_length;
    loop {
        if at + 8 > area {
            return Err(ImageRefusal(if truncated {
                "qcow2_header_truncated"
            } else {
                "qcow2_bad_extensions"
            }));
        }
        let kind = be32(head, at);
        let len = be32(head, at + 4) as usize;
        match kind {
            QCOW2_EXT_END => return Ok(()),
            QCOW2_EXT_BACKING_FORMAT => return Err(ImageRefusal("qcow2_backing_file")),
            QCOW2_EXT_DATA_FILE => return Err(ImageRefusal("qcow2_external_data_file")),
            _ => {}
        }
        at = at
            .checked_add(8)
            .and_then(|a| a.checked_add(len.div_ceil(8) * 8))
            .ok_or(ImageRefusal("qcow2_bad_extensions"))?;
    }
}

/// Validate the unified image tarball at `path` before `incus image import`.
pub fn validate_unified_image(path: &Path) -> Result<(), ImageRefusal> {
    validate_tarball(path, Layout::Unified, None)
}

/// Validate an upstream split image (community bases, I3) before `incus
/// image import <meta> <disk>`: the metadata tarball unpacks to at most
/// [`SPLIT_METADATA_UNPACKED_MAX`], holds one `metadata.yaml` (at most
/// 1 MiB) naming no refused property prefix ([`REFUSED_PROPERTY_PREFIXES`],
/// no exemption) plus optional flat templates, and nothing else (no links,
/// devices, traversal or disk); the disk is a sane qcow2 (the unified
/// checks: no backing or data file, no encryption) whose virtual size is at
/// most `max_virtual`.
pub fn validate_split_image(
    meta: &Path,
    disk: &Path,
    max_virtual: u64,
) -> Result<(), ImageRefusal> {
    validate_split_disk(disk, max_virtual)?;
    validate_tarball(
        meta,
        Layout::SplitMetadata,
        Some(SPLIT_METADATA_UNPACKED_MAX),
    )
}

fn validate_split_disk(disk: &Path, max_virtual: u64) -> Result<(), ImageRefusal> {
    let mut file = File::open(disk).map_err(|_| ImageRefusal("image_unreadable"))?;
    let total = file
        .metadata()
        .map_err(|_| ImageRefusal("image_unreadable"))?
        .len();
    let mut head = vec![0u8; (total.min(QCOW2_WINDOW_MAX as u64)) as usize];
    file.read_exact(&mut head)
        .map_err(|_| ImageRefusal("image_unreadable"))?;
    validate_qcow2_header(&head, total)?;
    let virtual_size = be64(&head, 24);
    if virtual_size == 0 {
        return Err(ImageRefusal("qcow2_bad_virtual_size"));
    }
    if virtual_size > max_virtual {
        return Err(ImageRefusal("qcow2_virtual_size_too_large"));
    }
    Ok(())
}

fn validate_tarball(
    path: &Path,
    layout: Layout,
    unpacked_max: Option<u64>,
) -> Result<(), ImageRefusal> {
    let mut file = File::open(path).map_err(|_| ImageRefusal("image_unreadable"))?;
    let compressed = file
        .metadata()
        .map_err(|_| ImageRefusal("image_unreadable"))?
        .len();
    let mut head = [0u8; BLOCK];
    let mut got = 0;
    while got < head.len() {
        match file.read(&mut head[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return Err(ImageRefusal("image_unreadable")),
        }
    }
    let compression =
        Compression::detect(&head[..got]).ok_or(ImageRefusal("unknown_image_format"))?;
    drop(file);
    let limit = unpacked_max
        .unwrap_or_else(|| UNPACKED_FLOOR.max(compressed.saturating_mul(UNPACKED_RATIO)));
    let mut guard = Decompressor { child: None };
    let source = match compression.program() {
        None => Source::File(File::open(path).map_err(|_| ImageRefusal("image_unreadable"))?),
        Some((program, args)) => {
            let input = File::open(path).map_err(|_| ImageRefusal("image_unreadable"))?;
            let mut command =
                crate::host_child::command(program, crate::host_child::Environment::PathOnly);
            command
                .args(args)
                .env("LC_ALL", "C")
                .stdin(Stdio::from(input))
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            let mut child = command
                .spawn()
                .map_err(|_| ImageRefusal("decompressor_unavailable"))?;
            let stdout = child
                .stdout
                .take()
                .ok_or(ImageRefusal("decompressor_unavailable"))?;
            guard.child = Some(child);
            Source::Child(stdout)
        }
    };
    let mut stream = Stream {
        source,
        read: 0,
        limit,
    };
    validate_tar(&mut stream, layout)?;
    stream.drain()?;
    drop(stream);
    if let Some(mut child) = guard.child.take() {
        let status = child
            .wait()
            .map_err(|_| ImageRefusal("decompressor_failed"))?;
        if !status.success() {
            return Err(ImageRefusal("decompressor_failed"));
        }
    }
    Ok(())
}

fn validate_tar(stream: &mut Stream, layout: Layout) -> Result<(), ImageRefusal> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut pax_path: Option<Vec<u8>> = None;
    let mut pax_size: Option<u64> = None;
    let mut long_name: Option<Vec<u8>> = None;
    let mut metadata = false;
    let mut rootfs = false;
    loop {
        let mut header = [0u8; BLOCK];
        stream.exact(&mut header)?;
        if header.iter().all(|b| *b == 0) {
            if pax_path.is_some() || pax_size.is_some() || long_name.is_some() {
                return Err(ImageRefusal("dangling_extended_header"));
            }
            break;
        }
        if !checksum_ok(&header) {
            return Err(ImageRefusal("bad_header_checksum"));
        }
        let typeflag = header[156];
        let size = octal(&header[124..136])?;
        match typeflag {
            b'x' | b'g' => {
                if size > PAX_MAX_BYTES {
                    return Err(ImageRefusal("bad_pax_header"));
                }
                let mut data = vec![0u8; size as usize];
                stream.exact(&mut data)?;
                stream.skip(padded(size) - size)?;
                for (key, value) in pax_records(&data)? {
                    if key == "linkpath" || key.starts_with("GNU.sparse") {
                        return Err(ImageRefusal("link_or_sparse_entry"));
                    }
                    if typeflag == b'g' {
                        if key == "path" || key == "size" {
                            return Err(ImageRefusal("global_path_override"));
                        }
                        continue;
                    }
                    match key.as_str() {
                        "path" => pax_path = Some(value),
                        "size" => {
                            let text = std::str::from_utf8(&value)
                                .map_err(|_| ImageRefusal("bad_pax_header"))?;
                            pax_size =
                                Some(text.parse().map_err(|_| ImageRefusal("bad_pax_header"))?);
                        }
                        _ => {}
                    }
                }
                continue;
            }
            b'L' => {
                if size > GNU_LONGNAME_MAX_BYTES {
                    return Err(ImageRefusal("bad_path"));
                }
                let mut data = vec![0u8; size as usize];
                stream.exact(&mut data)?;
                stream.skip(padded(size) - size)?;
                long_name = Some(cstr(&data).to_vec());
                continue;
            }
            b'1' | b'K' => return Err(ImageRefusal("hardlink_entry")),
            b'2' => return Err(ImageRefusal("symlink_entry")),
            b'3' | b'4' => return Err(ImageRefusal("device_entry")),
            b'6' => return Err(ImageRefusal("fifo_entry")),
            b'0' | 0 | b'5' => {}
            _ => return Err(ImageRefusal("unsupported_entry_type")),
        }
        let raw = if let Some(path) = pax_path.take() {
            long_name = None;
            path
        } else if let Some(name) = long_name.take() {
            name
        } else {
            let name = cstr(&header[0..100]);
            let ustar = &header[257..263] == b"ustar\0";
            let prefix = cstr(&header[345..500]);
            if ustar && !prefix.is_empty() {
                [prefix, b"/", name].concat()
            } else {
                name.to_vec()
            }
        };
        let size = pax_size.take().unwrap_or(size);
        let path = normalize(&raw)?;
        let kind = if typeflag == b'5' {
            Kind::Dir
        } else {
            Kind::File
        };
        if kind == Kind::Dir && size != 0 {
            return Err(ImageRefusal("bad_directory_entry"));
        }
        if !allowed(&path, kind, layout) {
            return Err(ImageRefusal("unexpected_entry"));
        }
        if !seen.insert(path.clone()) {
            return Err(ImageRefusal("duplicate_entry"));
        }
        match path.as_str() {
            "metadata.yaml" => {
                if size == 0 || size > METADATA_MAX_BYTES {
                    return Err(ImageRefusal("bad_metadata"));
                }
                metadata = true;
                if layout == Layout::SplitMetadata {
                    let mut data = vec![0u8; size as usize];
                    stream.exact(&mut data)?;
                    let text =
                        std::str::from_utf8(&data).map_err(|_| ImageRefusal("bad_metadata"))?;
                    if metadata_names_refused_property(text) {
                        return Err(ImageRefusal("metadata_refused_property"));
                    }
                    stream.skip(padded(size) - size)?;
                } else {
                    stream.skip(padded(size))?;
                }
            }
            "rootfs.img" => {
                let window = (size as usize).min(QCOW2_WINDOW_MAX);
                let mut head = vec![0u8; window];
                stream.exact(&mut head)?;
                validate_qcow2_header(&head, size)?;
                rootfs = true;
                stream.skip(padded(size) - window as u64)?;
            }
            _ => stream.skip(padded(size))?,
        }
    }
    if !metadata {
        return Err(ImageRefusal("missing_metadata"));
    }
    if !rootfs && layout == Layout::Unified {
        return Err(ImageRefusal("missing_rootfs_img"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "image_validate_tests.rs"]
pub(crate) mod tests;
