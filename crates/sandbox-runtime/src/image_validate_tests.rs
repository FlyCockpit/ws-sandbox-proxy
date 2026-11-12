use super::*;
use std::io::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Tar entry builders (ustar, plus raw typeflags for the crafted cases).
pub(crate) mod fixtures {
    use super::*;

    pub(crate) fn header(name: &str, size: u64, typeflag: u8, link: &str) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..107].copy_from_slice(b"0000644");
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
        h[136..147].copy_from_slice(b"15000000000");
        h[156] = typeflag;
        h[157..157 + link.len()].copy_from_slice(link.as_bytes());
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[148..156].copy_from_slice(b"        ");
        let sum: u64 = h.iter().map(|b| u64::from(*b)).sum();
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h
    }

    pub(crate) fn entry(out: &mut Vec<u8>, name: &str, typeflag: u8, data: &[u8], link: &str) {
        out.extend_from_slice(&header(name, data.len() as u64, typeflag, link));
        out.extend_from_slice(data);
        out.resize(padded(out.len() as u64) as usize, 0);
    }

    pub(crate) fn pax(out: &mut Vec<u8>, typeflag: u8, records: &[(&str, &str)]) {
        let mut data = Vec::new();
        for (key, value) in records {
            let body = format!(" {key}={value}\n");
            let mut len = body.len() + 1;
            while format!("{len}{body}").len() != len {
                len += 1;
            }
            data.extend_from_slice(format!("{len}{body}").as_bytes());
        }
        entry(out, "PaxHeaders/x", typeflag, &data, "");
    }

    /// A qcow2 v3 header: 64 KiB clusters, no backing file, an end marker.
    pub(crate) fn qcow2() -> Vec<u8> {
        let mut q = vec![0u8; 4096];
        q[..4].copy_from_slice(b"QFI\xfb");
        q[4..8].copy_from_slice(&3u32.to_be_bytes());
        q[20..24].copy_from_slice(&16u32.to_be_bytes());
        q[24..32].copy_from_slice(&(1u64 << 30).to_be_bytes());
        q[96..100].copy_from_slice(&4u32.to_be_bytes());
        q[100..104].copy_from_slice(&112u32.to_be_bytes());
        q
    }

    pub(crate) const METADATA: &[u8] =
        b"architecture: x86_64\ncreation_date: 1700000000\nproperties: {}\n";

    pub(crate) fn finish(mut out: Vec<u8>) -> Vec<u8> {
        out.extend_from_slice(&[0u8; BLOCK * 2]);
        out
    }

    /// The layout Incus exports for a VM image.
    pub(crate) fn unified(rootfs: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        entry(&mut out, "metadata.yaml", b'0', METADATA, "");
        entry(&mut out, "rootfs.img", b'0', rootfs, "");
        entry(&mut out, "templates/", b'5', b"", "");
        entry(
            &mut out,
            "templates/hostname.tpl",
            b'0',
            b"{{ name }}\n",
            "",
        );
        finish(out)
    }

    pub(crate) fn valid_unified() -> Vec<u8> {
        unified(&qcow2())
    }

    /// An upstream split image's metadata tarball: like the 26.04 cloud
    /// image's (properties, cloud-init seed templates), xz-compressed by the
    /// system `xz` (`None` when it is missing).
    pub(crate) const SPLIT_METADATA: &[u8] = b"architecture: x86_64\ncreation_date: 1700000000\n\
properties:\n  architecture: amd64\n  description: Ubuntu resolute amd64 (20261105_07:42)\n\
  os: Ubuntu\n  release: resolute\n  type: disk-kvm.img\n  variant: cloud\n\
templates:\n  /var/lib/cloud/seed/nocloud-net/user-data:\n    when:\n    - create\n    - copy\n\
    create_only: false\n    template: cloud-init-user.tpl\n    properties:\n      default: |\n\
        #cloud-config\n        {}\n";

    pub(crate) fn split_metadata_tar(metadata: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        entry(&mut out, "metadata.yaml", b'0', metadata, "");
        entry(&mut out, "templates/", b'5', b"", "");
        entry(
            &mut out,
            "templates/cloud-init-user.tpl",
            b'0',
            b"{{ config_get(\"user.user-data\", properties.default) }}\n",
            "",
        );
        finish(out)
    }

    pub(crate) fn xz(raw: &[u8]) -> Option<Vec<u8>> {
        // Synchronous `xz` over a scratch file (no async child in tests).
        let dir = scratch();
        let path = dir.0.join("meta.tar");
        std::fs::write(&path, raw).ok()?;
        let out = std::process::Command::new("xz")
            .args(["-c", "-0"])
            .arg(&path)
            .output()
            .ok()?;
        out.status.success().then_some(out.stdout)
    }

    /// A qcow2 header declaring `virtual_size` bytes.
    pub(crate) fn qcow2_sized(virtual_size: u64) -> Vec<u8> {
        let mut q = qcow2();
        q[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        q
    }
}

use fixtures::*;

struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch() -> Scratch {
    let dir = std::env::temp_dir().join(format!(
        "wssp-image-validate-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    Scratch(dir)
}

fn check(bytes: &[u8]) -> Result<(), ImageRefusal> {
    let dir = scratch();
    let path = dir.0.join("image.tar");
    std::fs::write(&path, bytes).unwrap();
    validate_unified_image(&path)
}

fn refused(bytes: &[u8]) -> &'static str {
    check(bytes).expect_err("crafted image accepted").0
}

#[test]
fn incus_vm_layout_is_accepted_with_or_without_dot_prefixes() {
    assert_eq!(check(&valid_unified()), Ok(()));
    let mut out = Vec::new();
    entry(&mut out, "./", b'5', b"", "");
    entry(&mut out, "./metadata.yaml", b'0', METADATA, "");
    entry(&mut out, "./rootfs.img", b'0', &qcow2(), "");
    assert_eq!(check(&finish(out)), Ok(()));
    // qcow2 v2 (72-byte header, extensions right after it).
    let mut v2 = qcow2();
    v2[4..8].copy_from_slice(&2u32.to_be_bytes());
    v2[96..112].fill(0);
    assert_eq!(check(&unified(&v2)), Ok(()));
}

#[test]
fn compressed_images_are_streamed_through_a_system_decompressor() {
    for (program, args) in [("gzip", &["-c"][..]), ("zstd", &["-q", "-c"][..])] {
        let Ok(mut child) = std::process::Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
        else {
            continue;
        };
        let raw = valid_unified();
        let mut stdin = child.stdin.take().unwrap();
        let writer = std::thread::spawn(move || stdin.write_all(&raw));
        let out = child.wait_with_output().unwrap();
        writer.join().unwrap().unwrap();
        assert_eq!(check(&out.stdout), Ok(()), "{program}");
        // A truncated stream is refused, never half-checked.
        assert!(
            check(&out.stdout[..out.stdout.len() / 2]).is_err(),
            "{program}"
        );
    }
}

#[test]
fn qcow2_backing_and_external_data_files_are_refused() {
    let mut backing = qcow2();
    backing[8..16].copy_from_slice(&512u64.to_be_bytes());
    backing[16..20].copy_from_slice(&13u32.to_be_bytes());
    backing[512..525].copy_from_slice(b"/etc/hostname");
    assert_eq!(refused(&unified(&backing)), "qcow2_backing_file");

    let mut data_bit = qcow2();
    data_bit[72..80].copy_from_slice(&4u64.to_be_bytes());
    assert_eq!(refused(&unified(&data_bit)), "qcow2_external_data_file");

    for (ext, reason) in [
        (QCOW2_EXT_DATA_FILE, "qcow2_external_data_file"),
        (QCOW2_EXT_BACKING_FORMAT, "qcow2_backing_file"),
    ] {
        let mut q = qcow2();
        // A harmless unknown extension first, then the forbidden one.
        q[112..116].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        q[116..120].copy_from_slice(&3u32.to_be_bytes());
        q[128..132].copy_from_slice(&ext.to_be_bytes());
        q[132..136].copy_from_slice(&13u32.to_be_bytes());
        assert_eq!(refused(&unified(&q)), reason);
    }

    let mut encrypted = qcow2();
    encrypted[32..36].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(refused(&unified(&encrypted)), "qcow2_encrypted");
    assert_eq!(refused(&unified(b"raw disk bytes")), "rootfs_not_qcow2");
    let mut v4 = qcow2();
    v4[4..8].copy_from_slice(&4u32.to_be_bytes());
    assert_eq!(refused(&unified(&v4)), "qcow2_unsupported_version");
}

#[test]
fn links_devices_and_fifos_are_refused() {
    for (typeflag, link, reason) in [
        (b'2', "/etc/shadow", "symlink_entry"),
        (b'1', "metadata.yaml", "hardlink_entry"),
        (b'3', "", "device_entry"),
        (b'4', "", "device_entry"),
        (b'6', "", "fifo_entry"),
        (b'S', "", "unsupported_entry_type"),
    ] {
        let mut out = Vec::new();
        entry(&mut out, "metadata.yaml", b'0', METADATA, "");
        entry(&mut out, "rootfs.img", typeflag, b"", link);
        assert_eq!(refused(&finish(out)), reason, "{}", typeflag as char);
    }
    // A link anywhere, not only at rootfs.img.
    let mut out = Vec::new();
    entry(&mut out, "metadata.yaml", b'0', METADATA, "");
    entry(&mut out, "templates/hosts.tpl", b'2', b"", "/etc/hosts");
    entry(&mut out, "rootfs.img", b'0', &qcow2(), "");
    assert_eq!(refused(&finish(out)), "symlink_entry");
    // PAX linkpath and GNU long links are links too.
    let mut out = Vec::new();
    pax(&mut out, b'x', &[("linkpath", "/etc/shadow")]);
    assert_eq!(refused(&finish(out)), "link_or_sparse_entry");
}

#[test]
fn absolute_traversal_and_unexpected_paths_are_refused() {
    for (name, reason) in [
        ("/etc/hostname", "absolute_path"),
        ("../../escape", "path_traversal"),
        ("templates/../../escape", "path_traversal"),
        ("rootfs/etc/passwd", "unexpected_entry"),
        ("templates/a/b.tpl", "unexpected_entry"),
        ("backdoor.sh", "unexpected_entry"),
    ] {
        let mut out = Vec::new();
        entry(&mut out, "metadata.yaml", b'0', METADATA, "");
        entry(&mut out, "rootfs.img", b'0', &qcow2(), "");
        entry(&mut out, name, b'0', b"x", "");
        assert_eq!(refused(&finish(out)), reason, "{name}");
    }
    // A PAX path override is checked like the header name.
    let mut out = Vec::new();
    entry(&mut out, "metadata.yaml", b'0', METADATA, "");
    pax(&mut out, b'x', &[("path", "../../rootfs.img")]);
    entry(&mut out, "rootfs.img", b'0', &qcow2(), "");
    assert_eq!(refused(&finish(out)), "path_traversal");
    let mut out = Vec::new();
    pax(&mut out, b'g', &[("path", "rootfs.img")]);
    assert_eq!(refused(&finish(out)), "global_path_override");
}

#[test]
fn layout_must_be_complete_and_unambiguous() {
    let mut out = Vec::new();
    entry(&mut out, "metadata.yaml", b'0', METADATA, "");
    assert_eq!(refused(&finish(out)), "missing_rootfs_img");
    let mut out = Vec::new();
    entry(&mut out, "rootfs.img", b'0', &qcow2(), "");
    assert_eq!(refused(&finish(out)), "missing_metadata");
    let mut out = Vec::new();
    entry(&mut out, "metadata.yaml", b'0', METADATA, "");
    entry(&mut out, "rootfs.img", b'0', &qcow2(), "");
    entry(&mut out, "./rootfs.img", b'0', &qcow2(), "");
    assert_eq!(refused(&finish(out)), "duplicate_entry");
    let mut out = Vec::new();
    entry(&mut out, "metadata.yaml", b'5', b"", "");
    assert_eq!(refused(&finish(out)), "unexpected_entry");
}

#[test]
fn malformed_archives_are_refused() {
    let mut bad_sum = valid_unified();
    bad_sum[0] = b'n';
    assert_eq!(refused(&bad_sum), "bad_header_checksum");
    let valid = valid_unified();
    assert_eq!(refused(&valid[..BLOCK * 3]), "archive_truncated");
    assert_eq!(refused(b"not an image at all"), "unknown_image_format");
    let mut trailing = valid_unified();
    trailing.extend_from_slice(b"smuggled");
    assert_eq!(refused(&trailing), "data_after_archive_end");
}

fn check_split(meta_tar: &[u8], disk: &[u8], max_virtual: u64) -> Option<Result<(), ImageRefusal>> {
    let meta = xz(meta_tar)?;
    let dir = scratch();
    let (meta_path, disk_path) = (dir.0.join("incus.tar.xz"), dir.0.join("disk.qcow2"));
    std::fs::write(&meta_path, meta).unwrap();
    std::fs::write(&disk_path, disk).unwrap();
    Some(validate_split_image(&meta_path, &disk_path, max_virtual))
}

#[test]
fn an_upstream_split_image_is_accepted_with_cloud_init_templates() {
    let Some(result) = check_split(
        &split_metadata_tar(SPLIT_METADATA),
        &qcow2(),
        SPLIT_VIRTUAL_SIZE_MAX,
    ) else {
        return;
    };
    assert_eq!(result, Ok(()));
    // The 26.04 image's metadata names no refused prefix (the template name
    // `cloud-init-user.tpl` is not `cloud-init.`).
    assert!(!metadata_names_refused_property(
        std::str::from_utf8(SPLIT_METADATA).unwrap()
    ));
}

/// I3: the disk's declared virtual size is bounded (32 GiB), and the
/// unified qcow2 rules (no backing file) apply to the bare disk too.
#[test]
fn a_split_disk_too_big_or_with_a_backing_file_is_refused() {
    let meta = split_metadata_tar(SPLIT_METADATA);
    let check = |disk: &[u8]| check_split(&meta, disk, SPLIT_VIRTUAL_SIZE_MAX);
    let Some(ok) = check(&qcow2_sized(SPLIT_VIRTUAL_SIZE_MAX)) else {
        return;
    };
    assert_eq!(ok, Ok(()));
    assert_eq!(
        check(&qcow2_sized(SPLIT_VIRTUAL_SIZE_MAX + 1)).unwrap(),
        Err(ImageRefusal("qcow2_virtual_size_too_large"))
    );
    assert_eq!(
        check(&qcow2_sized(0)).unwrap(),
        Err(ImageRefusal("qcow2_bad_virtual_size"))
    );
    let mut backing = qcow2();
    backing[8..16].copy_from_slice(&512u64.to_be_bytes());
    backing[16..20].copy_from_slice(&13u32.to_be_bytes());
    assert_eq!(
        check(&backing).unwrap(),
        Err(ImageRefusal("qcow2_backing_file"))
    );
    assert_eq!(
        check(b"not a qcow2").unwrap(),
        Err(ImageRefusal("rootfs_not_qcow2"))
    );
}

/// I3: metadata unpacks to at most 4 MiB, and every audit prefix is refused
/// with no exemption (not even wssp's own `user.flycockpit.*` or the
/// allocation audit's `limits.cpu`/`limits.memory`).
#[test]
fn split_metadata_too_big_or_naming_a_refused_prefix_is_refused() {
    let Some(_) = xz(b"probe") else {
        return;
    };
    let disk = qcow2();
    // Many template files: each under the 1 MiB metadata bound, together
    // past the 4 MiB unpacked bound.
    let mut big = Vec::new();
    entry(&mut big, "metadata.yaml", b'0', SPLIT_METADATA, "");
    for i in 0..5 {
        entry(
            &mut big,
            &format!("templates/t{i}.tpl"),
            b'0',
            &vec![b'x'; 1 << 20],
            "",
        );
    }
    assert_eq!(
        check_split(&finish(big), &disk, SPLIT_VIRTUAL_SIZE_MAX).unwrap(),
        Err(ImageRefusal("unpacked_too_large"))
    );
    for key in [
        "security.secureboot: \"false\"",
        "user.flycockpit.sandbox_id: x",
        "limits.cpu: \"2\"",
        "limits.memory: 1GiB",
        "raw.qemu: -x",
        "{volatile.base_image: x}",
        "- boot.autostart: true",
        "\"cloud-init.user-data\": x",
    ] {
        let metadata = format!("architecture: x86_64\nproperties:\n  {key}\n");
        assert_eq!(
            check_split(
                &split_metadata_tar(metadata.as_bytes()),
                &disk,
                SPLIT_VIRTUAL_SIZE_MAX
            )
            .unwrap(),
            Err(ImageRefusal("metadata_refused_property")),
            "{key}"
        );
    }
}

/// The metadata tarball has the unified rules minus the disk: no
/// `rootfs.img`, links, devices, traversal or a missing `metadata.yaml`.
#[test]
fn split_metadata_layout_is_strict() {
    let Some(_) = xz(b"probe") else {
        return;
    };
    let disk = qcow2();
    let refused = |tar: Vec<u8>| {
        check_split(&tar, &disk, SPLIT_VIRTUAL_SIZE_MAX)
            .unwrap()
            .unwrap_err()
            .0
    };
    let mut rootfs = Vec::new();
    entry(&mut rootfs, "metadata.yaml", b'0', SPLIT_METADATA, "");
    entry(&mut rootfs, "rootfs.img", b'0', &qcow2(), "");
    assert_eq!(refused(finish(rootfs)), "unexpected_entry");
    let mut link = Vec::new();
    entry(&mut link, "metadata.yaml", b'0', SPLIT_METADATA, "");
    entry(&mut link, "templates/x.tpl", b'2', b"", "/etc/shadow");
    assert_eq!(refused(finish(link)), "symlink_entry");
    let mut device = Vec::new();
    entry(&mut device, "metadata.yaml", b'0', SPLIT_METADATA, "");
    entry(&mut device, "templates/x.tpl", b'3', b"", "");
    assert_eq!(refused(finish(device)), "device_entry");
    let mut traversal = Vec::new();
    entry(&mut traversal, "metadata.yaml", b'0', SPLIT_METADATA, "");
    entry(&mut traversal, "../escape", b'0', b"x", "");
    assert_eq!(refused(finish(traversal)), "path_traversal");
    let mut none = Vec::new();
    entry(&mut none, "templates/x.tpl", b'0', b"x", "");
    assert_eq!(refused(finish(none)), "missing_metadata");
}
