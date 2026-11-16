//! Root growth: argv, the strict record, the decision, and the real helper run
//! against a temp sysfs/dev/mountinfo tree with a crafted superblock (never a
//! real disk, and the grow tools are not run).
use super::*;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

const NONCE: &str = "0123456789abcdef0123456789abcdef";
const GIB: u64 = 1 << 30;

fn out(stderr: &str) -> IncusCommandOutput {
    IncusCommandOutput {
        stdout: String::new(),
        stderr: stderr.into(),
        exit_code: 0,
    }
}

fn grown(disk: u64) -> RootRecord {
    // The community layout: a 100 MiB EFI partition at 1 MiB, then the root
    // to the end of the disk (minus the 33-sector backup GPT); ext4 rounds
    // to 4 KiB blocks.
    let part_end = disk - 33 * 512;
    let part = part_end - 206_848 * 512;
    RootRecord {
        disk_bytes: disk,
        part_end_bytes: part_end,
        part_bytes: part,
        fstype: RootFsType::Ext4,
        fs_bytes: part / 4096 * 4096,
        layout: RootLayout::Partition,
        statvfs_bytes: part / 100 * 97,
    }
}

#[test]
fn argv_is_host_derived() {
    let argv = root_grow_argv(NONCE, 48 * GIB, Duration::from_secs(120));
    assert_eq!(argv[..5], ["python3", "-I", "-S", "-B", "-c"]);
    assert_eq!(argv[5], ROOT_GROW_HELPER);
    // The helper's budget leaves the daemon's wait a margin for the record.
    assert_eq!(argv[6..], ["grow", NONCE, "51539607552", "115"]);
    assert_eq!(root_grow_argv(NONCE, GIB, Duration::from_secs(2))[9], "1");
    assert!(ROOT_GROW_HELPER.contains("wssp root-grow-helper"));
}

#[test]
fn records_are_strict_and_nonce_bound() {
    let good = format!(
        "WSSP_ROOT {NONCE} 51539607552 51539590656 51433684480 ext4 51433680896 partition 49778450432\n"
    );
    // The live 48 GiB community sandbox (cloud-init growpart, 2026-11-16).
    assert_eq!(
        parse_root_record(NONCE, &out(&good)),
        Some(RootRecord {
            disk_bytes: 51_539_607_552,
            part_end_bytes: 51_539_590_656,
            part_bytes: 51_433_684_480,
            fstype: RootFsType::Ext4,
            fs_bytes: 51_433_680_896,
            layout: RootLayout::Partition,
            statvfs_bytes: 49_778_450_432,
        })
    );
    for bad in [
        good.trim_end().to_string(),
        good.replace("ext4", "zfs"),
        good.replace("partition", "lvm"),
        good.replace("51433680896", "-1"),
        good.replace("51433680896", "5143368089x"),
        good.replace(" 49778450432", ""),
        good.replace(" 49778450432", " 49778450432 1"),
        format!("WSSP_ROOT ffff{} 1 1 1 ext4 1 whole 1\n", &NONCE[4..]),
        format!("WSSP_ROOT {NONCE} error\n"),
        format!("x\n{good}"),
    ] {
        assert!(parse_root_record(NONCE, &out(&bad)).is_none(), "{bad}");
    }
    let mut failed = out(&good);
    failed.exit_code = 1;
    assert!(parse_root_record(NONCE, &failed).is_none());
    let mut chatty = out(&good);
    chatty.stdout = "guest text".into();
    assert!(parse_root_record(NONCE, &chatty).is_none());
}

#[test]
fn a_root_grown_to_its_disk_passes() {
    for disk in [8 * GIB, 24 * GIB, 32 * GIB, 48 * GIB, 2048 * GIB] {
        assert_eq!(decide_root(disk, Some(grown(disk))), Ok(()), "{disk}");
    }
    // A volume the storage driver rounded up is still the configured disk.
    assert_eq!(
        decide_root(32 * GIB, Some(grown(32 * GIB + 4 * MIB))),
        Ok(())
    );
    let whole = RootRecord {
        layout: RootLayout::Whole,
        part_end_bytes: 32 * GIB,
        part_bytes: 32 * GIB,
        fs_bytes: 32 * GIB,
        ..grown(32 * GIB)
    };
    assert_eq!(decide_root(32 * GIB, Some(whole)), Ok(()));
    let btrfs = RootRecord {
        fstype: RootFsType::Btrfs,
        fs_bytes: grown(32 * GIB).part_bytes - 12 * MIB,
        ..grown(32 * GIB)
    };
    assert_eq!(decide_root(32 * GIB, Some(btrfs)), Ok(()));
}

#[test]
fn a_root_that_did_not_grow_fails_with_its_label() {
    let disk = 48 * GIB;
    assert_eq!(decide_root(disk, None), Err("no_record"));
    // The 32 GiB image root on a 48 GiB disk: nothing grew.
    let image = grown(32 * GIB);
    assert_eq!(
        decide_root(
            disk,
            Some(RootRecord {
                disk_bytes: disk,
                ..image
            })
        ),
        Err("partition_not_grown")
    );
    // The partition grew, the filesystem did not (even by 1 GiB).
    let partition = grown(disk);
    assert_eq!(
        decide_root(
            disk,
            Some(RootRecord {
                fs_bytes: partition.part_bytes - GIB,
                ..partition
            })
        ),
        Err("fs_not_grown")
    );
    assert_eq!(
        decide_root(
            disk,
            Some(RootRecord {
                fs_bytes: 0,
                ..partition
            })
        ),
        Err("fs_not_grown")
    );
    // The guest sees less disk than wssp configured.
    assert_eq!(decide_root(disk, Some(grown(32 * GIB))), Err("disk_small"));
    // Inconsistent geometry is never a pass.
    assert_eq!(
        decide_root(
            disk,
            Some(RootRecord {
                part_end_bytes: disk + 1,
                ..partition
            })
        ),
        Err("record_invalid")
    );
}

#[test]
fn an_unsupported_layout_passes_only_when_it_already_fills_the_disk() {
    let disk = 32 * GIB;
    let lvm = RootRecord {
        layout: RootLayout::Unsupported,
        fstype: RootFsType::Ext4,
        fs_bytes: 0,
        ..grown(disk)
    };
    assert_eq!(
        decide_root(
            disk,
            Some(RootRecord {
                statvfs_bytes: disk / 100 * 96,
                ..lvm
            })
        ),
        Ok(())
    );
    assert_eq!(
        decide_root(
            disk,
            Some(RootRecord {
                statvfs_bytes: disk / 2,
                ..lvm
            })
        ),
        Err("layout_unsupported")
    );
    let other = RootRecord {
        fstype: RootFsType::Other,
        statvfs_bytes: 8 * GIB,
        ..grown(disk)
    };
    assert_eq!(decide_root(disk, Some(other)), Err("layout_unsupported"));
    // An LVM root: the helper reports the 31 GiB logical volume, not the
    // 32 GiB disk. Judged against the configured disk, never `disk_small`.
    let lv = RootRecord {
        layout: RootLayout::Unsupported,
        fstype: RootFsType::Ext4,
        disk_bytes: 31 * GIB,
        part_end_bytes: 31 * GIB,
        part_bytes: 31 * GIB,
        fs_bytes: 0,
        statvfs_bytes: 30 * GIB,
    };
    assert_eq!(decide_root(disk, Some(lv)), Ok(()));
}

#[test]
fn failures_are_typed_root_disk_not_grown_with_a_constant_label() {
    let error = not_grown("fs_not_grown");
    assert_eq!(error.code, SandboxErrorCode::GuestUnavailable);
    assert_eq!(
        error.readiness_reason(),
        Some(ReadinessFailureReason::RootDiskNotGrown)
    );
    assert_eq!(
        ReadinessFailureReason::RootDiskNotGrown.as_str(),
        "root_disk_not_grown"
    );
}

// --- the real helper, against a temp tree -------------------------------

struct Tree {
    root: PathBuf,
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// An ext4 superblock image (1 KiB at offset 1024) with `blocks` 4 KiB blocks.
fn ext4_image(path: &Path, blocks: u64) {
    let mut image = vec![0u8; 4096];
    let sb = &mut image[1024..2048];
    sb[0x04..0x08].copy_from_slice(&((blocks & 0xffff_ffff) as u32).to_le_bytes());
    sb[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes()); // 1024 << 2 = 4096
    sb[0x38..0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
    sb[0x60..0x64].copy_from_slice(&0x80u32.to_le_bytes()); // 64bit
    sb[0x150..0x154].copy_from_slice(&((blocks >> 32) as u32).to_le_bytes());
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, image).unwrap();
}

/// `/` on sda2 (8:2): disk `disk_sectors`, root partition from sector
/// 206848 for `part_sectors`, ext4 of `fs_blocks`.
fn tree(name: &str, disk_sectors: u64, part_sectors: u64, fs_blocks: u64) -> Tree {
    let root = std::env::temp_dir().join(format!(
        "wssp-root-grow-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let disk = root.join("sys/devices/pci0000:00/virtio1/host0/block/sda");
    write(&disk.join("size"), &format!("{disk_sectors}\n"));
    write(&disk.join("sda2/partition"), "2\n");
    write(&disk.join("sda2/start"), "206848\n");
    write(&disk.join("sda2/size"), &format!("{part_sectors}\n"));
    std::fs::create_dir_all(root.join("sys/dev/block")).unwrap();
    symlink(disk.join("sda2"), root.join("sys/dev/block/8:2")).unwrap();
    ext4_image(&root.join("dev/sda2"), fs_blocks);
    write(
        &root.join("mountinfo"),
        "22 1 0:21 / /proc rw - proc proc rw\n28 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n",
    );
    Tree { root }
}

fn run_helper(tree: &Tree) -> String {
    let root = tree.root.to_str().unwrap();
    let harness = format!(
        "import sys\nsrc = sys.stdin.read()\ng = {{'__name__': 'wssp_test'}}\nexec(compile(src, 'root-grow-helper', 'exec'), g)\ng['SYS'] = {sys:?}\ng['DEV'] = {dev:?}\ng['MOUNTINFO'] = {mi:?}\ng['RUN'] = False\ng['SETTLE_S'] = 0.0\nsys.argv = ['helper', 'grow', {NONCE:?}, '1', '30']\ntry:\n    g['main']()\nexcept SystemExit:\n    pass\n",
        sys = format!("{root}/sys"),
        dev = format!("{root}/dev"),
        mi = format!("{root}/mountinfo"),
    );
    let mut child = Command::new("python3")
        .args(["-I", "-S", "-B", "-c", &harness])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(ROOT_GROW_HELPER.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.stdout.is_empty(), "no stdout");
    String::from_utf8(out.stderr).unwrap()
}

fn helper_record(tree: &Tree) -> RootRecord {
    let stderr = run_helper(tree);
    parse_root_record(NONCE, &out(&stderr)).unwrap_or_else(|| panic!("record: {stderr}"))
}

#[test]
fn helper_measures_a_grown_root_from_sysfs_and_the_superblock() {
    // The live 48 GiB community sandbox's geometry.
    let t = tree("grown", 100_663_296, 100_456_415, 12_557_051);
    let r = helper_record(&t);
    assert_eq!(r.disk_bytes, 51_539_607_552);
    assert_eq!(r.part_end_bytes, (206_848 + 100_456_415) * 512);
    assert_eq!(r.part_bytes, 100_456_415 * 512);
    assert_eq!(r.fstype, RootFsType::Ext4);
    assert_eq!(r.fs_bytes, 12_557_051 * 4096);
    assert_eq!(r.layout, RootLayout::Partition);
    assert!(r.statvfs_bytes > 0);
    assert_eq!(decide_root(48 * GIB, Some(r)), Ok(()));
}

#[test]
fn helper_reports_an_ungrown_root_without_guest_text() {
    // An 8 GiB image root on a 48 GiB disk (the tools are not run here).
    let t = tree("ungrown", 100_663_296, 16_570_335, 2_071_291);
    let stderr = run_helper(&t);
    assert!(stderr.starts_with(&format!("WSSP_ROOT {NONCE} ")));
    assert_eq!(stderr.lines().count(), 1);
    let r = parse_root_record(NONCE, &out(&stderr)).unwrap();
    assert_eq!(decide_root(48 * GIB, Some(r)), Err("partition_not_grown"));
}

#[test]
fn helper_reports_error_when_nothing_is_mounted_at_root() {
    let t = tree("nomount", 100_663_296, 100_456_415, 12_557_051);
    write(
        &t.root.join("mountinfo"),
        "22 1 0:21 / /proc rw - proc proc rw\n",
    );
    let stderr = run_helper(&t);
    assert_eq!(stderr, format!("WSSP_ROOT {NONCE} error\n"));
    assert_eq!(
        decide_root(48 * GIB, parse_root_record(NONCE, &out(&stderr))),
        Err("no_record")
    );
}

#[test]
fn helper_treats_device_mapper_roots_as_unsupported() {
    let t = tree("dm", 100_663_296, 100_456_415, 12_557_051);
    let dm = t.root.join("sys/devices/virtual/block/dm-0");
    write(&dm.join("size"), "100663296\n");
    std::fs::remove_file(t.root.join("sys/dev/block/8:2")).unwrap();
    symlink(dm, t.root.join("sys/dev/block/8:2")).unwrap();
    let r = helper_record(&t);
    assert_eq!(r.layout, RootLayout::Unsupported);
    assert_eq!(r.fs_bytes, 0);
}

#[test]
fn helper_reports_an_unresolvable_root_device_as_unsupported_not_an_error() {
    // btrfs-style anonymous device number with no block device behind it.
    let t = tree("anon", 100_663_296, 100_456_415, 12_557_051);
    write(
        &t.root.join("mountinfo"),
        "28 1 0:33 / / rw,relatime shared:1 - btrfs /dev/vda2 rw\n",
    );
    let r = helper_record(&t);
    assert_eq!(r.layout, RootLayout::Unsupported);
    assert_eq!(r.fstype, RootFsType::Btrfs);
    assert_eq!((r.disk_bytes, r.fs_bytes), (0, 0));
    assert!(r.statvfs_bytes > 0);
}
