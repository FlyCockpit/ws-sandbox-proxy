# wssp root-grow-helper (host-pushed per exec, run as guest root through
# `incus exec --user 0`; never an in-image copy). Arguments are host-derived
# only: grow <nonce> <expected-disk-bytes> <budget-seconds>. Exactly one
# record on stderr, exit 0, before the budget ends:
#
#   WSSP_ROOT <nonce> <disk> <part_end> <part> <fstype> <fs> <layout> <statvfs>
#
# Integers in bytes and constant tokens only, never guest text. The daemon
# decides (root_grow.rs); this helper only grows and measures:
# - the block device holding `/` (the mount source's device number, else
#   mountinfo's major:minor; btrfs reports an anonymous one), through sysfs.
#   A partition not ending at its disk's end is grown with `growpart`;
# - the filesystem from its own superblock (ext4, xfs, btrfs). One smaller
#   than its partition is grown online (resize2fs, xfs_growfs, btrfs
#   filesystem resize max), then measured again for a few seconds;
# - layout `partition`, `whole` (a filesystem on the whole disk) or
#   `unsupported` (device mapper, LVM, LUKS, md, anything else): nothing is
#   attempted, and only `statvfs` speaks for the root.
# Failures of the tools are not reported (their output is guest text): the
# measurement after them is the verdict.
import os
import stat
import struct
import subprocess
import sys
import time

SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
FSTYPES = ("ext4", "xfs", "btrfs")
SECTOR = 512
# Test hooks only (the unit tests exec this source under another __name__
# and point these at a temp tree they own). Production never changes them.
SYS = "/sys"
DEV = "/dev"
MOUNTINFO = "/proc/self/mountinfo"
RUN = True
SETTLE_S = 10.0
# Seconds kept back from the budget for the final measurement and record.
RESERVE_S = 3.0
DEADLINE = None


def at(root, path):
    return root.rstrip("/") + path


def read_int(path):
    with open(path) as handle:
        return int(handle.read().strip())


def remaining():
    if DEADLINE is None:
        return 3600.0
    return max(0.0, DEADLINE - time.monotonic())


def root_mount():
    """(major:minor, fstype) of the mount at `/` (the last one wins)."""
    found = None
    with open(MOUNTINFO) as handle:
        for line in handle:
            left, sep, right = line.partition(" - ")
            fields = left.split()
            tail = right.split()
            if not sep or len(fields) < 5 or fields[4] != "/" or len(tail) < 2:
                continue
            found = (fields[2], tail[0], tail[1])
    if found is None:
        raise RuntimeError("no root mount")
    majmin, fstype, source = found
    # btrfs (and some others) report an anonymous device number: the mount
    # source names the real block device.
    if source.startswith("/dev/"):
        try:
            st = os.stat(at(DEV, source[len("/dev") :]))
            if stat.S_ISBLK(st.st_mode):
                majmin = "%d:%d" % (os.major(st.st_rdev), os.minor(st.st_rdev))
        except OSError:
            pass
    return (majmin, fstype)


def device(majmin):
    """(layout, disk sysfs dir, part sysfs dir, disk node, part node, number)."""
    node = os.path.realpath(at(SYS, "/dev/block/" + majmin))
    name = os.path.basename(node)
    if not os.path.isdir(node) or name.startswith(("dm-", "md", "loop", "zram")):
        return ("unsupported", None, node, None, None, None)
    if os.path.exists(os.path.join(node, "partition")):
        disk = os.path.dirname(node)
        return (
            "partition",
            disk,
            node,
            at(DEV, "/" + os.path.basename(disk)),
            at(DEV, "/" + name),
            read_int(os.path.join(node, "partition")),
        )
    return ("whole", node, node, at(DEV, "/" + name), at(DEV, "/" + name), None)


def geometry(layout, disk, part):
    """(disk bytes, partition end bytes, partition bytes) from sysfs."""
    if layout == "unsupported":
        # Only statvfs speaks for such a root; an unresolvable device is 0.
        try:
            size = read_int(os.path.join(part, "size")) * SECTOR
        except (OSError, ValueError):
            size = 0
        return (size, size, size)
    disk_bytes = read_int(os.path.join(disk, "size")) * SECTOR
    if layout == "whole":
        return (disk_bytes, disk_bytes, disk_bytes)
    start = read_int(os.path.join(part, "start")) * SECTOR
    size = read_int(os.path.join(part, "size")) * SECTOR
    return (disk_bytes, start + size, size)


def superblock_bytes(fstype, node):
    """The filesystem's own size from its superblock, or 0."""
    try:
        with open(node, "rb") as handle:
            if fstype == "ext4":
                handle.seek(1024)
                sb = handle.read(1024)
                if len(sb) < 0x158 or struct.unpack_from("<H", sb, 0x38)[0] != 0xEF53:
                    return 0
                blocks = struct.unpack_from("<I", sb, 0x04)[0]
                if struct.unpack_from("<I", sb, 0x60)[0] & 0x80:
                    blocks |= struct.unpack_from("<I", sb, 0x150)[0] << 32
                return blocks * (1024 << struct.unpack_from("<I", sb, 0x18)[0])
            if fstype == "xfs":
                sb = handle.read(16)
                if len(sb) < 16 or sb[:4] != b"XFSB":
                    return 0
                return struct.unpack_from(">I", sb, 4)[0] * struct.unpack_from(">Q", sb, 8)[0]
            if fstype == "btrfs":
                handle.seek(65536)
                sb = handle.read(0x78)
                if len(sb) < 0x78 or sb[0x40:0x48] != b"_BHRfS_M":
                    return 0
                return struct.unpack_from("<Q", sb, 0x70)[0]
    except OSError:
        return 0
    return 0


def statvfs_bytes():
    st = os.statvfs("/")
    return st.f_blocks * st.f_frsize


def run(argv, timeout):
    timeout = min(timeout, remaining() - RESERVE_S)
    if not RUN or timeout <= 0:
        return
    try:
        subprocess.run(
            argv,
            env=ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def grow(nonce, expected):
    majmin, fstype = root_mount()
    fstype = fstype if fstype in FSTYPES else "other"
    layout, disk, part, disk_node, part_node, number = device(majmin)
    disk_bytes, part_end, part_bytes = geometry(layout, disk, part)
    # 2 MiB: growpart's 1 MiB alignment plus the 33-sector backup GPT.
    if layout == "partition" and disk_bytes - part_end > 2 * 1024 * 1024:
        run(["growpart", disk_node, str(number)], 120)
        disk_bytes, part_end, part_bytes = geometry(layout, disk, part)
    fs_bytes = superblock_bytes(fstype, part_node) if layout != "unsupported" else 0
    if layout != "unsupported" and fstype != "other" and fs_bytes < part_bytes - 4 * 1024 * 1024:
        timeout = 120 + part_bytes // (16 * 1024 ** 3)
        if fstype == "ext4":
            run(["resize2fs", part_node], timeout)
        elif fstype == "xfs":
            run(["xfs_growfs", "/"], timeout)
        else:
            run(["btrfs", "filesystem", "resize", "max", "/"], timeout)
        settle = time.monotonic() + min(SETTLE_S, max(0.0, remaining() - RESERVE_S))
        while True:
            fs_bytes = superblock_bytes(fstype, part_node)
            if fs_bytes >= part_bytes - 4 * 1024 * 1024 or time.monotonic() >= settle:
                break
            time.sleep(0.5)
    record(
        nonce,
        "%d %d %d %s %d %s %d"
        % (disk_bytes, part_end, part_bytes, fstype, fs_bytes, layout, statvfs_bytes()),
    )


def record(nonce, body):
    sys.stderr.write("WSSP_ROOT %s %s\n" % (nonce, body))
    sys.stderr.flush()


def main():
    global DEADLINE
    if (
        len(sys.argv) != 5
        or sys.argv[1] != "grow"
        or not sys.argv[3].isdigit()
        or not sys.argv[4].isdigit()
    ):
        sys.exit(2)
    nonce = sys.argv[2]
    DEADLINE = time.monotonic() + int(sys.argv[4])
    try:
        grow(nonce, int(sys.argv[3]))
    except Exception:
        record(nonce, "error")
    sys.exit(0)


if __name__ == "__main__":
    main()
