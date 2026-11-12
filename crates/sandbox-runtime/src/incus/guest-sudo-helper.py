# wssp guest-sudo-helper (host-pushed per exec, run as guest root through
# `incus exec --user 0`; never an in-image copy). Arguments are host-derived
# only: <mode> <nonce> <uid> <gid>. Exactly one record on stderr, exit 0:
#
#   WSSP_SUDO <nonce> <verdict> <impl> [<form>]
#
# Constant tokens only, never guest text. Modes:
# - grant: install /etc/sudoers.d/wssp-guest (`#<uid> ALL=(ALL) NOPASSWD:ALL`,
#   root:root 0440) through a temp file in /etc, then prove `sudo -n true`
#   as the guest uid. Verdicts: granted, sudo_missing, unsafe_dir, invalid,
#   not_effective. Any verdict but `granted` leaves no drop-in behind.
# - revoke: remove the drop-in (and a stale temp file). Verdicts: revoked,
#   root_granted <form> (a directory in its place, or unsafe parents).
# - revoke-audit: revoke, then a create-time hygiene audit for common static
#   root grants (not a security control: it runs on the guest's own python3).
#   Verdicts: clean, audit_inconclusive, root_granted <form>.
import os
import re
import stat
import subprocess
import sys

DROPIN = "wssp-guest"
TEMP = ".wssp-sudoers.tmp"
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
ENV = {"PATH": SAFE_PATH, "LC_ALL": "C", "LANG": "C"}
NAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
ROOT_GROUPS = (
    "sudo",
    "wheel",
    "admin",
    "root",
    "docker",
    "lxd",
    "incus",
    "incus-admin",
    "libvirt",
    "disk",
)
NOT_ALLOWED = "is not allowed to run sudo"
MAY_RUN = "may run the following commands"
# Test hooks only (the unit tests exec this source under another __name__
# and point these at a temp tree they own). Production never changes them.
ROOT = "/"
TRUSTED_UID = 0
TRUSTED_GID = 0
AS_GUEST = True


def at(path):
    """`path` (absolute) under ROOT."""
    return ROOT.rstrip("/") + path


class Unsafe(Exception):
    pass


def record(nonce, verdict, impl, form=None):
    line = "WSSP_SUDO %s %s %s" % (nonce, verdict, impl)
    if form:
        line += " " + form
    sys.stderr.write(line + "\n")
    sys.stderr.flush()
    sys.exit(0)


def safe_dir_stat(st):
    return (
        stat.S_ISDIR(st.st_mode)
        and st.st_uid == TRUSTED_UID
        and not (st.st_mode & (stat.S_IWGRP | stat.S_IWOTH))
    )


def open_dir(name, parent=None):
    """openat(O_DIRECTORY|O_NOFOLLOW); root-owned, no group/world write."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent)
    if not safe_dir_stat(os.fstat(fd)):
        os.close(fd)
        raise Unsafe()
    return fd


def walk_etc():
    """(etc_fd, sudoers_fd or None). Raises Unsafe on an unsafe parent."""
    root = open_dir(at("/"))
    try:
        etc = open_dir("etc", root)
    finally:
        os.close(root)
    try:
        sd = open_dir("sudoers.d", etc)
    except FileNotFoundError:
        sd = None
    except NotADirectoryError:
        os.close(etc)
        raise Unsafe()
    except OSError as error:
        # ELOOP: a symlink in place of the include directory.
        os.close(etc)
        raise Unsafe() from error
    return etc, sd


def resolve_trusted(path, setuid=False):
    """Resolve `path` component by component: every directory and symlink hop
    root-owned and not group/world-writable; the target a regular root-owned
    file (setuid when asked). Returns the resolved absolute path or None."""
    hops = 0
    parts = [p for p in path.split("/") if p]
    current = at("/")
    if not safe_dir_stat(os.lstat(current)):
        return None
    while parts:
        part = parts.pop(0)
        if part in (".", ""):
            continue
        if part == "..":
            # Every directory walked so far was checked; go back up.
            if current.rstrip("/") != at("/").rstrip("/"):
                current = os.path.dirname(current.rstrip("/")) or "/"
            continue
        candidate = os.path.join(current, part)
        try:
            st = os.lstat(candidate)
        except OSError:
            return None
        if stat.S_ISLNK(st.st_mode):
            hops += 1
            if hops > 16 or st.st_uid != TRUSTED_UID:
                return None
            target = os.readlink(candidate)
            if target.startswith("/"):
                current = at("/")
            parts = [p for p in target.split("/") if p] + parts
            continue
        if parts:
            if not safe_dir_stat(st):
                return None
            current = candidate
            continue
        if (
            not stat.S_ISREG(st.st_mode)
            or st.st_uid != TRUSTED_UID
            or st.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            return None
        if setuid and not st.st_mode & stat.S_ISUID:
            return None
        return candidate
    return None


def run(argv, timeout=10, **kwargs):
    try:
        done = subprocess.run(
            argv,
            env=ENV,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            cwd="/",
            close_fds=True,
            **kwargs
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return done


def impl_label(sudo):
    if sudo is None:
        return "none"
    done = run([sudo, "-V"], timeout=5)
    if done is None:
        return "unknown"
    first = (done.stdout or b"").split(b"\n", 1)[0].lower()
    if first.startswith(b"sudo-rs"):
        return "sudo_rs"
    if first.startswith(b"sudo version"):
        return "sudo_ws"
    return "unknown"


def unlink_entry(dirfd, name):
    """Remove a non-directory entry; True if it was a directory."""
    try:
        st = os.lstat(name, dir_fd=dirfd)
    except FileNotFoundError:
        return False
    if stat.S_ISDIR(st.st_mode):
        return True
    os.unlink(name, dir_fd=dirfd)
    return False


def fsync_dir(fd):
    try:
        os.fsync(fd)
    except OSError:
        pass


def grant(nonce, uid, gid):
    sudo = resolve_trusted("/usr/bin/sudo", setuid=True)
    impl = impl_label(sudo)
    visudo = resolve_trusted("/usr/sbin/visudo")
    try:
        etc, sd = walk_etc()
    except (Unsafe, OSError):
        # Unsafe parents: nothing here can be trusted, so nothing is touched.
        record(nonce, "unsafe_dir", impl)
    if sd is None:
        record(nonce, "unsafe_dir", impl)

    def fail(verdict):
        # U6: no drop-in survives a failed grant, including one an earlier
        # boot's grant installed (an early failure never leaves it live).
        try:
            unlink_entry(sd, DROPIN)
            fsync_dir(sd)
        except OSError:
            pass
        try:
            unlink_entry(etc, TEMP)
        except OSError:
            pass
        record(nonce, verdict, impl)

    if sudo is None:
        fail("sudo_missing")

    try:
        if unlink_entry(etc, TEMP):
            fail("invalid")
        fd = os.open(
            TEMP,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=etc,
        )
        try:
            os.fchown(fd, TRUSTED_UID, TRUSTED_GID)
            os.fchmod(fd, 0o440)
            os.write(fd, ("#%d ALL=(ALL) NOPASSWD:ALL\n" % uid).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        if visudo is not None:
            checked = run([visudo, "-c", "-f", at("/etc/" + TEMP)])
            if checked is None or checked.returncode != 0:
                fail("invalid")
        if unlink_entry(sd, DROPIN):
            fail("invalid")
        os.rename(TEMP, DROPIN, src_dir_fd=etc, dst_dir_fd=sd)
        fsync_dir(sd)
        fsync_dir(etc)
        if visudo is not None:
            checked = run([visudo, "-c"])
            if checked is None or checked.returncode != 0:
                fail("invalid")
    except OSError:
        fail("invalid")
    # The authoritative check: as the guest uid, no supplementary groups.
    identity = {"user": uid, "group": gid, "extra_groups": []} if AS_GUEST else {}
    proved = run([sudo, "-n", "true"], timeout=10, **identity)
    if proved is None or proved.returncode != 0:
        fail("not_effective")
    record(nonce, "granted", impl)


def revoke(nonce, impl):
    """Remove the drop-in and the temp file; returns on success."""
    try:
        etc, sd = walk_etc()
    except (Unsafe, OSError):
        record(nonce, "root_granted", impl, "unsafe_dir")
    try:
        if unlink_entry(etc, TEMP):
            record(nonce, "root_granted", impl, "sudoers_tmp_dir")
        if sd is not None:
            if unlink_entry(sd, DROPIN):
                record(nonce, "root_granted", impl, "sudoers_dir")
            fsync_dir(sd)
        fsync_dir(etc)
    except OSError:
        record(nonce, "root_granted", impl, "revoke_failed")


def read_lines(path):
    try:
        with open(path, "rb") as handle:
            data = handle.read(4 * 1024 * 1024)
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def sudo_rules(sudo, user):
    """True: rules listed; False: not allowed; None: inconclusive."""
    done = run([sudo, "-n", "-l", "-U", user], timeout=10)
    if done is None:
        return None
    text = (done.stdout or b"").decode("utf-8", "replace") + (
        done.stderr or b""
    ).decode("utf-8", "replace")
    if NOT_ALLOWED in text:
        return False
    if done.returncode == 0 and MAY_RUN in text:
        return True
    return None


def audit(nonce, uid, gid, impl):
    passwd = [line.split(":") for line in read_lines(at("/etc/passwd"))]
    passwd = [entry for entry in passwd if len(entry) >= 7]
    uid0 = [entry for entry in passwd if entry[2] == "0"]
    if len(uid0) > 1:
        record(nonce, "root_granted", impl, "uid0_alias")
    if gid == 0:
        record(nonce, "root_granted", impl, "gid0")
    guest = [entry for entry in passwd if entry[2] == str(uid)]
    name = guest[0][0] if len(guest) == 1 and NAME_RE.match(guest[0][0]) else None
    if name is not None and guest[0][3] == "0":
        record(nonce, "root_granted", impl, "gid0")
    findings = []
    inconclusive = False
    sudo = resolve_trusted("/usr/bin/sudo")
    if sudo is not None:
        rules = sudo_rules(sudo, "#%d" % uid)
        if rules is None and name is not None:
            rules = sudo_rules(sudo, name)
        if rules:
            findings.append("sudo_rule")
        elif rules is None:
            inconclusive = True
    groups = [line.split(":") for line in read_lines(at("/etc/group"))]
    groups = [entry for entry in groups if len(entry) >= 4]
    staff_writable = False
    try:
        st = os.lstat(at("/usr/local"))
        staff_writable = bool(st.st_mode & stat.S_IWGRP)
    except OSError:
        pass
    for entry in groups:
        members = [m for m in entry[3].split(",") if m]
        member = entry[2] == str(gid) or (name is not None and name in members)
        if not member:
            continue
        if entry[2] == "0":
            findings.append("gid0")
        elif entry[0] in ROOT_GROUPS:
            findings.append("group_" + entry[0].replace("-", "_"))
        elif entry[0] == "staff" and staff_writable:
            findings.append("group_staff")
    for path in ("/etc/doas.conf", "/usr/local/etc/doas.conf"):
        for line in read_lines(at(path)):
            if line.strip().startswith("permit"):
                findings.append("doas")
                break
    for line in read_lines(at("/etc/shadow")):
        fields = line.split(":")
        if len(fields) < 2:
            continue
        hashed = fields[1]
        if fields[0] == "root" and hashed == "":
            findings.append("root_password_empty")
        if name is not None and fields[0] == name:
            if hashed and hashed[0] not in "!*" and hashed != "x":
                findings.append("guest_password")
    if findings:
        record(nonce, "root_granted", impl, findings[0])
    if inconclusive:
        record(nonce, "audit_inconclusive", impl)
    record(nonce, "clean", impl)


def main():
    if len(sys.argv) != 5:
        sys.exit(2)
    mode, nonce, uid, gid = sys.argv[1:]
    if not re.match(r"^[0-9a-f]{32}$", nonce):
        sys.exit(2)
    if not uid.isdigit() or not gid.isdigit():
        sys.exit(2)
    uid, gid = int(uid), int(gid)
    if uid == 0 or uid > 4294967294 or gid > 4294967294:
        sys.exit(2)
    os.umask(0o077)
    if mode == "grant":
        grant(nonce, uid, gid)
    elif mode in ("revoke", "revoke-audit"):
        sudo = resolve_trusted("/usr/bin/sudo")
        impl = impl_label(sudo)
        revoke(nonce, impl)
        if mode == "revoke":
            record(nonce, "revoked", impl)
        audit(nonce, uid, gid, impl)
    sys.exit(2)


if __name__ == "__main__":
    main()
