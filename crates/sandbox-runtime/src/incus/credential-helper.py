# Credential helper, run as `python3 -I -S -B -c <helper> <mode>`
# after dirfd_walk.py and guest_freeze.py. Every control field and the
# restore payload arrive on stdin; nothing path-like is ever in argv.
#
# stdin : u32be controlLen | control JSON | payload (restore only)
# stdout: u32be reportLen  | report JSON  | bundle (pack only, report.bundleLen bytes)
#
# Credential scrub NEVER follows a link: a symlink is unlinked, its target is
# never touched (unlike the image-cache capture scrub). Pack never reads
# through a link. Correctness never depends on quiesce having stopped every
# writer: every step is descriptor-relative and scrub verifies absence.
# A scrub is durable before it is verified or reported: each parent directory
# is fsynced and every filesystem synced (a forced stop drops the page cache).
import json, signal, struct, sys
MAX_DEPTH = 32
MAX_ENTRIES = 4096
PATH_MAX = 1024
PATH_TOTAL_MAX = 524288
DECLARED_PATH_MAX = 255
CONTROL_MAX = 1 << 20
MODE_BUDGET_S = 10.0
QUIESCE_TERM_S = 3.0
QUIESCE_KILL_S = 3.0
QUIESCE_FREEZE_S = 3.0
started = time.monotonic()
counts = {"removed": 0, "links": 0, "skippedLinks": 0, "skippedSpecial": 0,
          "filesWritten": 0, "dirsCreated": 0, "terminated": 0, "killed": 0}
class Abort(Exception):
    pass
def budget():
    if time.monotonic() - started > MODE_BUDGET_S:
        raise Abort("time budget exceeded")
def read_exact(f, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = f.read(n - len(buf))
        if not chunk:
            raise Abort("truncated input")
        buf += chunk
    return bytes(buf)
def read_control(f):
    n = struct.unpack(">I", read_exact(f, 4))[0]
    if n > CONTROL_MAX:
        raise Abort("control too large")
    ctl = json.loads(read_exact(f, n).decode("utf-8"))
    if not isinstance(ctl, dict):
        raise Abort("control is not an object")
    return ctl
def emit(report, body=b""):
    data = json.dumps(report, sort_keys=True).encode("utf-8")
    out = sys.stdout.buffer
    out.write(struct.pack(">I", len(data)) + data)
    if body:
        out.write(body)
    out.flush()
def valid_rel(p, limit):
    if not isinstance(p, str) or not p or len(p.encode("utf-8", "surrogateescape")) > limit:
        return False
    if p.startswith("/") or any(c in p for c in "\\:") or any(ord(c) < 0x20 or ord(c) == 0x7F for c in p):
        return False
    parts = p.split("/")
    if any(s in ("", ".", "..") or s.startswith(".wssp-cred-") for s in parts) or parts[0].startswith(".wssp"):
        return False
    return True
def rel_list(ctl, key):
    value = ctl.get(key, [])
    if not isinstance(value, list) or not all(valid_rel(p, DECLARED_PATH_MAX) for p in value):
        raise Abort("invalid %s paths" % key)
    return value
def within(path, ancestor):
    return path == ancestor or path.startswith(ancestor + "/")
def open_home(home):
    if not isinstance(home, str) or not home.startswith("/") or "\0" in home:
        raise Abort("invalid home")
    try:
        return open_dir(home)
    except OSError:
        raise Abort("home is not a directory")
class LinkComponent(Exception):
    pass
def open_parent(hfd, parts, create):
    """fd of the directory holding parts[-1] (None when a component is
    missing and `create` is false). A symlink or non-directory component
    raises LinkComponent; it is never followed."""
    fd = os.dup(hfd)
    try:
        for part in parts[:-1]:
            try:
                nfd = os.open(part, O_DIR, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    counts["dirsCreated"] += 1
                except FileExistsError:
                    pass
                try:
                    nfd = os.open(part, O_DIR, dir_fd=fd)
                except OSError as e:
                    if e.errno in (errno.ELOOP, errno.ENOTDIR):
                        raise LinkComponent()
                    raise
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise LinkComponent()
                raise
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise
# ---- scrub (links unlinked, targets never touched) -------------------------
def cred_remove(dfd, name, shown, depth):
    budget()
    try:
        st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as e:
        fail(shown, e.strerror or "lstat")
        return
    before = len(errors)
    if stat.S_ISLNK(st.st_mode):
        checked_remove(dfd, name, st, shown, False)
        if len(errors) == before:
            counts["links"] += 1
        return
    if stat.S_ISDIR(st.st_mode):
        if depth > MAX_DEPTH:
            fail(shown, "depth limit exceeded")
            return
        _race_window("descend", shown)
        try:
            cfd = os.open(name, O_DIR, dir_fd=dfd)
        except OSError as e:
            fail(shown, "replaced during scrub" if e.errno in (errno.ELOOP, errno.ENOTDIR) else (e.strerror or "open"))
            return
        try:
            if not same(os.fstat(cfd), st):
                fail(shown, "replaced during scrub")
                return
            with os.scandir(cfd) as it:
                children = sorted(entry.name for entry in it)
            for child in children:
                cred_remove(cfd, child, shown + "/" + child, depth + 1)
        finally:
            os.close(cfd)
        before = len(errors)
    checked_remove(dfd, name, st, shown, stat.S_ISDIR(st.st_mode))
    if len(errors) == before:
        counts["removed"] += 1
def present(hfd, rel):
    parts = rel.split("/")
    try:
        pfd = open_parent(hfd, parts, False)
    except LinkComponent:
        return False
    if pfd is None:
        return False
    try:
        os.stat(parts[-1], dir_fd=pfd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False
    finally:
        os.close(pfd)
def make_durable(fd, shown):
    """fsync a directory whose entry was just removed. A failure fails the
    scrub: an unlink that never reached the disk is not a scrub."""
    try:
        os.fsync(fd)
    except OSError as e:
        fail(shown, "fsync failed: %s" % (e.strerror or "fsync"))
def staging_names(pfd):
    # Exactly the names write_entry creates: no prefix-only or broad glob.
    # Every path depth reserves this prefix, so no login may own a match.
    with os.scandir(pfd) as it:
        return sorted(e.name for e in it if len(e.name) == 27
                      and e.name.startswith(".wssp-cred-")
                      and all(c in "0123456789abcdef" for c in e.name[11:]))
def scrub_paths(hfd, rels):
    """Remove every declared path, then make the removal durable (fsync of
    each parent directory, then sync(2) of every filesystem) and only then
    verify absence. A forced power-off after the report (`incus stop
    --force`) discards the guest page cache: an unlink that is only there
    would come back on the next boot or in a captured disk."""
    for rel in rels:
        parts = rel.split("/")
        try:
            pfd = open_parent(hfd, parts, False)
        except LinkComponent:
            # The declared location runs through a link: nothing exists at
            # it in the real tree, and the link itself is not ours to remove.
            continue
        if pfd is None:
            continue
        try:
            cred_remove(pfd, parts[-1], rel, len(parts))
            for name in staging_names(pfd):
                shown = "/".join(parts[:-1] + [name])
                cred_remove(pfd, name, shown, len(parts))
            make_durable(pfd, rel)
        finally:
            os.close(pfd)
    os.sync()
    for rel in rels:
        if present(hfd, rel):
            fail(rel, "present after scrub")
        parts = rel.split("/")
        try:
            pfd = open_parent(hfd, parts, False)
        except LinkComponent:
            continue
        if pfd is not None:
            try:
                for name in staging_names(pfd):
                    fail("/".join(parts[:-1] + [name]), "present after scrub")
            finally:
                os.close(pfd)
def failed_paths():
    return sorted(set(e["path"] for e in errors))
def mode_scrub(ctl):
    hfd = open_home(ctl.get("home"))
    try:
        scrub_paths(hfd, rel_list(ctl, "paths"))
    finally:
        os.close(hfd)
    ok = not errors
    emit({"ok": ok, "verifiedAbsent": ok, "removed": counts["removed"],
          "linksUnlinked": counts["links"], "failed": failed_paths()})
    return 0 if ok else 1
# ---- pack -------------------------------------------------------------------
def mode_pack(ctl):
    digest = bytes.fromhex(ctl["digest"])
    if len(digest) != 32:
        raise Abort("invalid digest")
    max_bytes = int(ctl["maxBytes"])
    roots = sorted(set(rel_list(ctl, "required") + rel_list(ctl, "optional")))
    exclude = rel_list(ctl, "exclude")
    entries = {}
    totals = {"data": 0, "paths": 0}
    def excluded(p):
        return any(within(p, e) for e in exclude)
    def add(rel, kind, mode, data):
        if rel in entries:
            return
        raw = rel.encode("utf-8")
        if len(raw) > PATH_MAX:
            raise Abort("path length limit exceeded")
        totals["paths"] += len(raw)
        if totals["paths"] > PATH_TOTAL_MAX:
            raise Abort("path total limit exceeded")
        if len(entries) >= MAX_ENTRIES:
            raise Abort("entry limit exceeded")
        entries[rel] = (kind, mode, data)
    def visit(dfd, name, rel, depth):
        budget()
        if depth > MAX_DEPTH:
            raise Abort("depth limit exceeded")
        if excluded(rel):
            return
        if not valid_rel(rel, PATH_MAX):
            raise Abort("unsupported file name")
        try:
            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            counts["skippedLinks"] += 1
        elif stat.S_ISDIR(st.st_mode):
            _race_window("descend", rel)
            try:
                cfd = os.open(name, O_DIR, dir_fd=dfd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise Abort("replaced during pack")
                raise
            try:
                if not same(os.fstat(cfd), st):
                    raise Abort("replaced during pack")
                add(rel, 2, 0o700, b"")
                with os.scandir(cfd) as it:
                    children = sorted(entry.name for entry in it)
                for child in children:
                    visit(cfd, child, rel + "/" + child, depth + 1)
            finally:
                os.close(cfd)
        elif stat.S_ISREG(st.st_mode):
            _race_window("read", rel)
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
            except OSError as e:
                if e.errno in (errno.ELOOP, errno.ENXIO):
                    raise Abort("replaced during pack")
                raise
            try:
                fst = os.fstat(fd)
                if not stat.S_ISREG(fst.st_mode) or not same(fst, st):
                    raise Abort("replaced during pack")
                room = max_bytes - totals["data"]
                chunks = []
                got = 0
                while True:
                    chunk = os.read(fd, min(65536, room - got + 1))
                    if not chunk:
                        break
                    got += len(chunk)
                    chunks.append(chunk)
                    if got > room:
                        raise Abort("credential files exceed maxBytes")
                totals["data"] += got
                add(rel, 1, 0o700 if st.st_mode & 0o100 else 0o600, b"".join(chunks))
            finally:
                os.close(fd)
        else:
            counts["skippedSpecial"] += 1
    hfd = open_home(ctl.get("home"))
    try:
        for root in roots:
            if excluded(root):
                continue
            parts = root.split("/")
            try:
                pfd = open_parent(hfd, parts, False)
            except LinkComponent:
                counts["skippedLinks"] += 1
                continue
            if pfd is None:
                continue
            try:
                visit(pfd, parts[-1], root, len(parts))
            finally:
                os.close(pfd)
    finally:
        os.close(hfd)
    ordered = sorted(entries.items(), key=lambda kv: kv[0].encode("utf-8"))
    out = bytearray(b"WSCB\x01" + digest + struct.pack(">HH", len(ordered), 0))
    for rel, (kind, mode, data) in ordered:
        raw = rel.encode("utf-8")
        out += struct.pack(">BHH", kind, mode, len(raw)) + raw + struct.pack(">I", len(data)) + data
    emit({"ok": True, "bundleLen": len(out), "fileCount": len(ordered),
          "skippedLinks": counts["skippedLinks"], "skippedSpecial": counts["skippedSpecial"]},
         bytes(out))
    return 0
# ---- restore ----------------------------------------------------------------
def mode_restore(ctl):
    os.umask(0o077)
    declared = ctl.get("declared")
    if not isinstance(declared, dict):
        raise Abort("invalid declared paths")
    include = sorted(set(rel_list(declared, "required") + rel_list(declared, "optional")))
    exclude = rel_list(declared, "exclude")
    specs = ctl.get("entries")
    if not isinstance(specs, list) or len(specs) > MAX_ENTRIES:
        raise Abort("invalid entries")
    payload = []
    previous = None
    for spec in specs:
        kind, path, mode, size = spec["kind"], spec["path"], spec["mode"], spec["len"]
        if kind not in (1, 2) or not valid_rel(path, PATH_MAX) or not isinstance(size, int) or size < 0:
            raise Abort("invalid entry")
        if not any(within(path, d) for d in include) or any(within(path, e) for e in exclude):
            raise Abort("undeclared entry")
        raw = path.encode("utf-8")
        if previous is not None and previous >= raw:
            raise Abort("unsorted entries")
        previous = raw
        if kind == 2 and size != 0:
            raise Abort("directory carries data")
        payload.append((kind, path, (0o700 if kind == 2 or mode & 0o100 else 0o600), read_exact(sys.stdin.buffer, size)))
    if sys.stdin.buffer.read(1):
        raise Abort("trailing input")
    hfd = open_home(ctl.get("home"))
    try:
        scrub_paths(hfd, include)
        if errors:
            raise Abort("declared paths not cleared")
        for kind, path, mode, data in payload:
            budget()
            write_entry(hfd, kind, path, mode, data)
            if errors:
                raise Abort("restore failed")
    finally:
        os.close(hfd)
    emit({"ok": True, "filesWritten": counts["filesWritten"], "dirsCreated": counts["dirsCreated"]})
    return 0
def write_entry(hfd, kind, path, mode, data):
    parts = path.split("/")
    try:
        pfd = open_parent(hfd, parts, True)
    except LinkComponent:
        fail(path, "parent is not a directory")
        return
    name = parts[-1]
    try:
        try:
            st = os.stat(name, dir_fd=pfd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if kind == 2:
            if st is None:
                os.mkdir(name, 0o700, dir_fd=pfd)
                counts["dirsCreated"] += 1
            elif not stat.S_ISDIR(st.st_mode):
                fail(path, "target is not a directory")
            return
        if st is not None and not stat.S_ISREG(st.st_mode):
            fail(path, "target is not a regular file")
            return
        tmp = ".wssp-cred-%s" % os.urandom(8).hex()
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=pfd)
        try:
            try:
                view = memoryview(data)
                while view:
                    view = view[os.write(fd, view):]
                os.fchmod(fd, mode)
                os.fsync(fd)
            finally:
                os.close(fd)
            _race_window("rename", path)
            try:
                cur = os.stat(name, dir_fd=pfd, follow_symlinks=False)
                if not stat.S_ISREG(cur.st_mode):
                    fail(path, "target is not a regular file")
                    return
            except FileNotFoundError:
                pass
            os.rename(tmp, name, src_dir_fd=pfd, dst_dir_fd=pfd)
            os.fsync(pfd)
        finally:
            # Includes failed revalidation and rename, not only failed writes.
            try:
                os.unlink(tmp, dir_fd=pfd)
            except FileNotFoundError:
                pass
        counts["filesWritten"] += 1
    finally:
        os.close(pfd)
# ---- quiesce (root) ---------------------------------------------------------
def task_uids(pid):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("Uid:"):
                return [int(x) for x in line.split()[1:3]]
    return []
def uid_tasks(uid, keep):
    """Live user-space processes (not threads) whose real or effective uid is `uid`."""
    found = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) in keep:
            continue
        pid = int(name)
        try:
            state, _, flags = proc_stat(pid)
            if flags & PF_KTHREAD or state in ("Z", "X", "x"):
                continue
            if uid in task_uids(pid):
                found.append(pid)
        except (OSError, ValueError, IndexError):
            continue
    return sorted(found)
def send(pid, sig):
    try:
        os.kill(pid, sig)
        return True
    except ProcessLookupError:
        return False
def alive(pid):
    return os.path.exists("/proc/%d" % pid)
def wait_gone(uid, keep, seconds):
    deadline = time.monotonic() + seconds
    while True:
        left = uid_tasks(uid, keep)
        if not left or time.monotonic() > deadline:
            return left
        time.sleep(0.05)
def thaw_guest():
    """Undo freeze_guest: thaw every frozen cgroup, move held processes and
    this helper back to their own cgroups, remove the helper's cgroups."""
    for node in reversed(frozen_roots):
        try:
            cg_write(cgdir(node) + "/cgroup.freeze", "0")
        except OSError as e:
            fail("<thaw>", "cannot thaw %s: %s" % (node, e.strerror or e))
    hold, helper, origin = cg_state["hold"], cg_state["helper"], cg_state["origin"]
    if hold:
        try:
            cg_write(cgdir(hold) + "/cgroup.freeze", "0")
        except OSError as e:
            fail("<thaw>", "cannot thaw %s: %s" % (hold, e.strerror or e))
    for pid, where in sorted(held_from.items()):
        if alive(pid):
            try:
                cg_write(cgdir(where) + "/cgroup.procs", str(pid))
            except (ProcessLookupError, FileNotFoundError):
                pass
            except OSError as e:
                fail("<thaw>", "cannot return process %d: %s" % (pid, e.strerror or e))
    if helper and origin:
        try:
            cg_write(cgdir(origin) + "/cgroup.procs", str(os.getpid()))
        except OSError:
            pass
    for node in (hold, helper):
        if node:
            try:
                os.rmdir(cgdir(node))
            except OSError:
                pass
def scan_kill(uid, keep, seconds):
    deadline = time.monotonic() + seconds
    while True:
        left = uid_tasks(uid, keep)
        if not left or time.monotonic() > deadline:
            return left
        for pid in left:
            if send(pid, signal.SIGKILL):
                counts["killed"] += 1
        time.sleep(0.02)
def mode_quiesce(ctl):
    uid = ctl.get("uid")
    if not isinstance(uid, int) or uid <= 0:
        raise Abort("invalid guest uid")
    global FREEZE_DEADLINE_S
    FREEZE_DEADLINE_S = QUIESCE_FREEZE_S
    keep = exempt_pids()
    for pid in uid_tasks(uid, keep):
        if send(pid, signal.SIGTERM):
            counts["terminated"] += 1
    left = wait_gone(uid, keep, QUIESCE_TERM_S)
    freezer = False
    if left:
        if os.path.isfile(CGROUP + "/cgroup.controllers"):
            before = len(errors)
            freeze_guest()
            if len(errors) == before:
                freezer = True
                for pid in uid_tasks(uid, keep):
                    if send(pid, signal.SIGKILL):
                        counts["killed"] += 1
                left = wait_gone(uid, keep, QUIESCE_KILL_S)
            else:
                # The freeze could not be completed: discard its errors and
                # fall back to scan-and-kill below (after thawing).
                del errors[before:]
            thaw_guest()
        if not freezer:
            left = scan_kill(uid, keep, QUIESCE_KILL_S)
        if left:
            fail("<quiesce>", "%d guest processes survived" % len(left))
    ok = not errors
    emit({"ok": ok, "terminated": counts["terminated"], "killed": counts["killed"],
          "freezer": freezer, "errors": errors})
    return 0 if ok else 1
def main(argv):
    mode = argv[1] if len(argv) > 1 else ""
    try:
        ctl = read_control(sys.stdin.buffer)
        if mode == "pack":
            return mode_pack(ctl)
        if mode == "restore":
            return mode_restore(ctl)
        if mode == "scrub":
            return mode_scrub(ctl)
        if mode == "quiesce":
            return mode_quiesce(ctl)
        if mode == "probe":
            emit({"ok": True})
            return 0
        fail("<mode>", "unknown mode")
    except Abort as e:
        fail("<%s>" % mode, str(e))
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as e:
        fail("<%s>" % mode, "helper error: %s" % type(e).__name__)
    emit({"ok": False, "errors": errors, "failed": failed_paths()})
    return 1
if __name__ == "__main__":
    sys.exit(main(sys.argv))
