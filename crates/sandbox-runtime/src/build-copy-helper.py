import fnmatch, hashlib, json, sys, tarfile
# Template-build COPY helper (D1: runs as guest root inside build VMs only).
# argv: <context-path> <sha256> <dest> <uid> <gid> <mode|-> <src>...
# The context is opened ONCE with O_RDONLY|O_NOFOLLOW; it is hashed and then
# extracted from that same descriptor. Every member is validated before any
# write: absolute names, `..`, devices/FIFOs, symlinks whose target escapes
# the archive, hardlinks to anything but an earlier regular member, duplicate
# names and paths through a non-directory member are refused. Writes are
# descriptor-relative with O_NOFOLLOW, so nothing is written through a link.
MAX_MEMBERS = 100000
CHUNK = 1 << 20
REFUSED = 2
FAILED = 1


class Refused(Exception):
    pass


def refuse(why):
    raise Refused(why)


def split_rel(name):
    """Archive member name -> normalized parts; refuses absolute and `..`."""
    if name.startswith("/"):
        refuse("absolute member name: " + name)
    parts = []
    for part in name.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            refuse("member name escapes the context: " + name)
        parts.append(part)
    return tuple(parts)


def link_escapes(parts, target):
    if target.startswith("/"):
        return True
    stack = list(parts[:-1])
    for part in target.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not stack:
                return True
            stack.pop()
        else:
            stack.append(part)
    return False


def open_context(path):
    head, tail = os.path.split(path)
    try:
        pfd = open_dir(head)
    except OSError as e:
        refuse("context unavailable: " + (e.strerror or "open"))
    try:
        fd = os.open(tail, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=pfd)
    except OSError as e:
        refuse("context unavailable: " + (e.strerror or "open"))
    finally:
        os.close(pfd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        refuse("context is not a regular file")
    return fd


def sha256_of(fd):
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, CHUNK)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def index_members(tar):
    """Validate every member. Returns ([(parts, member, data)], names, dirs)
    where `data` is the regular member whose bytes a file entry carries."""
    members = []
    seen = set()
    nondirs = set()
    regular = {}
    dirs = {()}
    for member in tar:
        if len(members) >= MAX_MEMBERS:
            refuse("too many members")
        parts = split_rel(member.name)
        if not parts:
            if member.isdir():
                continue
            refuse("member without a name")
        if parts in seen:
            refuse("duplicate member: " + member.name)
        seen.add(parts)
        for i in range(1, len(parts)):
            if parts[:i] in nondirs:
                refuse("member path crosses a non-directory: " + member.name)
        data = None
        if member.isdir():
            if parts in nondirs:
                refuse("member type changes: " + member.name)
            dirs.add(parts)
        elif member.isreg() or member.issym() or member.islnk():
            if parts in dirs:
                refuse("member type changes: " + member.name)
            if member.issym():
                if link_escapes(parts, member.linkname):
                    refuse("symlink escapes the context: " + member.name)
            elif member.islnk():
                data = regular.get(split_rel(member.linkname))
                if data is None:
                    refuse("hardlink outside the context: " + member.name)
            else:
                data = member
                regular[parts] = member
            nondirs.add(parts)
        else:
            refuse("device or special file: " + member.name)
        for i in range(1, len(parts)):
            dirs.add(parts[:i])
        members.append((parts, member, data))
    return members, nondirs | dirs, dirs


def plan(srcs, dest, dest_is_dir, members, names, dirs):
    """Docker COPY subset -> (directory to create or None, [(dest parts, member, data)])."""
    matches = []
    for src in srcs:
        if src == ".":
            found = [()]
        else:
            parts = tuple(src.split("/"))
            if "*" in parts[-1]:
                found = sorted(n for n in names if len(n) == len(parts) and n[:-1] == parts[:-1]
                               and fnmatch.fnmatchcase(n[-1], parts[-1]))
            else:
                found = [parts] if parts in names else []
        if not found:
            refuse("source not found: " + src)
        matches.extend(found)
    if len(matches) > 1 and not dest.endswith("/"):
        refuse("several sources need a destination ending in /")
    dest_parts = tuple(p for p in dest.split("/") if p)
    into_dir = dest.endswith("/") or dest_is_dir
    make_dir = None
    wanted = {}
    for match in matches:
        if match in dirs:
            make_dir = dest_parts
            for parts, _, _ in members:
                if len(parts) > len(match) and parts[:len(match)] == match:
                    wanted.setdefault(parts, dest_parts + parts[len(match):])
        elif into_dir:
            make_dir = dest_parts
            wanted.setdefault(match, dest_parts + match[-1:])
        else:
            if not dest_parts:
                refuse("a file cannot replace /")
            wanted.setdefault(match, dest_parts)
    items = [(wanted[parts], member, data) for parts, member, data in members if parts in wanted]
    return make_dir, items


def dest_is_directory(dest):
    try:
        fd = open_dir(dest)
    except OSError:
        return False
    os.close(fd)
    return True


def enter(fd, name, uid, gid):
    """Open (or create) the plain directory `name` in `fd`; never follow a link."""
    try:
        os.mkdir(name, 0o755, dir_fd=fd)
        os.chown(name, uid, gid, dir_fd=fd, follow_symlinks=False)
    except FileExistsError:
        pass
    try:
        return os.open(name, O_DIR, dir_fd=fd)
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.ENOTDIR):
            refuse("destination path is not a plain directory: " + name)
        raise


def walk(parts, uid, gid):
    fd = os.open("/", O_DIR)
    try:
        for part in parts:
            nfd = enter(fd, part, uid, gid)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def clear(pfd, name):
    """Remove a non-directory entry so a fresh one is created in its place."""
    try:
        st = os.stat(name, dir_fd=pfd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if stat.S_ISDIR(st.st_mode):
        refuse("destination is a directory: " + name)
    os.unlink(name, dir_fd=pfd)


def write_file(tar, data, pfd, name, uid, gid, mode):
    clear(pfd, name)
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=pfd)
    total = 0
    try:
        source = tar.extractfile(data)
        while True:
            chunk = source.read(CHUNK)
            if not chunk:
                break
            view = memoryview(chunk)
            while view:
                view = view[os.write(fd, view):]
            total += len(chunk)
        os.fchown(fd, uid, gid)
        os.fchmod(fd, mode if mode is not None else data.mode & 0o777)
    finally:
        os.close(fd)
    return total


def extract(tar, items, uid, gid, mode):
    copied = 0
    written = 0
    for target, member, data in items:
        pfd = walk(target[:-1], uid, gid)
        name = target[-1]
        try:
            if member.isdir():
                fd = enter(pfd, name, uid, gid)
                try:
                    os.fchown(fd, uid, gid)
                    os.fchmod(fd, (member.mode & 0o777) | 0o700)
                finally:
                    os.close(fd)
            elif member.issym():
                clear(pfd, name)
                os.symlink(member.linkname, name, dir_fd=pfd)
                os.chown(name, uid, gid, dir_fd=pfd, follow_symlinks=False)
            else:
                written += write_file(tar, data, pfd, name, uid, gid, mode)
            copied += 1
        finally:
            os.close(pfd)
    return copied, written


def main(argv):
    if len(argv) < 8:
        print("wssp-build-copy: refused: usage", file=sys.stderr)
        return REFUSED
    context, expected, dest, uid, gid, mode = argv[1:7]
    srcs = argv[7:]
    uid, gid = int(uid), int(gid)
    mode = None if mode == "-" else int(mode)
    try:
        fd = open_context(context)
        with os.fdopen(fd, "rb") as handle:
            if sha256_of(fd) != expected:
                refuse("context sha256 mismatch")
            os.lseek(fd, 0, os.SEEK_SET)
            try:
                tar = tarfile.open(fileobj=handle, mode="r:*")
            except (tarfile.TarError, EOFError, OSError):
                refuse("context is not a tar archive")
            with tar:
                members, names, dirs = index_members(tar)
                make_dir, items = plan(srcs, dest, dest_is_directory(dest), members, names, dirs)
                if make_dir is not None:
                    os.close(walk(make_dir, uid, gid))
                copied, written = extract(tar, items, uid, gid, mode)
    except Refused as e:
        print("wssp-build-copy: refused: %s" % e, file=sys.stderr)
        return REFUSED
    except (OSError, tarfile.TarError, EOFError) as e:
        print("wssp-build-copy: failed: %s" % (getattr(e, "strerror", None) or e), file=sys.stderr)
        return FAILED
    print(json.dumps({"copied": copied, "bytes": written}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
