# Shared descriptor-relative walk primitives (image-cache capture scrub,
# template-build COPY and the credential helper). Every directory is opened
# one component at a time with O_NOFOLLOW | O_DIRECTORY via dir_fd; removals
# re-check the entry first. This file loads no module: each helper's single
# first line brings in every module (errno, os and stat among them) before
# anything runs (round-4 P1: nothing is loaded once a freeze begins).
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
errors = []
def fail(p, why):
    errors.append({"path": p, "error": why})
def _race_window(where, path):
    pass
def open_dir(path):
    """Open an absolute directory one component at a time, never following a link."""
    fd = os.open("/", O_DIR)
    try:
        for part in [c for c in path.split("/") if c]:
            nfd = os.open(part, O_DIR, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except BaseException:
        os.close(fd)
        raise
def same(a, b):
    return (a.st_dev, a.st_ino, stat.S_IFMT(a.st_mode)) == (b.st_dev, b.st_ino, stat.S_IFMT(b.st_mode))
def checked_remove(dfd, name, st, shown, is_dir):
    """Unlink or rmdir `name` in `dfd` only if it is still the entry `st` described."""
    _race_window("remove", shown)
    try:
        cur = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as e:
        fail(shown, e.strerror or "lstat")
        return
    if not same(cur, st):
        fail(shown, "replaced during scrub")
        return
    try:
        if is_dir:
            os.rmdir(name, dir_fd=dfd)
        else:
            os.unlink(name, dir_fd=dfd)
    except OSError as e:
        fail(shown, e.strerror or ("rmdir" if is_dir else "unlink"))
