# Executed inside the guest by Incus as the declared UID/GID. No host paths.
#
# put:     stdin = exactly <size> payload bytes, then one fence byte. The payload
#          is staged in `.wssp-upload-<token>` and verified (length + SHA-256).
#          The helper then prints `WSSP_COMMIT_READY <token>` and renames only
#          when the host answers `C`, which it writes while holding the current
#          RuntimePermit. EOF or any other byte aborts: the temporary file is
#          removed and the existing destination is never touched.
# read:    stream a regular file to stdout (bounded by <size>).
# recover: settle an interrupted put of this <token> from guest evidence.
import hashlib
import os
import stat
import sys
import datetime
import errno
import grp
import heapq
import json
import pwd
import time

# The listing budget counts from interpreter start, not from the scan.
START = time.monotonic()
committing = False
mutation_effect = 'none'


class Aborted(Exception):
    pass


class FsError(Exception):
    def __init__(self, code):
        self.code = code


# Bounds match sandbox-result-limits.json. The Rust reader independently caps
# stdout BEFORE decoding JSON. No guest value is a host filesystem path.
RESULT_BYTES = 24576
# Reserve space for the host version, observation and opaque operation cursor.
HOST_WRAPPER_BYTES = 1024
VISIT_MAX = 100000
OBSERVATION_MS = 30000
LIST_LIMIT_MAX = 100
DEPTH_MAX = 8
# Leading/trailing path whitespace, as sandbox-path-whitespace.json.
PATH_WHITESPACE = frozenset(chr(c) for c in (9, 10, 11, 12, 13, 32, 160, 5760, 8192, 8193, 8194, 8195, 8196, 8197, 8198, 8199, 8200, 8201, 8202, 8232, 8233, 8239, 8287, 12288, 65279))


def utf8(value, maximum):
    try:
        encoded = value.encode('utf-8', 'strict')
    except UnicodeError:
        raise FsError('fs_invalid_encoding') from None
    if b'\0' in encoded:
        raise FsError('fs_invalid_encoding')
    if len(encoded) > maximum:
        raise FsError('fs_entry_too_large')
    return encoded


def metadata_path(path):
    utf8(path, 4096)
    if not path.startswith('/') or path[-1:] in PATH_WHITESPACE or '..' in path.split('/'):
        raise FsError('protocol_error')
    return '/' + '/'.join(p for p in path.split('/') if p and p != '.')


def open_directory(name, parent):
    try:
        return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except OSError as error:
        # Linux returns ENOTDIR for O_DIRECTORY|O_NOFOLLOW on a symlink.
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            if stat.S_ISLNK(os.stat(name, dir_fd=parent, follow_symlinks=False).st_mode):
                raise FsError('fs_symlink_refused') from None
        raise


def metadata_parent(path):
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        parts = path.split('/')[1:]
        for part in parts[:-1]:
            nxt = open_directory(part, directory)
            os.close(directory)
            directory = nxt
        return directory, parts[-1] or '.'
    except BaseException:
        os.close(directory)
        raise


def mkdir_parent(path):
    """Open existing safe ancestors, remembering absent ones WITHOUT creating."""
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    parts = path.split('/')[1:]
    try:
        for index, part in enumerate(parts[:-1]):
            try:
                nxt = open_directory(part, directory)
            except FileNotFoundError:
                return directory, parts[index:]
            os.close(directory)
            directory = nxt
        return directory, parts[-1:]
    except BaseException:
        os.close(directory)
        raise


def commit_gate(token):
    sys.stdout.write('WSSP_COMMIT_READY ' + token + '\n')
    sys.stdout.flush()
    if sys.stdin.buffer.read(1) != b'C':
        raise Aborted('commit fence refused')


def changed():
    global mutation_effect
    mutation_effect = 'partial'


def durable_directory(directory):
    global committing
    try:
        os.fsync(directory)
    except OSError:
        # An issued mutation with missing durability proof stays unknown.
        committing = True
        raise


def mkdir_one(name, directory):
    try:
        refusable(os.mkdir, name, 0o755, dir_fd=directory)
        changed()
        durable_directory(directory)
        return True
    except FileExistsError:
        st = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            raise FsError('fs_symlink_refused') from None
        if not stat.S_ISDIR(st.st_mode):
            raise FsError('fs_already_exists') from None
        return False


def identity(fd):
    st = os.fstat(fd)
    return st.st_dev, st.st_ino


def remove_entry(directory, name, recursive):
    st = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISDIR(st.st_mode):
        refusable(os.unlink, name, dir_fd=directory)
        changed()
        durable_directory(directory)
        return
    if recursive:
        remove_tree(directory, name)
    else:
        refusable(os.rmdir, name, dir_fd=directory)
        changed()
    durable_directory(directory)


def remove_tree(directory, name):
    """Iterative depth-first removal: no recursion limit and one descriptor
    at a time. Names are passed back to dir_fd-relative syscalls exactly as
    read (surrogateescape), never decoded or emitted, so a non-UTF-8 name is
    removed like any other (B2-T-3/B2-C-4)."""
    fd = open_directory(name, directory)
    names = [name]
    parents = [identity(directory)]
    try:
        while True:
            with os.scandir(fd) as children:
                batch = [(child.name, child.is_dir(follow_symlinks=False))
                         for _, child in zip(range(256), children)]
            for child, is_dir in batch:
                if is_dir:
                    nxt = open_directory(child, fd)
                    parents.append(identity(fd))
                    names.append(child)
                    os.close(fd)
                    fd = nxt
                    break
                refusable(os.unlink, child, dir_fd=fd)
                changed()
            else:
                if batch:
                    continue
                # fd is empty: remove it from its (verified) parent.
                child = names.pop()
                parent = parents.pop()
                if not names:
                    os.close(fd)
                    fd = None
                    refusable(os.rmdir, child, dir_fd=directory)
                    changed()
                    return
                up = os.open('..', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = up
                if identity(fd) != parent:
                    # The tree moved under us: never remove outside it.
                    raise FsError('unknown_outcome')
                refusable(os.rmdir, child, dir_fd=fd)
                changed()
    finally:
        if fd is not None:
            os.close(fd)


def mutate_metadata(mode, path, token, options):
    global committing
    if path == '/':
        raise FsError('path_refused')
    if mode == 'ensure-dir':
        # Readiness template layout, never user-API input: `mkdir -p`
        # semantics, following template symlinks such as /home -> var/home.
        # Like every mutation, nothing is created before the commit gate.
        commit_gate(token)
        created = False
        current = ''
        for part in path.split('/')[1:]:
            current += '/' + part
            try:
                os.mkdir(current, 0o755)
                changed()
                created = True
            except FileExistsError:
                if not os.path.isdir(current):
                    raise FsError('fs_already_exists') from None
        return dict(type='file.mkdir', created=created)
    if mode == 'mkdir':
        directory, missing = mkdir_parent(path)
        try:
            commit_gate(token)
            for part in missing[:-1]:
                mkdir_one(part, directory)
                nxt = open_directory(part, directory)
                os.close(directory)
                directory = nxt
            created = mkdir_one(missing[-1], directory)
            return dict(type='file.mkdir', created=created)
        finally:
            os.close(directory)
    directory, name = metadata_parent(path)
    destination = None
    try:
        if mode == 'rename':
            target = metadata_path(options['destPath'])
            if target == '/':
                raise FsError('path_refused')
            destination, dest_name = metadata_parent(target)
        elif mode != 'remove' or type(options.get('recursive', False)) is not bool:
            raise FsError('protocol_error')
        commit_gate(token)
        if mode == 'remove':
            remove_entry(directory, name, options.get('recursive', False))
            return dict(type='file.remove', removed=True)
        # Exact POSIX rename: no mv directory interpretation and no EXDEV copy.
        refusable(os.replace, name, dest_name, src_dir_fd=directory, dst_dir_fd=destination)
        changed()
        # Metadata/durability failure after rename cannot manufacture a result
        # by retrying the mutation. Suppress completion until all proof exists.
        committing = True
        durable_directory(directory)
        durable_directory(destination)
        return dict(type='file.rename', entry=entry_info(destination, dest_name, target))
    finally:
        os.close(directory)
        if destination is not None:
            os.close(destination)


def entry_info(directory, name, path):
    utf8(path, 4096)
    display = '/' if path == '/' else name
    utf8(display, 255)
    st = os.stat(name, dir_fd=directory, follow_symlinks=False)
    if not 0 <= st.st_size <= 9007199254740991 or not (0 <= st.st_uid <= 4294967295 and 0 <= st.st_gid <= 4294967295):
        raise FsError('fs_metadata_unrepresentable')
    kind = 'dir' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'other'
    target = os.readlink(name, dir_fd=directory) if kind == 'symlink' else None
    if target is not None:
        utf8(target, 4096)

    def owner_name(lookup, identifier, field):
        try:
            value = getattr(lookup(identifier), field)
        except KeyError:
            return None
        utf8(value, 128)
        return value

    try:
        modified = (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=st.st_mtime_ns // 1000)).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    except (OverflowError, OSError, ValueError):
        modified = None
    return dict(name=display, path=path, type=kind, size=st.st_size,
                mode=stat.S_IMODE(st.st_mode), permissions=stat.filemode(st.st_mode)[1:],
                uid=st.st_uid, gid=st.st_gid,
                owner=owner_name(pwd.getpwuid, st.st_uid, 'pw_name'),
                group=owner_name(grp.getgrgid, st.st_gid, 'gr_name'),
                modifiedTime=modified, symlinkTarget=target)


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def errno_code(error):
    return {errno.ENOENT: 'fs_not_found', errno.EISDIR: 'fs_is_directory',
            errno.ENOTDIR: 'fs_not_directory', errno.EACCES: 'fs_permission_denied',
            errno.EPERM: 'fs_permission_denied', errno.EROFS: 'fs_read_only',
            errno.EEXIST: 'fs_already_exists', errno.ENOTEMPTY: 'fs_not_empty',
            errno.EXDEV: 'fs_cross_device', errno.ENOSPC: 'fs_no_space',
            errno.EDQUOT: 'fs_no_space', errno.ELOOP: 'fs_symlink_refused',
            errno.ENAMETOOLONG: 'fs_entry_too_large'}.get(error.errno, 'unknown_outcome')


# B2-C-4/B2R2-C-3: errnos with which one mkdir, rmdir, unlink or rename
# syscall refuses before changing anything (rename into its own subtree, a
# busy mount point, link count exhausted). Only those call sites use them;
# elsewhere (a directory fsync, a put) they stay unknown_outcome.
KERNEL_REFUSALS = {errno.EINVAL: 'path_refused', errno.EBUSY: 'path_refused',
                   errno.EMLINK: 'fs_no_space'}


def refusable(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except OSError as error:
        code = KERNEL_REFUSALS.get(error.errno)
        if code is None:
            raise
        # The effect is still the helper's own accounting.
        raise FsError(code) from None


class ReverseKey:
    def __init__(self, key):
        self.key = key

    def __lt__(self, other):
        return self.key > other.key


def directory_page(directory, name, root, options):
    depth, limit, generation = options['depth'], options['limit'], options['generation']
    after = options.get('lastKey')
    if type(depth) is not int or not 1 <= depth <= DEPTH_MAX or type(limit) is not int or not 1 <= limit <= LIST_LIMIT_MAX or type(generation) is not int or not 1 <= generation <= 2147483647:
        raise FsError('protocol_error')
    if after is not None:
        utf8(after, 4096)
        if not after or after.startswith('/') or any(p in ('', '.', '..') for p in after.split('/')) or len(after.split('/')) > depth:
            raise FsError('protocol_error')
    after_bytes = utf8(after, 4096) if after is not None else None
    # The host passes a budget that ends before its own kill deadline.
    budget = options.get('budgetMs', OBSERVATION_MS)
    if type(budget) is not int or not 1 <= budget <= OBSERVATION_MS:
        raise FsError('protocol_error')
    heap = []
    visited = 0
    deadline = START + budget / 1000

    def check_time():
        if time.monotonic() >= deadline:
            raise FsError('fs_listing_limit')

    def scan(fd, relative, level):
        nonlocal visited
        # scandir is a streaming iterator; at most depth directory descriptors
        # and limit+1 metadata records survive an iteration.
        with os.scandir(fd) as children:
            for child in children:
                visited += 1
                if visited > VISIT_MAX:
                    raise FsError('fs_listing_limit')
                check_time()
                key = relative + child.name
                key_bytes = utf8(key, 4096)
                path = (root.rstrip('/') + '/' + key)
                try:
                    info = entry_info(fd, child.name, path)
                except FileNotFoundError:
                    # B2-C-7: removed after readdir; a live listing missed it.
                    continue
                # A huge single record fails even if it is beyond this page.
                if len(encoded(dict(result=dict(type='file.stat', entry=info), continuation=None))) > RESULT_BYTES - HOST_WRAPPER_BYTES:
                    raise FsError('fs_entry_too_large')
                if after_bytes is None or key_bytes > after_bytes:
                    candidate = (ReverseKey(key_bytes), key, info)
                    if len(heap) < limit + 1:
                        heapq.heappush(heap, candidate)
                    elif key_bytes < heap[0][0].key:
                        heapq.heapreplace(heap, candidate)
                if info['type'] == 'dir' and level < depth:
                    try:
                        nxt = open_directory(child.name, fd)
                    except (FileNotFoundError, NotADirectoryError):
                        # Removed or replaced since lstat: nothing to descend.
                        check_time()
                        continue
                    except FsError as error:
                        if error.code != 'fs_symlink_refused':
                            raise
                        # Replaced by a link since lstat: never followed.
                        check_time()
                        continue
                    try:
                        scan(nxt, key + '/', level + 1)
                    finally:
                        os.close(nxt)
                check_time()

    fd = open_directory(name, directory)
    try:
        scan(fd, '', 1)
    finally:
        os.close(fd)
    selected = sorted(heap, key=lambda item: item[0].key)
    items = []
    result = dict(type='file.list', path=root, depth=depth, items=items, nextCursor=None, consistency='live')
    envelope = dict(result=result, continuation=None)
    for index, (_, key, info) in enumerate(selected[:limit]):
        items.append(info)
        continuation = dict(lastKey=key, root=root, depth=depth, limit=limit, generation=generation, kind='LIST_DIR') if index + 1 < len(selected) else None
        envelope['continuation'] = continuation
        if len(encoded(envelope)) > RESULT_BYTES - HOST_WRAPPER_BYTES:
            items.pop()
            if not items:
                raise FsError('fs_entry_too_large')
            # Resume after the last EMITTED key, never the inspected/heap key.
            envelope['continuation'] = dict(lastKey=selected[index - 1][1], root=root, depth=depth, limit=limit, generation=generation, kind='LIST_DIR')
            if len(encoded(envelope)) > RESULT_BYTES - HOST_WRAPPER_BYTES:
                raise FsError('fs_entry_too_large')
            break
    check_time()
    return envelope


def metadata(mode, path, token, options):
    path = metadata_path(path)
    if mode in ('mkdir', 'ensure-dir', 'remove', 'rename'):
        result = mutate_metadata(mode, path, token, options)
        envelope = dict(result=result, continuation=None)
        payload = encoded(envelope)
        if len(payload) > RESULT_BYTES - HOST_WRAPPER_BYTES:
            raise FsError('fs_entry_too_large')
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        print('WSSP_STATUS ' + token + ' ok', file=sys.stderr, flush=True)
        return
    directory, name = metadata_parent(path)
    try:
        if mode == 'stat':
            envelope = dict(result=dict(type='file.stat', entry=entry_info(directory, name, path)), continuation=None)
        elif mode == 'list':
            envelope = directory_page(directory, name, path, options)
        else:
            raise FsError('protocol_error')
        payload = encoded(envelope)
        if len(payload) > RESULT_BYTES - HOST_WRAPPER_BYTES:
            raise FsError('fs_entry_too_large')
        sys.stdout.buffer.write(payload)
        sys.stdout.buffer.flush()
        print('WSSP_STATUS ' + token + ' ok', file=sys.stderr, flush=True)
    finally:
        os.close(directory)


def run():
    global committing
    mode, path, token, size, digest = sys.argv[1:]
    size = int(size)
    if mode in ('stat', 'list', 'mkdir', 'ensure-dir', 'remove', 'rename'):
        if len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
            raise FsError('protocol_error')
        metadata(mode, path, token, json.loads(digest))
        return
    parts = path.split('/')
    if not path.startswith('/') or any(p in ('.', '..') for p in parts):
        raise FsError('protocol_error')
    parts = [p for p in parts if p]
    if not parts or len(token) != 64 or any(c not in '0123456789abcdef' for c in token):
        raise FsError('protocol_error')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[:-1]:
            if mode == 'put':
                try:
                    os.mkdir(part, 0o755, dir_fd=directory)
                    changed()
                except FileExistsError:
                    pass
            try:
                nxt = open_directory(part, directory)
            except FileNotFoundError:
                if mode == 'recover':
                    # No parent: neither the staging file nor our bytes exist here.
                    report(token, 'unknown')
                    return
                raise
            os.close(directory)
            directory = nxt
        act(mode, parts[-1], directory, token, size, digest)
    finally:
        os.close(directory)


def report(token, verdict):
    sys.stdout.write('WSSP_RECOVERED ' + token + ' ' + verdict + '\n')
    sys.stdout.flush()
    print('WSSP_STATUS ' + token + ' ok', file=sys.stderr, flush=True)


def regular(fd):
    regular_mode(os.fstat(fd).st_mode)


def regular_mode(mode):
    if stat.S_ISLNK(mode):
        raise FsError('fs_symlink_refused')
    if stat.S_ISDIR(mode):
        raise FsError('fs_is_directory')
    if not stat.S_ISREG(mode):
        raise FsError('fs_not_regular')


def hashed_regular(name, directory, size):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    regular(fd)
    hashed = hashlib.sha256()
    total = 0
    with os.fdopen(fd, 'rb') as source:
        while True:
            chunk = source.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > size:
                return None
            hashed.update(chunk)
    return total, hashed.hexdigest()


def act(mode, name, directory, token, size, digest):
    global committing
    temporary = '.wssp-upload-' + token

    def destination():
        try:
            st = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                raise FsError('fs_symlink_refused')
            if stat.S_ISDIR(st.st_mode):
                raise FsError('fs_is_directory')
            if not stat.S_ISREG(st.st_mode):
                raise FsError('fs_not_regular')
        except FileNotFoundError:
            pass

    if mode == 'read':
        # Reject special entries before opening them: Unix sockets cannot be
        # opened for read/fstat (ENXIO), and opening a device can have effects.
        # Recheck the opened descriptor below to fence a final-component swap.
        regular_mode(os.stat(name, dir_fd=directory, follow_symlinks=False).st_mode)
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        regular(fd)
        total = 0
        with os.fdopen(fd, 'rb') as source:
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > size:
                    raise FsError('fs_entry_too_large')
                sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
    elif mode == 'put':
        destination()
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            stdin = sys.stdin.buffer
            with os.fdopen(fd, 'wb') as target:
                hashed = hashlib.sha256()
                total = 0
                while total < size:
                    chunk = stdin.read(min(65536, size - total))
                    if not chunk:
                        raise FsError('protocol_error')
                    total += len(chunk)
                    target.write(chunk)
                    hashed.update(chunk)
                if hashed.hexdigest() != digest:
                    raise FsError('protocol_error')
                target.flush()
                os.fsync(target.fileno())
            os.fsync(directory)
            commit_gate(token)
            destination()
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            committing = True
            os.fsync(directory)
        except BaseException:
            if not committing:
                try:
                    os.unlink(temporary, dir_fd=directory)
                except FileNotFoundError:
                    pass
            raise
    elif mode == 'recover':
        try:
            st = os.stat(temporary, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None:
            # os.replace consumes the staging name atomically. While it exists the
            # rename has not happened, and after this unlink it never can.
            if not stat.S_ISREG(st.st_mode):
                raise FsError('fs_not_regular')
            os.unlink(temporary, dir_fd=directory)
            os.fsync(directory)
            report(token, 'not_committed')
            return
        try:
            observed = hashed_regular(name, directory, size)
        except (FileNotFoundError, ValueError, FsError):
            observed = None
        report(token, 'committed' if observed == (size, digest) else 'unknown')
        return
    else:
        raise FsError('protocol_error')
    print('WSSP_STATUS ' + token + ' ok', file=sys.stderr, flush=True)


try:
    run()
except BaseException as error:
    # After rename issue, IO failure is uncertainty, never a false FAILED receipt.
    if not committing:
        if isinstance(error, FsError):
            code = error.code
        elif isinstance(error, OSError):
            code = errno_code(error)
        elif isinstance(error, Aborted):
            code = 'cancelled'
        else:
            code = 'unknown_outcome'
        if code == 'unknown_outcome':
            mutation_effect = 'unknown'
        try:
            print('WSSP_STATUS ' + sys.argv[3] + ' ' + code + ' ' + mutation_effect, file=sys.stderr, flush=True)
        except BaseException:
            pass
    sys.exit(1)
