"""Plan §10 retire helper: one host-pushed guest-root exec per retirement.

argv: <mode> <nonce> <uid> <unit> <budget-ms>, all host-derived. It observes
the attempt's root-owned scope `wssp.slice/<unit>`; a kill mode kills only a
populated, due scope through its `cgroup.kill`. It writes nothing else, never
reads `cgroup.procs`, never signals a pid and never removes a cgroup. Its
only output is one stderr record:

    WSSP_RETIRE <nonce> <boot-id> <verdict> [<remaining-ms>]

Verdicts: absent | empty | killed (proofs, only after the uid-root check),
populated | not_due (still running), unscoped (a launch in this boot ran
outside its scope: no scoped proof), legacy (no cgroup2: today's arms),
unsupported | uid_populated | timeout (final, unproven). Any other exit
means no record.
"""
import errno
import os
import re
import stat
import subprocess
import sys
import time

CGROUP = '/sys/fs/cgroup'
MOUNTINFO = '/proc/self/mountinfo'
RUN_DIR = '/run/wssp'
MARKER = 'unscoped'
BOOT_ID = '/proc/sys/kernel/random/boot_id'
SYSTEMCTL = '/usr/bin/systemctl'
SLICE = 'wssp.slice'
ROOT_UID = 0
WALK_MAX = 4096
# HOST_SETUP_BUDGET (15 s) plus 5 s, in µs of CLOCK_MONOTONIC.
DEADLINE_SLACK_US = 20000000
KILL_POLL_S = 0.02
KILL_WAIT_S = 2.0
SHOW_TIMEOUT_S = 2

MODES = ('observe', 'kill-cancel', 'kill-deadline')
NONCE_RE = r'[0-9a-f]{32}'
UID_RE = r'[1-9][0-9]{0,9}'
UNIT_RE = r'wssp-cmd-[A-Za-z0-9_-]{1,128}-[0-9]{1,20}-[0-9]{1,20}\.scope'
BUDGET_RE = r'0|[1-9][0-9]{0,15}'

DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
GONE = (errno.ENOENT, errno.ENODEV)


class Verdict(Exception):
    def __init__(self, verdict, extra=None):
        super().__init__(verdict)
        self.verdict = verdict
        self.extra = extra


def owner_of(dirfd, name):
    """The owner uid of `name` relative to `dirfd` (absolute if None)."""
    return os.stat(name, dir_fd=dirfd, follow_symlinks=False).st_uid


def parse_args(argv):
    if len(argv) != 6:
        return None
    mode, nonce, uid, unit, budget = argv[1:]
    if (mode not in MODES or re.fullmatch(NONCE_RE, nonce) is None
            or re.fullmatch(UID_RE, uid) is None
            or re.fullmatch(UNIT_RE, unit) is None
            or re.fullmatch(BUDGET_RE, budget) is None):
        return None
    uid = int(uid)
    if uid > 0xFFFFFFFE:
        return None
    return mode, nonce, uid, unit, int(budget)


def cgroup2():
    """Rule 3: the last mount on CGROUP is cgroup2."""
    last = None
    with open(MOUNTINFO, 'rb') as mounts:
        for line in mounts:
            fields = line.split(b' - ', 1)
            left = fields[0].split()
            if len(fields) != 2 or len(left) < 5:
                continue
            if left[4] == CGROUP.encode():
                last = fields[1].split()[0] if fields[1].split() else None
    return last == b'cgroup2'


def marker_verdict():
    """Rule 4': a missing scope is `absent` only when this boot has no
    unscoped launch: `RUN_DIR` is missing, or it is a root-owned real
    directory, neither group- nor world-writable, without a marker."""
    try:
        info = os.lstat(RUN_DIR)
    except FileNotFoundError:
        return 'absent'
    except OSError:
        return 'unscoped'
    try:
        if (not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022
                or owner_of(None, RUN_DIR) != ROOT_UID):
            return 'unscoped'
        run = os.open(RUN_DIR, DIR_FLAGS)
    except OSError:
        return 'unscoped'
    try:
        os.stat(MARKER, dir_fd=run, follow_symlinks=False)
    except FileNotFoundError:
        return 'absent'
    except OSError:
        return 'unscoped'
    finally:
        os.close(run)
    return 'unscoped'


def open_dir(parent, name):
    try:
        return os.open(name, DIR_FLAGS, dir_fd=parent)
    except OSError as error:
        if error.errno in GONE:
            raise Verdict(marker_verdict())
        raise Verdict('unsupported')


def populated(dirfd):
    """`True`/`False` from `cgroup.events`; `None` when it is gone."""
    try:
        fd = os.open('cgroup.events', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=dirfd)
    except OSError as error:
        if error.errno in GONE:
            return None
        raise Verdict('unsupported')
    try:
        data = os.read(fd, 4096)
    except OSError as error:
        if error.errno in GONE:
            return None
        raise Verdict('unsupported')
    finally:
        os.close(fd)
    for line in data.split(b'\n'):
        if line == b'populated 0':
            return False
        if line == b'populated 1':
            return True
    raise Verdict('unsupported')


def monotonic_us():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC) // 1000


def deadline_gate(unit, budget_ms):
    """Rule 7: `None` when due, else the verdict that keeps the command."""
    if budget_ms == 0:
        return ('populated', None)
    try:
        shown = subprocess.run(
            [SYSTEMCTL, 'show', '--no-pager',
             '--property=ActiveState,ControlGroup,ActiveEnterTimestampMonotonic',
             '--', unit],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, timeout=SHOW_TIMEOUT_S, check=False,
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'SYSTEMD_PAGER': ''},
        )
    except (OSError, subprocess.SubprocessError):
        return ('populated', None)
    if shown.returncode != 0:
        return ('populated', None)
    props = {}
    for line in shown.stdout.split(b'\n'):
        key, sep, value = line.partition(b'=')
        if sep and key not in props:
            props[key] = value
    active_enter = props.get(b'ActiveEnterTimestampMonotonic', b'')
    if (props.get(b'ActiveState') != b'active'
            or props.get(b'ControlGroup') != ('/' + SLICE + '/' + unit).encode()
            or re.fullmatch(rb'[1-9][0-9]{0,19}', active_enter) is None):
        return ('populated', None)
    elapsed = monotonic_us() - int(active_enter)
    due = budget_ms * 1000 + DEADLINE_SLACK_US
    if elapsed < due:
        return ('not_due', str(-(-(due - elapsed) // 1000)))
    return None


def kill(slice_fd, scope_fd):
    """Rule 7: write the scope's `cgroup.kill`, then wait for it to empty."""
    try:
        os.stat('cgroup.kill', dir_fd=slice_fd, follow_symlinks=False)
    except OSError:
        # No cgroup.kill (Linux < 5.14): never fall back to pid signals.
        raise Verdict('unsupported')
    try:
        fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=scope_fd)
    except OSError as error:
        if error.errno in GONE:
            raise Verdict(marker_verdict())
        raise Verdict('unsupported')
    try:
        os.write(fd, b'1')
    except OSError as error:
        if error.errno not in GONE:
            raise Verdict('unsupported')
    finally:
        os.close(fd)
    deadline = time.monotonic() + KILL_WAIT_S
    while True:
        if not populated(scope_fd):
            return 'killed'
        if time.monotonic() >= deadline:
            raise Verdict('timeout')
        time.sleep(KILL_POLL_S)


def uid_roots(root_fd, uid, unit):
    """Rule 8: `(roots, populated)` over the cgroup tree; a uid root is a
    directory owned by `uid` (never descended). The attempt's own scope is
    exempt. More than `WALK_MAX` directories is `unsupported`."""
    roots = 0
    busy = 0
    visited = 0
    stack = [(os.dup(root_fd), '')]
    try:
        while stack:
            fd, path = stack.pop()
            try:
                with os.scandir(fd) as entries:
                    names = [e.name for e in entries if e.is_dir(follow_symlinks=False)]
            except OSError as error:
                os.close(fd)
                if error.errno in GONE:
                    continue
                raise Verdict('unsupported')
            try:
                for name in names:
                    child = path + '/' + name
                    if child == '/' + SLICE + '/' + unit:
                        continue
                    visited += 1
                    if visited > WALK_MAX:
                        raise Verdict('unsupported')
                    try:
                        owner = owner_of(fd, name)
                    except OSError as error:
                        if error.errno in GONE:
                            continue
                        raise Verdict('unsupported')
                    try:
                        sub = os.open(name, DIR_FLAGS, dir_fd=fd)
                    except OSError as error:
                        if error.errno in GONE:
                            continue
                        raise Verdict('unsupported')
                    if owner == uid:
                        roots += 1
                        try:
                            if populated(sub):
                                busy += 1
                        finally:
                            os.close(sub)
                        continue
                    stack.append((sub, child))
            finally:
                os.close(fd)
    finally:
        for fd, _ in stack:
            os.close(fd)
    return roots, busy


def observe_scope(root, mode, unit, budget_ms):
    """Rules 4'-7: the scope's verdict, before the uid-root check."""
    slice_fd = open_dir(root, SLICE)
    try:
        scope_fd = open_dir(slice_fd, unit)
        try:
            # Rule 5: never a delegated or relocated unit.
            for dirfd, name in ((root, SLICE), (slice_fd, unit),
                                (scope_fd, 'cgroup.procs')):
                if owner_of(dirfd, name) != ROOT_UID:
                    return ('unsupported', None)
            state = populated(scope_fd)
            if state is None:
                return (marker_verdict(), None)
            if not state:
                return ('empty', None)
            if mode == 'observe':
                return ('populated', None)
            if mode == 'kill-deadline':
                kept = deadline_gate(unit, budget_ms)
                if kept is not None:
                    return kept
            return (kill(slice_fd, scope_fd), None)
        finally:
            os.close(scope_fd)
    finally:
        os.close(slice_fd)


def decide(mode, uid, unit, budget_ms):
    if not cgroup2():
        return ('legacy', None)
    # Rule 5 starts at the hierarchy root: a tree this helper does not see
    # as root-owned proves nothing.
    if owner_of(None, CGROUP) != ROOT_UID:
        return ('unsupported', None)
    root = os.open(CGROUP, DIR_FLAGS)
    try:
        try:
            verdict, extra = observe_scope(root, mode, unit, budget_ms)
        except Verdict as found:
            verdict, extra = found.verdict, found.extra
        if verdict not in ('absent', 'empty', 'killed'):
            return (verdict, extra)
        # Rule 8 runs after every proof, never before.
        try:
            roots, busy = uid_roots(root, uid, unit)
        except Verdict as found:
            return (found.verdict, found.extra)
        if roots > 1:
            return ('unsupported', None)
        if busy:
            return ('uid_populated', None)
        return (verdict, None)
    finally:
        os.close(root)


def read_boot():
    with open(BOOT_ID, 'rb') as boot:
        value = boot.read().strip().decode('ascii')
    if re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                    value) is None:
        raise ValueError()
    return value


def main(argv):
    args = parse_args(argv)
    if args is None:
        return 2
    mode, nonce, uid, unit, budget_ms = args
    try:
        verdict, extra = decide(mode, uid, unit, budget_ms)
    except Verdict as found:
        verdict, extra = found.verdict, found.extra
    except OSError:
        verdict, extra = 'unsupported', None
    try:
        boot = read_boot()
    except (OSError, ValueError):
        return 1
    record = 'WSSP_RETIRE %s %s %s' % (nonce, boot, verdict)
    if extra is not None:
        record += ' ' + extra
    os.write(2, (record + '\n').encode('ascii'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
