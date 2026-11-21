# Guest channel helper (wssp-ssh increments 1 and 2). Run as `python3 -I -S -c <this> <phase> ...`.
#
# Phases (argv after the source):
#   launch <scope> <nonce> <uid> <gid> -- <tail...>   guest root: create the channel's own systemd scope
#   inner  <scope> <nonce> <uid> <gid> -- <tail...>   guest root inside the scope: cancel fence, drop, exec tail
#   wrap   WSSP_PID <nonce> <pty|exec> <0|1> <budget ms> <entries> <key> <value> <json> -- <argv...>
#                                                     guest user: prompt for the preamble (env + frame
#                                                     secret), start the workload, report its outcome
#   wrap   WSSP_PID <nonce> <tcp|unix> 0 <budget ms> <entries> <key> <value> <json> -- <port|path>
#                                                     guest user: prompt for the preamble (frame secret),
#                                                     connect to guest 127.0.0.1/[::1]:<port> or the Unix
#                                                     socket <path> and relay (no workload, no env)
#   kill   <nonce> <scope>:<0|1> ...                  guest root: tombstone, kill and prove each scope gone
#
# There is no unscoped fallback: a channel without its scope never runs. Frames are
# `\x1eWSSP_CHAN <nonce> <verb> ...\x1f`, written with one write() each (below PIPE_BUF).
# PROMPT and REFUSED carry the public argv nonce; READY and EXIT carry the secret that
# arrives in the preamble on stdin, so the workload can never forge them.
# Nothing here ever prints workload data, argv or environment values.
#
# Relay mode: stdout is framed (`D` + u32 big-endian length + bytes; `E` once the guest service
# shut its write side; `R` once the connection failed), so an EOF from the service never
# overtakes its data and travels while the other direction stays open. stdin (after the
# preamble) is framed the same way by the host: `D` frames, then `E` for the client's EOF,
# which becomes shutdown(SHUT_WR). A stdin that ends without its `E` (the host client or the
# daemon died), or breaks the framing, is an abort. The relay exits once both directions
# reached EOF (exit 0), or on a reset or an abort (exit 1), also one after `E`: then `R`
# follows the `E` (the only byte that may), the socket is watched for an error while nothing
# else is due, and the host must not read the earlier `E` as a clean end.
# Abort is RST: a TCP socket carries SO_LINGER {1, 0} from before its connect, so every end
# but the clean one (exit 0, both directions done) resets the guest service, also a SIGKILL
# of the helper at any time (a kill close). A Unix socket has no reset: an aborted relay is a
# full close there (the service reads EOF and its next write fails with EPIPE, or it sees
# ECONNRESET if its output was still unread), while a client EOF is only a write shutdown.
# A failed connect is a secret-bound `FAILED <refused|denied|failed>` frame on stderr before
# READY. The only host the relay ever connects to is the guest's own loopback.
import os
import re
import signal
import stat
import sys

ID = r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}"
SCOPE_RE = r"wssp-chan-" + ID + r"\." + ID + r"\.scope"
NONCE_RE = r"[A-Za-z0-9]{16,128}"
CANCEL_DIR = "/run/wssp/chan-cancel"
CGROUP_ROOT = "/sys/fs/cgroup/wssp.slice/"
EXIT_REFUSED = 120
EXIT_CANCELLED = 121
EXIT_FENCE_UNKNOWN = 122
RELAY_CHUNK = 32 * 1024
RELAY_CONNECT_TIMEOUT = 10
RELAY_DATA_MAX = 64 * 1024
# struct linger {l_onoff, l_linger} as two native ints.
LINGER_ABORT = (1).to_bytes(4, sys.byteorder) + (0).to_bytes(4, sys.byteorder)
LINGER_ORDERLY = bytes(8)
UNIX_PATH_MAX = 107


def frame(nonce, *fields):
    return ("\x1eWSSP_CHAN %s %s\x1f" % (nonce, " ".join(fields))).encode("ascii")


def write_all(fd, data):
    try:
        while data:
            n = os.write(fd, data)
            data = data[n:]
    except OSError:
        pass


def refuse(nonce, reason):
    write_all(1 if os.isatty(1) else 2, frame(nonce, "REFUSED", reason))
    os._exit(EXIT_REFUSED)


def own_source():
    argv = getattr(sys, "orig_argv", None)
    if not argv:
        with open("/proc/self/cmdline", "rb") as handle:
            argv = [a.decode("utf-8", "surrogateescape") for a in handle.read().split(b"\0")[:-1]]
    index = argv.index("-c")
    return argv[index + 1]


def scope_usable():
    import subprocess

    if not os.access("/usr/bin/systemd-run", os.X_OK) or not os.path.isdir("/run/systemd/system"):
        return False
    try:
        with open("/proc/1/comm", encoding="ascii") as comm:
            if comm.read().strip() != "systemd":
                return False
        version = subprocess.run(
            ["/usr/bin/systemd-run", "--version"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, check=False,
        )
        fields = version.stdout.split()
        return (version.returncode == 0 and len(fields) >= 2
                and fields[0] == b"systemd" and int(fields[1]) >= 254)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def parse_fence_args(argv):
    # <scope> <nonce> <uid> <gid> -- <tail...>
    if len(argv) < 6 or argv[4] != "--":
        os._exit(1)
    scope, nonce, uid, gid = argv[:4]
    if (re.fullmatch(SCOPE_RE, scope) is None or re.fullmatch(NONCE_RE, nonce) is None
            or not uid.isdigit() or not gid.isdigit()):
        os._exit(1)
    return scope, nonce, int(uid), int(gid), argv[5:]


def launch(argv):
    scope, nonce, uid, gid, tail = parse_fence_args(argv)
    if os.getuid() != 0:
        os._exit(1)
    if not scope_usable():
        refuse(nonce, "scope")
    try:
        source = own_source()
        os.execv("/usr/bin/systemd-run", [
            "/usr/bin/systemd-run", "--scope", "--quiet", "--collect", "--no-ask-password",
            "--description=wssp-channel", "--property=OOMPolicy=continue",
            "--expand-environment=no", "--unit=" + scope, "--slice=wssp.slice", "--",
            sys.executable, "-I", "-S", "-c", source, "inner", scope, nonce, str(uid), str(gid),
            "--", *tail,
        ])
    except Exception:
        pass
    refuse(nonce, "scope")


def inner(argv):
    scope, nonce, uid, gid, tail = parse_fence_args(argv)
    try:
        with open("/proc/self/cgroup", "rb") as current:
            if current.read() != b"0::/wssp.slice/" + scope.encode() + b"\n":
                refuse(nonce, "scope")
    except OSError:
        refuse(nonce, "scope")
    # Cancel fence: the kill helper writes the tombstone BEFORE it kills the scope, so
    # either this check sees it, or this scope existed before it and the kill covers us.
    try:
        os.lstat(CANCEL_DIR + "/" + scope)
        os._exit(EXIT_CANCELLED)
    except FileNotFoundError:
        pass
    except Exception:
        os._exit(EXIT_FENCE_UNKNOWN)
    try:
        import grp
        import pwd

        account = pwd.getpwuid(uid)
        if uid <= 0 or gid <= 0 or account.pw_gid != gid or not tail:
            raise ValueError()
        if os.isatty(0):
            # `incus exec --user 0 -t` allocated the guest tty for root; hand it to the
            # guest user as login does, so screen, gpg and mesg keep working.
            try:
                tty_gid = grp.getgrnam("tty").gr_gid
            except KeyError:
                tty_gid = gid
            try:
                os.fchown(0, uid, tty_gid)
                os.fchmod(0, 0o620)
            except OSError:
                pass
        os.initgroups(account.pw_name, gid)
        os.setgid(gid)
        os.setuid(uid)
        if os.getuid() != uid or os.geteuid() != uid:
            raise ValueError()
        os.execvp(tail[0], tail)
    except Exception:
        pass
    os._exit(1)


def default_signals():
    for sig in signal.valid_signals():
        if sig in (signal.SIGKILL, signal.SIGSTOP):
            continue
        try:
            signal.signal(sig, signal.SIG_DFL)
        except (OSError, ValueError):
            pass
    signal.pthread_sigmask(signal.SIG_SETMASK, [])


def birth(nonce):
    with open("/proc/sys/kernel/random/boot_id", "rb") as handle:
        boot = handle.read(64).strip().decode("ascii")
    pid = os.getpid()
    with open("/proc/%d/stat" % pid, "rb") as handle:
        raw = handle.read(4096)
    fields = raw[raw.rindex(b") ") + 2:].split()
    return frame(nonce, "READY", str(pid), boot, fields[19].decode("ascii"), str(os.getuid()))


def start_workload(login, argv, announce):
    # READY goes out only once the child runs with default signal dispositions, and the
    # workload starts only after READY: a signal the host delivers after READY always
    # reaches the workload, never only the wrapper's no-op handlers.
    ready_r, ready_w = os.pipe()
    go_r, go_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(ready_r)
            os.close(go_w)
            default_signals()
            os.write(ready_w, b"1")
            os.close(ready_w)
            if os.read(go_r, 1) != b"1":
                os._exit(1)
            os.close(go_r)
            if not argv:
                shell = os.environ.get("SHELL", "/bin/sh")
                name = os.path.basename(shell)
                os.execv(shell, [("-" + name) if login else name])
            os.execvp(argv[0], argv)
        except PermissionError:
            os._exit(126)
        except Exception:
            os._exit(127)
        os._exit(127)
    os.close(ready_w)
    os.close(go_r)
    try:
        os.read(ready_r, 1)
    except OSError:
        pass
    os.close(ready_r)
    announce()
    try:
        os.write(go_w, b"1")
    except OSError:
        pass
    os.close(go_w)
    return pid


def outcome(status):
    if os.WIFSIGNALED(status):
        sig = os.WTERMSIG(status)
        return ("signal", sig, 128 + sig)
    code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else 1
    return ("code", code, code)


def noop(_sig, _frame):
    pass


def wrap(argv):
    if len(argv) < 10 or argv[0] != "WSSP_PID" or argv[9] != "--":
        os._exit(1)
    nonce, mode, login = argv[1], argv[2], argv[3] == "1"
    if (re.fullmatch(NONCE_RE, nonce) is None or mode not in ("pty", "exec", "tcp", "unix")
            or not all(a.isdigit() for a in argv[4:9])):
        os._exit(1)
    budget, limits = int(argv[4]), [int(a) for a in argv[5:9]]
    workload = argv[10:]
    relay = mode in ("tcp", "unix")
    if relay and (login or relay_target(mode, workload) is None):
        os._exit(1)
    frame_fd = 1 if mode == "pty" else 2
    env, secret = read_preamble(nonce, mode == "pty", frame_fd, budget, limits)
    if relay:
        # A relay starts nothing: the environment is never applied.
        wrap_relay(secret, mode, relay_target(mode, workload))
    os.environ.update(env)
    if mode == "pty":
        wrap_pty(secret, login, workload)
    else:
        wrap_exec(secret, login, workload)


def read_preamble(nonce, tty, frame_fd, budget, limits):
    # `<8 hex>:<base64 env JSON>` then the 32-character frame secret and a newline. The
    # host writes it only after PROMPT, and its last byte is the go: until then nothing of
    # the workload runs, and a truncated preamble (the channel was closed) exits here.
    import base64
    import json
    import select
    import termios
    import time
    import tty as ttymod

    max_entries, key_cap, value_cap, json_cap = limits
    saved = None
    if tty:
        try:
            saved = termios.tcgetattr(0)
            # Raw, no echo, and anything queued before the prompt is discarded.
            ttymod.setraw(0, termios.TCSAFLUSH)
        except Exception:
            os._exit(1)
    deadline = time.monotonic() + budget / 1000.0
    write_all(frame_fd, frame(nonce, "PROMPT"))

    def exact(n):
        data = b""
        while len(data) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
                os._exit(1)
            chunk = os.read(0, n - len(data))
            if not chunk:
                os._exit(1)
            data += chunk
        return data

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                os._exit(1)
            result[key] = value
        return result

    try:
        header = exact(9)
        if header[8:] != b":" or any(c not in b"0123456789abcdef" for c in header[:8]):
            os._exit(1)
        length = int(header[:8], 16)
        if length > 4 * ((json_cap + 2) // 3):
            os._exit(1)
        env = {}
        if length:
            payload = base64.b64decode(exact(length), validate=True)
            if len(payload) > json_cap:
                os._exit(1)
            env = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=unique)
            if not isinstance(env, dict) or len(env) > max_entries:
                os._exit(1)
            for key, value in env.items():
                if (not key or not (key[0].isascii() and (key[0].isalpha() or key[0] == "_"))
                        or not all(c.isascii() and (c.isalnum() or c == "_") for c in key)
                        or key in ("__proto__", "prototype", "constructor", "HOME", "SHELL", "TERM")
                        or not isinstance(value, str) or "\0" in value
                        or len(key.encode("utf-8")) > key_cap
                        or len(value.encode("utf-8")) > value_cap):
                    os._exit(1)
        line = exact(33)
        secret = line[:32].decode("ascii", "replace")
        if line[32:] != b"\n" or re.fullmatch(NONCE_RE, secret) is None or secret == nonce:
            os._exit(1)
    except Exception:
        os._exit(1)
    if saved is not None:
        try:
            termios.tcsetattr(0, termios.TCSANOW, saved)
        except Exception:
            os._exit(1)
    return env, secret


def wrap_pty(nonce, login, workload):
    # The agent made this process the tty's session leader. It stays alive to report
    # the workload's outcome, so tty signals must never kill it.
    child = [0]

    def hangup(_sig, _frame):
        if child[0]:
            try:
                os.kill(child[0], signal.SIGHUP)
            except OSError:
                pass

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGQUIT, signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(sig, noop)
    signal.signal(signal.SIGHUP, hangup)
    for sig in (signal.SIGTTOU, signal.SIGTTIN, signal.SIGTSTP):
        signal.signal(sig, signal.SIG_IGN)
    try:
        ready = birth(nonce)
    except Exception:
        os._exit(1)
    child[0] = start_workload(login, workload, lambda: write_all(1, ready))
    while True:
        try:
            _, status = os.waitpid(child[0], 0)
            break
        except ChildProcessError:
            status = 1 << 8
            break
    child[0] = 0
    kind, value, code = outcome(status)
    try:
        if os.isatty(1):
            os.tcsetpgrp(1, os.getpgrp())
    except OSError:
        pass
    write_all(1, frame(nonce, "EXIT", kind, str(value)))
    os._exit(code)


def wrap_exec(nonce, login, workload):
    # The agent's direct child is a session leader and the agent stops relaying stdin
    # when it exits, so it stays as a relay parent. Its death (the host client went
    # away) closes `hold`, and the wrapper then hangs up its own process group.
    hold_r, hold_w = os.pipe()
    pid = os.fork()
    if pid:
        os.close(hold_r)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_DFL)
        null = os.open("/dev/null", os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(null, fd)
        while True:
            try:
                _, status = os.waitpid(pid, 0)
                break
            except ChildProcessError:
                os._exit(1)
        os._exit(outcome(status)[2])
    os.close(hold_w)
    os.setsid()
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT,
                signal.SIGUSR1, signal.SIGUSR2):
        signal.signal(sig, noop)
    try:
        ready = birth(nonce)
    except Exception:
        os._exit(1)
    child = start_workload(login, workload, lambda: write_all(2, ready))
    # stdout EOF is the workload's own; stderr stays for the EXIT frame.
    null = os.open("/dev/null", os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(null, 1)
    os.close(null)
    import select

    held = True
    while True:
        try:
            done, status = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            done, status = child, 1 << 8
        if done:
            break
        if held:
            try:
                readable = select.select([hold_r], [], [], 0.1)[0]
                if readable and os.read(hold_r, 1) == b"":
                    held = False
                    os.killpg(0, signal.SIGHUP)
            except InterruptedError:
                pass
            except OSError:
                held = False
        else:
            select.select([], [], [], 0.1)
    kind, value, code = outcome(status)
    write_all(2, frame(nonce, "EXIT", kind, str(value)))
    os._exit(code)


def relay_target(mode, workload):
    # Exactly one argument: a port 1-65535 (tcp) or an absolute path (unix).
    if len(workload) != 1:
        return None
    target = workload[0]
    if mode == "tcp":
        if not target.isdigit() or len(target) > 5 or not 1 <= int(target) <= 65535:
            return None
        return int(target)
    raw = target.encode("utf-8", "surrogateescape")
    if not target.startswith("/") or "\0" in target or len(raw) > UNIX_PATH_MAX:
        return None
    return target


def connect_failure(error):
    import errno

    if isinstance(error, OSError) and error.errno in (errno.ECONNREFUSED, errno.ENOENT):
        return "refused"
    if isinstance(error, OSError) and error.errno in (errno.EACCES, errno.EPERM):
        return "denied"
    return "failed"


def relay_connect(mode, target):
    # Guest loopback only: the address is fixed here, never taken from the host. A refusal on
    # 127.0.0.1 tries [::1] (a service bound to `localhost` may listen on either); the answer
    # reported is the first one.
    import errno
    import socket

    if mode == "unix":
        candidates = [(socket.AF_UNIX, target)]
    else:
        candidates = [(socket.AF_INET, ("127.0.0.1", target)),
                      (socket.AF_INET6, ("::1", target, 0, 0))]
    first = None
    for family, address in candidates:
        sock = None
        try:
            sock = socket.socket(family, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
            if family != socket.AF_UNIX:
                # Abortive close from the start: a SIGKILL at any time, and every end but
                # the clean one, resets the service (cleared only on the clean path).
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER_ABORT)
            sock.settimeout(RELAY_CONNECT_TIMEOUT)
            sock.connect(address)
            return sock, None
        except OSError as error:
            if sock is not None:
                sock.close()
            if first is None:
                first = error
            if first.errno != errno.ECONNREFUSED:
                break
    return None, connect_failure(first)


def relay_input(state, chunk):
    # Decode one stdin chunk of the host's framing (`D` + u32 big-endian length + bytes, then
    # `E`): its payload (never longer than the chunk) and "eof" once `E` arrived, or "abort"
    # for anything that is not the host's framing (also any byte after `E`).
    out = []
    pos = 0
    while pos < len(chunk):
        if state[2]:
            return b"".join(out), "abort"
        if state[0]:
            take = min(state[0], len(chunk) - pos)
            out.append(chunk[pos:pos + take])
            state[0] -= take
            pos += take
            continue
        head = state[1]
        if not head:
            tag = chunk[pos:pos + 1]
            if tag == b"E":
                state[2] = True
                pos += 1
                continue
            if tag != b"D":
                return b"".join(out), "abort"
        take = min(5 - len(head), len(chunk) - pos)
        head += chunk[pos:pos + take]
        pos += take
        state[1] = head
        if len(head) == 5:
            length = int.from_bytes(head[1:5], "big")
            state[1] = b""
            if length == 0 or length > RELAY_DATA_MAX:
                return b"".join(out), "abort"
            state[0] = length
    return b"".join(out), ("eof" if state[2] else None)


def wrap_relay(secret, mode, target):
    import fcntl
    import select
    import socket
    import struct

    sock, failure = relay_connect(mode, target)
    if sock is None:
        write_all(2, frame(secret, "FAILED", failure))
        os._exit(1)
    try:
        ready = birth(secret)
    except Exception:
        os._exit(1)
    write_all(2, ready)
    sock.setblocking(False)
    for fd in (0, 1):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    to_sock = b""
    to_out = b""
    # stdin framing: [payload bytes still due, partial header, `E` seen].
    framing = [0, b"", False]
    in_eof = False
    shut = False
    sock_eof = False
    reset = False
    # The service closed both of its sides (a Unix peer's close): no reset to
    # watch for any more.
    hup = False
    # The socket reported an error while unread data may precede it: the
    # next recv returns that data first, then the error.
    sock_err = False
    sock_fd = sock.fileno()
    while True:
        if in_eof and not to_sock and not shut and not reset:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                reset = True
                to_out += b"R"
            shut = True
        if not to_out and (reset or (shut and sock_eof)):
            break
        watch = {}
        if not reset:
            if not in_eof and not to_sock:
                watch[0] = select.POLLIN
            mask = 0
            if not sock_eof and not to_out:
                mask |= select.POLLIN
            if to_sock:
                mask |= select.POLLOUT
            # Also with nothing to read or write (the service shut its write
            # side, the client is idle): a reset then is POLLERR, reported
            # now and not only at the client's next byte. Not once our side
            # is shut too (POLLHUP would then report the clean end forever),
            # nor while a seen error waits for the recv (stdout is due then).
            if mask or not (shut or hup or sock_err):
                watch[sock_fd] = mask
        if to_out:
            watch[1] = select.POLLOUT
        poller = select.poll()
        for fd, mask in watch.items():
            poller.register(fd, mask)
        try:
            ready = dict(poller.poll())
        except InterruptedError:
            continue
        if ready.get(1):
            try:
                to_out = to_out[os.write(1, to_out):]
            except BlockingIOError:
                pass
            except OSError:
                # The host side is gone: nobody to report to.
                os._exit(1)
        sock_ready = ready.get(sock_fd, 0)
        if sock_ready & select.POLLERR and not reset:
            if sock_eof:
                # Nothing can precede it any more: a reset after `E`.
                reset = True
                to_sock = b""
                to_out += b"R"
            else:
                sock_err = True
        elif sock_ready & select.POLLHUP and not watch.get(sock_fd):
            hup = True
        if sock_ready & select.POLLOUT and to_sock and not reset:
            try:
                to_sock = to_sock[sock.send(to_sock):]
            except BlockingIOError:
                pass
            except OSError:
                reset = True
                to_sock = b""
                to_out += b"R"
        if ready.get(0) and not reset:
            try:
                chunk = os.read(0, RELAY_CHUNK)
            except BlockingIOError:
                chunk = None
            except OSError:
                chunk = b""
            if chunk is not None:
                # A raw EOF before the host's `E` is an abort (the host is gone).
                data, end = relay_input(framing, chunk) if chunk else (b"", "abort")
                to_sock = data
                if end == "eof":
                    in_eof = True
                elif end == "abort":
                    reset = True
                    to_sock = b""
                    to_out += b"R"
        if sock_ready & (select.POLLIN | select.POLLHUP | select.POLLERR) \
                and watch.get(sock_fd, 0) & select.POLLIN \
                and not reset:
            try:
                chunk = sock.recv(RELAY_CHUNK)
                if chunk:
                    to_out = b"D" + struct.pack(">I", len(chunk)) + chunk
                else:
                    sock_eof = True
                    to_out = b"E"
            except BlockingIOError:
                pass
            except OSError:
                reset = True
                to_out += b"R"
    code = 1 if reset else 0
    try:
        if code == 0 and mode == "tcp":
            # The clean end only: an orderly close (both directions are done).
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER_ORDERLY)
        sock.close()
    except OSError:
        pass
    write_all(2, frame(secret, "EXIT", "code", str(code)))
    os._exit(code)


def safe_dir(parent_fd, name, mode):
    try:
        os.mkdir(name, mode, dir_fd=parent_fd)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent_fd)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        os.close(fd)
        raise OSError("unsafe directory")
    return fd


def scope_gone(path):
    try:
        with open(path + "/cgroup.events", "rb") as events:
            for line in events.read(4096).splitlines():
                if line == b"populated 0":
                    return True
        return False
    except FileNotFoundError:
        return not os.path.isdir(path)
    except OSError:
        return False


def kill(argv):
    import subprocess
    import time

    if len(argv) < 2 or re.fullmatch(NONCE_RE, argv[0]) is None or os.getuid() != 0:
        os._exit(1)
    nonce = argv[0]
    scopes = []
    for item in argv[1:]:
        scope, _, forget = item.rpartition(":")
        if re.fullmatch(SCOPE_RE, scope) is None or forget not in ("0", "1"):
            os._exit(1)
        scopes.append((scope, forget == "1"))
    try:
        root = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        run = safe_dir(root, "run", 0o755)
        wssp = safe_dir(run, "wssp", 0o755)
        cancel = safe_dir(wssp, "chan-cancel", 0o700)
    except Exception:
        for scope, _ in scopes:
            print("WSSP_CHAN_KILL %s %s present" % (nonce, scope), flush=True)
        os._exit(0)
    fenced = []
    for scope, forget in scopes:
        try:
            marker = os.open(scope, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
                             | os.O_NONBLOCK, 0o600, dir_fd=cancel)
            os.close(marker)
            fenced.append((scope, forget))
        except OSError:
            # Without its tombstone a delayed launcher could still start the
            # workload after this kill: never report such a scope gone.
            print("WSSP_CHAN_KILL %s %s present" % (nonce, scope), flush=True)
    scopes = fenced
    for scope, _ in scopes:
        path = CGROUP_ROOT + scope
        try:
            with open(path + "/cgroup.kill", "wb") as handle:
                handle.write(b"1")
        except FileNotFoundError:
            pass
        except OSError:
            try:
                subprocess.run(["systemctl", "kill", "--kill-whom=all", "--signal=KILL", scope],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=3, check=False)
            except Exception:
                pass
    deadline = time.monotonic() + 5
    pending = list(scopes)
    while True:
        still = []
        for scope, forget in pending:
            if scope_gone(CGROUP_ROOT + scope):
                if forget:
                    try:
                        os.unlink(scope, dir_fd=cancel)
                    except OSError:
                        pass
                print("WSSP_CHAN_KILL %s %s gone" % (nonce, scope), flush=True)
            else:
                still.append((scope, forget))
        pending = still
        if not pending or time.monotonic() >= deadline:
            break
        time.sleep(0.05)
    for scope, _ in pending:
        print("WSSP_CHAN_KILL %s %s present" % (nonce, scope), flush=True)
    os._exit(0)


def main():
    if len(sys.argv) < 2:
        os._exit(1)
    phase, argv = sys.argv[1], sys.argv[2:]
    if phase == "launch":
        launch(argv)
    elif phase == "inner":
        inner(argv)
    elif phase == "wrap":
        wrap(argv)
    elif phase == "kill":
        kill(argv)
    os._exit(1)


main()
