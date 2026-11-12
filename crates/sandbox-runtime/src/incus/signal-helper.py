"""Tracked TERM/INT/HUP delivery (approved Q2 Branch A), run as the guest UID.

Invoked as `python3 -I -c <this> wssp-signal NONCE PID BOOT TICKS UID CMDNONCE NAME`.
`wssp-signal-probe NONCE` runs only the zero-signal support probe below and
reports `group` or `unsupported` (the host reports it as the guest's
supported signals once the guest is ready; delivery still re-probes).
Open-then-verify: the leader pidfd is opened FIRST and retained through
delivery; boot UUID, start ticks, session/process-group leadership, UID and
the host-local wrapper identity are verified against /proc afterwards, then
the pidfd itself is re-checked for liveness. Delivery uses only
pidfd_send_signal(..., PIDFD_SIGNAL_PROCESS_GROUP) (Linux >= 6.9). There is
no numeric kill, no PID reopen, no member census and no flags=0 fallback:
without kernel/Python support the helper reports `unsupported` before any
nonzero signal. Status lines are bound to a fresh host nonce on stderr:

  unsupported | gone | mismatch | unverified   (terminal, no effect)
  verified                                      (effect boundary)
  delivered | exited | failed                   (after `verified` only)
"""

import errno
import os
import signal
import sys

# include/uapi/linux/pidfd.h; absent from the Python stdlib constants.
PIDFD_SIGNAL_PROCESS_GROUP = 4
SIGNALS = {"TERM": signal.SIGTERM, "INT": signal.SIGINT, "HUP": signal.SIGHUP}
STAT_MAX = 4096
CMDLINE_MAX = 256 * 1024


def emit(nonce, verdict):
    sys.stderr.write("WSSP_SIGNAL %s %s\n" % (nonce, verdict))
    sys.stderr.flush()


def group_signal_supported():
    """Zero-signal self probe: no target is signalled and nothing is sent."""
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        return False
    try:
        fd = os.pidfd_open(os.getpid())
    except OSError:
        return False
    try:
        signal.pidfd_send_signal(fd, 0, None, PIDFD_SIGNAL_PROCESS_GROUP)
        return True
    except OSError as error:
        # EINVAL: the kernel does not know the group flag (e.g. 6.8). Any other
        # errno (ESRCH when this helper is not itself a group leader) means the
        # flag was accepted; still no signal was sent (signal 0).
        return error.errno != errno.EINVAL
    finally:
        os.close(fd)


def stat_fields(pid):
    with open("/proc/%d/stat" % pid, "rb") as handle:
        raw = handle.read(STAT_MAX + 1)
    if len(raw) > STAT_MAX:
        raise ValueError("stat")
    # Fields after the final ") " start at field 3 (state); comm may hold ") ".
    return raw[raw.rindex(b") ") + 2 :].split()


def main(argv):
    if len(argv) == 2 and argv[0] == "wssp-signal-probe":
        emit(argv[1], "group" if group_signal_supported() else "unsupported")
        return 0
    if len(argv) != 8 or argv[0] != "wssp-signal":
        return 2
    _, nonce, pid_text, boot, ticks, uid_text, command_nonce, name = argv
    sig = SIGNALS.get(name)
    if sig is None or not pid_text.isdigit() or not uid_text.isdigit():
        emit(nonce, "mismatch")
        return 0
    if not group_signal_supported():
        emit(nonce, "unsupported")
        return 0
    pid = int(pid_text)
    try:
        fd = os.pidfd_open(pid)
    except ProcessLookupError:
        emit(nonce, "gone")
        return 0
    except OSError:
        emit(nonce, "unverified")
        return 0
    try:
        try:
            with open("/proc/sys/kernel/random/boot_id", "rb") as handle:
                actual_boot = handle.read(64).strip()
            fields = stat_fields(pid)
            owner = os.stat("/proc/%d" % pid).st_uid
            with open("/proc/%d/cmdline" % pid, "rb") as handle:
                cmdline = handle.read(CMDLINE_MAX)
        except (FileNotFoundError, ProcessLookupError):
            emit(nonce, "gone")
            return 0
        except (OSError, ValueError):
            emit(nonce, "unverified")
            return 0
        wrapper = ("WSSP_PID %s " % command_nonce).encode()
        if (
            len(fields) < 20
            or actual_boot != boot.encode()
            or fields[19] != ticks.encode()
            or fields[2] != pid_text.encode()
            or fields[3] != pid_text.encode()
            or owner != int(uid_text)
            or wrapper not in cmdline.replace(b"\0", b" ")
        ):
            emit(nonce, "mismatch")
            return 0
        try:
            # The verified /proc facts describe this pidfd only while it lives.
            signal.pidfd_send_signal(fd, 0)
        except ProcessLookupError:
            emit(nonce, "gone")
            return 0
        except OSError:
            emit(nonce, "unverified")
            return 0
        emit(nonce, "verified")
        try:
            signal.pidfd_send_signal(fd, sig, None, PIDFD_SIGNAL_PROCESS_GROUP)
        except ProcessLookupError:
            emit(nonce, "exited")
            return 0
        except OSError:
            emit(nonce, "failed")
            return 0
        emit(nonce, "delivered")
        return 0
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
