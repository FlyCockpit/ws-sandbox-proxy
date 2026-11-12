# Isolated guest helper. Only non-secret policy, nonce and absolute wrapper argv
# appear in argv. Exact unbuffered reads leave fd 0 at the first user byte.
import base64
import enum
import termios
import tty
import json
import os
import select
import sys
import time


class SetupFailure(enum.IntEnum):
    TRUNCATED = 1
    INVALID = 2
    TIMEOUT = 3
    EXEC_FAILED = 4


def main():
    mode, nonce, budget, entries, key_cap, value_cap, json_cap = sys.argv[1:8]
    wrapper = sys.argv[9:]
    deadline = time.monotonic() + int(budget) / 1000
    saved_mode = None

    def refuse(code):
        if mode == "pty":
            try:
                if saved_mode is not None:
                    termios.tcsetattr(0, termios.TCSANOW, saved_mode)
            except Exception:
                pass
            try:
                os.write(1, ("\x1eWSSP_ENV_FAILED %s\x1f" % nonce).encode("ascii"))
            except OSError:
                pass
            os._exit(1)
        data = ("WSSP_PID %s %d\n\nWSSP_SETUP_FAILED %s %d\n" %
                (nonce, os.getpid(), nonce, code)).encode("ascii")
        try:
            while data:
                n = os.write(2, data)
                data = data[n:]
        except OSError:
            pass  # Lost proof is uncertainty at the host; never print a traceback.
        os._exit(1)

    def exact(n):
        chunks = []
        while n:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([0], [], [], remaining)[0]:
                refuse(SetupFailure.TIMEOUT)  # timeout
            chunk = os.read(0, n)
            if not chunk:
                refuse(SetupFailure.TRUNCATED)  # truncated
            chunks.append(chunk)
            n -= len(chunk)
        return b"".join(chunks)

    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                refuse(SetupFailure.INVALID)
            result[k] = v
        return result

    try:
        if mode not in ("piped", "pty") or not wrapper or not os.path.isabs(wrapper[0]):
            refuse(SetupFailure.INVALID)
        frame = None
        if mode == "pty":
            saved_mode = termios.tcgetattr(0)
            tty.setraw(0, termios.TCSANOW)
            os.write(1, ("\x1eWSSP_ENV_READY %s\x1f" % nonce).encode("ascii"))
            # Startup before READY spends none of this exact-read budget.
            deadline = time.monotonic() + int(budget) / 1000
            prefix = exact(9)
            if prefix[8:] != b":" or any(c not in b"0123456789abcdef" for c in prefix[:8]):
                refuse(SetupFailure.INVALID)
            encoded_len = int(prefix[:8], 16)
            if encoded_len < 4 or encoded_len > 21864:
                refuse(SetupFailure.INVALID)
            frame = base64.b64decode(exact(encoded_len), validate=True)
            if len(frame) < 13 or len(frame) > 13 + int(json_cap):
                refuse(SetupFailure.INVALID)
            header = frame[:13]
        else:
            header = exact(13)
        n = int.from_bytes(header[9:13], "big")
        if header[:9] != b"WSSPENV\0\x01" or n < 2 or n > int(json_cap):
            refuse(SetupFailure.INVALID)
        if frame is not None and len(frame) != 13 + n:
            refuse(SetupFailure.INVALID)
        payload = frame[13:] if frame is not None else exact(n)
        env = json.loads(payload.decode("utf-8", "strict"), object_pairs_hook=unique)
        if not isinstance(env, dict) or len(env) > int(entries):
            refuse(SetupFailure.INVALID)
        for k, v in env.items():
            if (not k or not (k[0].isascii() and (k[0].isalpha() or k[0] == "_")) or
                not all(c.isascii() and (c.isalnum() or c == "_") for c in k) or
                k in ("__proto__", "prototype", "constructor", "HOME", "SHELL") or
                not isinstance(v, str) or "\0" in v or
                len(k.encode("utf-8")) > int(key_cap) or
                len(v.encode("utf-8")) > int(value_cap)):
                refuse(SetupFailure.INVALID)
        canonical = json.dumps(env, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8")
        if len(canonical) > int(json_cap):
            refuse(SetupFailure.INVALID)
        if time.monotonic() >= deadline:
            refuse(SetupFailure.TIMEOUT)
        if mode == "pty" and "TERM" in env:
            refuse(SetupFailure.INVALID)
        merged = dict(os.environ)
        merged.update(env)
        if mode == "pty":
            termios.tcsetattr(0, termios.TCSANOW, saved_mode)
            os.write(1, ("\x1eWSSP_ENV_DONE %s\x1f" % nonce).encode("ascii"))
        try:
            os.execve(wrapper[0], wrapper, merged)
        except OSError:
            refuse(SetupFailure.EXEC_FAILED)  # exec failed; no target ran
    except Exception:
        refuse(SetupFailure.INVALID)  # invalid; never include data or traceback


main()
