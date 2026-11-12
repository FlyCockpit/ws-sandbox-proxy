import json, os, pathlib, subprocess, sys, time
root = pathlib.Path(__file__).parent
args = sys.argv[1:]
# Never run guest-root identity setup against host accounts in a transport shim.
# The launcher argv: python3 -I -S -c <helper> <unit> <uid> <gid> <command...>.
if args[:4] == ['python3', '-I', '-S', '-c']:
    assert args[5].startswith('wssp-cmd-') and args[5].endswith('.scope'), args[5]
    args = args[8:]
(root / 'actual-argv').write_text(json.dumps(args, ensure_ascii=False))
(root / 'actual-proc').write_bytes(pathlib.Path('/proc/self/cmdline').read_bytes())
mode = (root / 'transport-mode').read_text()
base = dict(os.environ, HOME='/home/user', SHELL='/bin/bash')
if mode == 'pass':
    os.execve(args[0], args, base)
def exact(n):
    result = b''
    while len(result) < n:
        part = os.read(0, n-len(result))
        if not part: break
        result += part
    return result
header = exact(13)
exact(int.from_bytes(header[9:13], 'big'))
invalid = (root / 'invalid-frame').read_bytes()
p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=base)
# Capture the actual helper cmdline before delivering any payload.
(root / 'helper-proc').write_bytes(pathlib.Path('/proc/%d/cmdline' % p.pid).read_bytes())
out, err = p.communicate(invalid)
(root / 'helper-stderr').write_bytes(err)
os.write(1, out)
if mode != 'lost':
    os.write(2, err)
(root / 'proof-finished').touch()
if mode == 'late':
    while not (root / 'close-stdin').exists(): time.sleep(.002)
    os.close(0)  # single production pump now gets EPIPE, after proof is complete
    (root / 'stdin-closed').touch()
    while not (root / 'finish-wait').exists(): time.sleep(.002)
