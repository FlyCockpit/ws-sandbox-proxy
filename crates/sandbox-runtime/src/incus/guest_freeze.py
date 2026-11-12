# Shared cgroup v2 guest freezer (image-cache capture scrub and credential
# quiesce). Never thaws by itself; a caller that must resume the guest
# thaws explicitly from `frozen_roots`, `cg_state` and `held_from`. Loads no
# module: the including helper's first line brings in os and time.
PF_KTHREAD = 0x00200000
CGROUP = "/sys/fs/cgroup"
FREEZE_DEADLINE_S = 30.0
frozen_roots = []
held = set()
held_from = {}
cg_state = {"helper": None, "hold": None, "keep": set(), "origin": None}
def proc_stat(pid, tid=None):
    where = "/proc/%d/stat" % pid if tid is None else "/proc/%d/task/%d/stat" % (pid, tid)
    with open(where) as f:
        data = f.read()
    rest = data[data.rindex(")") + 2:].split()
    return rest[0], int(rest[1]), int(rest[6])
def exempt_pids():
    """This helper and its ancestors below PID 1 (the Incus agent running it)."""
    keep = {os.getpid()}
    pid = os.getpid()
    while pid > 1:
        try:
            pid = proc_stat(pid)[1]
        except (OSError, ValueError, IndexError):
            break
        if pid > 1:
            keep.add(pid)
    return keep
def cgroup_of(pid, tid=None):
    """The task's cgroup v2 path; anything but a pure v2 hierarchy raises."""
    where = "/proc/%d/cgroup" % pid if tid is None else "/proc/%d/task/%d/cgroup" % (pid, tid)
    with open(where) as f:
        lines = f.read().splitlines()
    if len(lines) != 1 or not lines[0].startswith("0::/"):
        raise ValueError("not a cgroup v2 hierarchy")
    return lines[0][3:]
def cgdir(path):
    return CGROUP if path == "/" else CGROUP + path
def cg_read(path):
    with open(path) as f:
        return f.read()
def cg_write(path, value):
    with open(path, "w") as f:
        f.write(value)
def is_frozen(path):
    if path == "/":
        return False
    try:
        return "frozen 1" in cg_read(cgdir(path) + "/cgroup.events").splitlines()
    except OSError:
        return False
def cg_children(path):
    found = []
    try:
        with os.scandir(cgdir(path)) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=False):
                    found.append(path.rstrip("/") + "/" + entry.name)
    except OSError:
        pass
    return found
def user_tasks(keep):
    """(pid, tid) of every live user-space thread outside `keep`."""
    tasks = []
    for name in os.listdir("/proc"):
        if not name.isdigit() or int(name) in keep:
            continue
        pid = int(name)
        try:
            tids = [int(t) for t in os.listdir("/proc/%d/task" % pid)]
        except OSError:
            continue
        for tid in tids:
            try:
                state, _, flags = proc_stat(pid, tid)
            except (OSError, ValueError, IndexError):
                continue
            if flags & PF_KTHREAD or state in ("Z", "X", "x"):
                continue
            tasks.append((pid, tid))
    return tasks
def frozen_problems():
    """Why the guest is not entirely frozen; empty when it is."""
    problems = []
    for node in frozen_roots + [cg_state["hold"]]:
        if os.path.isdir(cgdir(node)) and not is_frozen(node):
            problems.append("cgroup %s did not freeze" % node)
    for pid, tid in user_tasks(cg_state["keep"]):
        try:
            where = cgroup_of(pid, tid)
        except (OSError, ValueError):
            continue
        if where == cg_state["helper"]:
            problems.append("process %d runs beside the scrub helper" % pid)
        elif not is_frozen(where):
            problems.append("process %d is not frozen" % pid)
    return sorted(set(problems))
def freeze_guest():
    """Freeze every guest task except this helper and the agent chain running it."""
    try:
        if not os.path.isfile(CGROUP + "/cgroup.controllers"):
            raise OSError("no cgroup2 root")
        origin = cgroup_of(os.getpid())
    except (OSError, ValueError):
        fail("<freeze>", "cgroup v2 freezer unavailable")
        return
    me = os.getpid()
    keep = exempt_pids()
    helper = "/wssp-scrub-%d" % me
    hold = "/wssp-hold-%d" % me
    try:
        os.mkdir(cgdir(helper), 0o700)
        os.mkdir(cgdir(hold), 0o700)
        cg_write(cgdir(hold) + "/cgroup.freeze", "1")
        cg_write(cgdir(helper) + "/cgroup.procs", str(me))
        isolated = (cgroup_of(me) == helper
                    and cg_read(cgdir(helper) + "/cgroup.procs").split() == [str(me)])
    except (OSError, ValueError) as e:
        fail("<freeze>", "cannot isolate the scrub helper: %s" % (getattr(e, "strerror", None) or e))
        return
    if not isolated:
        fail("<freeze>", "cannot isolate the scrub helper")
        return
    cg_state.update(helper=helper, hold=hold, keep=keep, origin=origin)
    # The path from the root to the agent's cgroup keeps running (the agent
    # carries this helper's output); every other subtree is frozen whole.
    running = ["/"]
    for part in [c for c in origin.split("/") if c]:
        running.append(running[-1].rstrip("/") + "/" + part)
    skip = set(running) | {helper}
    deadline = time.monotonic() + FREEZE_DEADLINE_S
    while True:
        changed = False
        for node in running:
            for child in cg_children(node):
                if child in skip or child in frozen_roots:
                    continue
                try:
                    cg_write(cgdir(child) + "/cgroup.freeze", "1")
                except FileNotFoundError:
                    continue
                except OSError as e:
                    fail("<freeze>", "cannot freeze %s: %s" % (child, e.strerror or e))
                    return
                frozen_roots.append(child)
                changed = True
        # Any other process in a running cgroup (the root, the agent's path)
        # moves into the frozen holding cgroup and freezes on arrival.
        for pid, tid in user_tasks(keep):
            try:
                where = cgroup_of(pid, tid)
            except (OSError, ValueError):
                continue
            if where in skip:
                try:
                    cg_write(cgdir(hold) + "/cgroup.procs", str(pid))
                except ProcessLookupError:
                    continue
                except OSError as e:
                    fail("<freeze>", "cannot freeze process %d: %s" % (pid, e.strerror or e))
                    return
                held.add(pid)
                held_from.setdefault(pid, where)
                changed = True
        if not changed and not frozen_problems():
            return
        if time.monotonic() > deadline:
            for problem in frozen_problems() or ["guest tasks kept escaping the freeze"]:
                fail("<freeze>", problem)
            return
        time.sleep(0.02)
