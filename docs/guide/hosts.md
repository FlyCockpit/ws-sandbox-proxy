# Hosts

A host is a Linux machine you control that runs the `wssp host run` daemon. The
daemon holds one outbound WSS connection to the server, executes dispatched
work against the local Incus daemon, and enforces sandbox leases on its own
even while disconnected. The control plane never talks to Incus directly.

Command and flag details: [CLI reference](../../apps/cli/docs/cli-reference.md).
Daemon internals (receipt journal, leases, file staging): [CLI README](../../apps/cli/README.md).

## Quick start: your first host

The steps a new node owner follows, in order. Each links to the section with
the details; the dashboard's **Settings → Hosts → Add host** shows the same
steps with copyable commands.

1. **Check the machine** ([requirements](#requirements)): Linux with KVM,
   Incus 6.14 or newer with the `network_acl` extension, and the
   `br_netfilter` module loaded with `net.bridge.bridge-nf-call-ip6tables=1`.
   The user that will run the daemon must be an Incus admin.
2. **Install `wssp`** ([install](#install)) as that user.
3. **Enroll** ([enroll](#enroll)): `wssp host enroll --slug <name> --server
   <server-origin>`. It prints a link and a code; open the link in a browser
   signed in to the dashboard (verified email, and 2FA if your server requires
   it) and approve. The command then finishes and tells you the next step.
4. **Install the egress guard, once, as root** ([egress guard](#egress-guard)):
   `sudo "$(command -v wssp)" host guard install --daemon-user "$USER"`.
   Without it the host connects but cannot start any sandbox. If the machine
   runs ufw or firewalld with a default-drop policy, add `--configure-ufw` or
   `--configure-firewalld` ([host firewall](#host-firewall-ufwfirewalld)).
5. **Start the daemon**: `wssp host run` in a terminal to try it, then
   [run it as a systemd user service](#run-as-a-service) so it survives
   logouts and reboots.
6. **Check the dashboard**: the host shows **Connected** on **Settings →
   Hosts**, and its detail page shows the guard, network, storage and capacity
   it reported. Optional limits (guest RAM, vCPU budget, per-VM CPU cap,
   storage budgets) are in [capacity, drain and deletion](#capacity-drain-and-deletion).
7. **Give it work**: add a template (the quickest is **Templates → Create from
   community image**; see [templates](../operations/templates.md#community-bases)),
   and, to place sandboxes across hosts or share them, add the host to a
   [pool](./pools.md#dashboard-walkthrough).

## Dashboard capacity

Each **Hosts** card shows live count without a count limit, charged RAM and
aggregate vCPU budgets, reserved/available/overcommitted resources, and per-VM
CPU/memory caps. These are commitments, not measured RSS or dedicated CPUs.
RAM includes guest memory plus a fixed host allowance. A smaller budget preserves
existing holds and can show overcommit; running guests are never resized or evicted.

Storage cards show up to 16 configured local pools: opaque identity, effective and
total-based caps, persisted implicit ceiling, connection-time T/F/C/A/H inputs,
commitments, physical usage, source, drain, health and observation age. Storage
observations expire after 15 seconds; heartbeat freshness alone cannot renew them.
A healthy zero cap admits no new roots but can still start a retained root when
live resources fit. A pool over its cap keeps its existing commitments.

**Drained** means zero live holds while host drain is enabled. Stopped/uncertain
roots and unfinished work can still block deletion indefinitely. Pool drain blocks
only new roots; global host drain also refuses cold starts. Host edit changes the
label only; configure budgets/pools in local TOML and reconnect to apply them.

Copied `host enroll`/`host run` commands need no capacity flags. The picker estimates joint
RAM/vCPU/disk fit from current discovery and an exact revision or explicit sizes;
the server rechecks authority, source and all resource dimensions on acceptance.
Admin observability remains metadata-only and exposes no guest execution authority.

## Node settings for agents and terminals

Open **Settings → Hosts → Details** for the node's **Agent access** card. It
shows the node-reported settings **Agents may run host commands** and **People
may open a host terminal**. Both are off by default. You can turn either off
from the dashboard or on the node. Raising must be done in a local login
session on the node. Dashboard lowering sets a durable server-side veto:
the node cannot undo it by reporting off or reconnecting. Every hello/report
that says on while vetoed receives another turn-off request. **Allow again**
is a person-only action that lifts the dashboard block only while the node is
online and its live report at the current epoch says the setting is off. It
does not turn the node setting on. If the node still reports on, first run
`wssp host config set-agent-host-commands off` or `wssp host config set-host-terminal off`
at the node and wait for its off report. The card warns if something on the node turned it back on
while vetoed. Lowering agent access cancels in-flight
host commands and pending file work; lowering terminals closes host PTYs.

**Trust model.** Agent host access means the agent can do what the wssp daemon
user can do. It is off until a person enables it at the node. Agent host
commands and host file tools run as the daemon user, an Incus admin: they can
reach every sandbox on this node, including other users' shared-pool
sandboxes. **Own sandboxes only does not limit host commands or host file
tools.** An agent with host commands can read the daemon's credential or edit
its config; the local raise gate and process-tree cleanup are best effort
against that uid. Cron jobs and systemd user units outside the tracked process
tree can survive lowering. Enable it only for agents you trust with that
account. The emergency stop is the dashboard veto plus credential revocation;
after an agent had host commands, audit the daemon user's
`~/.config/systemd/user` units and enabled links, crontab, wssp `config.toml`
and shell startup files (`.profile`, `.bashrc`, `.zshrc`) if you no longer
trust it.

Run these as the daemon user in a local login session on the node:

```sh
wssp host config set-agent-host-commands on
wssp host config set-host-command-max-time 600
wssp host config set-host-file-roots /srv/projects /home/operator/work
wssp host config set-host-terminal on
```

Use existing absolute directories you intend to expose for file roots. At most
32 roots are accepted, never `/`; no roots means file tools remain disabled.
The command time cap defaults to 600 seconds, with a range of 1–86400 seconds.
Enabling either setting, raising the cap or adding roots requires stdin and
stderr TTYs and typing `on`; there is no `--yes`. The environment variable
`WSSP_HOST_COMMAND` and `WSSP_HOST_TERMINAL` must be absent, and the process
must have no daemon ancestry. A startup
`wssp host run --host-terminal on` override uses the same gate. Revision latches
reduce accidental config changes; unreadable config fails closed.

Run the daemon as a service (a system or user unit) and raise settings from a
separate local login. A daemon started in the same terminal session or scope
as your shell makes the cgroup check refuse the raise. The marker, ancestry
and cgroup checks refuse the direct dashboard host-terminal/host-command case,
but are best effort against the daemon's own uid. A person or agent with host
execution can escape the process tree with `systemd-run --user`, `setsid`
followed by killing the supervisor, or cron, or edit `config.toml` directly.
These checks are not a kernel-enforced sandbox.

Lowering never prompts:

```sh
wssp host config set-agent-host-commands off
wssp host config set-host-command-max-time 60
wssp host config clear-host-file-roots
wssp host config set-host-terminal off
```

`set-host-file-roots` replaces the roots; removing roots also lowers access.
Sensitive daemon config/state, credential/journal keys and `/proc`, `/sys` and
`/dev` remain denied even inside a configured root. Host file reads and command
output are masked on the daemon before delivery. Audit records contain the
credential, node, program and a command/path HMAC, never command text or output.
Queued commands intentionally retain text for your review; see
[queued host commands](./terminal.md#queued-host-commands).

The API/MCP credential still needs `hosts:execute` or `hosts:files`, an owned
host grant and current account authority. Host access is allowed only on nodes
owned by that credential's own user, checked before server dispatch and again
by the daemon against the owner from `hello.ok`. Shared-pool access never
permits host access to someone else's node. These controls are independent of
guest command/file scopes and guest terminal attachment. See
[ADR-006](../design/adr-006-agent-host-access.md) for the decision and
[CLI reference](../../apps/cli/docs/cli-reference.md) for syntax.

## Requirements

Check these three first. A host that misses one connects but cannot run a
sandbox:

- **Linux with KVM** (x86_64 or aarch64), with `/dev/kvm` usable by the Incus
  daemon. Sandboxes are Incus `virtual-machine` instances only, never
  containers.
- **Incus 6.14 or newer with the `network_acl` API extension.** Every sandbox
  gets an enforced network policy (open internet by default, or an allowlist), so the daemon advertises egress
  enforcement only when the daemon proves support. Releases before 6.14 are
  refused: 6.12 and 6.13 accept the bridge anti-spoofing settings but cannot
  reliably enforce them (CVE-2025-52890), and no daemon reports a patched
  backport. On such a host the dashboard's host card shows **No egress
  enforcement**, the daemon log prints the version it found (`egress
  enforcement unavailable; this host cannot create sandboxes: incus 6.0.0 is
  older than 6.14 …`), and every create or cold start is refused with
  `UNSUPPORTED_CAPABILITY`. `GET /v1/hosts` reports it as
  `egressEnforcement: false`.

  Very large domain allow-lists need an `incus` CLI of 7.4 or newer on the
  host. Older clients can only pass the network update on the command line,
  so a create whose resolved domain records exceed about 96 KiB (roughly
  1,400 records) is refused instead of being partly applied. If a running
  sandbox's records grow past that limit, its DNS refresh fails and the
  grants it already has lapse at their normal expiry.
  Restart the node daemon after upgrading the Incus CLI to 7.4 or newer:
  inline-only detection is cached for the client's lifetime, shared by its
  clones. Until restart, the daemon keeps the inline query fallback and its
  size limit; allowlisted names and resolved addresses also remain visible
  in the query process's arguments to host users permitted to read them.
- **The `br_netfilter` kernel module, loaded and persisted, with
  `net.bridge.bridge-nf-call-ip6tables=1`.** Sandbox NICs set
  `security.ipv6_filtering`, which Incus cannot start without bridge
  netfilter. `wssp host run --runtime incus` checks for `/proc/sys/net/bridge`
  and that `bridge-nf-call-ip6tables` reads `1`, and refuses to start
  otherwise:

  ```sh
  sudo modprobe br_netfilter
  echo br_netfilter | sudo tee /etc/modules-load.d/wssp-br_netfilter.conf
  # only if the sysctl was turned off (the module loads it as 1):
  sudo sysctl -w net.bridge.bridge-nf-call-ip6tables=1
  echo net.bridge.bridge-nf-call-ip6tables=1 | sudo tee /etc/sysctl.d/90-wssp-bridge-nf.conf
  ```

  A first create whose start is definitely refused and whose VM is confirmed
  absent after cleanup fails with `sandbox_not_running`. Its dashboard error
  detail carries the Incus reason (the daemon logs it at error level too).
  A start whose outcome cannot be proven (the CLI lost its daemon connection,
  or the VM is in neither the Running nor the Stopped state afterwards) stays
  `unknown_outcome`.

  Before runtime execution, a refused create releases its live resources only with
  journal-proven first-attempt evidence and an observed absent VM. A refused
  first cold reconnect also releases when the VM is positively observed stopped:
  it issued no start, keeps its disk, and the sandbox stays STOPPED. A running VM,
  observation error, retry or ambiguous history stays `unknown_outcome`.
  Size/policy validation, journal-full and authority refusals use the same
  kind-specific observation. A full journal can prove a first attempt by reading
  retained history; conflicting lineage stays UNKNOWN. UnsupportedRuntime cannot
  observe existing VMs and therefore cannot prove absence or stopped state;
  its allocation refusals stay UNKNOWN. If the observation lane is saturated or
  closed, the host answers UNKNOWN immediately and continues serving the session.
  Refusal reports retain the server's owner, host, connection epoch and operation
  fences. An authority refusal because the host is shutting down or unavailable
  uses `host_effect_not_issued` only for a journal-proven first-claim
  create/reconnect refused before admission. Replays, uncertain lineage and other
  operation kinds retain `protocol_error`.

  A cold reconnect held UNKNOWN after a pre-admission refusal has no new host
  lease whose expiry can release it. A successful retry can resume the sandbox;
  destroy releases the reservation and deletes its disk. Warm reconnects can
  also release through a successful stop. First-attempt pre-runtime refusals
  with a stopped or absent VM use FAILED above and need no later convergence.

  On the relay, the server asks about held UNKNOWN allocations
  in pages of at most 256 sandbox ids, after an allocation UNKNOWN result, after
  reconciliation, and periodically while candidates exist. Negative answers
  back off the scan for at least ten minutes; a new committed UNKNOWN can
  immediately request its own id. Fresh allocation triggers are deduplicated
  in a bounded queue; overflow bypasses the negative cooldown for one scan,
  then resumes the ten-minute cooldown from the latest negative answer.
  Idle sessions park the timer. This exchange
  stays in the current session; terminals, transfers and other creates continue normally.
  The general census still contains only managed instances and leases.

  For each requested id, the host atomically checks its journal for leases,
  allocation receipts, workers and cleanup history before checking runtime
  existence. Only an id with none of those blockers and a confirmed absent VM
  is settled-never-issued. Runtime errors and untagged managed-name VMs with
  that id withhold proof for that id. Lifetime history is retained locally and
  looked up per id; it is never shipped in the census.

  Release additionally requires every prior allocation dispatch to have the
  same durable journal identity, and every dispatch in the current session to
  precede the request's monotonic barrier. Prepared but unsent dispatches,
  newer attempts, missing/pruned bindings, a replaced journal and older peers
  keep the hold. Old unacknowledged allocations become UNKNOWN after
  reconciliation and then use the targeted exchange. REQUESTED/SCHEDULED
  allocations refused before progress use the same rule.

  A proven never-issued allocation becomes FAILED with public error code
  `host_effect_not_issued`; the sandbox becomes ERROR and its live count and pinned
  RAM/vCPU are released once. A new generation fences late results. A late
  success that wins first keeps its reservation. After release, a contradictory
  present VM quarantines new host admissions without closing the session or
  blocking owner destroy. Destroy completion clears this quarantine in the same
  transaction once all contradictory auto-released placements on that host are
  retired. Other rows reported present in the current census keep quarantine,
  including during their teardown; absent auto-released rows do not. A later
  completed census recomputes quarantine from the contradictions it observes,
  replacing stale reasons from earlier sessions. Retirement clears quarantine
  only on hosts locked by that transaction; other hosts wait for their next
  census. On the retired placement's locked host, no reconnect is needed after
  the last contradictory placement reaches DELETED.
  Legacy ERROR/`instance_missing` rows retain normal
  recovery to STOPPED when their stopped VM reappears. The one automatic
  destroy is for a sandbox already DELETED whose VM the host still reports
  (`deleted_instance_present`): the sandbox stays DELETED and the host is
  neither quarantined nor disconnected, but the remnant's pinned RAM/vCPU is
  counted against that host again and one system destroy, fenced to the host,
  its epoch and a fresh sandbox generation, is queued to it. Repeated reports
  add nothing while that destroy is in flight; a failed or uncertain destroy is
  replaced on the next report. The charge is released only when the destroy
  succeeds or a later complete census no longer reports the VM. There is no
  other orphan-kill command. Reconnects use the same conservative proof; retained
  VMs, leases and history block it. Cold reconnect retains its existing
  completed host-lease-expiry release path. Other UNKNOWN holds require proven
  host expiry or explicit stop/kill/destroy.

  A positively refused create attempts to delete its bound, stopped VM and
  tear down its network. If VM deletion fails or absence is uncertain,
  the refusal stays `unknown_outcome` and retains its live resources; the stopped VM
  can remain until the sandbox is destroyed. The durable
  cleanup obligation covers the network: its drain still tears down the owned bridge and ACL
  and retires that obligation without retrying VM deletion; it does not release
  the UNKNOWN create hold.

**Ubuntu 24.04.** The archive's `incus` package is 6.0.0, which is too old.
Install the current stable Incus from the
[Zabbly repository](https://github.com/zabbly/incus) (the upstream
maintainers' packages), then check `incus version`:

```sh
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL https://pkgs.zabbly.com/key.asc -o /etc/apt/keyrings/zabbly.asc
sudo sh -c 'cat > /etc/apt/sources.list.d/zabbly-incus-stable.sources <<EOF
Enabled: yes
Types: deb
URIs: https://pkgs.zabbly.com/incus/stable
Suites: $(. /etc/os-release && echo ${VERSION_CODENAME})
Components: main
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/zabbly.asc
EOF'
sudo apt-get update && sudo apt-get install incus
```

Restart the daemon after upgrading Incus; the next connection advertises the
capability and the badge disappears.

The rest of the setup:

- **A user with access to the Incus daemon** that runs the daemon. The daemon
  creates and uses the Incus project `wssp` (override with `--incus-project` or
  `WSSP_INCUS_PROJECT`; `default` uses the default project directly). The
  project shares the `default` project's profiles and images. The `default`
  profile must hold only a root disk and one `eth0` NIC and no `config` keys;
  anything else fails preflight before a VM is created.
- **One `wssp` daemon per Incus server.** A host is one machine with one Incus
  server and one daemon. Two daemons on one Incus server share its image
  store and network namespace, so their image fingerprints and sandbox
  bridge names (`wsn-<id>`) collide. The daemon enforces exclusive ownership
  with a host marker. See
  [One daemon per Incus server](#one-daemon-per-incus-server).
- **The shared lock directory**, provisioned once by an administrator. Every
  daemon user that drives this Incus daemon must be in the group:

  ```sh
  sudo install -d -m 2770 -o root -g <daemon-users-group> /var/lib/wssp/incus-daemon-locks
  ```

  The daemon creates it (mode 2770) only when it does not exist yet and the
  daemon may create it, for example when run as root. It never repairs an
  existing one. A directory that is not a real directory, not owned by root
  or the daemon user, or not exactly mode 2770 is refused, and the error names
  it.
- **A private, durable data directory** on local storage with working file
  locks, atomic rename and fsync (the platform data directory, or
  `WSSP_DATA_DIR`). It holds the device credential, the receipt journal and
  lease checkpoints. Every directory the daemon creates under it is mode 0700
  and every file 0600, whatever the umask. A directory that already exists
  keeps its mode, so a `WSSP_DATA_DIR` you create yourself should be private
  too. Never delete it to "retry" something: losing it loses the local proof
  of what ran, and that work stays unknown on the server.
- At least one [template image](../operations/templates.md) prepared in the
  host's local Incus image store.

### One daemon per Incus server

`wssp host run --runtime incus` checks for another `wssp` daemon on its Incus
server before it touches Incus, and refuses to start while one is running.
This works whatever Unix user, data directory or control-plane URL each
daemon uses, because each daemon keeps a marker in Incus itself: a profile
named `wssp-daemon-lease-<n>-<id>` in the `default` project, where `<n>`
orders markers and `<id>` is random, so no name is ever reused. Its
`user.wssp.lease.*` keys name the daemon's host id, label, machine and pid,
and an expiry; the daemon replaces it with a fresh one every 15 seconds. A
marker stays live for 60 seconds. No credential is stored there. CLI
commands that only read Incus (`wssp host config show`, `wssp host images list`) never
check or write a marker.

The marker coordinates current `wssp` daemons; it cannot arbitrate unrelated
Incus users. Stop any other `wssp` daemon before starting the intended service
on that Incus server.

A refused start says which daemon holds the server and what to do:

```text
another wssp daemon already drives this Incus server: host `<id>` (label `<label>`, pid <pid> on `<machine>`). One wssp daemon per Incus server is supported ... Stop the other daemon ..., or, if it crashed, wait <N>s for its marker ... to expire, then start this daemon again
```

- **The other daemon is running.** Stop it (`systemctl --user stop
  wssp-host` as the user that runs it). A graceful stop releases its marker,
  so this daemon can start at once.
- **The other daemon crashed.** Its marker expires within 60 seconds of its
  last renewal; the message gives the remaining seconds. Under systemd,
  `Restart=always` retries on its own.
- **The same daemon restarts** on the same machine (same `/etc/machine-id`,
  host id and data directory) and takes its marker back at once, even after a
  crash: the data directory's lock proves the old process is gone. The same
  host id and paths on another machine wait for the expiry like any other
  daemon.

A running daemon is never stopped or replaced by another one. Two daemons
that start at the same moment cannot both start: each creates the next
numbered marker and then re-reads twice, two seconds apart; of markers with
the same number the lowest `<id>` stays and every other start backs off.
Markers are only ever created and deleted, never edited: every 15 seconds a
daemon creates a new numbered marker and then deletes at most two of its
older ones (it warns when they pile up), and a graceful stop deletes its
markers. At each renewal the daemon re-reads every
marker and decides from that read, whether or not its own write succeeded.

If a running daemon finds another daemon's live marker (for example one
started while the first could not reach Incus for over 60 seconds), it
reports guard reason `incus_server_shared` and follows one rule until the
other marker is gone: **no VM starts of any kind.** That covers new
sandboxes, starting a stopped sandbox (cold reconnect) and restoring a
sandbox from its own offload, plus image downloads, imports and template
captures, because a VM start is exactly what collides with the other daemon
(bridges, images). Running sandboxes, lease expiry, the journal, commands,
files and terminals on running sandboxes, and stopping and destroying
sandboxes all continue. A refused start is answered like an
[egress guard](#egress-guard) outage, so the server reports it and retries
it the same way. The daemon logs an error naming the other daemon at every
renewal and accepts new work again two minutes (two leases) after the last
read that showed the other daemon's marker.

Each read is judged at the moment it was sent, not when Incus answered,
and a renewal or start whose read and write take longer than 15 seconds
(a quarter lease) leaves the daemon's own claim unconfirmed, which also
stops VM starts until a faster renewal. A daemon stops VM starts the
moment any of its reads shows another daemon's live marker, before it
writes its own. Together this bounds detection: once two daemons both run
on one Incus server, each stops VM starts within the 15-second renewal
interval plus five Incus calls (a renewal makes at most two calls between
its two marker reads and three after them). That is about 16 seconds when
Incus answers promptly, 85 seconds when every call takes 14 seconds, and
never more than 90 seconds, because each call times out after 15 seconds.
It holds through Incus outages and pauses, with clocks up to a few
seconds apart.

A daemon that can still read the markers but can no longer write its own,
with no other live marker, stays admitted and logs a warning at each
renewal, as a start does for a client that may not write profiles. Another
daemon's expired marker is removed only after it has been expired for five
leases (five minutes), and only if a fresh read just before the delete
still shows it expired. Expiry compares wall clocks, so daemons on
different machines that point at one remote Incus server need synchronized
clocks.

If Incus cannot be reached at startup, the daemon does not start unchecked.
It exits with the error, and its service manager retries. If this Incus
client may not read or create profiles in the `default` project (HTTP 401 or
403, for example a restricted certificate or an `incus-user` project), the
daemon logs a warning that the check is unavailable and starts without it.
A restricted project normally keeps its own images and networks, so two
daemons there do not collide in the way this check guards against.

**Trust boundary and bogus markers.** The check trusts whoever may write
profiles in the `default` project. Such a user (or a `wssp` daemon on another
machine pointed at this Incus server) can plant a marker that keeps every
daemon from starting, or keeps a running one refusing new sandboxes,
indefinitely, for example with a far-future expiry, or with the highest
possible number (`wssp-daemon-lease-18446744073709551615-<id>`), after which no
daemon can create a newer marker; the error then names that profile. To recover, inspect the
markers and check each against the daemons you run:

```sh
incus profile list --project default | grep wssp-daemon-lease-
incus profile show wssp-daemon-lease-<n>-<id> --project default
```

The `user.wssp.lease.host_id`, `label`, `machine` and `pid` keys name the
daemon that wrote it: compare them with the host's id on the dashboard, the
daemon's `--label`, the machine's hostname and a running `wssp host run`
process there. A marker that names no daemon you run, or one whose daemon
is stopped, is bogus or stale. Delete it with
`incus profile delete wssp-daemon-lease-<n>-<id> --project default`. A running
daemon recovers at its next renewal (within 15 seconds), and a refused one
starts at its next retry. After you uninstall `wssp` you can remove a leftover
marker the same way.

**Test-only override.** The local chaos stack (`scripts/relay-chaos-live.ts`,
`scripts/offload-live.ts`) runs dedicated daemons beside `wssp-host` on one
machine. Those daemons set `WSSP_TEST_SHARED_INCUS=1`, which skips the check.
Only debug builds (`target/debug/wssp`) know the override; release builds
compile it out and never name it. A debug daemon accepts it only when its
control plane is loopback (`localhost`, 127.0.0.0/8 or `::1`), refuses to
start with any other value or server, and logs a `TEST-ONLY OVERRIDE`
warning at startup. Image fingerprints and bridge names can still collide
under it.

## Install

The CLI is Linux-only. After a public release, use the shell installer on
Linux in the [CLI README](../../apps/cli/README.md#install-after-release).
From source (Rust 1.99+):

```sh
cargo install --path apps/cli --bin wssp
```

## Enroll

**Device login (recommended).** The slug names the host in your account:

```sh
wssp host enroll --slug desk-01 --server https://api.example.com
wssp host run
```

`wssp host enroll` prints a verification URL and code and never opens a browser or
reads stdin. Open the URL while signed in to the dashboard, approve the
request (verified email and 2FA required), and the daemon stores one
`wssp_device_…` credential bound to that host. Approving a slug you have not
used yet creates the host.

**Dashboard host token.** Mint a token on **Host credentials** for an existing
host, put it in an environment variable named `WSSP_…`, and record the
variable name (the secret itself is never written to config):

```sh
export WSSP_HOST_TOKEN=wssp_host_…
wssp host enroll --token-env WSSP_HOST_TOKEN
wssp host run --server https://api.example.com --host-id <host-id>
```

A host token always needs `--host-id`. `wssp host run --host-token-env <VAR>`
selects a token explicitly for one run.

Until a machine is enrolled (no device credential and no recorded host token
variable), `wssp host --help` lists only `enroll`; `wssp host --help --all`
shows every host command. Hidden commands stay callable: only `wssp host run`,
`drain` and `undrain` need an enrollment (or an explicit `--host-token-env`)
and otherwise exit 6 with "this device is not an enrolled host; run `wssp host
enroll --slug <slug>` or `wssp host enroll --token-env <ENV>` (or pass
`--host-token-env`)". Node-local commands such as `wssp host config` (saved defaults like
the server and CA file) and `wssp host guard` work before enrollment.

Hosts must connect using the canonical server origin configured in
`BETTER_AUTH_URL` for environment-bearing work. Set `--server` (or the enrolled
server URL) to that origin, including its scheme and port. An alias such as
`127.0.0.1` when `BETTER_AUTH_URL` uses `localhost` fails the journal-key binding
check. The daemon logs a constant warning, installs no key and sends no key ACK.
The connection, reconciliation, inventory and key-free Kill / Stop cleanup
continue; environment-bearing and keyed work remain
refused until a valid key is installed on a connection to the canonical origin.

## Private certificate authorities

The dashboard's enrollment and per-host connect sections show an optional
`--ca-file <path>` note. Add it when the server uses a private CA, or set
`WSSP_CA_FILE` to the CA bundle path. A certificate-verification failure names
the server origin and points to both options. Check the hostname and certificate
validity as well: adding a trusted CA does not bypass either check.

`--ca-file <path>` adds every PEM certificate in a file to the default Mozilla
webpki roots for `wssp host run`, `wssp host enroll` (authorization and exchange),
`wssp host drain`, and `wssp host undrain`. Selection is **flag → `WSSP_CA_FILE` → saved
`ca_file`**. Certificate chains, expiry, and hostnames are always verified;
there is no insecure mode. HTTPS/WSS is required except for explicit loopback
development. A missing, unreadable, empty, malformed, or certificate-free file
stops the command; it never falls back to default trust. Use a PEM bundle
containing only PEM certificate blocks and whitespace.

On Unix, the CA file and its immediate parent directory must be owned by your
current user or root. Neither may be group- or world-writable: fix ownership
and run `chmod go-w /path/to/ca.pem /path/to/parent` if refused. Modes 0644 and
0600 are accepted. Copying a CA under umask 002 can produce a group-writable
0664 file; run `chmod 644 /path/to/ca.pem` (or `chmod go-w /path/to/ca.pem`)
after copying it. Symlinks are followed; these checks apply to the final
target and its parent. The loader checks the opened file and reads certificates
from that same handle. This applies equally to `--ca-file`, `WSSP_CA_FILE`, and
the saved `ca_file` setting. Keep local test roots in a private directory rather
than directly in a shared writable directory such as `/tmp`.

```sh
wssp host enroll --slug desk-01 --server https://api.internal.example --ca-file /etc/wssp/root-ca.pem
wssp host run
```

Successful device login with an explicit `--ca-file` saves its absolute path
alongside the canonical server URL. `WSSP_CA_FILE` applies only to that run,
including `host enroll`, and never becomes a saved default. An existing saved path
is retained when `host enroll` has no explicit CA flag. Saved files must remain readable
by the service user after restarts. To save a default explicitly:

```sh
wssp host config set-server https://api.internal.example
wssp host config set-ca-file /etc/wssp/root-ca.pem
wssp host config show
# To remove the saved extra trust (also unset WSSP_CA_FILE if set):
wssp host config clear-ca-file
```

The daemon loads the bundle at process startup and reuses it across reconnects;
restart after changing the file. Only the path and certificate count are logged.
Keep using the exact canonical origin in `BETTER_AUTH_URL`, including its port;
extra CA trust does not change the journal-key binding check.

### Local production-profile stack

Start `pnpm dev:docker 3200 --prod` in another terminal. The canonical origin is
`https://localhost:9300` (`3200 + 6100`), as configured by
[`docker-compose.agent.yml`](../../docker-compose.agent.yml) and
[`scripts/dev-docker.sh`](../../scripts/dev-docker.sh). Its `tls-proxy` service
runs Caddy with `--internal-certs`. Caddy stores the public root certificate at
`/data/caddy/pki/authorities/local/root.crt` inside that container; see
[Caddy's local HTTPS documentation](https://caddyserver.com/docs/running#local-https-with-docker).
Copy only the root certificate, using the project recorded by the stack:

```sh
TLS_PROJECT=$(node -p "JSON.parse(require('node:fs').readFileSync('.agent-ports.json', 'utf8')).project")
TLS_RUNTIME=$(node -p "JSON.parse(require('node:fs').readFileSync('.agent-ports.json', 'utf8')).runtime")
TLS_PROXY=$("$TLS_RUNTIME" ps --filter "label=com.docker.compose.project=$TLS_PROJECT" \
  --filter label=com.docker.compose.service=tls-proxy --format '{{.ID}}')
mkdir -p "$HOME/.config/wssp/local-tls"
chmod 700 "$HOME/.config/wssp/local-tls"
"$TLS_RUNTIME" cp "$TLS_PROXY:/data/caddy/pki/authorities/local/root.crt" "$HOME/.config/wssp/local-tls"/root.crt
wssp host enroll --slug local-host --server https://localhost:9300 --ca-file "$HOME/.config/wssp/local-tls"/root.crt
wssp host run --server https://localhost:9300 --ca-file "$HOME/.config/wssp/local-tls"/root.crt
```

For a different base port, use `https://localhost:<base-port + 6100>` in both
commands. With a dashboard token, select it with `wssp host enroll --token-env <ENV_VAR>`
and add `--host-id <host-id>` to `wssp host run`. The CA exists in the Caddy
container's data storage; copy the current root again if that storage is
replaced and Caddy generates a new CA. Browser trust is separate from CLI trust.
Do not substitute `127.0.0.1` or the cleartext backend port: that changes the
canonical binding and refuses environment-bearing work.

## Egress guard

Every host needs the **egress guard** before it can take sandboxes, in either
egress mode. Install it once per host, as root, after enrolling:

```sh
sudo wssp host guard install --daemon-user <user>
```

`<user>` is the unprivileged user that runs `wssp host run`. The command copies
the binary to `/usr/local/lib/wssp/wssp-guard`, writes `/etc/wssp/guard.toml`
and the `wssp-guard.service` systemd unit
([example](../../apps/cli/examples/wssp-guard.service)), creates an empty
`/etc/wssp/egress-blocklist` if there is none, starts the service and waits for
its first status. Re-running it upgrades the guard. Every directory it writes
into (`/usr/local/lib/wssp`, `/etc/wssp`, `/etc/systemd/system` and each parent
up to `/`) must be a real directory, owned by root and not group- or
world-writable; a symlink or a user-owned or writable directory refuses the
install before anything is written. Fix the directory, then re-run. On a first
install the guard holds sandbox forwarding until the daemon pushes the deployment
blocklist (start or restart `wssp host run`): the install prints "waiting for the
daemon's first deployment push", waits up to 10 s for it, and then shows the
status. Each install step is announced on stderr; a failure names the step it
stopped at and the steps already done, and the install ends by checking that
`wssp-guard.service` is enabled and active. If a step fails (for example
`systemctl daemon-reload`) or the install is interrupted after the new binary
and unit were written, systemd may still have the previous unit loaded and the
guard service can fail to start; re-run
`sudo wssp host guard install --daemon-user <user>` until it completes. A dropped terminal session does not
interrupt it, and re-running it is always safe. `wssp host enroll` prints this
command when the guard is not healthy, and `wssp host guard status [--json]` shows
the health lease, policy sources and bridges. The daemon never runs `sudo`.

**What it is.** The guard is the only WS Sandbox Proxy component that runs as root. It owns
one nftables table, `inet wssp_guard`, that contains **drops only**: the
protected ranges, every address of the host, its routed internal prefixes, and
the operator blocklist. It reads only root-owned files and its own socket, and
the daemon (checked by `SO_PEERCRED`) can only push the deployment-wide
blocklist, never remove a root entry. While healthy it also publishes that
same ceiling on its socket, so the daemon's own credential-proxy connections
obey it; an unhealthy or unreachable guard means no proxied connections. The
daemon itself stays unprivileged. See
[network egress](./network.md#what-is-always-blocked) for what the sandboxes
can and cannot reach.

**Dead-man.** The guard renews its rules every few seconds. Sandbox forwarding
exists only while it keeps renewing: if the service stops or hangs, forwarding
for sandbox bridges stops within **30 s**. The daemon treats a guard whose health
lease (15 s) is stale as unhealthy. A restarted guard leaves the loaded table as
it was and turns forwarding back on only after it has checked the host again;
it never reloads an older table.

**Quarantine.** When a check fails, the guard cuts sandbox forwarding in its
table at once and deletes the sandbox subnets' conntrack entries, retrying until
a follow-up listing succeeds and shows none left. If its table cannot stop the
traffic on its own, the guard also **takes every `wsn-*` sandbox bridge and its
ports down**: that covers an unsupported packet path (XDP and tc redirects
bypass every firewall), a packet path it could not check (a failed check or a
stopped change monitor; the links go down before the cleanup runs), a
quarantine table it could not verify, and a conntrack cleanup that has not
succeeded yet. VMs keep running but have no network. The guard records the links
it took down in `/var/lib/wssp-guard/fenced.json`. When the host checks healthy
again, and the cleanup has succeeded, it brings exactly those links back up
(matched by name and interface index) and restores forwarding. It never brings
up a link it did not take down. `wssp host guard status` lists the reasons, for
example `fenced_links:<n>`, `fence_unverified`, `conntrack_delete_failed` or
`conntrack_cleanup_unconfirmed`.

**No guard, no sandboxes.** A host whose guard is missing, outdated,
quarantined or stale takes no new sandboxes (create and cold reconnect fail
with `UNSUPPORTED_CAPABILITY`, reason `egress_guard_unavailable`), and the host
card shows the guard state. The same is true if the deployment blocklist is
invalid and the guard has no earlier valid one. Running sandboxes are not
deleted.

**`conntrack` package (required).** Install the `conntrack` tool (Debian/Ubuntu
package `conntrack`, on other distributions `conntrack-tools`). The guard turns
on sandbox forwarding only while it can run it. Without the tool, the guard is
quarantined with reason `conntrack_unavailable`, its sandbox bridges are taken
down, and the host takes no new sandboxes.

**Operator blocklist.** `/etc/wssp/egress-blocklist` is root-owned. One entry per line: an IPv4 CIDR (or a bare
address) or a domain name; `#` starts a comment; IPv6 entries are not accepted. At
most 4096 CIDRs and 2048 domains. Edits apply **live**: adding or removing a
CIDR takes effect on running sandboxes and cuts the matching flows; domain
entries apply to sandboxes created afterwards. A missing or invalid file keeps
the last valid content and makes the host unhealthy; only an existing empty
file clears it. The deployment-wide list
([`SANDBOX_EGRESS_BLOCKLIST`](../operations/environment-variables.md)) is
unioned with this file.

**Unsupported packet paths.** The guard checks that nothing can let a sandbox
packet skip or precede it. These make the host **unhealthy** (it takes no new
sandboxes and the guard quarantines): any nftables **flowtable** or flow
offload rule, in any family; another `ip`/`inet` base chain at or before the
guard's priority on prerouting, input or forward; a `netdev` chain, XDP program
or `ingress`/`clsact` qdisc on a sandbox bridge, its ports or an uplink; and any
`bridge` table other than Incus's own. The guard also takes the sandbox
bridges and ports down (see Quarantine). Remove the offending configuration,
then check `wssp host guard status`. Forwarding comes back on its own once the host
checks healthy.

**Uninstall.** `sudo wssp host guard uninstall` disables and stops the service and
confirms it stopped. It then empties the table's live set and reads it back, so
sandbox forwarding stops immediately. Only after both steps succeed does it
remove the binary, unit and `guard.toml`. If either step fails, it removes
nothing and reports the error. It keeps `/etc/wssp/egress-blocklist` and
`/var/lib/wssp-guard`. The `inet wssp_guard` table **stays loaded**, so the host
fails closed and takes no new sandboxes. Links the guard took down during a
quarantine stay down. Once no sandboxes run on the host, remove the table with:

```sh
sudo nft delete table inet wssp_guard
```

**Host egress settings** (saved in the host config, changed with `wssp host config`):

| Key                            | Command                                                                      | Default                  |
| ------------------------------ | ---------------------------------------------------------------------------- | ------------------------ |
| `allow_open_egress_for_others` | `set-open-egress-for-others on\|off` (also asked once by `wssp host enroll`) | off                      |
| `allow_guest_sudo_for_others`  | `set-allow-guest-sudo-for-others on\|off\|default`                           | on                       |
| `egress_block_smtp`            | `set-egress-block-smtp on\|off`                                              | on (tcp/25 blocked)      |
| `egress_block_external_dns`    | `set-egress-block-external-dns on\|off`                                      | off (direct DNS allowed) |
| `egress_dns_upstreams`         | `set-egress-dns-upstreams IP,...` or `--clear`                               | host resolvers           |

The last three apply to sandboxes created afterwards. See
[network egress](./network.md#other-users-hosts) for what each means.

**Guest sudo for other users' sandboxes.** `allow_guest_sudo_for_others`
(default **on**) lets sandboxes from other users' pools get
[`guestSudo`](./sandboxes.md#root-in-the-guest), root inside their own VM. Your
own sandboxes always can. Guest root does not change the host boundary (KVM,
the bridge ACL, the egress guard), but it lets the workload drive the guest
kernel, load guest drivers and replace the Incus guest agent, which widens the
QEMU device-model and agent-protocol surface this node exposes. If you take
foreign workloads and want only operator-chosen guest kernels and agents to
run, set it **off**. With it off, a foreign create gets no sudo (reason
`node_policy`), and an existing foreign sudo sandbox's next create or cold
reconnect here is refused with `guest_sudo_not_permitted` (the VM stays
stopped with its disk). Daemon recovery of a running VM does not re-check it.
A running daemon reloads the setting. The daemon advertises the `guestSudo`
capability; the server never sends guest privilege to a daemon without it.

### Host firewall (ufw/firewalld)

A host firewall that drops traffic by default (ufw with `DEFAULT_INPUT_POLICY="DROP"`,
firewalld's default zone, or Docker's `FORWARD` policy) also drops the
sandboxes' DHCP, DNS and forwarding on the `wsn-*` bridges. Without an
allow, a sandbox boots with no IPv4 address and no network.

The guard detects this: an `ip`/`inet` input or forward chain outside Incus's
table and its own that drops by default with no rule admitting `wsn*`
traffic. The host is then **unhealthy** with reason
`host_firewall_blocks_sandboxes` and takes no new sandboxes. `wssp host guard status`,
`wssp host enroll` and the host card show the reason and the fix. Sandbox readiness
also refuses a guest that has no IPv4 default route after 30 s
(`guest_network_unavailable`), so a create never reports READY without a network,
even with a firewall the guard cannot see (legacy iptables).

The fix allows only what the bridges need: DHCP (67/udp), DNS (53/udp and
tcp) and the login proxy (`credential_proxy_port`, default 48080/tcp) in from the
sandboxes, plus routing in and out of the bridges. It never allows everything
in on `wsn+`. The guard still enforces every block (protected ranges, the host's
own addresses, the blocklists) on top of these rules. Let the guard add them
(opt-in; each rule is printed before it is applied):

```sh
sudo wssp host guard install --daemon-user <user> --configure-ufw
# or, on firewalld hosts:
sudo wssp host guard install --daemon-user <user> --configure-firewalld
# if you changed the daemon's credential_proxy_port, add --credential-proxy-port <port>
```

`--configure-ufw` is idempotent. It skips rules that already exist. A broad
`ufw allow in on wsn+` is replaced by the tight set, and the install prints that
it is doing so. Every rule carries the comment `wssp-guard managed`.
`--configure-firewalld` creates a `wssp-guard` zone that holds `wsn+` with only those
ports open, and a `wssp-guard-out` policy (ingress zone `wssp-guard`, egress
`ANY`, target `ACCEPT`) that routes it out. It requires firewalld 1.0 or later,
and moves `wsn+` out of the `trusted` zone if it was there.
`--configure-firewalld` refuses with a clear message when firewalld is not
installed or not running (`firewall-cmd --state`). `--configure-ufw` does not
check that ufw is enabled: it refuses when ufw is not installed (or a `ufw`
command fails), but on an inactive ufw it still adds the rules, and they take
effect when ufw is enabled. To see whether ufw is enforcing rules, run
`sudo ufw status` (`Status: active`); `systemctl is-active ufw` reports only
the boot unit, which can be active while ufw itself is disabled.
`sudo wssp host guard uninstall --configure-ufw` removes every ufw rule tagged
`wssp-guard managed`, including the tagged rules install put in place of
untagged duplicates and of the broad rule; those originals are not restored.
`sudo wssp host guard uninstall --configure-firewalld` deletes the `wssp-guard` zone
and the `wssp-guard-out` policy; it does not move `wsn+` back into `trusted`.

To add the ufw rules yourself:

```sh
sudo ufw allow in on wsn+ to any port 67 proto udp
sudo ufw allow in on wsn+ to any port 53 proto udp
sudo ufw allow in on wsn+ to any port 53 proto tcp
sudo ufw allow in on wsn+ to any port 48080 proto tcp
sudo ufw route allow in on wsn+
sudo ufw route allow out on wsn+
```

With Docker, also allow the bridges in `DOCKER-USER`:
`sudo iptables -I DOCKER-USER -i wsn+ -j ACCEPT` and
`sudo iptables -I DOCKER-USER -o wsn+ -j ACCEPT`.

## Run as a service

Keep ExecStart as `wssp host run --runtime incus` with no capacity flags and
the existing credential/private-directory setup. Capacity flags are optional; storage is local TOML. Apply reviewed TOML
changes by reconnect/restart, retaining the same journal.

[`apps/cli/examples/wssp-host.service`](../../apps/cli/examples/wssp-host.service)
is a systemd **user** unit. Install the binary at `~/.local/bin/wssp`, enroll,
copy the unit into `~/.config/systemd/user/`, then:

```sh
systemctl --user daemon-reload
systemctl --user enable --now wssp-host
```

Ask the host administrator to enable lingering for that user if lease
enforcement must continue after you log out.

**Existing installs: update the unit.** The current example uses
`KillMode=mixed` and `TimeoutStopSec=75s`. With the old unit, `systemctl stop`
signals the whole control group at once and can cut the daemon's terminal and
relay cleanup short. It also sets `LimitCORE=0`, so a crash never writes a
core file holding [CLI-login](./cli-logins.md#security-model) values. Copy
the new unit and run `systemctl --user daemon-reload`.

A host on a release before `wssp host` must update its unit **before**
installing the new binary: set
`ExecStart=%h/.local/bin/wssp host run --runtime incus` (keep any existing
arguments) and `ExecReload=%h/.local/bin/wssp host daemon quiesce`, or copy
the current example, then run `systemctl --user daemon-reload`. Only then
install the new binary and reload or restart (see [Upgrades](#upgrades)). With
the old unit, the reload fails (`unrecognized subcommand 'daemon'`) and any
restart crash-loops on `unrecognized subcommand 'connect'`.

**Graceful reload.** The example unit sets
`ExecReload=%h/.local/bin/wssp host daemon quiesce`. `systemctl --user reload
wssp-host` then restarts the daemon without cutting off running commands:

1. The daemon stops taking new commands. The server keeps new
   `command.run` work queued for this host (nothing is refused or retried)
   and refuses new terminal sessions; other work keeps flowing.
2. Running commands finish, for at most `quiesce_max` (default `"10m"`,
   at most `"24h"`, in the host config TOML). A command still running at
   the cap is stopped, and the daemon logs how many there were.
3. The daemon closes its terminals and the relay normally, exits 0, and
   `Restart=always` starts the binary now on disk. The queued commands run
   on the new daemon.

An SDK `commands.start` or `commands.run` sent during a quiesce returns
only after the new daemon starts the command, because the call waits for
the guest to confirm the process started. Expect that call to take as
long as the drain: up to `quiesce_max` in the worst case, usually under a
minute.

A template build step waiting in the queue meanwhile does not spend its
build timeout (at most 60 minutes of credit per quiesce). A reconnect during those steps keeps the hold in place. If the server does
not acknowledge the quiesce within 30 seconds (an older server), the daemon
restarts at once, as `systemctl stop` would.

`wssp host daemon quiesce` signals the daemon only after it checks the daemon's
private control file, `<data>/relay/<host>/daemon.json`. The file must name
the same process (pid and start time), must not be a symlink, and must be
owned by you with mode 0600, and the process is pinned with a pidfd so a
reused pid is never signalled (a kernel without pidfds gets the SIGTERM
restart instead). Without that proof it sends SIGTERM to the
service's main process: an ordinary graceful restart. Run by hand
(`$MAINPID` unset), it needs `--pid <daemon pid>`, and it sends nothing
unless the control file verifies that pid.

The capacity settings are optional. The example's ExecStart stays
`wssp host run --runtime incus`; a service with no capacity flags uses detection
or saved TOML. Restart the service after changing saved overrides.

**Daemon log.** The daemon logs to stderr (the journal, under systemd). At the
default `info` level each host operation gets a `host operation started` line
and a finish line with its kind, operation and sandbox ids, outcome
(`succeeded`, `refused`, `failed`, `cancelled`, `unknown`), error code and
`duration_ms`. Lines never include command arguments, scripts, environment,
stdin, working directories, guest paths, file contents or credentials. Only
a lifecycle operation (create, reconnect, stop, kill) that did not succeed
adds the runtime reason. A refusal before any host effect, such as host
capacity, is a warning; a create or other lifecycle failure after the
runtime acted is an error; other failures and unknown outcomes are warnings.

## Stopping, signals and reconnects

- **SIGTERM or SIGINT** (`systemctl stop`, Ctrl-C) requests a graceful
  shutdown: every terminal session is closed with intent `shutdown` and
  reaped, the relay connection closes normally (1000), then the process dies
  from that same signal so the service manager sees it. The daemon never
  reconnects after a shutdown request.
- **SIGUSR1** (sent by `wssp host daemon quiesce`) starts a
  [graceful reload](#run-as-a-service) instead. It is not a shutdown
  signal: a SIGTERM or SIGINT during the quiesce still shuts down at once,
  as above.
- **A second signal**, or 60 seconds without finishing, exits at once.
  SIGKILL is the only way to stop the daemon without closing its terminals.
- **Connection setup is bounded.** The relay connect (name lookup, TCP, TLS
  and the WebSocket upgrade) gives up after 15 s, also against a server that
  sends its reply a byte at a time, and stops within about 100 ms of a
  shutdown request, so a stalled server cannot hold a stopping daemon.
- **Connection loss.** The first connect fails fast (bad URL, refusal,
  redirect, or the 15 s setup bound). Once a session has existed, a dropped
  connection or any server close other than 4003 (1000, no code, 1001, 1002,
  1008, 1011, 1013, or a code the daemon does not know) reconnects in-process
  with jittered backoff from 250 ms up to 30 s. A 1013 (try again later, for
  example the per-host connection limit) waits at least about 5 s, and a
  `Retry-After` on a refused reconnect (HTTP 429/503) is honoured, up to
  30 s. The daemon process never exits because the server closed the
  connection; only a credential failure or a local shutdown ends it. A
  server that falls behind on a host's frames stops reading that connection
  until it catches up (TCP backpressure) instead of closing it.
  Certificate verification failures on reconnect also back off, with
  the `--ca-file` / `WSSP_CA_FILE` hint; a first-connect failure exits.
  Restart the daemon after changing the CA file; it loads the bundle at startup.
  A credential failure (4003, or HTTP 401/403 at upgrade) ends the
  process with exit code 4; fix or replace the credential.
- **In-flight work survives a dropped connection.** When the transport is
  lost (a reset or half-closed socket, any server close but 4003, 30 s without any frame
  from the server, a write blocked for 30 s, or a reconnect that fails before
  the session starts), running commands and lifecycle work keep running. They
  are _detached_: nothing new is issued for them (a queued create or command
  waits before its first effect) and nothing is published until the reconnect
  _adopts_ them. Before `reconcile.complete`, the daemon sends one
  `operation.adopt` per carried attempt; the server re-binds the exact
  journaled attempt to the new connection only if it is still current (same
  generation and identity, not cancelled or superseded, sharing and placement
  unchanged, lease not expired, and, for work that never started, the same
  credential, egress and storage gates as a fresh dispatch). Two of those
  gates expire on the server 15 s after their last report: the egress-guard
  lease (`host.egress-state`) and storage health (`inventory.update`). A hello
  resets both, so the daemon reports them on the session's own cadence from
  `hello.ok` on, through reconciliation, and a create that never started (for
  example one still downloading its template image) is adopted however long
  the reconnect takes. Adopted work then
  delivers its output and result normally; a cancel requested while the host
  was away is delivered afterwards. Refused work is revoked and settles by its
  journaled receipt. Work the server sent that died with the connection is
  not lost either: on reconnect the daemon audits the server's unacknowledged
  attempts and proves, for an earlier connection it owned, that it never
  received them; the server then dispatches them again (or settles a
  cancelled one as cancelled) instead of reporting an unknown outcome. That
  redelivery is bounded: non-lifecycle work proven undelivered on its fifth
  attempt settles as `host_effect_not_issued` instead of being sent again. A
  dispatch that decodes but is invalid for its kind (a process identity or
  sizing field that does not match) is refused as that one operation with
  `protocol_error`; it never ends the relay session. Work
  the daemon received but could not carry settles as `host_effect_not_issued`,
  never `cancelled`. How long carried work survives is counted from the
  first drop of the outage (failed reconnects never move it); see
  [Carry window and cap](#carry-window-and-cap). In short: work that never
  started is revoked after `carry_intent_window` (default 10 min) or at the
  sandbox lease, whichever comes first, and settles `host_effect_not_issued`;
  a running command ends only by its own timeout (`timeout`), the lease
  (normal lease expiry) or `max_carry` (default 24 h), where the host stops it
  and reports `host_disconnect_expired`. While work is carried the daemon retries at
  least every second. Uploads still receiving bytes and downloads never
  survive a drop (terminals: see below). An upload the daemon proves it never started writing
  is sent again from the start (at most three times per upload) while the
  server still retains its committed bytes; otherwise it settles as
  `host_effect_not_issued`. A server verdict (`protocol.error`, which the server
  sends before closing, or 4003), a local protocol failure, a journal failure
  or a shutdown revokes in-flight work at once. The `rate_limited` refusal of
  an extra connection is not a verdict: it keeps the work carried.
- **Silent connections are dropped by the server.** The server pings every
  host connection every 15 s and ends one that sends nothing, neither a frame
  nor a pong, for 45 s (a half-open TCP connection), exactly like a transport
  loss. The clock stops while the server itself has paused reading that
  connection for backpressure. On startup, before it accepts connections, the
  server marks every host still recorded as connected by the previous process
  disconnected; a failure there fails startup.
- **Sandbox terminals wait for a reattach.** When the server answered
  `terminalResume`, a sandbox terminal whose connection dropped stays open for
  `terminal_resume_grace` (host config, for example `terminal_resume_grace =
  "5m"`; default 2 minutes, clamped to 1 s ..= 10 minutes; a restart applies
  it) so the browser can reattach to the same shell. While detached it keeps
  the last 256 KiB of output, accepts no input, and still closes at once on
  lease expiry, stop, kill, a newer generation or daemon shutdown. Detached
  terminals count toward the sandbox's limit of two live PTYs: a new terminal
  beyond it closes the oldest detached one, never an attached one. Host
  terminals never wait, and a daemon restart ends every terminal.
- **Leases keep running while disconnected.** Accepted sandbox deadlines are
  enforced locally (stop or destroy at expiry). A powered-off host or a
  stopped service cannot enforce anything: stop the guests before disabling
  the service. Incus autostart stays disabled for sandbox VMs.
- **File and process requests during a reconnect are queued, not refused.**
  Between a host's hello and its admission report (every relay reconnect,
  including each server restart) the host has not yet re-reported its runtime.
  File and process operations are accepted and queued; nothing is sent until
  the admission report arrives. Sandbox capabilities report
  `unavailableReason: "host_unavailable"` in that window. Only positive
  evidence for the current connection — a negotiated protocol other than the
  supported one, or an admitted runtime without file/process support — refuses
  with 400 `UNSUPPORTED_CAPABILITY` (capabilities: `unsupported_runtime`). If
  the admission report shows no support, the queued operation fails with
  `unsupported_capability`.
- **Environment-bearing work waits for the journal key.** Commands with env,
  sandboxes with private defaults and fresh launches are never accepted
  without the current connection's journal key ACK. For 30 s after a hello the
  missing ACK is answered with 503 `sandbox.host_reconnecting` (Retry-After
  1 s; nothing is stored, and the SDK retries under the same key). After that
  it is the permanent 409 `digest_key_unavailable` (see the canonical-origin
  note above).
- Exit codes: [CLI README](../../apps/cli/README.md#exit-codes).

## Capacity, drain and deletion

Revision defaults are 1 vCPU / 1024 MiB / 32 GiB. Create independently overrides
each dimension. CPU is 1–32; RAM 512–65536 MiB in 256-MiB steps; root size is
1–2048 GiB. Every start checks exact CPU/RAM and the original pool/marker/root
size. Images that do not fit fail rather than enlarging the root. Stop and cold
reconnect keep the same disk, size and identity on the host that holds the disk;
there is no resize or live migration. A stopped disk can move only through
[disk offload](#disk-offload-on-a-host).

### Guest RAM budget and CPU cap

Bare `wssp host run` inspects daemon CPU/RAM totals through bounded
`/1.0/resources` reads and caps RAM by kernel `/proc/meminfo` MemTotal.
Reserve max(4096 MiB, 25% of detected RAM),
then align the remainder down to 256 MiB (maximum 16777216 MiB). A 16-GiB host
gets 12288 MiB. The advertised maximum guest RAM is the budget minus the
320-MiB overhead, capped at 65536 MiB. Each live VM holds guest RAM + 320 MiB, independently of its
vCPU hold. Total vCPU defaults to detected threads × 2; per-VM CPU defaults to
min(32, threads). FakeRuntime uses 4096 MiB, four threads, eight total vCPU.

The 2026-11-01 six-VM qualification on a reference host (Incus 7.5, ~124 GiB /
32 threads) measured at most 67 MiB of QEMU private memory, about 9 MiB page
tables and 45 MiB slab per VM. The noisy host-wide upper estimate was 253 MiB
per VM; adding a 64-MiB boot/virtio margin and rounding up gives 320 MiB. PSS was unavailable. The worst desktop
baseline was about 9 GiB; the 25% reserve covers it plus variance and cache.
The 4096-MiB minimum is a conservative small-host policy, not a measurement.
Detection uses the lower of Incus installed memory and `/proc/meminfo` MemTotal.

Flags override TOML independently, then detection supplies omitted dimensions:
`--sandbox-memory-mib` / `sandbox_memory_mib`, `--sandbox-vcpu-budget` /
`sandbox_vcpu_budget` (1–8192), and `--max-sandbox-cpu-count` /
`max_sandbox_cpu_count` (1–32). Missing detection requires the corresponding
explicit overrides; diagnostics name the missing dimensions. Above-detection
overrides warn; the operator owns shared physical headroom. Avoid multiple daemons
on one daemon; if unavoidable split both RAM and aggregate vCPU budgets so their
sum fits one reviewed daemon budget. Projects do not partition hardware.

`wssp host config show --json` works without Incus and returns typed partial inspection,
sources and scalar diagnostics. It is read-only, never initializes markers, and
never guesses missing journal commitments or implicit ceilings. Connect recovers
the journal and pinned weights before hello. Server startup and admission rebuild
liveCount/RAM/vCPU and retained-root/pool counters under the host lock. Ordinary
reserve/release aborts mismatches rather than clamping or repairing them.

### Local storage budgets

Without a storage list use the audited profile-root pool; dir, lvm, zfs and btrfs
are supported when VM-capable. All use Incus pool resources, never host-path
statfs. Let T be total bytes, F free bytes, C retained root commitments,
A measured physical usage of charged roots (at most C, or zero if untrusted),
H = ceil(5% × T), B = floor(80% × T). The initial automatic cap is
floor(min(B, max(0, F + A − H)) / 2^30). Persist it as P before hello;
reconnect uses min(P, B, max(0, F + A − H)), rounded down to GiB and durably
lowers P. Never add C to free space: sparse unwritten commitments are already
free. Automatic caps cannot rise after reconnect, cleanup or config omission.
Caps/inputs freeze for the connection; polls update only health and usage.

Only an explicit TOML capacity can raise a cap. A nonempty list replaces the
implicit pool entirely (maximum 16); the daemon never creates pools or formats disks:

```toml
sandbox_memory_mib = 95232
sandbox_vcpu_budget = 64
max_sandbox_cpu_count = 32

[[storage_pools]]
name = "default"
capacity_gib = 96
draining = false

[[storage_pools]]
name = "wssp-capacity-test"
capacity_gib = 64
draining = false
```

The 160-GiB example fits below the observed 167-GiB automatic budget on the
reference host; recheck current shared backing free space. It cannot fit the
six-VM calibration's 198-GiB commitment without separately reviewed safe caps. Explicit caps are
1–1048576 GiB. Leave physical headroom for native image caches, marker and other
workloads; dir caps do not physically isolate storage. lvm/zfs/btrfs may keep
native optimized image volumes; dir has no artificial image cache/charge. Source
archives remain on the daemon filesystem; first-use unpack is create progress.
ENOSPC is a typed runtime failure, not a reason to silently enlarge a disk.

**Why an automatic cap can be far below free space.** P records the lowest
cap any connect ever derived for that pool marker, and nothing automatic
raises it. This is deliberate: after sparse roots are written, a cap
recomputed from free space would admit more than the disk can hold. A `dir`
pool shares the host filesystem (often `/`), so a single connect made while
that filesystem was briefly full (build caches, downloads, earlier test VMs)
keeps the automatic cap low after the space comes back. `wssp host config show
--json` shows it: a low `implicitCeilingGiB` next to a much larger
`totalBasedCapacityGiB` and `derivationFreeBytes` means P is stale, not that
the daemon read the wrong filesystem. To raise it, set an explicit cap for that
pool in `config.toml` and reconnect. For the implicit profile-root pool, use
the profile's pool name (usually `default`):

```toml
[[storage_pools]]
name = "default"
capacity_gib = 1000
```

Choose a value below the current free space minus the headroom you want to
keep for other workloads. An explicit cap is your decision: the daemon does
not check it against free space. Remove the entry to go back to the
automatic cap. The old P still applies then, because removing the entry does
not reset it.

**Capture needs about twice the root size.** A capture holds root + 1 GiB for
the capture VM's copy plus another root size for the published image, on the
source sandbox's pool, on top of the sandbox's own retained charge. A stopped
32-GiB sandbox therefore holds 33 GiB, and capturing it needs another 65 GiB
free in the pool's cap. With a 99-GiB cap that capture fits only while nothing
else on the pool holds disk. Any other 32-GiB sandbox makes it fail with
`sandbox.host_capacity` (`reason: disk`). The charge follows the sandbox's own
disk, not its template's default: a sandbox created at a template's minimum
(10 GiB for a build on the 8 GiB community base) holds 11 GiB stopped and
needs another 21 GiB to capture, and the resulting revision's minimum is
10 GiB.

Connect automatically creates and retains a 1-GiB filesystem custom volume
`wssp-pool-marker` in each configured pool/project. Its volume config ID and
versioned `/storage-id` backing file must match on every storage fence. The
project must own custom volumes (`features.storage.volumes=true`); insufficient
rights or incomplete/missing/swapped markers makes only that pool unavailable.
Creation races re-read the winner; no repair, takeover or metadata update occurs.
Never attach the marker to guests or delete it with a sandbox/config entry.
Restore the original marker/backing storage; missing evidence preserves holds.

New roots select the healthy non-draining pool with the most free committed
budget (marker breaks ties), and reserve root size + 1 GiB. Stopped/UNKNOWN roots
keep that charge and one of the fixed 250 retained/pending allocation positions
(stopped disks retain bridges). The guard is operational, not a user count cap.
Cold start adds no disk charge and bypasses pool cap/drain, but needs fresh
original-marker health and live RAM/vCPU/per-VM fit. Omitted pools cannot get
new roots; retained cleanup/start still needs original-storage proof.

Positive stopped proof frees liveCount and pinned RAM/vCPU once. Confirmed root
absence/deletion on the original healthy pool plus network cleanup frees the
retained disk/guard once. Timeouts, disconnects, missing pools and raw inventory
counts never prove absence. Startup/release use the boot's pinned charged weights,
including across RAM-policy changes; a new live hold uses current policy.

Fresh creates require current admission/census/key ACK and exact source
verification. Offline cold starts may queue against last stored live budgets;
known unavailable storage refuses. Warm renewal adds no hold. Capacity conflicts
are `sandbox.host_capacity` (pooled: `sandbox.pool_full`) with
`ram | vcpu | disk | storage | ceiling`; unsupported per-VM size remains
`sandbox.vm_size_unsupported`. Server and daemon enforce the same joint fit.
Pool placement prefers the requester's own member hosts (pool setting, on by
default), then the host with the lowest dominant share after placement (RAM,
vCPU or the chosen storage pool's committed GiB, whichever is fullest); see
[pool placement](./pools.md).

- `wssp host run --max-concurrent-commands <n>` bounds commands running across
  the host (default 16, range 1 to 256). Each sandbox may run at most 8
  commands at once, or the host limit when lower. Commands waiting for a slot
  start in FIFO order within each sandbox; the daemon serves sandbox queues
  round-robin. The host queues at most 16 commands; a full queue applies
  backpressure.
- Lifecycle work (create, reconnect/start, lease renewal and probe) uses a
  separate bounded pool with the same host concurrency limit. Different
  sandboxes can create and boot concurrently; operations for one sandbox
  start in FIFO order with at most one active at a time. Up to 16 lifecycle
  jobs may wait. Stop and kill have one additional reserved worker so commands,
  file work and queued boots do not consume the reserved cleanup worker.
  While that reserved worker is busy, an idle lifecycle worker also takes the
  next fresh stop or kill, so teardowns of different sandboxes run in parallel
  instead of queueing behind one another. The reserved worker remains the
  guaranteed lane: a teardown still runs when every other lifecycle worker is
  busy, and a single teardown never takes a create's slot. Resumed teardown
  retries run only on the reserved worker.
  Admission revokes older same-sandbox permits and interrupts readiness.
  Already-issued create init/config/network commands settle under the sandbox
  lock before teardown. Image initialization/unpack has a timeout of at least
  600 s so dir-pool unpack under IO pressure can finish. Other host calls use
  the Incus agent timeout (120 s by default via `WSSP_INCUS_AGENT_TIMEOUT_SECS`);
  ACL fence releases are capped at 5 s so a stalled release yields to expiry fencing.
  Grant withdrawals and additions retain their own budgets. Calls remain clamped
  by any remaining permit deadline, without a separate teardown settle deadline. That wait
  can delay other teardowns on the reserved worker. No subsequent create
  command may spawn after revocation.
  The interrupted create settles with an unknown outcome; teardown supplies
  its own stop/deletion proof. Other same-sandbox operation pairs retain FIFO
  ordering, and cancelled jobs ahead of teardown are refused in order. Live resource and retained-root budgets
  continue to bound create admission independently. File and other
  non-command work retains its separate work lane. Shutdown revokes permits,
  closes queues and drains completions within the existing five-second grace.
  UNKNOWN teardown is retried automatically in bounded cycles and on heartbeat
  or reconnect. At most two resumes are admitted per heartbeat into two
  additional queue positions; all 16 wire teardown positions remain available.
  Fresh wire teardowns are scheduled ahead of queued resumes. A running retry
  must finish its admitted host calls before fresh wire work can run.
  An uncertain create timeout or internal failure queues durable teardown;
  its capacity holds remain until the host proves VM and root absence.
  Known interim state: when the daemon is stopped (for example by SIGTERM)
  while an Incus create is in flight, the Incus daemon keeps creating the
  instance after the daemon exits. The restarted daemon settles that create as
  `unknown_outcome` and queues its teardown kill, but the kill cannot wait for
  the daemon's create: the per-sandbox lock that orders a kill after a create
  belongs to the old daemon process. Until the daemon finishes, the kill cannot
  prove the VM and root absent. After three quick tries it reports
  `unknown_outcome` and is retried on heartbeat until it succeeds. In live
  testing this took about 25 s (six retry rounds). An SDK `destroy()` waiting
  on that kill can therefore see `unknown` before the final `succeeded`. Keep
  polling the operation or the sandbox rather than treating that interim
  `unknown` as a failure. The VM, root disk and capacity holds are released
  only after the kill succeeds.
  Graceful stop holds the sandbox lock through its timeout plus five seconds
  of stop slack; sweeps and local expiry may wait for it. This serializes stop
  with other mutations. Stop never waits on those sweeps under the lock, and
  every CLI wait is bounded, so there is no lock cycle. A newly admitted wire kill revokes
  the stop permit, reaps its CLI and releases that lock promptly.
  Workers belong to the daemon process, not to one connection: a transport
  drop detaches their work for adoption (see _Stopping, signals and
  reconnects_), and only a revoking session end or process exit revokes it.
  Reconnect recovery never resumes a teardown or releases a retained root for
  a sandbox with carried or queued lifecycle work. A revoked worker may outlive
  the five-second revoke grace and overlap a resumed teardown in the next
  session: per-sandbox runtime serialization, idempotent stop/kill and journal
  terminal-result arbitration make that overlap safe.
  There is one residual daemon uncertainty: if init exceeds its settle bound,
  killing its CLI does not cancel the daemon task. Absence observed before
  that task inserts the instance is not an instance-creation fence; a stopped
  VM can appear later. Network/DNS tombstones do not fence instance creation.
  Operators should inspect Incus after a timed-out init; automatic instance
  tombstoning remains follow-up work.
- **Deployment caps.** An account may have at most
  `SANDBOX_MAX_HOSTS_PER_OWNER` hosts (default 20, counting hosts pending
  deletion). Creating or enrolling a host past it is refused: device-login
  approval says so in the browser, and `wssp host enroll` stops with a 409 naming
  the variable. Each host accepts at most `SANDBOX_MAX_SOCKETS_PER_HOST`
  concurrent daemon connections per server (default 2: one session plus one
  overlapping reconnect). An extra connection gets a `rate_limited` protocol
  error naming the limit and close 1013; the daemon logs it, keeps its
  running work carried, and retries after a longer backoff (at least about
  5 s). A self-hosted
  operator can raise both, or set the host cap to `unlimited`; see
  [environment variables](../operations/environment-variables.md#host-and-connection-caps).
- `wssp host drain` refuses new creates, cold starts and template registration on
  the host (`sandbox.host_draining`); running guests and their work continue.
  `wssp host undrain` restores admission. Both report the live sandbox count;
  `--json` prints it for scripts. `drained` is true only while draining with
  zero live reservations; an idle host with drain off reports false. Draining
  never stops a VM. A draining host is never a restore target.
- `wssp host drain --offload` (or the **Offload stopped sandboxes** switch in the
  dashboard's drain dialog) also empties the host of stopped disks: its
  stopped sandboxes are offloaded to the image store first, whatever their
  [offload policy](./sandboxes.md#offload-policy), and each cached
  copy is then evicted once another host the sandbox may use could restore
  it. An eviction is still refused while no such host exists, so that copy
  stays here. `wssp host undrain` clears the switch; `--offload` is refused with
  `wssp host undrain`.
- Deleting a host in the dashboard first marks it pending deletion: new
  creates, templates and enrollments are refused, while stop/destroy work,
  results and receipts still flow on its credentials. The host is removed once
  no live sandbox or unfinished work remains. Stopped disks with a stored
  copy detach to `OFFLOADED` once the host proves them gone; a disk that
  lives only on the host still blocks deletion. A state that does not allow
  deletion is refused with `sandbox.host_delete_conflict`.
- **Forget unreachable host** (dashboard only, owner session, type the slug
  to confirm) is for a host that will never come back: offline, stale,
  revoked or stuck pending deletion. A connected host with a fresh heartbeat
  is refused (`sandbox.host_delete_conflict`); delete it instead. Forget acts
  only on stopped sandboxes whose disk has a stored copy in the image store:
  each leaves the host as `OFFLOADED` (its next start restores it elsewhere)
  and the host's cached copies are forgotten. It is all or nothing: a
  sandbox that may still be running there (disconnected lifecycle work keeps
  running, a stopped daemon enforces nothing, and a revoked credential or a
  passed deadline is not proof) refuses the whole forget with
  `sandbox.host_forget_unsafe`, which lists up to 50 such sandbox ids;
  destroy them, let their work settle, or bring the host back. Forget never
  deletes a sandbox and never boots a second copy. Sandboxes without a
  stored copy, and unfinished work, keep the host pending deletion as before.

## Upgrades

Deploy matching schema, server, worker, CLI and SDK builds. Preserve host
journals and pinned disk identities across upgrades. Resolve uncertain work
through supported recovery before retiring a host or its state directory.
Service units need no mandatory capacity flags. Complete
[capacity and storage qualification](#capacity-and-storage-qualification)
before production.

**Upgrading from a release before `wssp host`.** Update the user unit first:
`ExecStart=%h/.local/bin/wssp host run --runtime incus` (keep any existing
arguments) and `ExecReload=%h/.local/bin/wssp host daemon quiesce`, or copy
the current [example](../../apps/cli/examples/wssp-host.service); run
`systemctl --user daemon-reload`; then install the new binary and reload or
restart as below. With the old unit, the reload fails (`unrecognized
subcommand 'daemon'`) and any restart crash-loops on `unrecognized subcommand
'connect'`. The root guard keeps working on its old copy: it is a separate
binary under `/usr/local/lib/wssp/` and its socket protocol is unchanged.
Re-running `sudo wssp host guard install --daemon-user <user>` later upgrades
it and rewrites the guard unit to the new `__wssp-guard` entry.

Check for systemd drop-ins too: a file under
`~/.config/systemd/user/wssp-host.service.d/` that sets `ExecStart=` (or
`ExecReload=`) overrides the unit and still runs the old command line. Edit
each one the same way (`systemctl --user cat wssp-host` lists the unit and
every drop-in), then run `systemctl --user daemon-reload`.

**Upgrading a running host.** Install the new binary, then run
`systemctl --user reload wssp-host` (the example unit's `ExecReload` runs
`wssp host daemon quiesce`). Running commands finish first, for at most
`quiesce_max`, and new ones wait in the server queue until the new daemon
connects. Two limits apply:

- Without a usable control file, quiesce falls back to SIGTERM; running
  commands may stop. Preserve journals and reconcile uncertain outcomes.
- A command longer than `quiesce_max` is stopped at restart.

Relay protocol 1.0 requires the full capability set. Deploy matching artifacts;
unsupported versions/capabilities are refused, with no downgraded hello retry.

For maintenance (a reboot, an Incus upgrade), drain first so no new sandbox
lands here, then reload: `wssp host drain`, then
`systemctl --user reload wssp-host`. Drain is a persistent placement policy;
quiesce is transient and holds only new commands.

Reconnect adoption (`operation.adopt`) retains carried work only after the
server validates its exact identity. Server verdicts and journal-write failure
revoke carried authority; a transient disconnect preserves it for reconciliation.

## Rotating host credentials

See [rotating credentials](./auth-planes.md#rotating-credentials). In short:
enroll the replacement (new device login or new token), restart the daemon on
it, then revoke the old credential on **Host credentials**; a live connection
on a revoked credential closes with 4003.

## Release notes for operators

Version 1.0.0 uses one strict relay contract. Preserve private state (directories
0700, files 0600), the documented systemd service settings, host journals and
pinned disk identities. The node requires current storage/guard observations;
reconnect census and expiry results are fenced per entry. Command output chunks
are negotiated up to 64 KiB. UNKNOWN receipts retire only with exact proof and
never cause automatic command replay.

- **Unknown commands on a running VM: per-command guest scopes.** Every
  command now runs in its own root-owned systemd scope,
  `wssp.slice/wssp-cmd-<operation>-<generation>-<attempt>.scope`, so guest
  `system.slice` resource settings no longer apply to commands. When the
  host loses track of a command, a root helper (pushed by the host for each
  check, never stored in the image) reads that scope:
  - **Gone or empty:** the receipt retires while the VM keeps running. Gone
    means every process the command started (including detached `setsid`
    descendants) has exited and no cgroup owned by the guest user is still
    running. Work the command handed to another process over IPC is not
    tracked.
  - **Still running and due:** the host kills the whole scope with
    `cgroup.kill`, then retires the receipt. A command is due after a cancel,
    after a stop the host could not prove, or once its `timeoutMs` budget
    plus about 20 s has passed on the guest's monotonic clock (time the guest
    spends suspended does not count). A command with `timeoutMs: 0` is never
    killed this way.
  - **Still running, not due:** the receipt is kept and checked again while
    the host stays connected: about every 15 s at most across the host's
    retries, with a backoff from 30 s up to 10 min for a command without a
    budget. Otherwise the check runs at the next reconnect. With many due
    commands, a kill can wait about 15 s for each due retry ahead of it.
    Fresh checks at a reconnect are not paced: up to 64 can queue behind the
    host's single observation worker (at most about 5 s each), which also
    classifies dispatch allocation refusals, so those may wait up to 40 s.

  Requirements: systemd 254 or newer as PID 1, cgroup v2, and Linux 5.14 or
  newer for the kill (`cgroup.kill`; without it a due command is kept). A
  command that could not run in its scope (older systemd, the 2 s
  `systemd-run --version` probe timed out, or a `Slice=` drop-in moved it)
  first writes the per-boot marker `/run/wssp/unscoped`; for the rest of that
  boot only the old proofs apply. If that marker cannot be written (for
  example `/run/wssp` is not a root-owned directory without group or world
  write, `/run` is read-only, or it is full), the command fails before it
  starts instead of running unscoped. A guest whose user lingers with
  running user services (`loginctl enable-linger`), or whose template
  defines delegated units for the guest user, never retires on a running
  VM: a running cgroup owned by the guest user blocks the proof. Lingering
  guests also lose the reboot proof while the VM runs. The host journals
  each command's start (one extra fsync per command), with the VM's QEMU
  identity (pid and start time from the host's `/proc`, after its `-name`
  argument named the instance; a later, different identity proves the
  command gone for any sandbox); a failure of that
  write latches the journal like any other write, while the command keeps
  running.
- **Guest sudo and host-proof retirement.** The hello offers `guestSudo`; `host.egress-state` carries
  `allowGuestSudoForOthers`. For a `guestRoot` sandbox the daemon trusts no
  guest-side proof: an UNKNOWN command retires only when the VM is stopped or
  absent or its QEMU process changed. Unproven entries park (a due kill still
  runs once), are rechecked from the host only every 120 s, and re-arm on a
  stop, kill, reconnect, create or probe. A guest reboot may keep the same
  QEMU process, so stop the sandbox to free them reliably. Host-proof entries
  hold at most 4 per sandbox, 8 per owner and 16 per node of the 64 retirement
  slots. Every sandbox now holds at most `max(64, max_concurrent_commands)`
  unfinished command receipts (`host_capacity`, reason `sandbox_receipts`).
  Unsupported or corrupt journal records fail closed.
- **Layered lease policy.** Every accepted host advertises its lease ceiling
  and reports policy changes. The server combines deployment, host, pool and
  membership limits; every lease pull-in is shorten-only. Ship matching SDK,
  daemon, server and worker artifacts.

Retained sandbox authority names the exact
revision and the sandbox's current host (or, while offloaded, the host it last
ran on); cold reconnect and restore keep the pinned configuration.

Drain applies to every pool containing the host; undrain restores eligibility without a restart when admission and exact revision evidence are current. See [host pools](./pools.md).

## Images and pool membership

Pool membership is independent of template verification. After adding a host
on **Pools → Members**, verify each exact image from **Templates → Manage
revision**, or let image distribution fetch it at create time (see
[image cache](#image-cache)). Only the node daemon talks to Incus; the control
plane never calls Incus. Drain skips that host for all future placements,
including overlapping pools, without moving accepted sandboxes. Disabling a
member affects that pool alone. Cold reconnect boots the sandbox's disk on
the host that holds it and ignores the cached source image; it still needs
current host admission and capacity. An offloaded disk restores onto an
eligible host instead ([disk offload](#disk-offload-on-a-host)). See [pool recovery](./pools.md#choosing-a-recovery-action).

## Image cache

The daemon keeps a managed cache of template images it fetched or captured
(docs/operations/templates.md#image-distribution). Configure it in the host
config (TOML; a restart applies changes):

```toml
image_cache_gib = "auto"        # min(100 GiB, 15% of the largest pool); 0 turns fetch, serve and capture off
accept_foreign_images = false   # other accounts' images (shared pools); see the qualification note below
foreign_image_grace = "10m"     # keep another account's image this long after its last use (0..24h)
# builder = false               # opt out of template builds (default: on while the cache is enabled)
accept_foreign_builds = false   # run template builds for other accounts (shared pools); needs accept_foreign_images
```

The [graceful reload](#run-as-a-service) has one key in the same file:

```toml
quiesce_max = "10m"             # wait for running commands before a reload restarts (0..24h)
```

- **What counts against `image_cache_gib`.** Managed images, plus the
  daemon's staging: a download's `.part` file is reserved at its full size
  before the first byte is written, and so is an export for serving or
  uploading. A new capture is admitted like a download (least recently used
  images are evicted to fit it; if it cannot fit, the capture fails and its
  image is deleted). Staging left behind by an interrupted download or
  export keeps counting until it is resumed or, after 24 hours unused,
  removed.

- **Shared image store.** The `wssp` project shares the `default` project's
  image store (`features.images=false`), so every daemon on one Incus daemon
  sees the same images. The daemon manages only images it imported or
  published itself; operator images are never evicted. An image with an
  alias, or the base image of any instance in any project, is never evicted.
- **Accounting.** The cache budget (compressed bytes plus staging) is carved
  out of every configured storage pool's derived capacity at connect, frozen
  like the other derivation inputs, so placement never counts it as free.
- **Eviction.** Least recently used first, never an image in use (an
  in-flight create, capture or serve) and never a capture's origin pin: the
  only copy stays until the server reports it stored in the image store.
  In peer mode (no image store) nothing is ever stored, so the capturing
  host keeps its captures pinned for as long as their revision lives, even
  when other hosts have fetched copies: a fetched copy is an evictable cache
  entry, never a second durable copy, and releasing the origin on its
  strength could lose the image everywhere. This is by design: in peer mode
  the capturing host is the image's home, so `prune` never frees the
  capture of a live revision. Once nothing needs the image any more (every
  revision using it retired, no sandbox or unfinished build on it, no fetch
  or capture in progress), the server releases the origin pin and the daemon
  evicts it, as it does for a capture that never became a revision (such
  as one a build cancel overtook while it was still running: the cancel
  wins, and the host's image is released as soon as its result arrives). Use
  the S3 image store when captures should leave the host.
  `wssp host images list [--json]` shows the cache (it first asks the running
  daemon to drop entries for images deleted from Incus out of band, waiting up
  to 8 s; the daemon also does this every minute and re-sends its cache census
  every 10 minutes); `wssp host images prune
  [--dry-run] [--json]` asks the running daemon to evict every unpinned,
  unused image (fetched copies, and in S3 mode stored captures), never a
  pinned capture.
- **Capture** needs copy-on-write storage (btrfs, ZFS, LVM-thin) for a
  running sandbox; a stopped sandbox can be captured on `dir`. Templates
  without cloud-init must regenerate SSH host keys at boot (capture removes them).
  The capture VM boots without a network device; its scrub freezes every
  guest task first with the cgroup v2 freezer (PID 1 included, so nothing can
  resume a workload), scrubs (cloud-init state included, removed directly:
  `cloud-init clean` and its guest hooks never run), syncs and verifies while
  frozen, executes nothing from the guest after the freeze, and the VM is
  then powered off, not shut down. A guest without cgroup v2 fails the
  capture. The scrub uses the guest's own kernel, `python3` and agent: it
  guards against ordinary concurrent workloads, not against hostile code with
  root in the guest or a template whose kernel, agent or interpreter were
  tampered with (see docs/operations/templates.md).
- **Foreign images and Incus confinement.** `incus image import` runs in the
  Incus daemon, and Incus 7.5.1 accepts crafted images (a qcow2
  `backing_file` or external data file pointing at a host path, tar entries
  with `..`, a symlink and a device node). The daemon validates every image
  before it imports it and refuses anything but the unified VM layout. With
  `accept_foreign_images = false` (the default) it also refuses to fetch
  another account's image at all, whatever the server plans. Keep it `false`
  until you have run the crafted-import qualification on your Incus version;
  see [foreign-image qualification](../operations/templates.md#foreign-image-qualification).
- **Template builds.** A capture-capable host runs build VMs unless
  `builder = false` (`wssp host config set-builder off`; `default` restores the
  default). Build steps may run as **guest root**, but only inside build
  VMs: the daemon admits a root step or a COPY step only for a sandbox whose
  journaled create carried a build id, and such a sandbox refuses
  reconnect, terminals, process signals and every file operation except
  the upload of its own build context. Every other command, file and
  terminal runs as the template's declared guest user. COPY runs a fixed
  helper that opens the context once with `O_NOFOLLOW`, checks its sha256
  and refuses absolute or `..` names, devices, escaping symlinks and
  hardlinks before writing anything. `accept_foreign_builds`
  (`wssp host config set-accept-foreign-builds on`) also runs builds for other
  accounts. A restart applies both.
- **Community bases (upstream images).** The first build of a community
  template (for example Ubuntu 26.04) boots the distribution's raw cloud
  image. The control plane pins it from the simplestreams index (the path,
  sha256 and size of `incus.tar.xz` and `disk.qcow2`, and the combined
  fingerprint) and plans it on that build VM's create only. The builder
  then downloads it itself:
  - **Outbound 443 to `https://images.linuxcontainers.org/` only.** The
    host is compiled into the daemon. Paths must sit under `images/` and
    both files must share one directory. The TLS trust is the built-in
    webpki roots only (no `WSSP_CA_FILE`), and redirects are never
    followed. A builder behind an egress allowlist needs that host.
  - **Verification.** The daemon checks each file's size and sha256, then
    the combined fingerprint. It validates both files before any import:
    the metadata unpacks to at most 4 MiB, holds no links, devices or
    traversal, and names no Incus launch-config property prefix (no
    exemptions, not even WS Sandbox Proxy's own). The disk must be a qcow2 with no
    backing or data file and at most 32 GiB of virtual size.
  - **Import.** The daemon imports `incus image import <meta> <disk>` into
    its configured Incus project. With `features.images=true` the image
    lands in that project's own store. It then compares the imported
    fingerprint with the pinned one and deletes the image on a mismatch.
  - **Accounting.** Each file has its own staging entry and reservation
    (`<hex>.meta.part`, `<hex>.disk.part`), charged at full size before the
    first byte, and each resumes with an HTTP range (a `200` answer restarts
    the file). The image is then a managed fetched image like any other,
    charged at the two files' combined size. One download serves concurrent
    creates.
  - **Failures.** An upstream `404`, `410` or redirect is
    `image_unavailable`. A size or hash mismatch is `image_corrupt`. A
    validation or post-import refusal is `image_rejected`, logged with its
    fixed reason.
  - **The foreign gate applies.** With `accept_foreign_images = false`, the
    daemon never downloads a community base for another account's build.
  - **Bootstrap readiness.** The raw image does not carry the template's
    declared guest user yet, so that one build VM boots with bootstrap
    readiness. The daemon trusts the dispatch's `build.bootstrap` flag for
    this: the server sets it only on its own community prep build, and the
    daemon accepts it only on a create dispatch that carries a build, with
    builds enabled, never on a reconnect. The flag grants no root step, COPY
    or file access.
  - **What bootstrap readiness checks.** It runs the same restart-tolerant
    pass as standard readiness (agent wait, binding and architecture
    checks, guest sudo revoke, network), so the image's first-boot reboot is
    tolerated. It replaces the identity script and the repo check with a
    boot settle: `systemctl is-system-running --wait`, run as the declared
    uid with cwd `/`, must answer `running` or `degraded`. Any other answer
    re-runs the pass, up to the restart bound. The pass gets at least 300 s
    (or `WSSP_INCUS_AGENT_TIMEOUT_SECS`, when larger): the first boot of a
    raw upstream image runs cloud-init and reboots once, which can take
    minutes on a busy host.
  - **Daemon restarts.** The mode is persisted with the VM's readiness
    metadata, so recovery and probes after a restart use it too. Every
    other create, and every reconnect, gets standard readiness, which
    refuses the raw image's identity.
- **Relayed copies** use `https://<server>/host/image-relay/v1/parts/<link>`
  with the host credential in `Authorization` and a one-time link token in
  `X-Wssp-Image-Link`.
- **Capture uploads (S3 mode).** The daemon PUTs each part to its presigned
  URL. Parts are whole 1 MiB records, `max(16, ceil(records / 10 000))` of
  them: 16 MiB for any image up to about 156 GiB, larger only as needed to
  stay within S3's 10 000 parts (105 MiB at the 1 TiB maximum). A socket read
  or write that moves no byte for 120 s fails the attempt (`stalled`); a slow
  upload that keeps moving never fails for slowness down to a floor of
  16 KiB per 10 minutes (about 27 B/s: progress is counted per 16 KiB
  socket chunk, and the server ends an upload with no progress for
  10 minutes `upload_stalled`), and the response to a
  part is awaited up to 300 s (the last bytes may still be draining from the
  kernel buffer).
  - **Retries.** Each part gets up to 4 attempts, 2, 8 and 30 s apart (plus
    up to 25 % jitter), for `timeout`, `stalled`, `reset`, `connect` and
    store answers 5xx, 408 and 429; every other failure is final at once. A
    403 gets one fresh URL (below) and one more try. Each retry is logged as
    `image store part upload retrying` (cause, `io_kind`, `http_status`,
    part, attempt). The upload is never restarted as a whole: a part that
    still fails ends it.
  - **URLs are pulled.** The first grant names up to 64 parts; the daemon
    asks for fresh ones (`image.upload.renew`) when it has used them up or
    the next URL has less than 60 s left (at most half the URL lifetime,
    judged on the host's own clock), after reporting the parts it uploaded.
    Uploaded parts are reported every 16 parts, every 30 s and before each
    renew. A URL's lifetime counts from when its grant arrived. A presign
    lifetime of `IMAGE_S3_PRESIGN_TTL_SECONDS` (default 600 s) therefore
    only has to cover one part.
  - **Busy server.** Over the host's image grant budget the server drops a
    parts report, heartbeat or renew without answering: the daemon asks
    again (5, 15, 30, 60 s, then every 60 s, up to 180 s for a renew) and
    reports a part again when a renewed grant names it; the server logs the
    first such drop of each transfer. A capture's begin refused
    `rate_limited`, `artifact_deleting` or `store_unavailable` is sent again
    after 5, 15, 30 and 60 s (within 3 minutes of the first refusal, however
    late in the first wait it came, a resume wait in between included), then
    reported `refused` with that reason. A publish begin is not sent again: the publish ends with the
    refusal and the server's backfill asks for it later.
  - **Relay reconnects.** A capture or publish upload survives a relay
    reconnect: the new connection first sends `image.job.resume` for it (by
    operation before its first grant), and once the server answers
    `continue` the daemon renews its URLs from the server's lowest
    unrecorded part and goes on (`refused` + `stale_transfer` otherwise).
    Waits do not run down while the relay is down, and a failure that
    happened meanwhile is sent, with its cause, after the resume; so is a
    failure or completion whose socket write or flush failed (it counts as
    sent only once written and flushed), with the parts reports and
    heartbeats of that write; its other frames (begins, census pages, disk
    offload frames) are not sent again. A resume wait inside a renew or a begin retry spends that
    wait's own budget, never one of its own.
  - Every failure is logged as `image store part upload failed` / `image
    upload ended` with its cause, `io_kind`, `http_status`, part and attempt,
    never a URL or header, and is reported to the server, which fails the
    capture at once with that cause (see docs/operations/templates.md#capture).

  Troubleshooting:
  - **Slow uplinks.** At 120 KB/s a 16 MiB part, the smallest this daemon
    sends, takes about 140 s. The S3 endpoint must not sit behind a proxy
    with a short request-body timeout (for example Traefik's
    `respondingTimeouts.readTimeout`, 60 s by default): such a timeout fails
    every part (even S3's 5 MiB minimum needs about 44 s at that rate). `stalled` or `reset` at about the same
    point on every attempt means something between the host and the store
    cuts long request bodies; serve the S3 endpoint without such a timeout.
  - `url_expired`: the store answered 403 after the URL's lifetime had run
    out on the host's clock, so the part took longer than its URL lived:
    raise `IMAGE_S3_PRESIGN_TTL_SECONDS` above the time one part takes.
  - `http_status` 403 after the renewed try (a fresh URL, not past its
    lifetime): the store refuses the URL itself (clock skew between the
    server and the store, a revoked key or a bucket policy), not its age.
  - `connect` or `tls` after every attempt: the host cannot reach the store,
    or does not trust its certificate (`WSSP_CA_FILE`).
  - `export`: the published image could not be exported from Incus (disk
    full, or a split image).
  - A daemon restart mid-upload is not resumed: the server fails the
    capture (`upload_lost`); capture again.

### Disk offload on a host

With the S3 image store and `DATA_ENCRYPTION_KEY` configured, the daemon
offloads stopped sandbox disks ([sandboxes](./sandboxes.md#disk-offload)).
Only daemons that advertise disk offload receive offload, evict or restore
work; a daemon missing required capabilities is never a restore target.

```toml
offload_upload_mbps = 0   # cap offload uploads (0 = unlimited)
offload_fetch_mbps = 0    # cap restore downloads (0 = unlimited)
```

- **Export.** After a stop, once the sandbox's offload policy makes it due
  (at once by default; see
  [offload policy](./sandboxes.md#offload-policy)), or earlier when this
  host needs the space, the daemon publishes the stopped VM to a
  temporary image (`wssp-off-<hostTag>-<offloadId>`, the tag derived from
  this host's id), encrypts it record by record with
  the upload's key and uploads it. One export runs per host and two per
  account. Staging is reserved against `image_cache_gib` (about twice the
  used disk, at most twice the sandbox's `diskGiB`); if it does not fit, the
  offload fails and the disk stays local.
- **Plaintext on this host.** The temporary image and the staged export are
  plaintext copies of the whole root disk, on this host only. They are
  deleted once the server confirms the copy is stored, when the offload
  fails or is superseded, and after a crash by the start-up sweep (which
  removes this host's own `wssp-off-<hostTag>-*` images the journal
  `disk-offload.json` does not name; another daemon's images in the shared
  Incus image store, and untagged ones, are kept and logged). The 24-hour staging sweep is the backstop. Keep the image store
  and staging on encrypted storage.
- **Eviction.** Under cache pressure (its storage pool at least 90% full)
  the daemon asks to evict the least recently used stored disk; at the same
  threshold the server also exports stopped disks whose offload policy
  would otherwise keep them here; the server grants it only when the sandbox is
  idle and another eligible restore host exists. The daemon deletes the VM,
  proves the root volume is gone, and the sandbox becomes `OFFLOADED`. A
  start during eviction is refused `sandbox.disk_evicting` (retryable).
- **Restore.** The daemon fetches the encrypted disk, checks its hash,
  validates the image (always, even from your own account), imports it into
  staging, creates the VM with the sandbox's name, size, storage and network
  rules, and deletes the imported image right after. Restoring needs a
  healthy egress guard, like any new VM.
- **Out-of-band changes.** Starting a cached sandbox's VM outside WS Sandbox Proxy
  makes the cached copy stale: that start fails `disk_stale` without
  booting, and the next start has the server discard the local copy and
  restore the stored copy instead. The same happens when the daemon refuses
  a server eviction grant and lets it expire.
- **Rate caps.** `offload_upload_mbps` and `offload_fetch_mbps` are in
  megabits per second (1 Mbps = 125 000 bytes/s); 0 or unset is unlimited.
  A daemon restart applies a change.

## Troubleshooting accounting integrity errors

A server log with `sandbox_reservation_underflow`, `sandbox_allocation_mismatch`
or `sandbox_reservation_nonzero_memory` means stored reservation accounting is
inconsistent. The failing transaction rolls back without clamping counters. If
this occurs while processing a host session's result, receipt or inventory, the
server intentionally closes that host's socket with a protocol error. Replaying
the same evidence on reconnect fails again until an operator repairs the corrupt
database row against the held allocations and confirmed guest state. This affects
only that host; other hosts and owners continue dispatching and reclaiming leases.
The affected event stays pending and is retried on each dispatcher scan, and
owner API calls that reach the corrupt row return a generic server error.
Restarting the daemon alone does not repair the row. Restarting the server
reconstructs liveCount, pinned RAM/vCPU, rootCount and pool disk commitments
from held rows. Missing bindings or conflicting allocations still require operator
recovery; never clear a counter without the corresponding positive evidence.

## Owner host detail and local terminals

Open a host's Details and terminal link from Hosts. The owner-only detail keeps
edit/drain/delete controls and shows foreign guest opaque allocation IDs,
size/state/expiry only: no creator identity, labels, envs, paths, command output
or guest terminal authority. Sharing never grants this host detail to grantees.

Local configuration owns `allow_host_terminal=false` and
`host_terminal_require_totp=true`. Use `wssp host config set-host-terminal on|off`
and `wssp host config set-host-terminal-totp required|optional` locally; the startup
`wssp host run --host-terminal on|off` override does not override later local
changes. Hot off is fail-closed within two seconds without restarting guests.
The dashboard can raise the TOTP requirement on an authenticated connected
host, after persisted acknowledgement; offline/timeout TOTP raises are unconfirmed
and never queued. Only local access can make TOTP optional. Separately, the
owner can turn host terminals or agent host access off in the dashboard,
including durable offline lowering. Enabling host access is node-only. See
[node settings](#node-settings-for-agents-and-terminals) and [terminal](./terminal.md).

### Credential revocation stops the VMs

When the server gives an explicit verdict that this enrolled credential has
lost its authority, the daemon can no longer receive stop requests. The verdict
is the reason `credential_revoked` (the credential was revoked) or
`owner_unavailable` (the owner is banned or deleting the account), carried
either as the reason on a 4003 close or, at connect, in the
`x-wssp-credential-refusal` header and `code` field of the 401 response. The
server sends a verdict only after the full secret has verified, so a caller
without the secret learns nothing new. A mistyped, unknown or expired token, a
plain 401/403, a 4003 with any other reason, or a dropped connection is not a
verdict: the daemon exits (4003 and 401/403 still exit with code 4) and leaves
its VMs running. On a verdict the daemon
records a durable "authority revoked" marker in its journal and stops every
sandbox VM it runs. It never destroys anything: disks are kept and no deletion
starts. Every later start of the daemon stops them again before connecting,
until a session registers again (after an unban or re-enrollment), which lifts
the marker; the server then starts sandboxes through the normal cold start.
The daemon keeps retrying each stop (graceful, then forced) until it confirms
every VM stopped or absent; it does not exit on its own (only an operator
shutdown interrupts it) while one is still running.
On a shared host this includes other users' sandboxes: banning a contributor
or revoking their host credential stops every sandbox on that contributor's
host, including those of other pool users (disks are kept), because the host
loses its relay.

### Carry window and cap

When the relay connection drops, in-flight work is carried until the
reconnect adopts it (see
[Stopping, signals and reconnects](#stopping-signals-and-reconnects)). Two
flat settings bound how long, both counted from the first drop of the outage:

| Key                   | Default | Range        | What it bounds                                                                                                                                                                                                                                          |
| --------------------- | ------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `carry_intent_window` | `10m`   | `1m`..`24h`  | Work that never started: queued commands and creates, or work waiting before its first effect. Never longer than the sandbox lease or `max_carry`. Ends as `host_effect_not_issued`.                                                                    |
| `max_carry`           | `24h`   | `10m`..`24d` | Running work. A running command is stopped through the normal cancel path; once the stop is proven it fails with `host_disconnect_expired` (without proof it is `UNKNOWN_OUTCOME`). Other started work is revoked and settles by its journaled receipt. |

```sh
wssp host config set-carry-intent-window 30m
wssp host config set-max-carry 7d
wssp host config set-max-carry default
```

A restart of `wssp host run` applies them; an invalid value makes the config
unreadable. Endings during an outage otherwise keep their natural code: a
command that reaches its own `timeoutMs` reports `timeout`, and lease expiry
stops or destroys the sandbox exactly as when connected. The window never
extends a lease or a command timer. A template-build step ended by
`host_disconnect_expired` fails the build as `build_step_host_disconnected`.

Costs of a long carry: each queued command or create still waiting holds its
worker slot on the host until the window ends (bounded by the worker lanes and
the 512-entry adoption cap), and output a running command writes while the
host is away is not streamed, so the gap in its streamed output grows with the
outage.

### Lease ceiling and drain

`max_lease` in the local config is the longest sandbox lifetime this machine
accepts: `"90m"`, `"6h"`, `"7d"` (5 minutes to 24 days) or `"unlimited"`. The
default is `"24h"`. Set it with:

```sh
wssp host config set-max-lease 6h
wssp host config set-max-lease unlimited
```

A running daemon reloads it within about a second without a restart, enforces it
at once for every new lease, logs how many current leases end later, and
reports it to the server, which shortens those leases (an offline host reports
on its next hello). An invalid value makes the config unreadable; the daemon
keeps its last ceiling until the file is fixed. The server and dashboard can
never raise or lower it: the dashboard shows it read-only, and pools and
memberships can only lower a sandbox's lifetime further. "Unlimited" takes
effect only where the deployment also allows it.

While a host drains, its detail page shows when it will be empty: now, "empty
by" the latest end of any sandbox still holding it (its enforced deadline or
access grace, whichever is earlier), or never while sandboxes without a time
limit remain; shorten or stop those to finish the drain.

Contribution accepts foreign egress from your IP and host budget consumption.
Withdrawal retains foreign disks for the accepted pool grace (up to 30 days);
host deletion waits for positive original-storage cleanup proof, potentially
longer if storage is offline/dead. An incus-admin local operator can reach every
VM; disabled dashboard host terminals provide no physical guest isolation.
Offline access-loss STOP happens on reconnect or the effective local lease,
whichever is enforceable first; a powered-off daemon cannot enforce deadlines.

## Capacity and storage qualification

Before production, measure RAM headroom on the intended host under representative
idle, boot and loaded guests. The current shared capacity policy charges 320 MiB overhead
per live VM and reserves max(4096 MiB, 25% of host RAM) for the host. Full QEMU RSS
includes guest pages: subtract verified simultaneously resident guest bytes,
include attributable helpers, and count shared kernel/cache overhead once.
Use worst-case measured overhead plus a documented margin, rounded upward to
64 MiB, and verify the reserve envelope covers baseline variance. Apply policy
changes through the shared manifest, rerun accounting/parity tests and repeat
measurements after deployment. Existing holds retain their pinned weights.

Qualify with an isolated test pool, exact owned sandbox IDs and measured backing
headroom. A 32 GiB root commits 33 GiB; logical caps do not reserve physical
space and must leave room for native image cache, the marker and unrelated work.
After a guest sentinel write, stop and cold-start the retained disk and verify
both persistence and exactly-once live/root accounting. Test vCPU, RAM and disk
refusals without accepting extra work. Never infer cleanup from a disconnected
host, expired timer or unavailable pool.

Verify the pool marker survives daemon restart without raising implicit caps.
For a reversible availability check, preserve the original marker bytes and
record all test roots before making only the test marker unreadable. The pool
must become unavailable while sibling pools continue; cold start and deletion
must retain holds without original-storage proof. Restore the original identity,
then verify the sentinel, size and pool binding. This tests marker availability,
not physical disk loss. Preserve unresolved recovery IDs and journals.

For guest Docker, use the [32 GiB root checklist](../operations/templates.md#docker-inside-a-32-gib-vm-root)
with an exact verified image, uncached layers and a pinned public image digest.
Verify guest-only socket access, overlay/cgroup/kernel support, bridge DNS,
registry grants and periodic DNS refresh. Record package/driver versions and
free-space scalars, check at least 2 GiB remains, and verify a cold reconnect can
run the already-pulled image without fetching it again. Restore reviewed caps
and drain settings, destroy only recorded test guests, and prove live/root
ledgers returned to baseline. Automated fixtures alone do not qualify hardware.

## Command output transport

The node and server negotiate 64 KiB command-output chunks. The server stores
output in 8 KiB rows, preserving retention caps, gap detection and paging.
Back-to-back chunks of one attempt can be admitted in a batch of at most
16 chunks or 1 MiB, with credential and fence checks in one transaction.
Frames never reorder and each chunk receives its own acknowledgement. If a
batch cannot commit, chunks are checked individually. These transport bounds
do not alter SDK output or its retention contract.
