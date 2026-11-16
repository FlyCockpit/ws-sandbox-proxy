# Template builds

A template build turns a **recipe** (JSON, or a subset of the Dockerfile
syntax) into a new revision of one of your templates. WS Sandbox Proxy starts a build VM
from a base template on one of your builder hosts, runs the recipe's steps in
it, stops it, and saves it through the same capture path as a manual capture
([templates](../operations/templates.md)). The result is stored, distributed,
tagged and retained exactly like a captured revision.

Start a build from the dashboard (**Templates → Build**, then
`/dashboard/templates/builds` for progress, step output and cancel), from the
SDK (`client.templates.build(Template()…)`, see the
[SDK README](../../packages/sdk/README.md#template-builds)) or with
`POST /v1/template-builds` and an SDK key with the `templates:build` scope.

**Where builds run.** A build VM runs on a builder host: one of your own
hosts with the image cache on (`builder`, see
[hosts](./hosts.md#image-cache)), or, when you turn on foreign builds in
settings, another account's builder in a shared pool that accepts foreign
builds and foreign images. Foreign builders also need the S3 image store and
a target template whose image placement allows any host. A build that no
host can run is refused with `template.build_no_builder` and boolean
`skipped` hints (`builder`, `capture_policy`, `lease`). Build VMs are
managed: they never appear in your sandbox list and accept no ordinary
commands, files or terminals.

**Cancel.** A cancel stops the build wherever it is, including while it is
CAPTURING: an in-flight capture loses to the cancel (no revision is created
and the tag does not move), and the image the builder produced is released
and evicted. Only a capture whose host result was already recorded before
the cancel still publishes (the build then ends SUCCEEDED); with an S3 image
store the build VM stays until that image is stored. A
[community base build](#community-base-builds) is the exception: it verifies
before it publishes, so a cancel always wins, and its capture fails and its VM
is killed at once.

The capture holds the build VM's root disk twice over (the root plus the copy)
on the builder's storage pool, and the VM's memory. When the builder has no
room for that hold yet, the build stays CAPTURING with phase
`capture_waiting_capacity` ("Waiting for disk or memory on the builder host")
and retries until room frees up or the capture window ends.

The build VM's lease is the build timeout plus about two and a quarter hours
by default: the capture window (60 minutes), a 60-minute window to store the
image and 15 minutes of slack. The deployment's lease ceiling
(`SANDBOX_MAX_TIMEOUT_MS`) and the builder's own ceiling must allow it, and a
capture that cannot reach the image store before the VM's lease ends fails the
build with `build_store_failed`.

Builds are not `docker build`. The output is a KVM VM image, the base is a
WS Sandbox Proxy template (never a Docker image), and there is no per-step layer cache:
either the whole recipe matches an earlier successful build (the existing
revision is reused) or every step runs. The match includes the resolved VM
size (`cpuCount`, `memoryMiB`, `diskGiB`) and the new revision's
`defaultDiskGiB`, so a build that differs only in size neither reuses nor joins
a build of another size.

### Disk size

The build VM's disk becomes the new revision's `minDiskGiB`: the image is that
VM's whole root, and roots never shrink, so it is also the floor of every
template built or captured from it. Builds therefore default to a small disk:
the base's `minDiskGiB` plus 2 GiB of headroom for what the steps install
(10 GiB on the 8 GiB community base). A recipe or request that installs more
sets `resources.diskGiB` (request: top-level `diskGiB`); one below the base's
minimum is refused with `sandbox.disk_below_image`.

The new revision's `defaultDiskGiB` (what creates get when they omit a size) is
the request's `defaultDiskGiB`, else the base's default, never below the build
disk: a build on the community base keeps the 32 GiB default. A sandbox created
larger than the minimum grows its root filesystem at create
([root disk](./sandboxes.md#root-disk-minimum-and-default)).

A build carries two digests, shown on its page under their API names.
`buildDigest` is the match key: the recipe plus the resolved base revision,
args, build context, egress request and VM size. `recipeDigest` covers the
canonical recipe alone, so the same recipe built with a different base, context
or size has the same `recipeDigest` and a different `buildDigest`.

## Recipe format

The canonical recipe is JSON:

```json
{
  "version": 1,
  "from": { "template": "wssp-base", "tag": "latest" },
  "args": { "NODE_MAJOR": "22" },
  "steps": [
    { "type": "arg", "name": "NODE_MAJOR", "default": "20" },
    { "type": "run", "script": "apt-get update && apt-get install -y jq", "user": "root" },
    { "type": "env", "values": { "APP_HOME": "/home/user/app" } },
    { "type": "workdir", "path": "${APP_HOME}" },
    { "type": "copy", "src": ["app/", "package.json"], "dest": "./", "owner": "user" },
    { "type": "run", "script": "npm ci" }
  ],
  "resources": { "cpuCount": 2, "memoryMiB": 4096, "diskGiB": 32 },
  "egress": { "mode": "open", "presets": ["ubuntu-apt", "npm"] },
  "scrubPaths": ["/home/user/.cache/pip"]
}
```

| Field        | Meaning                                                                                                                                            |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `from`       | `{template, tag?}` (a template slug; no tag means `latest`) or `{revisionId}`                                                                      |
| `args`       | Values for declared ARGs. A build request can override them; an undeclared name is refused                                                         |
| `steps`      | Up to 256, applied in order (below)                                                                                                                |
| `resources`  | CPU, guest RAM and disk of the build VM; CPU and RAM are the new revision's defaults, the disk its minimum ([disk size](#disk-size))               |
| `egress`     | The build VM's egress request ([egress](#egress))                                                                                                  |
| `scrubPaths` | Up to 16 extra absolute guest paths removed at capture, on top of the mandatory scrub list                                                         |
| `start`      | `{command, ready?, readyTimeoutMs?}`: run at every boot of a sandbox from the revision (see [Start and ready commands](#start-and-ready-commands)) |

### Steps

| Step      | Effect                                                                                                                                                                                                                             |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run`     | Runs `script` with the shell. `user` is `root` or `user` (default: the current USER)                                                                                                                                               |
| `env`     | Sets variables for later steps; the final values become the revision's default envs                                                                                                                                                |
| `arg`     | Declares a build argument (`default` optional). ARG values are visible to later RUN steps but never stored on the revision                                                                                                         |
| `workdir` | Sets the working directory of later steps; the final one becomes the revision's default cwd, where the start command, commands without a `cwd` and the dashboard terminal begin. A relative path needs an earlier absolute WORKDIR |
| `user`    | `root` or `user` (the base template's guest user) for later RUN steps                                                                                                                                                              |
| `copy`    | Copies `src` (paths in the build context) to `dest`. `owner` is `root` (default, as in Docker) or `user`; `mode` is optional octal permission bits such as `"0644"`                                                                |

**Users.** Only `root` and `user` exist in recipes. `user` is the guest
identity declared by the base template; the new revision keeps it. **A recipe
starts as `user`, not as root the way a Docker build does**: a step that needs
root (`apt-get install`, writing under `/etc` or `/usr`) needs `USER root`
before it (Dockerfile), `"user": "root"` on the step or a `user` step (JSON),
or `setUser("root")` / `aptInstall` in the SDK builder; switch back with
`USER user`. The default is deliberate: root is opt-in per step, and any root
step marks the revision. Root steps
run as guest root **only inside build VMs**. Ordinary sandboxes run commands as
the guest user, who may use `sudo` when the sandbox has
[`guestSudo`](sandboxes.md#root-in-the-guest); build and verify VMs never have
it, and the daemon never runs the create-time root audit in a build VM. A
revision built with any root step carries a **Built with root steps** badge, a
revision captured with guest root carries **Captured with guest root**, and
their sandboxes are `guestRoot`. Root steps can install setuid programs, so later sandboxes
from that revision can reach root inside their own VM; the image belongs to
you, as with a manually prepared template.

**COPY paths.** Sources are relative to the context root (`.` is the root
itself). Absolute paths, `..` and `*` outside the last path segment are
refused. A destination is absolute or relative to the current WORKDIR; with
several sources or a wildcard it must end in `/`.

**Substitution.** `$NAME`, `${NAME}`, `${NAME:-default}` and
`${NAME:+alternative}` are replaced in ENV values, ARG defaults, WORKDIR and
COPY paths, from ARG values and earlier ENV values (ENV wins over an ARG of the
same name). An unset name is empty. `\$` is a literal dollar sign and `\\` a
literal backslash. RUN scripts are not substituted: they receive ARG and ENV
values as environment variables and the shell expands them.

### Limits

| Item              | Limit                                                                                                                            |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| Recipe            | 64 KiB of canonical JSON                                                                                                         |
| Dockerfile source | 64 KiB                                                                                                                           |
| Steps             | 256                                                                                                                              |
| One RUN step      | 32 KiB for the script, the working directory and the effective environment together (the base template's default envs count too) |
| Environment       | The sandbox env limits: 64 variables, 4 KiB per value, 16 KiB in total                                                           |
| Substitution      | 4 KiB per expanded value; 1 MiB of expanded text for the whole recipe                                                            |
| COPY sources      | 64 per step                                                                                                                      |
| Egress presets    | 16                                                                                                                               |
| Extra scrub paths | 16                                                                                                                               |

`HOME`, `SHELL` and `TERM` cannot be set by ENV or ARG: they belong to the
guest identity.

## Dockerfile subset

A Dockerfile is compiled to the recipe above. Errors carry the line and
column.

**Supported:** exactly one `FROM <template>[:<tag>]` or `FROM revision/<id>`
as the first instruction; `RUN <shell>` and `RUN ["exec", "form"]` (quoted
into a shell script); `ENV name=value …` and the legacy `ENV name value`;
`ARG name[=default] …`; `WORKDIR`; `USER root|user`;
`COPY [--chown=root|user] [--chmod=<octal>] <src>… <dest>` (also in JSON
form); line continuations with `\`; comments.

**Parser directives:** `# syntax=` is ignored with a warning. `# escape=` is
refused: a different escape character would silently change the meaning of
every line.

**Ignored with a warning:** `EXPOSE`, `LABEL`.

**Refused:** `ADD`, `ENTRYPOINT`, `CMD`, `VOLUME`, `HEALTHCHECK`, `ONBUILD`,
`SHELL`, `STOPSIGNAL`, `COPY --from`, other `COPY` and `RUN` flags
(`--mount`, `--link`, …), heredocs, `ARG` before `FROM`, `FROM … AS` and a
second `FROM` (no multi-stage builds).

**WS Sandbox Proxy extension comments** set the recipe fields that Dockerfiles have no
syntax for:

| Comment                                                       | Recipe field                                |
| ------------------------------------------------------------- | ------------------------------------------- |
| `# wssp:egress-mode open\|allowlist`                          | `egress.mode`                               |
| `# wssp:egress domain <name>…` / `# wssp:egress cidr <cidr>…` | `egress.domains` / `egress.cidrs`           |
| `# wssp:egress-preset <name>…`                                | `egress.presets`                            |
| `# wssp:resources cpu=2 memory=4096 disk=32`                  | `resources`                                 |
| `# wssp:scrub <path>…`                                        | `scrubPaths`                                |
| `# wssp:start <cmd>` / `# wssp:ready <cmd>`                   | `start` (`readyTimeoutMs` defaults to 60 s) |

An unknown `# wssp:` comment is refused rather than ignored, so a typo cannot
silently drop an egress setting. Extension comments cannot appear inside a
continued instruction.

## Start and ready commands

A revision built from a recipe with `start` runs its start command at every
boot of a sandbox created from it: on create and on every reconnect of a
stopped sandbox. It is not a snapshot resume; the process starts fresh.

- The command runs as the guest user, in the recipe's final
  `WORKDIR`, with the same environment as the sandbox's commands. It runs in
  the background; its output goes to `/tmp/wssp-start.log` in the guest.
- With `ready`, the sandbox becomes READY only once the ready command exits 0.
  It is polled for up to `readyTimeoutMs` (1 s to 10 min, default 60 s).
- If the start command cannot be launched (`startup_failed`) or the ready
  command does not succeed in time (`startup_timeout`), the launch fails with
  that code. A new sandbox is destroyed; a reconnected one is stopped and keeps
  its disk.
- Only hosts whose daemon supports start commands run these sandboxes.
  Placement skips the others: a pool with no such host refuses the create
  with `sandbox.pool_no_compatible_host`, a capacity refusal may carry
  `skipped: ["template_startup"]`, and an explicit host without support
  refuses it with `UNSUPPORTED_CAPABILITY`. If the daemon changes after
  placement (a reconnect, or a downgrade), the launch is still refused with
  `unsupported_capability` instead of booting without its start command.

## Egress

A build VM gets network access like any sandbox ([network egress](./network.md)).
The recipe's `egress` is a **request**: `mode` is `open` or `allowlist`;
`domains`, `cidrs` and `presets` are grants. Without `mode`, any grant or
preset makes the request `allowlist` (fail-safe). In `open` mode the grants
are fallback grants: they apply if the host runs the build with an allowlist.

Where the build runs decides the effective mode, exactly as for a sandbox:
open on your own builders and on another user's builder that allows open
internet for others; on any other foreign builder the request is downgraded
to the allowlist of its fallback grants (no build is skipped for that). The
build page then says the build ran with the allowlist (host policy), and
blocked-name hints name what the resolver refused. A recipe without `egress`
is an open request with no fallback grants, like a plain create: downgraded,
it reaches nothing. No preset is ever added for you.

Blocked-name hints come from the build VM's own bridge resolver: in allowlist
mode, and for build VMs only, it forwards every name it does not answer itself
to a small DNS stub the node daemon runs on loopback. Granted names still
resolve from the host-published answers, and names on the host's blocklist
still get NXDOMAIN from the resolver; neither ever reaches the stub. The stub
answers at once: NXDOMAIN for a name outside the build's grants, and an empty
answer (NODATA) for a granted name's other record types, such as its IPv6
(AAAA) lookup, so dual-stack lookups of granted names are not slowed down. It
records the name in memory, deduplicated and bounded, never on disk; a name
outside the build's grants becomes a "blocked" line in the step log. Names
under the bridge's own `.incus` domain (the guest resolver's search-suffix
expansions, such as `archive.ubuntu.com.incus`) and service lookups (names
with `_`, such as apt's `_http._tcp.archive.ubuntu.com`, which no grant can
name) are never hints. No resolver logs queries, and no other sandbox (nor a
build with open internet) has a stub. On another user's builder the line
only says the host reported the name.

Only the build bridge's own resolver can add hints. The daemon identifies it
from evidence a local user cannot forge: the root-owned pid file Incus keeps
for the bridge's dnsmasq (`/var/lib/incus/networks/<bridge>/dnsmasq.pid`, or
under `INCUS_DIR`), whose recorded process start time must match the running
process, never from a process's own command line. The stub then records a
name only when the query's source socket belongs to that process's user
(Incus's `incus` user), so another local user querying the stub's loopback
port gets an answer but adds no line. The identity is re-read at most once a
second, so a restarted resolver is picked up. When it cannot be established
(no pid file, a mismatch, or a `/proc` that hides other users' processes with
`hidepid`), queries are still answered as usual but no hint is recorded, and
the daemon logs that to stderr (at most once a minute per build). One
residual remains: a process that queries the bridge's resolver address goes
through it exactly like the build VM does.

Every refused name the build VM looked up before a step ended belongs to that
step. The daemon sends at most one hint frame per build every 2 s, and the
server files a hint under the step running when it arrives, so before the
daemon reports a step's result it sends that build's waiting names first; if
the 2 s window has not passed yet, the result waits for it (at most 10 s), so
a name looked up just before a short step ends is never lost or filed under
the next step.

The stub's port is recorded with the build's network, and a restarted daemon
binds the same port again. While the daemon is down or restarting, lookups of
non-granted names get no answer and time out in the build VM instead of
failing at once; granted names keep resolving. If the stub cannot start, the
build runs without hints and its resolver refuses those names itself.

Daemons from before the stub logged a build resolver's queries to a
daemon-owned pipe instead. Current daemons no longer migrate such a build:
its recorded network is refused (fails closed), so a build left running by
one of those daemons fails and must be started again.

Presets expand into ordinary domain grants before validation:

| Preset       | Domains                                                                                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------- |
| `ubuntu-apt` | `archive.ubuntu.com`, `security.ubuntu.com`, `ports.ubuntu.com`                                                     |
| `debian-apt` | `deb.debian.org`, `security.debian.org`                                                                             |
| `pypi`       | `pypi.org`, `files.pythonhosted.org`                                                                                |
| `npm`        | `registry.npmjs.org`                                                                                                |
| `github`     | `github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com` |

Domain grants are host-resolved IP destinations, not hostname isolation
([what a domain grant means](./network.md#what-a-domain-grant-means)). Private,
link-local and metadata ranges are refused in every grant.

## Node daemon restarts

The DNS stub survives a node daemon restart; a running build step does not.
Restarting, upgrading or crashing the daemon while a recipe step runs ends
that step with an unknown outcome: the daemon cannot tell whether the
step finished, failed or is still changing the VM. The build then fails with
`build_step_unknown` (detail `unknown_outcome`), and the dashboard says the
daemon restarted or lost the step.

A lost step is never re-run. A recipe step is an arbitrary command, and its
first run may already have changed the VM (a package half installed, a file
appended), so running it again could capture a different image than the
recipe describes. Start the build again instead: a build always starts from a
fresh VM. The failed build's VM is destroyed by the build's cleanup once the
host reconnects.

Only the capture is retried after an unknown outcome (at most twice), because
a capture is idempotent: an interrupted capture's VM and snapshot are removed
before the next attempt, and no revision is published until one succeeds.

| Error code                     | Meaning                                                                                                                                                     |
| ------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `build_step_failed`            | A step exited non-zero.                                                                                                                                     |
| `build_step_timeout`           | A step ran past its time limit.                                                                                                                             |
| `build_step_host_disconnected` | The builder host stayed disconnected past its carry limit (`max_carry`), so it stopped the running step (`host_disconnect_expired`). Start the build again. |
| `build_step_unknown`           | A step's outcome is unknown, usually because the node daemon restarted while it ran. Start the build again.                                                 |
| `build_host_lost`              | The builder host went away during the build.                                                                                                                |

## Build context

A recipe with COPY needs a context: a tar archive of the files the steps copy.
The SDK packs a directory for you (deterministic ustar: sorted entries,
zeroed timestamps and owners, permission bits kept; symlinks must stay inside
the directory; devices, FIFOs and sockets are refused). The context is hashed
before the build is accepted and checked again inside the build VM.

The SDK reads the directory through open descriptors (`/proc/self/fd`), so a
concurrent writer cannot swap outside files into the upload. Where that is
unavailable (every platform but Linux) packing is refused (`unsupported`,
reason `unanchored_context`) unless you pass `allowUnanchoredContext: true`.
That opt-in leaves one risk: someone else on your machine who can write inside
the context could swap a directory out and back while it is read and get
outside files uploaded.

Contexts pass through the server's spool and, on another owner's builder, that
operator's host in plain form until the copy step finishes. Do not put
secrets in a context.

## Secrets

ARG and ENV values are stored in plain form (in the recipe, the build record
and, for ENV, the revision's default envs). Do not pass tokens, passwords or
API keys as ARG or ENV values, and do not leave them on disk in a RUN step:
the capture scrub removes known credential files, not everything, and it is
not a boundary against a recipe's own root steps, which run in the same VM
before the capture ([capture](../operations/templates.md#capture)). Build
secrets are planned for later.

## Rebuild on miss

When a tag's current revision came from a successful build without COPY and
its image is no longer available anywhere (no host has it and it is not
stored), a create of that tag starts a rebuild of the same recipe instead of
failing. The rebuild is charged to the template owner's build minutes and
concurrency. A pool create waiting for capacity shows the blocker
`image_rebuilding` and re-resolves the tag when the rebuild ends. Otherwise the
create is refused with `sandbox.template_image_unavailable` and typed fields:

| Field                      | Meaning                                                                        |
| -------------------------- | ------------------------------------------------------------------------------ |
| `reason: "rebuilding"`     | A rebuild is running; retry the create later.                                  |
| `reason: "rebuild_quota"`  | The owner's build quota refused the rebuild.                                   |
| `hint: "rebuild_required"` | The revision was built with a context (COPY); build it again with the context. |

A pinned revision (`revision/<id>`) is never rebuilt. The SDK exposes `reason`
and `hint` on `WsspError`.

A community template's rebuild on miss does not reuse the old pin: it prepares
a new revision from the current upstream image (see
[community base builds](#community-base-builds)).

## Community base builds

A [community base](../operations/templates.md#community-bases) is prepared by
a template build that WS Sandbox Proxy composes; you never write its recipe. It differs
from a user build in four ways.

- **Bootstrap.** The build VM boots the pinned upstream image itself, which
  still has the cloud image's `ubuntu` user and no WS Sandbox Proxy guest user. Readiness
  runs in _bootstrap_ mode for it: it waits for the agent, checks the
  architecture, waits for the boot to settle
  (`systemctl is-system-running --wait`, accepting `running` or `degraded`)
  and checks the guest network. The guest-user checks wait for the verify VM.
  The image's first-boot reboot is tolerated like any other restart.
- **Verify in CAPTURING.** After the capture is stored the build stays
  CAPTURING with phase `verifying` ("Verifying the image in a fresh VM"). The
  new revision shows **Verifying** and no sandbox, tag or grant can use it.
  WS Sandbox Proxy boots it in a fresh verify VM under the build's own principal, runs a
  fixed smoke as the guest user, and kills the verify VM before the build
  ends. The verify VM uses the revision's default disk (32 GiB), above the
  8 GiB build disk, so its create also proves the root grows. Only a passing smoke publishes the revision and moves `latest`. The
  whole build reserves 40 minutes: 30 for the recipe and 10 for the verify
  window.
- **No guest root.** Build and verify VMs always run with `guestSudo` off;
  a community create never asks for it. The recipe's root steps are WS Sandbox Proxy's
  own, so the revision carries **Built by WS Sandbox Proxy's base recipe** rather than a
  root taint.
- **Codes.** Besides the usual build errors a community build can fail with:

  | Code                         | Meaning                                                                                                 |
  | ---------------------------- | ------------------------------------------------------------------------------------------------------- |
  | `build_verify_failed`        | The smoke failed, timed out or could not run in the verify VM. The revision retires as `verify_failed`. |
  | `build_upstream_unavailable` | The pinned upstream image is gone from the index host. Use **Refresh now** to pin a newer one.          |

  The create itself may be refused with `template.community_key_scope` (an
  allowlist key), `template.community_unavailable` (index unreachable or no
  tested version) or `template.build_disabled` with `reason`
  `image_distribution_off` or `community_timeout_exceeds_max`. A user build,
  capture or tag move into a community template is refused with
  `template.community_managed`.
