# Templates: qualifying and registering an Incus VM image

A WS Sandbox Proxy template is an owner-local logical identity with immutable revisions.
Each revision pins an Incus virtual-machine fingerprint and guest identity;
separate availability records say which enrolled hosts verified that exact image.
You prepare the first image on a host with Incus, then register it from the
dashboard (**Templates → Register template**) or with `POST /v1/templates`
(see [native HTTP contract](../design/native-http-contract.md)). After that,
WS Sandbox Proxy can copy the exact image to other eligible hosts when a create needs it
([image distribution](#image-distribution)), keep it in an S3-compatible image
store ([image store](#image-store)), and save a running or stopped sandbox as a
new revision ([capture](#capture)). There is still no image builder or
Dockerfile upload.

**An OCI or Docker image is not a template.** Sandboxes are KVM virtual
machines: the image must be an Incus `virtual-machine` image with its own
kernel, init system and the Incus guest agent. A container image, or an OCI
image imported into Incus as a container, is refused at registration.

## What registration checks

Registration asks the chosen host, over its relay connection, to look the image
up in its **local** Incus image store (the host's configured project; a
`remote:` prefix never selects another daemon).

- The host must be connected and not draining. Otherwise registration is
  refused with `sandbox.host_unavailable` (409) or `sandbox.host_draining` (409)
  and nothing is stored.
- The reference must be an alias (`ubuntu-dev`, `local:ubuntu-dev`). A content
  digest or `sha256:` fingerprint is refused before the host is asked.
- The host resolves the alias to a fingerprint, confirms the image type is
  `virtual-machine` and that its architecture equals the template's
  (`x86_64` by default). A type, architecture or launch-verification refusal is
  `sandbox.template_image_rejected` (400) with a constant safe reason, and
  nothing is stored. A missing local image or alias instead uses
  `sandbox.template_image_missing`; no revision is created. Over `/v1`,
  registration returns 202 with a FAILED receipt carrying that error code
  (reading the receipt returns 200); the browser oRPC refusal uses CONFLICT.
- On success the template stores that fingerprint. Launches always use the
  fingerprint, so moving the alias later never changes an existing template.
  Append a revision to pick up a new image or change private defaults. Creating
  an existing logical slug is `sandbox.template_revision_exists`; registration
  never silently appends. Every successful append explicitly moves `latest`.

## Revisions, tags and access

Create a logical template and its first revision with `POST /v1/templates`.
Append with `POST /v1/templates/{id}/revisions`; associate an existing revision
with another owned host using `POST /v1/templates/{id}/availability` and
`{revisionId, hostId}`. Association verifies the exact fingerprint, not a moved
alias, and never copies an image. Revision and availability discovery use
separate cursor pages. The dashboard exposes revision tags, retirement and
host verification in **Manage revision**. Tags and retirement require a browser
session. Archiving prevents future creates and preserves existing disks.

Use `template: "my-template"`, `"my-template:tag"`, `"template/<logicalId>"`
or `"revision/<revisionId>"` with exactly one pool or explicit host. Missing `latest`, retired,
absent and ungranted revisions produce the same template-not-found response.
ALLOWLIST keys grant exact revision IDs; an append never expands their grants.
Minting requires a pending or available association on a selected owned host.

Fresh creation requires current negotiated admission, complete inventory,
journal-key ACK and exact available evidence on the current host connection.
A bounded hello census has page deadlines and retries; omitted replies never
prove image absence. The host rechecks the fingerprint immediately before the
fresh create effect. A cold reconnect of a retained disk, and a restore of an
offloaded one, ignore cached template-image availability.

Revision `envs` are private defaults. Changes require a new revision. Create
snapshots template defaults plus sandbox overrides; command overrides apply
last. HOME/SHELL/TERM are reserved in stored defaults. The shared environment
limits and redaction rules apply to registration, creation and execution.

See [SDK resource grants](../guide/auth-planes.md#minting-sdk-resource-grants)
for selecting exact revisions and hosts.

## Dashboard revision size defaults

**Templates → Register template** has explicit **Default vCPUs** and
**Default memory (MiB)**, **Default root disk (GiB)** and **Minimum root disk
(GiB, optional)** inputs, initially 1, 1024, 32 and blank. The minimum is the
image's own root size (creates below it are refused; blank: the default is the
minimum, since wssp cannot see inside a registered image). CPU is a whole count
from 1 to 32; memory is 512–65536 MiB in 256 MiB steps. For the browser
recipe, enter 2 and 2048. Registration verifies the image without starting a
VM or reserving memory; the defaults may exceed the verification host's cap.

Each paged revision card shows its saved CPU/RAM/root defaults and its minimum
root disk. **Add revision**
starts a new registration form with explicit 1/1024/32 values. **Append with these
defaults** copies only that revision's CPU/RAM/root into the new form; choose a
verification host and image alias again. You can edit the copied values before
submitting. Both actions append an immutable revision and move `latest`; they
never resize a sandbox or edit an existing revision. **Manage revision** stays
an edit sheet for tags and availability.

## What each sandbox start checks (guest readiness)

Registration does not boot the image. Every sandbox start runs a read-only
readiness check inside the guest, as the template's declared user, and a
sandbox that fails it is never reported ready:

- The Incus guest agent runs, so the host can execute in the VM.
- `uname -m` matches the template architecture.
- The declared guest user exists with the declared UID and GID (default
  1000/1000), home directory (default `/home/user`) and shell (default
  `/bin/bash`); the home directory exists, is owned by that UID:GID, and is
  writable and searchable; the shell is executable. If `$HOME/repo` exists it
  must be owned by that user and writable too.
- These tools are on `PATH`: `setsid`, `sh`, `stat`, `find`, `mkdir`, `mv`,
  `rm`, `kill`, `sync`, `python3`. `setsid` must accept `-w` (util-linux).

Readiness tolerates a guest that reboots itself during boot. Every new
instance of an `images:ubuntu/26.04/cloud` base reboots once, about a second
after its agent starts. The whole readiness check, the agent wait and every
guest check, runs inside one agent budget (`WSSP_INCUS_AGENT_TIMEOUT_SECS`,
default 120 s). After each pass the host re-reads the VM's state and the
guest kernel's boot id (`/proc/sys/kernel/random/boot_id`, through the
agent). A pass counts as a restart, and runs again, when the state left
Running, the QEMU process changed, or the boot id changed. The boot id is what
catches a reset Incus performs inside the same QEMU process, where the state
stays Running. Readiness fails when the VM stays stopped for 15 s, enters an
error, frozen or other non-boot state, restarts more than twice, or the
budget runs out before that final observation. Creates from such a base take
a few seconds longer.

A failed check is recorded on the create or reconnect operation. The `/v1`
operation read (`wssp.operations.get` in the SDK) returns it as
`readinessReason` with `errorCode: "guest_unavailable"`, and the SDK's error
message names it. The operation's stored error detail carries fixed text, for
example `Sandbox guest readiness failed (guest_home: …); cleanup queued.`; the
sandbox's own last error is cleared once the failed VM is deleted. The daemon
logs it in its `sandbox lifecycle operation …` line as
`readiness=<reason>`, and logs `readiness restart tolerated n=<count>` when a
sandbox became ready across guest restarts. The reasons are `agent_timeout`,
`vm_not_running`, `guest_restarts`, `architecture`, `guest_user`,
`guest_home`, `guest_shell`, `guest_repo`, `guest_tooling` and
`guest_check`. They are fixed labels; guest output is never recorded.
Readiness runs its guest commands with `/` as the working directory, so a
declared uid or gid that cannot enter HOME fails quickly as `guest_user` or
`guest_home` rather than waiting out the budget.

Supervised commands use their own root-owned scope
`wssp.slice/wssp-cmd-<operation>-<generation>-<attempt>.scope` with
`OOMPolicy=continue` when the guest has an executable `/usr/bin/systemd-run`
version 254 or newer, systemd as PID 1, and `/run/systemd/system`. The wrapper
checks these before starting the command. Otherwise it executes directly,
initializing supplementary groups before dropping GID and UID, after writing
the per-boot marker `/run/wssp/unscoped`. For the rest of that boot, an
unknown command on the running VM is retired only by the older proofs (the VM
stopped, or the guest rebooted). Keep these template rules so running-VM
retirement works:

- These scope rules apply only to sandboxes that are not `guestRoot`; with
  guest root no guest-side marker or scope is proof, root-owned or not.
- Add no `Delegate=`, `User=` or `Slice=` drop-ins for `wssp.slice` or
  `wssp-cmd-*.scope`. A relocated scope writes the marker; a delegated or
  non-root-owned one is never proof.
- Do not create `/run/wssp` yourself. If it exists it must be a root-owned
  directory without group or world write; otherwise every command that needs
  the marker fails before it starts. The same happens when `/run` is
  read-only or full.
- Do not enable linger for the guest user, and do not let it enable linger
  itself ([deny self-linger](#deny-self-linger)). Do not ship units that run
  as the guest user with `Delegate=yes`. A running cgroup owned by the guest
  user (for example `user@<uid>.service`) blocks every running-VM proof, and
  it also hides the reboot proof while the VM runs.
- The kill of a due command needs cgroup v2 and Linux 5.14 or newer
  (`cgroup.kill`); without it a due command is kept until the VM stops. A selected scope is never retried through direct execution.
  Scopes preserve pipes, working directory, environment and supplementary groups;
  argument expansion is disabled. With a scope, a workload OOM can report its
  killed exit without stopping `incus-agent.service`. Direct execution retains
  the guest agent's OOM policy: an OOM may stop the agent and lose the exit
  channel, leaving the command outcome unknown. See the
  [command guide](../guide/sandboxes.md#files-and-tracked-command-dashboard).
  See [systemd-run](https://www.freedesktop.org/software/systemd/man/255/systemd-run.html)
  and [scope OOM policy](https://www.freedesktop.org/software/systemd/man/255/systemd.scope.html).

Guests receive no control-plane credentials; commands and file transfers run as
the declared user.

## Image checklist

Required (readiness fails without them):

- **The Incus guest agent**, started at boot. Every command, file transfer and
  terminal goes through it (`incus exec`); WS Sandbox Proxy installs no daemon of its own.
  Incus `cloud` VM images ship it.
- **The guest user and HOME**: an account with the UID, GID, home directory
  and shell you will declare (defaults 1000/1000, `/home/user`, `/bin/bash`).
  The home directory must be owned by that user. Commands, files and terminals
  all run as this user. With `guestSudo` (default on) the daemon installs a
  `sudo` drop-in for it; `sudo` is then required (any implementation that
  accepts `#<uid>` sudoers rules). With `guestSudo` off the create audits for
  static root grants (hygiene, not a security control).
- **The tools on `PATH`** listed above, including `python3` (the file helper)
  and util-linux `setsid`.

Recommended (not checked by readiness, but expected by typical agent and CI
workloads):

- **`git` and `tar`**, so a workload can clone or unpack a repository into
  `$HOME/repo`. If you create `$HOME/repo` in the image, it must be owned by
  and writable for the guest user.
- **Preset toolchains** (language runtimes, compilers, package managers)
  installed in the image, system-wide or under the guest user's home, on the
  `PATH` the guest user gets. Sandboxes start with deny-all egress, so a
  toolchain that is not in the image can only be installed at runtime if the
  sandbox was created with an egress grant for its download hosts. Domain
  grants are IP grants that are re-resolved while the sandbox runs and
  withdrawn when resolution fails, so prefer baking toolchains into the image
  rather than depending on a download at boot
  ([network egress](../guide/network.md)).
- `ca-certificates`, a working `/etc/resolv.conf` from DHCP, and nothing that
  expects inbound ports: sandboxes have no published ports.

The default base image is `images:ubuntu/26.04/cloud`. Ubuntu 24.04 cloud
images remain supported. Non-kill process signals require a guest kernel of
at least 6.9; use the HWE kernel on 24.04 for those signals. Verify the booted
kernel and helper probe; see the [support/refusal matrix](../guide/sandboxes.md#filesystem-and-command-result-limits).

## Preparing an image (outline)

Run every `incus` command in the daemon's Incus project
(`--project <project>`, for example `--project wssp`). Registration looks the
alias up only in that project, so an image published elsewhere is
`sandbox.template_image_missing` unless the project shares the default
project's images (`features.images=false`).

1. Start from a VM cloud image, for example
   `incus launch images:ubuntu/26.04/cloud prep --vm --project <project>`.
   A new 26.04 instance reboots once on first boot, about a second after its
   agent starts; wait for it (`cloud-init status --wait`) before step 2.
   Sandboxes from the image reboot the same way, and readiness tolerates it
   ([guest readiness](#what-each-sandbox-start-checks-guest-readiness)).
2. Inside it, create the guest user with the UID, GID, home and shell you will
   declare ([Ubuntu cloud-image guest identity](#ubuntu-cloud-image-guest-identity)),
   and install `python3`, the tools above, `git`, `tar` and your toolchains.
   The 26.04 cloud image has no `git`. Remove cloud-init's passwordless
   grant for the default user: `rm -f /etc/sudoers.d/90-cloud-init-users`.
3. [Deny self-linger](#deny-self-linger) for the guest user (the polkit rule
   below).
4. Clear the per-instance identity, as root, as the last step inside the VM:

   ```sh
   cloud-init clean --logs --seed
   truncate -s 0 /etc/machine-id
   rm -f /var/lib/dbus/machine-id
   ```

   `--seed` also drops the prep VM's cached cloud-init seed, so each sandbox
   runs cloud-init from its own instance data. An empty `/etc/machine-id` makes systemd generate a new one on each
   sandbox's first boot. Without it, every sandbox from the image shares the
   prep VM's machine ID (journald, DHCP client IDs and D-Bus use it). An image
   published without this step keeps the shared ID: re-publish it from a
   prep VM rather than editing the image. Captures and builds reset it (see
   [Capture](#capture)), but sandboxes created straight from such a base
   image all share the prep VM's ID; check with `cat /etc/machine-id` in two
   sandboxes, and re-prepare the base when they match.
5. Stop it and publish it as a local image with an alias:

   ```sh
   incus stop prep --project <project>
   incus publish prep --alias ubuntu-dev --project <project>
   ```

6. Register the alias on that host. The dashboard shows the resolved
   fingerprint and host when registration succeeds. The template architecture
   (default `x86_64`) must match the image and the host.

### Ubuntu cloud-image guest identity

On `images:ubuntu/26.04/cloud`, `ubuntu` occupies UID 1000 (GID 1001),
and the `lxd` group occupies GID 1000. Both collide with the default template
identity, 1000:1000 at `/home/user`. In a dedicated preparation VM, as root,
replace them before publishing:

```sh
userdel -r ubuntu
rm -f /etc/sudoers.d/90-cloud-init-users /etc/sudoers.d/wssp-guest /etc/.wssp-sudoers.tmp
groupdel lxd
groupadd -g 1000 user
useradd -m -u 1000 -g 1000 -d /home/user -s /bin/bash user
printf 'users: []\n' > /etc/cloud/cloud.cfg.d/99-wssp-no-default-user.cfg
```

`userdel` leaves cloud-init's `ubuntu ALL=(ALL) NOPASSWD:ALL` sudoers file
behind; remove it so no future `ubuntu` account inherits root. The
`users: []` cloud-init configuration prevents the default `ubuntu` sudo
user from being recreated on the first boot of every sandbox. Keep the home
owned by 1000:1000. Ubuntu 26.04's uutils coreutils are supported; readiness
passed with uutils 0.10.0, so replacing them with GNU coreutils is unnecessary.

### Deny self-linger

On stock Ubuntu 26.04 (polkit 127), polkit lets any local user enable systemd
linger for itself without authentication
(`org.freedesktop.login1.set-self-linger` is `yes` for `any`). A lingering
guest user keeps `user@<uid>.service` running, which blocks running-VM
retirement of unknown commands until the VM stops. Retirement fails safe (it
keeps the receipt), but any workload can trigger it. In the prep VM, as root,
add a polkit rule that refuses linger to every user except root:

```sh
cat > /etc/polkit-1/rules.d/50-wssp-deny-self-linger.rules <<'EOF'
// wssp: no non-root user may enable systemd linger. A lingering guest user
// keeps user@<uid>.service running, which blocks running-VM retirement.
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.login1.set-self-linger" ||
         action.id == "org.freedesktop.login1.set-user-linger") &&
        subject.user != "root") {
        return polkit.Result.NO;
    }
});
EOF
chmod 0644 /etc/polkit-1/rules.d/50-wssp-deny-self-linger.rules
loginctl disable-linger user
```

polkitd reloads rules when the directory changes. Check it as the guest user.
`pkcheck` asks polkit about the shell's own process and changes nothing; it
prints `1` (not authorized) once the rule applies, and `0` before:

```sh
incus exec prep --project <project> --user 1000 --group 1000 -- sh -c \
  'pkcheck --action-id org.freedesktop.login1.set-self-linger --process $$ >/dev/null 2>&1; echo $?'
```

A polkit rule is the supported block: logind has no setting that disables
linger, and the linger state itself lives in `/var/lib/systemd/linger`, which
only root can write. The 24.04 base used in testing had no polkit and was not
affected; the daemon's linger probe (below) reports any image that is.

The daemon probes linger once each sandbox is ready. When the guest user has
linger enabled, or polkit would let it enable linger, the daemon logs a
warning with `linger=enabled` or `linger=allowed` and the sandbox ID. This is
a warning, not a readiness failure: retirement already fails safe, and a
workload could enable linger after readiness anyway, so refusing the create
would not close the gap. Fix the template instead.

For a tested browser workload, see the [agent-browser template recipe](../guide/recipes/agent-browser.md).

## Community bases

**Create from community image** (Templates page) or
`POST /v1/templates/community` (SDK `templates.createFromCommunity`; scopes
`templates:write` and `templates:build`, not an allowlist key) makes a base
template for you from a tested community image, without a prep VM. The
picker shows tested images only; today that is Ubuntu 26.04 LTS (x86_64).
A community template is managed by WS Sandbox Proxy: user builds, captures, appended
revisions and tag moves into it are refused (`template.community_managed`).
You may still archive it or retire its revisions. Build your own images _from_
it (`fromTemplate("ubuntu-26-04")`) like any other base.

- **The pin.** The server reads the simplestreams index of
  `images.linuxcontainers.org` over HTTPS and pins the newest VM build of the
  image (`ubuntu:resolute:amd64:cloud`) by its SHA-256. The pin is recorded as
  a hidden **Upstream image** revision. Sandboxes never launch from it, and
  it cannot be tagged, published or associated. The builder host's daemon
  downloads the disk (at most 4 GiB) and checks its digest before import. An
  unreachable index, or no tested version, is 409
  `template.community_unavailable` with `reason` `index_unreachable` or
  `no_tested_version`.
- **The recipe.** A fixed WS Sandbox Proxy recipe (build VM `guestSudo` off) waits for
  cloud-init and replaces the `ubuntu` user with `user` (1000:1000,
  `/home/user`, `/bin/bash`). It removes `/etc/sudoers.d/90-cloud-init-users`
  and stops cloud-init from recreating a default user. It installs the polkit
  rule that refuses linger to everyone but root (see
  [Deny self-linger](#deny-self-linger)), then `python3`, `util-linux`, `git`,
  `tar`, `ca-certificates`, `cloud-guest-utils` and `e2fsprogs` (asserting
  `growpart` and `resize2fs`). It turns cloud-init's own root growth off
  (`growpart: off`, `resize_rootfs: false`): the node daemon grows and checks
  the root at every create instead. Finally it runs `cloud-init clean --logs --seed`,
  empties `/etc/machine-id` and checks that no passwordless grant remains. Its
  last step runs as `user` and asserts that privilege escalation and linger
  are both refused. The revision shows **Built by WS Sandbox Proxy's base recipe**.
- **Verify and smoke.** The captured revision is not launchable yet. It shows
  **Verifying** while the build, still `CAPTURING`, boots it in a fresh verify
  VM (`guestSudo` off, no egress). The verify VM runs the smoke as `user`: no
  escalation, groups `user` only, no `ubuntu` user, linger refused, a fresh
  machine ID and SSH host keys, `setsid -w`, `python3` and a writable home.
  Only a passing smoke publishes the revision as `latest`. A failing one
  retires it (`verify_failed`), and the build fails with
  `build_verify_failed`.
- **Refresh.** The server checks the index daily. It builds a new revision
  only when upstream changed **and** the last refresh is at least 7 days old.
  The template's **Refresh automatically** switch (default on) turns the
  daily check off. **Refresh now** is always available and skips the 7-day
  minimum. A refresh reuses the last preparation's host or pool. Older
  upstream pins that no active build uses retire as `superseded`.
- **Retention.** The index host keeps each build for about three weeks. With
  the 7-day minimum the current pin normally stays downloadable until the
  next refresh replaces it. A pin that has gone from the index fails its
  build with `build_upstream_unavailable`; **Refresh now** pins a newer one.
- **Recovery.** When the latest preparation failed or was cancelled, the
  template offers **Try again**. It runs the same recipe on the same pin and
  target (or a target you pass through the API). The template header shows
  the latest preparation's state and error.
- **Storage.** Use the S3 image store. Peer storage works, but a community
  base is only as available as the hosts that hold it; the dashboard warns
  about it on the create dialog and the template. With
  `IMAGE_DISTRIBUTION=off` the feature is unavailable:
  `template.build_disabled` with `reason` `image_distribution_off`.
- **Time limit.** A community build reserves 40 minutes: 30 for the recipe
  and 10 for the verify window. A server whose build `maxMinutes`, or whose
  lease ceiling, cannot fit that refuses the create with
  `template.build_disabled` and `reason` `community_timeout_exceeds_max`. It
  never truncates the build.
- **First boot.** The 26.04 image reboots once on first boot, in the build
  VM, in the verify VM and in every sandbox. Readiness handles it; see
  [guest readiness](#what-each-sandbox-start-checks-guest-readiness).

See [template builds](../guide/template-builds.md#community-base-builds) for
the build phases and codes.

## Availability and archiving

Logical activity, revision retirement and host availability are separate. The
Templates page pages revisions and host associations independently, showing
`AVAILABLE`, `PENDING`, `MISSING` or `REJECTED` for each exact host/revision.
`PENDING` is grantable for key minting but cannot start a new sandbox. Current
connection evidence, fresh heartbeat and all other admission gates are still
required even for a stored `AVAILABLE` record.

When an association check finds the revision's exact fingerprint absent, it
records `MISSING` before refusing with `sandbox.template_image_missing`, unless
newer same-epoch census evidence already exists. Over `/v1`, association returns
202 with a FAILED receipt; reading it returns 200 with that `errorCode`. The
browser oRPC refusal uses CONFLICT.
A create failing its host-side exact-image recheck records the same operation
code and marks only that exact current-connection association MISSING. The
refused sandbox held nothing, so it ends `DELETED` (with that code as its last
error) rather than staying behind as an `ERROR` row. Later
direct creates refuse with that same 409 code. Restore the fingerprint on the
host and verify the revision again. A missing Incus project or an unproven
lookup failure is not evidence that the exact image is absent.

**Manage revision** opens an edit sheet: point a tag to the exact revision or
verify the fingerprint on a selected owned host. **Retire revision** requires
the exact revision ID as confirmation and prevents fresh creates; existing
sandboxes keep their original revision, disk and private configuration.
Archiving the logical template (`retireTemplate`) prevents new selector
resolution, even while retained sandboxes use it. It does not remove host
associations, release live VM slots or destroy existing sandboxes. Exact
revisions remain readable by `sandboxTemplates.getTemplateRevision`. There is
no template delete; resources are removed with their owner's account.

A latest/tag selector resolves only once at acceptance. Moving a tag never
changes replay or an existing sandbox. An ALLOWLIST key must grant the resolved
exact revision; granting its old latest revision grants no future append.
The key picker displays exact IDs and each selected host's verified/pending
association. Follow the [re-mint walkthrough](../guide/auth-planes.md#minting-sdk-resource-grants).

Pools use only exact revisions already associated with member hosts; placement
does not copy or build images. Grant the pool, selected hosts and exact
revisions for restricted SDK keys. See [pools](../guide/pools.md).

## Immutable CPU and guest RAM defaults

Register and append accept optional independent `cpuCount` / `memoryMiB` /
`defaultDiskGiB` / `minDiskGiB`. Omission normalizes to 1 vCPU / 1024 MiB / 32 GiB
for each new revision, and `minDiskGiB` to the default; append does not
inherit the previous revision. CPU is 1–32, RAM 512–65536 MiB in 256 MiB steps.
Disks are integers 1–2048 GiB with `minDiskGiB` ≤ `defaultDiskGiB`; declare the
image's real root as `minDiskGiB` to allow smaller creates (a create below the
image's real root fails on the host). A larger disk grows the root at create.
A revision's defaults may exceed the verification host's budget: registration
verifies an image without launching a VM or reserving RAM. Changing only size
policy preserves the artifact/architecture/guest `manifestDigest` and exact
image availability. Existing revisions and accepted sandbox sizes stay immutable.

Create independently overrides each dimension after selecting the exact
revision. Read revisions to discover defaults; only host read grants expose host
capacity. See the [VM size guide](../guide/sandboxes.md#vm-size).

## Docker inside a 32-GiB VM root

Prepare a dedicated derivative of the existing wssp-base VM using the preparation
recipe above. Never change the shared base alias. Inside that dedicated prep VM
as root (Ubuntu supported distro packages):

```sh
apt-get update
apt-get install -y docker.io ca-certificates
systemctl enable --now docker
```

Do not add the guest user to the `docker` group: that is a static root grant
(a `guestSudo` off create then fails with `guest_root_granted`). Use
`sudo docker` in sandboxes with `guestSudo`.

These packages supply Engine/CLI/containerd. Preserve the Incus guest agent,
declared user/tools and a root image no larger than 32 GiB. Verify from a fresh
declared-user session with `id` and `docker info`; record distro/package versions,
architecture and Docker storage driver. Require working overlayfs/cgroups/kernel
support and writable `/var/lib/docker` on the root disk, without another volume.
Docker socket membership is guest-root-equivalent; grant it only to this test
VM's declared user. Never mount a host socket/device or give the guest host or
control-plane credentials. Stop/publish under a new dedicated alias, register
it through the supported owner flow and verify the exact resolved fingerprint.
This is an Incus VM template, not an OCI template or new image-builder subsystem.

For qualification, use a fresh template without cached test layers. SDK create
uses 2 vCPU/2048 MiB and omits disk override; assert 32 GiB root/33 GiB commitment.
Pin a public small `docker.io/library/alpine@sha256:<verified-platform-digest>`
and record digest/architecture. Begin with exact grants for `registry-1.docker.io`,
`auth.docker.io`, `production.cloudfront.docker.com`, `index.docker.io`. Only add
another exact domain after failed-pull sanitized hostname/status evidence, using
a newly created sandbox because egress is immutable. No redirect discovery helper,
tokens, signed URLs, headers, raw debug logs or registry login.

Via SDK commands as the declared user, pull the pinned image and run
`docker run --rm --network none <pinned-image> sh -c 'printf "docker-in-vm-ok\n"'`.
Require exit 0 and the exact marker. Before/after, record `df -B1 /`,
`du -x -B1 -s /var/lib/docker` (operator scalar sample if permissions deny),
`docker system df`, and Incus root readback. Require unchanged 32-GiB allocation,
less than 32×2^30 used bytes, at least 2 GiB free, no ENOSPC and unchanged 33-GiB
server commitment. Stop/cold-reconnect and run with `--pull=never`, then SDK
destroy the exact test ID. See the [capacity and storage qualification](../guide/hosts.md#capacity-and-storage-qualification).

Registry/CDN grants authorize host-resolved IPs, not hostname/TLS identity;
shared IPs broaden reach. Rotating or different DNS answers can refuse pulls.
Use the supported bridge DNS path (IPv4-only); normal 300-second leases refresh
around 150 seconds and fail closed. Record observed endpoint names and refresh
behavior; no wildcard/CIDR/proxy/open-internet workaround. See
[registry caveats](../guide/network.md#registry-and-cdn-pulls).

## Shared-pool image verification

The dashboard registration and Manage revision flows can verify through a
usable pool plus opaque member ID. Users without an owned host register their
own exact sha256 fingerprint this way. Logical templates, revisions and private
defaults remain creator-owned. Verification sends only public image identity;
foreign host labels, heartbeat and local storage details are not part of the
member picker. Current use/contribution/epoch is checked again after verifier IO.
There is no image distribution or callable routing grant from stale availability.
Immutable SDK keys independently select usable pools and owned revisions;
foreign pool members need no foreign host allowlist grant. See
[pools](../guide/pools.md#sharing-invitations-and-contribution-consent).

## Image distribution

A create no longer needs the image on the chosen host in advance. When a host
has no current verified copy, placement may still choose it if the image can
be fetched there right now; hosts that already have it rank first.

- **Modes.** `IMAGE_DISTRIBUTION=off` keeps the old behaviour exactly (no
  fetch, no capture, no image store, lease from acceptance). `auto` uses the
  S3 image store when `IMAGE_S3_BUCKET` and both keys are set, otherwise
  _peer mode_: the image is copied from one of the image owner's own connected
  hosts through the server, in one-time 32 MiB parts. Peer copies are never
  stored by the server; a server restart fails relayed copies and the hosts
  ask again.
- **Eligibility.** The host advertises an image cache (`image_cache_gib` is
  not 0), its cache has room after other planned downloads, and the image is
  known to be unified (`incus publish` output). Split images are refused for
  distribution with a re-publish hint. Another account's host also needs
  `accept_foreign_images = true` on that host, and the template's (or the
  account's) image placement must be **Any host**; **Owned hosts only** keeps
  every copy on your own hosts. Set the account default under **Settings →
  Template images** and a template's own under its **Image settings**. A pool
  owner may cap other accounts' image bytes per contributed host (pool
  settings, **Image cache per member**). A host's detail page shows its cache
  size, use, other accounts' bytes as one total, and your cached images.
- **Access loss.** A copy on another account's host lives only while every
  gate that admitted it still holds: the image owner is active, the host
  still accepts foreign images, the owner can still use a pool the host is a
  member of, and a live revision pins the image with **Any host** placement.
  When one stops holding (a share revoked, a host withdrawn, a policy
  tightened, a ban or account deletion) the copy stops counting for
  placement at once and the host is told to drop it (`image.release`,
  `access_lost`); an offline host is told again when it reconnects.
- **Verification.** The host checks the SHA-256 of the whole file against
  the revision's fingerprint and its size before `incus image import`, then
  resolves the imported image (VM type, exact fingerprint, architecture).
  A failure deletes the import and fails the create with `image_corrupt` or
  `image_rejected`. The server re-checks the operation, epoch, sharing,
  placement policy and the account's downloads per hour on every grant.
- **Errors.** No eligible host: `sandbox.template_image_unavailable` (pools
  reselect another host first). During a create: `image_unavailable`,
  `image_cache_full`, `image_corrupt`, `image_rejected`, `image_fetch_timeout`.
- **Progress.** The operation shows `fetching_image` (bytes) and
  `importing_image` phases.

## Capture

**Save as template** (dashboard) or `POST /v1/sandboxes/{id}/capture` turns a
sandbox into a new revision of its template (or another template you own).

- **READY** sandboxes are captured live: the guest root filesystem is frozen
  for a moment, snapshotted, and thawed. This needs copy-on-write storage
  (btrfs, ZFS or LVM-thin); a `dir` pool refuses with
  `sandbox.capture_unsupported` (`reason: storage`). **STOPPED** sandboxes can
  be captured on any pool, including `dir`: the stopped root is copied
  directly (a full copy, so it can be slow; progress is shown).
- The copy boots as a separate capture VM with **no network device**, is
  scrubbed as root, powered off and published (`incus publish --compression
  zstd`). The sandbox itself keeps running and keeps its credentials.
- **Settled boot first.** The scrub waits (up to 600 s) until the capture
  VM's boot has settled: the agent answers, `systemctl is-system-running
  --wait` reports `running` or `degraded`, and the guest boot id is the
  same before and after. An agent can answer early in boot, before
  `systemd-machine-id-commit` has replaced the read-only transient
  `/etc/machine-id` (a capture of an image whose machine-id was emptied),
  and a fresh Ubuntu 26.04 instance reboots once during first boot. A
  failed capture logs its cause on the host (`template capture failed …
  error=…`). A scrub failure names the helper's first error as a fixed
  class (`read_only_fs`, `protected_link`, ...) and its path only when that
  is a fixed manifest path; a link target, a guest-chosen path or the
  helper's own text is never logged. The server only sees `capture_failed`.
- **Frozen scrub.** Before anything is removed, the scrub helper checks that
  the capture VM has no network device besides `lo` and freezes every guest
  task with the cgroup v2 freezer, PID 1 (`init.scope`) included: it moves
  itself alone into its own cgroup, freezes every other cgroup subtree except
  the path to the Incus agent that runs it, moves any other process found on
  that path (or in the root cgroup) into a frozen holding cgroup, and waits
  until every one reports `frozen 1`. A frozen task cannot run, so no signal
  resumes it. The scrub, `sync` and a final verification (every guest task
  still frozen, nothing else beside the helper, every scrubbed path absent,
  every truncated file empty) all run frozen, in that order. Once the freeze
  begins, nothing from the guest is executed: the helper starts no
  subprocess and imports nothing more, it does not run `cloud-init clean`
  (whose `/etc/cloud/clean.d/` hooks are guest code running as root), and the
  host runs nothing in the guest after the verification. Nothing is thawed:
  the VM is powered off rather than shut down. A guest without a cgroup v2
  hierarchy, a cgroup that cannot be frozen, or a helper that cannot be
  isolated fails the capture. The walk itself opens each directory without
  following links and re-checks every entry's device and inode before
  removing it; an entry replaced underneath the scrub fails the capture
  instead of publishing.
- **What is scrubbed** (`packages/config/src/template-capture-scrub.json`):
  shell, REPL and editor histories and the common CLI credential locations
  (Claude, Codex, gh, git credentials, docker, npm, netrc, AWS, gcloud, kube,
  SSH private keys, GnuPG) for the guest home and `/root`; SSH host keys;
  `/etc/machine-id` (truncated: it is left present and empty, and created
  empty when missing, so systemd generates a fresh ID on each sandbox's first
  boot; D-Bus then reads it) and `/var/lib/dbus/machine-id` (Ubuntu links it
  to `/etc/machine-id`: the link is removed, never its target);
  `/var/log/journal`;
  swap files; `/tmp` and `/var/tmp`; the cloud-init state that `cloud-init
  clean --logs --seed` would remove (`/var/lib/cloud/*`, seed included, and
  `/var/log/cloud-init.log*`, `/var/log/cloud-init-output.log*`), removed by
  the helper itself. Add
  paths per template (**Template settings → Extra scrub paths**) or per
  request (`scrubPaths`). A symlinked path, and any symlink found anywhere
  inside a scrubbed directory, is removed together with its target (link
  cycles are detected), and the capture result lists such paths. A link into
  a system directory (`/usr`, `/etc`, ...) or a virtual filesystem is never
  followed: the capture fails instead of publishing an unscrubbed image.
  **Scrubbing is best effort: never bake secrets into a sandbox you intend to
  capture.** The scrub runs on the guest image's own kernel, Incus agent and
  `python3` interpreter with its standard library, which stay trusted; it
  runs as `python3 -I -S`, so no environment variable, working directory,
  `site-packages`, `.pth` file or `sitecustomize` is loaded. It protects
  against ordinary concurrent workloads in the guest (PID 1 included). It is
  **not** a boundary against hostile code with root inside the guest: such
  code can tamper with what the helper sees (for example with mounts) or
  modify the kernel, agent or interpreter, and so keep a secret in the
  published image. Root code in the guest could already read those secrets
  while the sandbox ran; treat a template captured from a sandbox that ran
  untrusted code with root as possibly carrying its secrets.
- **Tags and retention.** Over the SDK a capture may only move `latest`; a
  browser session may name another tag. Each template keeps the newest
  `captureKeep` (default 3) captures per tag and retires older ones
  (`retiredReason: retention`), never a revision another tag points to.
  `pruneAfterDays` retires untagged revisions older than that many days
  (`auto_prune`).
- **Foreign hosts.** A sandbox on another account's host can be captured only
  when the image store is S3 (the revision must not live only on someone
  else's host): otherwise `sandbox.template_store_unavailable`. The host's
  operator receives the published image (they already had the root disk).
- **Cleanup.** The capture VM and snapshot are deleted after every capture,
  and their absence is checked; a failed deletion is retried with backoff
  before the result is reported, so the capture's hold covers the leftover
  disk until it is really gone.
- **Holds.** While a capture runs, the host is charged 1 vCPU, 1 GiB of guest
  memory plus overhead and the root size twice on the sandbox's pool; one
  capture per host and per sandbox at a time (`sandbox.capture_busy`).
- **Dashboard.** Each revision shows its source (Manual, or Snapshot with
  its tag), its image-store state (Not stored, Uploading, Verifying, Stored,
  Corrupt) and size. **Image settings** (a Sheet on each template) sets
  placement, `captureKeep`, `pruneAfterDays` and extra scrub paths. **Prune
  now** (type the template slug to confirm) runs the retention rule at once
  with no age threshold: untagged revisions outside the newest `captureKeep`
  of their tag retire (`retiredReason: manual`, at most 100 per click);
  revisions a sandbox uses are kept. In S3 mode **Publish to image store**
  wakes the auto-publish for one revision.
- **Daemon restart during a capture.** Steps are not journaled one by one;
  the receipt only records that the capture started. If the daemon restarts
  before it records the result, recovery deletes that capture's own VM
  (`wssp-cap-<operation>`) and source snapshot and checks both are gone
  (until they are, the operation stays open, keeps its capacity hold and is
  retried at every reconnect), then reports the operation as
  `UNKNOWN_OUTCOME`: a publish may already have produced an image, so
  neither success nor failure is provable. The server releases the capture
  hold and creates no revision. The guest is never left frozen (the freeze
  helper thaws when its pipe closes). What can remain on the host: an
  unaliased Incus image if the publish finished (find it with
  `incus image list` by its creation time), and, if the restart came after
  the daemon recorded that image in its cache, an origin-pinned cache entry
  that counts against `image_cache_gib` until the server's origin-pin GC
  releases it (no revision uses that image, so it is released once the
  daemon's cache census reports it) and the daemon deletes the image. An image
  the daemon never recorded is not removed automatically. Run the capture
  again for a revision.
- Snapshot restore and fork stay unsupported (`UNSUPPORTED_CAPABILITY`).

## Image store

With `IMAGE_S3_BUCKET` set (R2, MinIO or S3), images live in
`<IMAGE_S3_PREFIX>/owners/<ownerId>/<fingerprint>/<sessionId>/image.tar[.wsspenc]`,
one copy per owner (no cross-account deduplication) and one key per upload
session, so two uploads never write the same key.

- **Objects are create-only.** The server completes every upload (template
  image or disk) with `If-None-Match: *`, so an existing object is never
  overwritten, by a concurrent upload or by the SDK retrying a Complete. A
  refused Complete (412, or 409 for a concurrent conditional write) aborts
  that multipart upload. The existing object is never assumed to be the
  upload's: it stays **Verifying** and the verify job hashes it (after
  authenticated decryption under the upload's own data key when encrypted);
  only an exact match is **Stored**, anything else is corrupt and deleted.
  Any other Complete failure fails the upload. The store must honour
  `If-None-Match` on CompleteMultipartUpload: AWS S3 documents it and
  `pnpm test:s3` proves it against the pinned RustFS (412 for a second
  Complete, for a racing one and for a retried one). Check any other
  provider before relying on it: one that ignores the header overwrites.
- Hosts only ever get presigned per-object GET or UploadPart URLs (their
  `Content-Length` is signed). They cannot list, delete or choose keys. The
  server lists the parts and checks every size before completing an upload,
  and a worker job re-reads and hashes the object before it is **Stored**.
- **One upload at a time.** Each upload is its own session: its multipart
  upload id, parts and data key belong to that job, never to the shared
  image. While one job's upload of an image is live, another begin for the
  same owner and image is refused (`upload_in_progress`); the waiting
  capture finishes when that upload is stored. An upload whose job lost its
  authority (an older dispatch attempt, an ended transfer) is superseded and
  its multipart upload aborted.
- **Encryption.** `IMAGE_STORE_ENCRYPTION=on` with
  `IMAGE_STORE_ENCRYPTION_KEY` (base64 of 32 bytes) encrypts each image with
  its own data key (AES-256-GCM, 1 MiB records); the data key is wrapped
  under the master key and the grant hands it to the host for one transfer.
- **Auto-publish.** Live revisions available on a connected owned host are
  uploaded automatically (one per host, two per account at a time).
- **GC.** An image no live revision, open transfer or in-flight create uses
  is deleted after `IMAGE_GC_GRACE_DAYS` (default 7). A sweeper removes
  objects with no row and multipart uploads older than a day, fails uploads
  with no progress for a day, and aborts the multipart uploads of ended
  sessions. Set the bucket lifecycle rule "abort
  incomplete multipart uploads after 1 day" as well.
- **Quotas.** `IMAGE_STORE_MAX_GIB_PER_ACCOUNT` (default 50) and
  `IMAGE_DOWNLOADS_PER_HOUR_MAX` (default 120); an administrator can lower
  either per account (**Admin → Users → Image quotas**). **Settings →
  Template images** shows your stored bytes and downloads against them. Refusals: `sandbox.image_quota_exceeded`
  (`scope: stored | downloads`).
- **Local development.** `pnpm dev:s3` runs one long-running loopback
  RustFS gateway (the pinned image `pnpm test:s3` uses; pull it once with
  `pnpm test:s3:pull-image`), at 127.0.0.1:7457 (`--port` and `--name`
  override the port and container), bucket `wssp-offload-dev`, state in the
  gitignored `.local/dev-s3/`, and writes the `IMAGE_S3_*` variables into
  the local `.env` without printing them; `pnpm dev:s3:stop` removes the
  container and keeps the data. Its URLs are http, so the daemons that use
  it must run on the same machine.
- **Disk offload variables.** `SANDBOX_OFFLOAD` (`auto` or `off`, default
  `auto`), `SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT` (default 200),
  `SANDBOX_OFFLOAD_GIB_PER_DAY` (default 500) and
  `SANDBOX_OFFLOAD_SHRED_GRACE_HOURS` (default 24, 1 to 720); see
  [disk offload](#disk-offload).
- The image bucket is not part of database backups. After a database restore
  the sweeper and the missing/corrupt handling reconcile the bucket.

### Disk offload

Stopped sandbox disks share the image bucket with templates but are separate
objects with their own rows, keys and checks; template GC, quotas and fetch
grants never see them. The product behaviour is in
[sandboxes](../guide/sandboxes.md#disk-offload); the key handling is in
[credential vault](../design/credential-vault.md#whole-disk-offload).

- **Layout.** One object per upload session:
  `<IMAGE_S3_PREFIX>/owners/<ownerId>/sandboxes/<sandboxId>/<offloadId>/<sessionId>.wsspenc`,
  64 MiB multipart parts, always encrypted with a per-session data key
  wrapped under `DATA_ENCRYPTION_KEY`. `IMAGE_STORE_ENCRYPTION` does not
  apply to disks. A worker decrypts and hashes every copy before it is
  stored; a corrupt copy is deleted and never restored.
- **Availability.** New offloads and evictions need S3 mode,
  `DATA_ENCRYPTION_KEY`, `SANDBOX_OFFLOAD=auto` (the variables above) and a
  host daemon that supports it. Restore needs only S3 and the key, so
  `SANDBOX_OFFLOAD=off` stops new offloads and evictions only and leaves
  existing `OFFLOADED` sandboxes restorable and destroyable. S3 is detected
  from the bucket settings, so `IMAGE_DISTRIBUTION=off` does not stop
  offloads. Without S3 or the key a restore is refused
  `sandbox.disk_unavailable`. Never remove `DATA_ENCRYPTION_KEY` while
  offloaded disks exist: they cannot be restored without it.
- **Stored quota.** `SANDBOX_OFFLOAD_MAX_GIB_PER_ACCOUNT` caps the bytes of
  an account's live offloaded copies (an administrator can lower it per
  account, **Admin → Users → Image quotas**). Copies in their consumed
  grace do not count. Over quota, the offload fails and the sandbox's
  `disk.offloadFailure` reads
  `quota_exceeded` (a DTO value, not an HTTP error): the disk stays on its
  host and nothing is evicted.
- **Daily upload ledger.** `SANDBOX_OFFLOAD_GIB_PER_DAY` caps offload upload
  bytes per account per UTC day, counted in the database; an exhausted
  budget also fails the offload `quota_exceeded`. Restore downloads
  never count against it and are never refused; the connect budget bounds
  them. An export larger than the sandbox's `diskGiB` (plus a small slack)
  fails `size_exceeded`; a root guest can fill the whole disk.
- **Consumed grace.** After a restore (or a cached start) reaches READY, the
  copy is kept for `sandbox.offload.consumedGraceSeconds` (**Admin →
  Settings**, default 3600, an integer from 0 to 604800; 0 deletes at once).
  READY reads the setting once, so a change applies to later starts only.
  The copy is a salvage window for an operator, never a restore source.
- **Shred grace.** Destroying an offloaded sandbox keeps its wrapped key and
  object for `SANDBOX_OFFLOAD_SHRED_GRACE_HOURS` (default 24), then the
  worker shreds the key (zeroes the wrap) and deletes the object, but only
  if the sandbox is still `DELETED` by that destroy. If that check fails the
  worker raises an alert and keeps the object. Shredded rows are deleted
  after 30 days.
- **Maintenance.** The worker's disk-offload maintenance (stale attempts,
  verify backstop, consumed-grace and destroy shreds, retention) runs twice
  an hour whenever S3 and `DATA_ENCRYPTION_KEY` are configured, whatever
  `IMAGE_DISTRIBUTION` says.
- **Sweeper.** A disk object is kept only while a verifying, stored or
  evicting row, a copy in its grace, a destroy in its shred grace, or an
  open upload session names it. Every other disk object is deleted after a
  day by the image store sweep, like template objects. That sweep runs only
  while `IMAGE_DISTRIBUTION` is not `off`.
- **Host staging.** The export reserves image-cache space (about twice the
  used disk, at most twice `diskGiB`). If it does not fit, the offload fails
  `staging_full`, the disk stays local, and the next attempt waits about two
  minutes (other failures wait 30 minutes). Upload and fetch bandwidth are
  node settings ([hosts](../guide/hosts.md#disk-offload-on-a-host)).
- **Own-host restore limit.** A restore reads at most 1,024 of the owner's
  connected hosts that have room, in host id order, before it tries the
  origin pool. An owner with more such hosts can miss an eligible one past
  that point; name it with `sandboxHostId` on the reconnect.
- **Managed sandboxes** (template builds) are never offloaded.
- Like template images, offloaded disks are not in database backups; see
  [backup and restore](./backup-and-restore.md#disk-offload).

## Foreign-image qualification

`incus image import` runs in the Incus daemon on bytes another account
controls, and Incus does not refuse crafted images on its own: Incus 7.5.1
**accepts** every crafted image below (a qcow2 `rootfs.img` with a host-path
backing file or an external data file, a `rootfs.img` symlink or character
device, and a `../../escape` entry). The daemon
therefore validates every image before `incus image import`, whoever owns it
(`validate_unified_image` in `crates/sandbox-runtime`). It accepts only the
unified VM layout (`metadata.yaml`, a qcow2 `rootfs.img` with no backing
file, external data file or encryption, optional flat `templates/`) and
refuses links, device nodes, FIFOs, absolute or `..` paths, duplicates and
any other entry. With `accept_foreign_images = false` (the default) the daemon
also refuses to fetch another account's image at all, whatever the server
plans.

Qualify the pinned Incus version once, with no VM and no instance. Each
crafted tarball is a complete VM image with exactly one defect, and the
`metadata.yaml` carries a real `creation_date` (Incus refuses `0` as
"Missing creation date" before it looks at the payload, which would make
every case pass without testing anything). The `control` image must be
accepted, or the check proves nothing.

```sh
incus project create wssp-qual -c features.images=true -c features.profiles=true
work=$(mktemp -d) && cd "$work"
printf 'architecture: x86_64\ncreation_date: %s\nproperties: {}\n' "$(date +%s)" > metadata.yaml
qemu-img create -q -f qcow2 good.img 1M
# 0. control: a valid image
cp good.img rootfs.img && tar -cf control.tar metadata.yaml rootfs.img
# 1. qcow2 whose backing file is a host path
qemu-img create -q -f qcow2 -F raw -b /etc/hostname rootfs.img 1M
tar -cf backing.tar metadata.yaml rootfs.img
# 2. qcow2 with an external data file
qemu-img create -q -f qcow2 -o data_file="$work/data.raw" rootfs.img 1M
tar -cf datafile.tar metadata.yaml rootfs.img
# 3. rootfs.img is a symlink to a host file
mkdir -p evil && cp metadata.yaml evil/ && ln -s /etc/shadow evil/rootfs.img
tar -cf symlink.tar -C evil metadata.yaml rootfs.img
# 4. a valid image plus a traversal entry
cp good.img rootfs.img
python3 -I -c "import tarfile,io;t=tarfile.open('traversal.tar','w');t.add('metadata.yaml');t.add('rootfs.img');i=tarfile.TarInfo('../../escape');i.size=1;t.addfile(i,io.BytesIO(b'x'));t.close()"
# 5. rootfs.img is a character device
python3 -I -c "import tarfile;t=tarfile.open('device.tar','w');t.add('metadata.yaml');i=tarfile.TarInfo('rootfs.img');i.type=tarfile.CHRTYPE;i.devmajor=1;i.devminor=1;t.addfile(i);t.close()"
for f in control backing datafile symlink traversal device; do
  incus image import --project wssp-qual "$f.tar" --alias "qual-$f" && echo "ACCEPTED $f" || echo "refused $f"
done
incus image list --project wssp-qual
for f in control backing datafile symlink traversal device; do incus image delete --project wssp-qual "qual-$f" 2>/dev/null; done
incus project delete wssp-qual
rm -rf "$work"
```

Record the Incus version and which crafted images it accepted. Pass for
Incus alone: `control` is accepted and every crafted image is refused, or an
accepted one carries no host bytes (`incus image export`, inspect, and
`qemu-img info` shows no backing or data file). Incus 7.5.1 fails this (all
five crafted images accepted), so on 7.5.1 the daemon's validation is the only
barrier: keep `accept_foreign_images = false` on daemons without it, and flip
the default only in a follow-up.
