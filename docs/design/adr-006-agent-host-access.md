# ADR-006: Agent access to hosts

## Status

Accepted — 2026-11-12

## Context and superseded statements

Programs and agents need an explicit way to maintain their owner's nodes, as
well as work inside sandbox VMs. This decision supersedes earlier blanket
statements that SDK credentials never reach host execution. It replaces or
narrows these statements from the preceding documentation:

- [Authentication planes](../guide/auth-planes.md#shared-pools-and-owner-browser-terminals):
  “Neither SDK nor admin/impersonation grants execution authority.” SDK keys
  can now authorize host commands and files; admin/impersonation still cannot.
  The introduction's “three authentication planes” becomes four with MCP.
- [Terminal guide](../guide/terminal.md#owner-host-terminal): “There is
  no dashboard enable/lower control.” The dashboard can now turn host terminals
  off. Its introduction's “The SDK plane (`/v1`) has no terminal” remains true
  for PTYs, but does not exclude the separate host command API.
- [ADR-003](./adr-003-host-enrollment.md#host-dashboard-edits-and-daemon-metadata):
  “It never holds a host credential and offers no host shell or host exec.”
  The dashboard still holds no host credential; an owner can open a host
  terminal and review queued commands. Scoped credentials can run host commands.
  The host-drain section's “SDK scopes do not grant host administration” now
  describes the drain API only, not a limit on an opted-in host command's power.
- [ADR-004](./adr-004-runtime-boundary.md#terminal-pty): “No host shell
  ever runs”. This describes the guest PTY opener only. The separate owner
  host terminal and agent host command opener can run host shells.
- [Browser terminal authentication](./browser-terminal-auth.md#sharing-and-host-terminal-boundary):
  “No SDK or admin execution authority is added.” This remains a property of
  terminal tickets, not a prohibition on scoped host command execution.

The documentation search for `host execution` and `never reach` also finds
network/metadata restrictions, operator-secret isolation, sandbox command
lifetime and native HTTP reconciliation statements. Those describe different
boundaries and remain in force.

## Credential kinds, scopes and planes

An `SdkKey` row is one of `API`, `AGENT_TOKEN` or `OAUTH_GRANT`. All resolve to
the same credential principal and use the same stored scopes, resource grants,
expiry, revocation and owner policy:

| Kind          | Authentication plane | Credential                                                       |
| ------------- | -------------------- | ---------------------------------------------------------------- |
| `API`         | `/v1`                | `wssp_sdk_…` bearer key                                          |
| `AGENT_TOKEN` | `/mcp`               | Person-minted `wssp_agent_…` bearer token                        |
| `OAUTH_GRANT` | `/mcp`               | OAuth access token backed by a grant and secretless `SdkKey` row |

The wrong kind on either endpoint returns 401. Cookie sessions authorize
person actions on the dashboard; host/device credentials authorize only the
host plane. Neither API keys nor MCP credentials authorize a browser PTY,
key/token management, consent, policy changes or decisions on queued commands.

`hosts:execute` grants host command start, status/output, stdin, cancel and
queue. `hosts:files` grants host file read/list/write/edit. Neither scope
implies the other or `hosts:read`. Minting either host scope requires all-owned
resource mode or at least one directly allowlisted owned host; a pool grant
alone is insufficient. Command status, stdin and cancel are bound to the
credential that started the command, even among credentials of one owner.
All host HTTP POST routes require `Idempotency-Key`, including the file
read/list POSTs; retries reuse the original key.

Host access is allowed only when the node's owner is the credential's own user.
The server verifies `SandboxHost.userId == principal.ownerId`, the host grant,
current link owner and effective node policy before dispatch. The daemon
rechecks the request's owner against `hostOwnerId` from `hello.ok`, current
connection epoch, live policy and policy revision for each start/file request;
stdin is bound to the command's owner and accepted revision and rechecks live
policy. Shared-pool use never grants host access to someone else's node.

## Node-local opt-in and lowering

Two independent settings default off: `allow_agent_host_commands` permits host
commands and host file tools; `allow_host_terminal` permits people to open host
terminals. The server cannot turn either on. Enabling locally requires stdin
and stderr TTYs, absence of `WSSP_HOST_COMMAND` and `WSSP_HOST_TERMINAL`,
no daemon ancestry, and typing `on`; there is no `--yes`. Raising the command
time cap or adding file roots uses the same gate. Config revision/enable latches
reduce accidental changes; unreadable config fails closed. Exact commands are
in [node settings](../guide/hosts.md#node-settings-for-agents-and-terminals).

Run the daemon as a service (a system or user unit) and raise settings from a
separate local login. A daemon started in the same terminal session or scope
as your shell makes the cgroup check refuse the raise. The marker, ancestry
and cgroup checks refuse the direct dashboard host-terminal/host-command case,
but are best effort against the daemon's own uid. A person or agent with host
execution can escape the process tree with `systemd-run --user`, `setsid`
followed by killing the supervisor, or cron, or edit `config.toml` directly.
These checks are not a kernel-enforced sandbox.

The node owner can lower either setting locally or through the dashboard.
Dashboard lowering sets a durable server-side veto that refuses host commands,
files or terminal tickets immediately. The node cannot clear it by reporting
off, reconnecting, editing config or using its credential. Every hello/report
that says on while vetoed causes another lowering request. Only the owner's
live, non-impersonated browser session can choose **Allow again** to lift a veto;
the node must be connected and its live report at the current epoch must say
that setting is off. An offline lower or failed node save cannot be undone by
lifting the veto. Turn it off at the node first with
`wssp host config set-agent-host-commands off` or `wssp host config set-host-terminal off`.
The lift is audited as PERSON/POLICY_VETO_LIFT and never enables a node setting.
After lowering, the setting stays off until someone raises it locally. `host.policy.lower` persists off, reports the new policy and
acknowledges it. Lowering agent access cancels in-flight host commands and
pending file work; lowering terminals closes host PTYs. An agent policy
revision change interrupts in-flight commands. Disconnect and shutdown also
terminate command process groups. Guest workloads are separate from this
policy action. Processes an agent starts outside the daemon's
process tree, such as cron jobs or systemd user units, are not stopped by lowering. Queued
commands remain for the person's decision.

The default command cap is 600 seconds (configurable 1–86400 seconds). Host
commands run as the daemon user with a cleared,
narrowly allowed environment and bounded masked output rings. They do not use setuid or automatically invoke sudo.
Host file tools additionally require explicit canonical roots, empty by default;
root `/`, sensitive daemon state/config and system pseudo-filesystems are
denied. The implementation also refuses hardlink aliases and common secret/key
path components. Physical symlinks within a root work; escapes and parent swaps
fail closed. Read offsets/sizes describe masked UTF-8 text, while ETags bind
original content. Full text reads/edits are capped at 4 MiB, read/write payloads
at 256 KiB, and aggregate edit old/new text at 256 KiB across at most 20 edits.
File tools are credential-only and run as the daemon user. Roots constrain file tools, not
arbitrary host commands.

## Trust and own-sandbox limits

The daemon user is an Incus admin. Host commands and host file tools
can reach every sandbox on that node, including sandboxes other users run there through
shared pools. A credential's **own sandboxes only** setting does not limit
host commands or host file tools. A node owner has full access to those guests
regardless of dashboard visibility. Turning off remote host access does not
isolate guests from their node's local administrator. Once a person turns on
agent host commands, an agent acts as the daemon user and can
change that node's settings and read the daemon's own credential. The emergency stop is
the dashboard lower (a server-side veto the node cannot undo), plus revoking
the credential. Investigate a node that reports on while vetoed before allowing
access again.

For sandbox APIs, effective creator restriction is `resourceMode == ALLOWLIST`
or `ownSandboxesOnly`: only the credential that originally created the sandbox
can access it. API keys default `ownSandboxesOnly` off; agent tokens and OAuth
grants default it on. This does not restrict host command or host file authority.

## Queued commands for a person

A credential with `hosts:execute` can queue a command for its owner's node even
while agent host access is off. Nothing runs at queue time. A person can review
the text, reason, credential and expiry, then dismiss or choose Run. Run marks
the queue decision and supplies a shell-quoted wrapper; it does not execute the
command. The browser pre-types printable one-line ASCII without a newline into
the owner's terminal, or shows the wrapper to copy. **Pressing Enter is the
person's decision.** Host terminal policy and fresh TOTP, when required, still
apply.

The wrapper removes `SUDO_ASKPASS`, `BASH_ENV` and `ENV`, invalidates cached sudo
authentication with `sudo -k` before and after the command, and preserves its
exit status. It does not automatically run the command as root. Queued commands
expire after 24 hours by default (1–168 hours selectable), with at most 50
pending per user. Decided/expired rows are retained for seven days.

## Audit and output masking

Host audit events identify the credential (or person), node, action, program
basename, command ID, timestamps and outcome. A domain-separated
`hmac-sha256:<hex>` subject HMAC covers command text or a file path. Audit rows
and logs never contain command text, argv, cwd contents, file contents or
output. Queue rows intentionally retain the command and reason for the person's
review; they are distinct from audit events. Host audit retention is 90 days.

The daemon masks command output before it enters bounded rings and masks host
file reads. It matches in-memory login-lease values, its host/device secret,
qualifying secret-valued environment variables, product credential patterns
(including `wssp_agent_`) and PEM private-key blocks. Streaming matching spans
chunk boundaries. Reads use opaque keyed ETags; writes/edits refuse the
`⟦redacted` marker so masked reads cannot silently overwrite hidden values.
Masking reduces accidental disclosure; it does not make arbitrary host commands
safe against a malicious credential or hide secrets the daemon does not know.
The control plane never decrypts vault values to mask host output.

## Consequences and rejected alternatives

- Host maintenance becomes available through the native API and MCP with the
  same scoped owner checks, explicit node opt-in and remote emergency off.
  Browser terminals retain cookie-only authentication and their separate PTY
  protocol. The [terminal relay contract](./terminal-relay-contract.md) does
  not turn host command polling into a terminal.
- We reject wsmp-style `READ`/`FULL` levels: command execution cannot honestly
  be presented as read-only, and host Incus-admin access bypasses guest scopes.
  Two explicit scopes and two off-by-default node switches state the authority.
- We reject server-side masking of decrypted vault values: it would broaden
  write-only secret disclosure into the control plane's host-output path.
  Values already held by the daemon are masked there instead.
- Agents the owner enables are trusted to act as the daemon user. Agent host
  access means the agent can do what the wssp daemon user can do, and it is
  off until a person enables it at the node. We rejected a per-node isolated
  mode (a root-owned broker running agent commands as a separate unprivileged
  user): its root setup and failure modes cost more than it protected, since
  file tools, the daemon's Incus-admin socket and persistence from earlier runs
  kept daemon-level reach. Owner decision 2026-11-13.
- We reject running host commands as root. Incus-admin power remains
  substantial even without Unix uid 0.
- We reject treating pool membership or own-sandbox filtering as a host
  security boundary. Pool users must trust node owners; credentials never get
  host access to another owner's node.

Wire sources: `crates/sandbox-protocol/src/host_access.rs`, `capabilities.rs`,
`control.rs` and `crates/sandbox-protocol/fixtures/control_host_access.json`.
Public HTTP shapes are in the [native HTTP contract](./native-http-contract.md);
MCP callers connect to `/mcp` and manage tokens or connected apps under
**Settings → Agent tokens**.
