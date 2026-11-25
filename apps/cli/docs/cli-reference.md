# `wssp` command reference

This reference is generated from the clap definitions in `apps/cli/src/cli.rs`
and `apps/cli/src/commands/`, the same definitions that render `wssp --help`.
`cargo test -p wssp --test cli_reference` fails when it drifts; regenerate it
with `WSSP_BLESS_CLI_REFERENCE=1 cargo test -p wssp --test cli_reference`.
The same test checks every `wssp …` invocation written in the repository docs
against these commands and flags.

For behavior (enrollment, state directory, signals, drain semantics), see the
[CLI README](../README.md) and the [host operations guide](../../../docs/guide/hosts.md).
For `wssp sandbox shell`, `forward`, `wssp ssh` and `wssp ssh-config`, see
[shells, port forwards and ssh](../../../docs/guide/connect.md) and the
[ssh, VS Code, rsync and sftp guides](../../../docs/guide/ssh/README.md).

Capacity is local to the host. Flags override TOML independently; automatic
vCPU capacity is detected threads × 2 and RAM includes each VM's host overhead.
No capacity flags are required by the systemd service example.

Storage lists are TOML-only; an explicit list replaces profile-root selection:

```toml
sandbox_vcpu_budget = 64
sandbox_memory_mib = 95232
max_sandbox_cpu_count = 32

[[storage_pools]]
name = "default"
capacity_gib = 96
draining = false
```

Without a list, `wssp host run` inspects the audited profile-root pool and creates the
project-owned `wssp-pool-marker` filesystem volume once. Restore the original
marker/backing storage after identity failure; the daemon never repairs or deletes
it automatically. Implicit caps use free space, measured charged-root usage,
headroom and a persisted ceiling that can only fall. Only explicit TOML can raise
a cap. Pool drain blocks new roots; retained roots keep their pool and size.
`wssp host config show --json` is read-only and reports partial inspection when Incus or
original journal evidence is unavailable. Restart/reconnect to apply changes.

Journal v5 requires the coordinated breaking deployment: retire old allocations
using the old daemon, preserve its journal, then use a fresh private directory.
Never delete or convert a journal to make active or unknown roots launchable.

<!-- BEGIN GENERATED: WSSP_BLESS_CLI_REFERENCE=1 cargo test -p wssp --test cli_reference -->

### Global options

Accepted by every command, before or after the subcommand.

| Argument | Description | Notes |
| --- | --- | --- |
| `--log-format <LOG_FORMAT>` | How to format log output. `text` is human-friendly; `json` is for machines (pipe into `jq`, ship to a log collector, etc.) | default `text`; one of `text`, `json` |
| `-v`, `--verbose` (repeatable) | Increase log verbosity (-v = debug, -vv = trace). Overridden by the `WSSP_LOG` / `RUST_LOG` env var if set |  |
| `-q`, `--quiet` | Silence all logs except errors |  |

### `wssp login`

Log in to a wssp server as yourself (device flow; the browser chooses what this login may do).

```text
wssp login [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--server <URL>` | Server origin, e.g. `https://wssp.example.com` (default: the origin of the current login) |  |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots for this server (saved with the login; `WSSP_CA_FILE` overrides) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp logout`

Revoke this machine's user login on the server and remove it here.

```text
wssp logout [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--local` | Only remove the saved login; do not revoke its key on the server |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp whoami`

Show the user login of this machine and what its key may do.

```text
wssp whoami [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--offline` | Show only the saved login; make no network call |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox`

Create, inspect, run commands in and manage sandboxes through the `/v1` API.

```text
wssp sandbox [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp sandbox create`

Create a sandbox from a template on a pool or one of your hosts.

```text
wssp sandbox create [OPTIONS] --template <SEL>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--template <SEL>` | Template selector: a template slug or id, `slug:tag`, `template/<id>` or `revision/<id>` | required |
| `--pool <ID>` | Place the sandbox through this pool |  |
| `--host <ID>` | Place the sandbox on this host (one of yours) |  |
| `--name <N>` | Sandbox name (default: a generated adjective-noun name) |  |
| `--timeout <DUR>` | Lease, e.g. `30m`, `2h`, `1d` (`0`: no lease timer where policy allows it; default 5m) |  |
| `--cpu <N>` | vCPUs (default: the template revision's) |  |
| `--memory <MiB>` | Guest memory in MiB (default: the template revision's) |  |
| `--disk <GiB>` | Root disk in GiB (default: the template revision's) |  |
| `--metadata <K=V>` | Metadata label `key=value` (repeatable) |  |
| `--wait` | Wait until the sandbox is READY (or fails) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox list`

List sandboxes (newest first, one bounded page).

```text
wssp sandbox list [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--state <S>` | Only sandboxes in this state (repeatable; default READY), e.g. `--state STOPPED` |  |
| `--limit <N>` | Page size, 1–100 (default 20) |  |
| `--cursor <C>` | Continue after a previous page (`nextCursor`) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox get`

Show one sandbox.

```text
wssp sandbox get [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox exec`

Run a command in a sandbox and stream its output; exits with the command's exit code.

```text
wssp sandbox exec [OPTIONS] <ID> -- <ARGV>...
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--timeout <DUR>` | Command timeout, e.g. `90s` or `10m` (at most 30m; default 2m) |  |
| `--cwd <P>` | Working directory in the guest (absolute) |  |
| `--env <K=V>` | Environment variable `KEY=VALUE` for the command (repeatable) |  |
| `--detach` | Start the command and print its operation id without waiting |  |
| `--json` | Print `{operationId, exitCode, stdout, stderr, truncated, gaps, restarts}` at the end instead of streaming |  |
| `<ARGV>` | The command and its arguments, after `--` | required |

### `wssp sandbox shell`

Open a shell in a sandbox, or run a command there interactively; exits with the remote status.

```text
wssp sandbox shell [OPTIONS] <SANDBOX> [-- <ARGV>...]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SANDBOX>` | Sandbox id or name | required |
| `--cwd <PATH>` | Working directory in the guest (absolute; default: the guest user's home) |  |
| `--env <K=V>` | `TERM`, `COLORTERM`, `LANG` or `LC_*` for the remote side, `KEY=VALUE` (repeatable) |  |
| `-T`, `--no-tty` | Never allocate a tty: separate stdout and stderr, piped stdin (the default when stdin or stdout is not a terminal) |  |
| `--json` | Report a failure as one JSON line on stderr (the session itself is raw bytes) |  |
| `<ARGV>` | The command and its arguments, after `--` (default: a login shell) |  |

### `wssp sandbox forward`

Forward local ports (or a local Unix socket) to ports on a sandbox's loopback.

```text
wssp sandbox forward [OPTIONS] <SANDBOX> <PORTS>...
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SANDBOX>` | Sandbox id or name | required |
| `<PORTS>` | `<guestPort>[:<localPort>]` (repeatable; the local port defaults to the guest port, `0` picks a free one) | required |
| `--address <ADDR>` | Local address to listen on (an IP address; default `127.0.0.1`; anything but loopback warns) |  |
| `--unix <PATH>` | Listen on a Unix socket at PATH (mode 0600) instead of a TCP port; one guest port only |  |
| `--json` | Print the listening addresses as JSON lines; report a failure as one JSON line on stderr |  |

### `wssp sandbox ps`

List the commands running in a sandbox.

```text
wssp sandbox ps [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--limit <N>` | Page size, 1–100 |  |
| `--cursor <C>` | Continue after a previous page (`nextCursor`) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox logs`

Print a command's retained output by operation id.

```text
wssp sandbox logs [OPTIONS] <OPERATION_ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<OPERATION_ID>` | Operation id of the command (`wssp sandbox exec --detach` prints it) | required |
| `--follow` | Keep reading until the command completes |  |
| `--json` | Print `{operationId, state, exitCode, complete, stdout, stderr, truncated, gaps, restarts}` instead of streaming |  |

### `wssp sandbox stop`

Stop a sandbox (its disk is kept).

```text
wssp sandbox stop [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--wait` | Wait until the operation finishes (and, for `start`, the sandbox is READY) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox start`

Start a stopped sandbox again (cold reconnect).

```text
wssp sandbox start [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--wait` | Wait until the operation finishes (and, for `start`, the sandbox is READY) |  |
| `--json` | Emit JSON instead of human-readable text |  |
| `--timeout <DUR>` | New lease, counted from when the start is accepted: `30m`, `2h`, `1d` (`0`: no lease timer where policy allows it). Later starts reuse it. Default: the sandbox's remembered lease (the create's `--timeout`, or the last one a start set) |  |

### `wssp sandbox destroy`

Destroy a sandbox and its disk.

```text
wssp sandbox destroy [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--wait` | Wait until the operation finishes (and, for `start`, the sandbox is READY) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox files`

Guest files: list, stat, read, write, mkdir, move and remove.

```text
wssp sandbox files [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp sandbox files ls`

List a directory.

```text
wssp sandbox files ls [OPTIONS] <ID> <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest directory path | required |
| `--depth <N>` | Levels to list below the directory, 1–8 |  |
| `--limit <N>` | Page size, 1–100 (default 100) |  |
| `--cursor <C>` | Continue after a previous page (`nextCursor`) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox files stat`

Show one entry's metadata.

```text
wssp sandbox files stat [OPTIONS] <ID> <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest path | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox files read`

Print a file's bytes (or save them with `--output`).

```text
wssp sandbox files read [OPTIONS] <ID> <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest file path | required |
| `-o`, `--output <FILE>` | Write the bytes to this local file instead of stdout |  |
| `--json` | With `--output`: print `{path, bytes, sha256}` as JSON |  |

### `wssp sandbox files write`

Replace a file with the bytes of a local file or stdin.

```text
wssp sandbox files write [OPTIONS] --from <FILE|-> <ID> <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest file path | required |
| `--from <FILE|->` | Local file to upload, or `-` for stdin | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox files mkdir`

Create a directory.

```text
wssp sandbox files mkdir [OPTIONS] <ID> <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest path | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox files mv`

Move or rename an entry.

```text
wssp sandbox files mv [OPTIONS] <ID> <PATH> <DEST>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest source path | required |
| `<DEST>` | Absolute guest destination path | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox files rm`

Remove an entry.

```text
wssp sandbox files rm [OPTIONS] <ID> <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PATH>` | Absolute guest path | required |
| `-r`, `--recursive` | Remove a directory and everything in it |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox ports`

Preview tunnel ports: show, expose, change, close and link.

```text
wssp sandbox ports [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp sandbox ports get`

Show the tunnel: exposed ports, state and preview URLs.

```text
wssp sandbox ports get [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox ports expose`

Expose declared ports through the tunnel (default: every declared port).

```text
wssp sandbox ports expose [OPTIONS] <ID> [PORT]...
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PORT>` | Declared ports to expose (default: all of them) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox ports set`

Change the declared ports of a tunnel sandbox.

```text
wssp sandbox ports set [OPTIONS] <--add <PORT>|--remove <PORT>> <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--add <PORT>` | Port to declare (repeatable) |  |
| `--remove <PORT>` | Port to stop declaring (repeatable); removing an exposed port replaces the tunnel |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox ports close`

Close the tunnel; every link to it stops working.

```text
wssp sandbox ports close [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp sandbox ports link`

Mint a short-lived access link to one exposed port and print it.

```text
wssp sandbox ports link [OPTIONS] <ID> <PORT>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Sandbox id | required |
| `<PORT>` | The exposed port the link opens | required |
| `--ttl <S>` | Seconds the link can be redeemed, 30–3600 (default 60) |  |
| `--multi-use` | Let the link be opened more than once |  |
| `--session-ttl <S>` | Seconds the browser session it grants lasts, 60–86400 (default 3600) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp template`

List templates and their revisions.

```text
wssp template [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp template list`

List templates (newest first, one bounded page).

```text
wssp template list [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--limit <N>` | Page size, 1–100 (default 20) |  |
| `--cursor <C>` | Continue after a previous page (`nextCursor`) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp template get`

Show one template and its revisions.

```text
wssp template get [OPTIONS] <ID>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ID>` | Template id | required |
| `--cursor <C>` | Continue the revision list after a previous page (`revisionsNextCursor`) |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp ssh`

Open an ssh session to a sandbox with the system `ssh` (no keys); `--stdio` is the ProxyCommand endpoint.

```text
wssp ssh [OPTIONS] <SANDBOX> [-- <SSH-ARGS>...]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--stdio` | Speak SSH on stdin and stdout (the `ProxyCommand` of the generated config) |  |
| `<SANDBOX>` | Sandbox id or name (with `--stdio` also `<name-or-id>.wssp`) | required |
| `<SSH-ARGS>` | Arguments for `ssh` after `--` (options, then the remote command) |  |

### `wssp ssh-config`

Print or install the ssh config for `ssh <name>.wssp`, `scp` and `rsync`, and keep its local host key.

```text
wssp ssh-config [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--install` | Write `~/.ssh/config.d/wssp` and add `Include config.d/wssp` at the top of `~/.ssh/config` (asks first) |  |
| `--yes` | With `--install`: edit `~/.ssh/config` without asking |  |
| `--rotate-host-key` | Replace the local ssh host key and its known_hosts entry |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host`

Run this machine as a wssp host: enroll, run the node daemon, manage node settings.

```text
wssp host [OPTIONS] <COMMAND>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--all` | With `--help`: list every host subcommand, also on a machine that is not enrolled |  |

### `wssp host enroll`

Enroll this machine as a host: device login for a host slug, or a dashboard host token's environment variable.

```text
wssp host enroll [OPTIONS] <--slug <SLUG>|--token-env <ENV>>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--slug <SLUG>` | Sandbox host slug to enroll with the device flow (`host-slug:<slug>` scope) |  |
| `--token-env <ENV>` | Record the environment variable that holds a dashboard-minted host token instead of running the device flow (the token itself is never written to config) |  |
| `--server <SERVER>` | Control plane origin override (defaults to configured `server_url`) |  |
| `--json` | Emit JSON instead of human-readable text |  |
| `--open-egress-for-others <on|off>` | Let sandboxes from other users' pools reach the open internet from this machine. Without it, an interactive device enrollment asks once | one of `on`, `off` |

### `wssp host run`

Run the node daemon: connect to the sandbox host relay and execute dispatched operations.

```text
wssp host run [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--host-terminal <HOST_TERMINAL>` | Initial host-terminal override; later local policy changes take precedence | one of `on`, `off` |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--server <SERVER>` | Control plane origin (defaults to configured `server_url`) |  |
| `--host-token-env <HOST_TOKEN_ENV>` | Environment variable holding a dashboard host token (overrides saved selection) |  |
| `--host-id <HOST_ID>` | Sandbox host id (required with a host token; assigned automatically for device login) |  |
| `--label <LABEL>` | Human-readable label reported to the control plane | default `wssp-host` |
| `--runtime <RUNTIME>` | Sandbox execution backend. Defaults to Incus on Linux, fake elsewhere (`WSSP_RUNTIME=fake` also forces fake on Linux) | default depends on the platform (see description); one of `fake`, `incus` |
| `--incus-project <INCUS_PROJECT>` | Incus project for sandbox VMs (default: `WSSP_INCUS_PROJECT` or `wssp`; dedicated projects share `default` profiles and images; use `default` to skip auto-provisioning) |  |
| `--sandbox-vcpu-budget <SANDBOX_VCPU_BUDGET>` | Total vCPU budget (1..8192); TOML sandbox_vcpu_budget, otherwise threads x 2 |  |
| `--sandbox-memory-mib <SANDBOX_MEMORY_MIB>` | Optional RAM budget including per-VM host overhead in MiB (512..16777216, steps of 256). Overrides TOML sandbox_memory_mib, otherwise detected from the runtime |  |
| `--max-sandbox-cpu-count <MAX_SANDBOX_CPU_COUNT>` | Optional per-VM CPU cap (1..32), independent of the number of VMs. Overrides TOML max_sandbox_cpu_count, otherwise detected from the runtime |  |
| `--max-concurrent-commands <MAX_CONCURRENT_COMMANDS>` | Maximum concurrent commands across this host (1 to 256; default 16) | default `16` |

### `wssp host logout`

Clear the stored host device credential and, best effort, any configured host token binding.

```text
wssp host logout [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host drain`

Refuse new guest work on this host; running guests keep running.

```text
wssp host drain [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--server <SERVER>` | Control plane origin (defaults to the saved selection) |  |
| `--host-token-env <HOST_TOKEN_ENV>` | Environment variable holding a dashboard host token |  |
| `--host-id <HOST_ID>` | Host id (required with a dashboard host token) |  |
| `--json` | Print the committed drain state and live sandbox count as JSON |  |
| `--offload` | Drain only: also offload this host's stopped sandboxes to the image store, whatever their offload policy, and free their host copies once another eligible host could restore them. Undrain clears it |  |

### `wssp host undrain`

Restore admission on this host.

```text
wssp host undrain [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--server <SERVER>` | Control plane origin (defaults to the saved selection) |  |
| `--host-token-env <HOST_TOKEN_ENV>` | Environment variable holding a dashboard host token |  |
| `--host-id <HOST_ID>` | Host id (required with a dashboard host token) |  |
| `--json` | Print the committed drain state and live sandbox count as JSON |  |
| `--offload` | Drain only: also offload this host's stopped sandboxes to the image store, whatever their offload policy, and free their host copies once another eligible host could restore them. Undrain clears it |  |

### `wssp host images`

Inspect or prune the managed template image cache.

```text
wssp host images [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp host images list`

List managed cached images (fetched, captured, replicas).

```text
wssp host images list [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Print JSON |  |

### `wssp host images prune`

Evict unpinned images nothing uses (asks the running daemon).

```text
wssp host images prune [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--dry-run` | Only list what would be evicted |  |
| `--json` | Print JSON |  |

### `wssp host config`

Inspect and change node settings, the configuration file and resolved paths.

```text
wssp host config [OPTIONS] <COMMAND>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-agent-host-commands`

Allow agents to run host commands and use host file tools. The daemon user is an Incus admin: these tools can reach every sandbox on this node, including other users' sandboxes in shared pools. A credential's "own sandboxes only" setting does not limit host commands. Enabling requires local stdin and stderr TTYs, verified process ancestry outside the daemon, and typed confirmation.

```text
wssp host config set-agent-host-commands [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-host-command-max-time`

Cap each host command at 1..86400 seconds (default 600). Raising requires local confirmation.

```text
wssp host config set-host-command-max-time [OPTIONS] <SECONDS>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SECONDS>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-host-file-roots`

Set up to 32 absolute host file roots (never `/`). Adding roots requires local confirmation.

```text
wssp host config set-host-file-roots [OPTIONS] <PATHS>...
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<PATHS>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config clear-host-file-roots`

Disable host file tools by clearing their roots. Never prompts.

```text
wssp host config clear-host-file-roots [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-host-terminal`

Enable or disable host terminals locally.

```text
wssp host config set-host-terminal [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-host-terminal-totp`

Require TOTP, or permit host terminals without a fresh code.

```text
wssp host config set-host-terminal-totp [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `required`, `optional` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-max-lease`

Set this host's sandbox lease ceiling: `6h`, `90m`, `7d` (5m..24d) or `unlimited`. A running daemon reloads it and reports it to the server.

```text
wssp host config set-max-lease [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-carry-intent-window`

How long work that never started is carried across a relay outage: `10m` (1m..24h), or `default` (10 minutes). Never past the sandbox lease or `max_carry`. A restart of `wssp host run` applies it.

```text
wssp host config set-carry-intent-window [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-max-carry`

How long a running command is carried across a relay outage before the node stops it (`host_disconnect_expired`): `24h`, `7d` (10m..24d), or `default` (24 hours). A restart of `wssp host run` applies it.

```text
wssp host config set-max-carry [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-builder`

Run template-build VMs on this host: `on`, `off`, or `default` (on whenever the image cache is enabled). Build steps may run as guest root inside build VMs. A restart of `wssp host run` applies it.

```text
wssp host config set-builder [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off`, `default` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-accept-foreign-builds`

Run template builds for other accounts in shared pools (default off; also needs `accept_foreign_images`). A restart applies it.

```text
wssp host config set-accept-foreign-builds [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config path`

Print the path to the config file.

```text
wssp host config path [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config show`

Print the effective configuration (defaults merged with the file).

```text
wssp host config show [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config init`

Create a default config file if one does not already exist.

```text
wssp host config init [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-server`

Set the control plane server URL.

```text
wssp host config set-server [OPTIONS] <URL>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<URL>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-ca-file`

Save a PEM CA file for HTTPS/WSS (added to webpki roots).

```text
wssp host config set-ca-file [OPTIONS] <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<PATH>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config clear-ca-file`

Clear the saved CA file (WSSP_CA_FILE can still override it).

```text
wssp host config clear-ca-file [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-slug`

Store a host slug label (`wssp host enroll` still requires an explicit `--slug`).

```text
wssp host config set-slug [OPTIONS] <SLUG>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SLUG>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-open-egress-for-others`

Let sandboxes from other users' pools reach the open internet from this machine (your own sandboxes always can). A running daemon reloads it.

```text
wssp host config set-open-egress-for-others [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-allow-guest-sudo-for-others`

Let sandboxes from other users' pools use `sudo` (root inside their own VM) on this machine. Default on; your own sandboxes always can. A running daemon reloads it for the next create or cold reconnect.

```text
wssp host config set-allow-guest-sudo-for-others [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off`, `default` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-egress-block-smtp`

Reject outbound SMTP (tcp/25) from sandboxes created afterwards.

```text
wssp host config set-egress-block-smtp [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-egress-block-external-dns`

Reject DNS to resolvers other than the sandbox gateway, for sandboxes created afterwards.

```text
wssp host config set-egress-block-external-dns [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host config set-egress-dns-upstreams`

Upstream resolvers for open-internet sandboxes created afterwards: up to 4 comma-separated IPv4 addresses, or `--clear` for the host resolvers.

```text
wssp host config set-egress-dns-upstreams [OPTIONS] [IP,...]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<IP,...>` |  |  |
| `--clear` | Use the host resolvers again |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp host daemon`

Manage the running node daemon (graceful restart for upgrades).

```text
wssp host daemon [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp host daemon quiesce`

Gracefully restart the running daemon: finish running commands (up to `quiesce_max`, default 10 minutes), then exit for the service manager to restart. Use as the service's `ExecReload`.

```text
wssp host daemon quiesce [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--pid <PID>` | The daemon's process id, when not run by systemd (`$MAINPID` unset). Only a daemon whose control file verifies this pid is signalled |  |

### `wssp host guard`

Root-owned egress guard: install, uninstall and status.

```text
wssp host guard [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp host guard install`

Install or upgrade the egress guard system service (run with sudo).

```text
wssp host guard install [OPTIONS] --daemon-user <USER>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--daemon-user <USER>` | Unprivileged user that runs `wssp host run`; only it may push the deployment blocklist | required |
| `--configure-ufw` | Also add the minimal ufw rules sandbox bridges need (DHCP, DNS, login proxy in; routing in and out), printing each one |  |
| `--configure-firewalld` | Also add a minimal firewalld zone and policy for the sandbox bridges, printing each command |  |
| `--credential-proxy-port <PORT>` | The daemon's `credential_proxy_port`, opened by `--configure-ufw`/`--configure-firewalld` | default `48080` |

### `wssp host guard uninstall`

Remove the egress guard service (run with sudo); keeps /etc/wssp/egress-blocklist.

```text
wssp host guard uninstall [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--configure-ufw` | Also remove the ufw rules `install --configure-ufw` added (only those) |  |
| `--configure-firewalld` | Also remove the firewalld zone and policy `install --configure-firewalld` added |  |

### `wssp host guard status`

Show the egress guard's health lease, policy sources and bridges.

```text
wssp host guard status [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Print the status as JSON |  |

### `wssp host tunnel`

Preview tunnels: install, inspect or remove the pinned `tunnel` client.

```text
wssp host tunnel [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp host tunnel install`

Copy a `tunnel` client binary into wssp's data directory after checking its SHA-256, and enable preview tunnels (restart applies).

```text
wssp host tunnel install [OPTIONS] --file <FILE> --sha256 <SHA256>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--file <FILE>` | The client binary to install (a static `tunnel` build) | required |
| `--sha256 <SHA256>` | Its expected SHA-256 (64 lowercase hex characters) | required |
| `--max-tunnels <MAX_TUNNELS>` | Most tunnel clients at once (1..=256) | default `16` |
| `--allow-for-others` | Let sandboxes from other users' pools use tunnels here |  |

### `wssp host tunnel status`

Show the configured client and whether it still verifies.

```text
wssp host tunnel status [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Print JSON |  |

### `wssp host tunnel remove`

Disable preview tunnels on this node (restart applies).

```text
wssp host tunnel remove [OPTIONS]
```

No command-specific options.

### `wssp completions`

Generate shell completion scripts.

```text
wssp completions [OPTIONS] <SHELL>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SHELL>` | Shell to generate completions for | required; one of `bash`, `elvish`, `fish`, `powershell`, `zsh` |

<!-- END GENERATED -->
