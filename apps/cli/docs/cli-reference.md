# `wssp` command reference

This reference is generated from the clap definitions in `apps/cli/src/cli.rs`
and `apps/cli/src/commands/`, the same definitions that render `wssp --help`.
`cargo test -p wssp --test cli_reference` fails when it drifts; regenerate it
with `WSSP_BLESS_CLI_REFERENCE=1 cargo test -p wssp --test cli_reference`.
The same test checks every `wssp …` invocation written in the repository docs
against these commands and flags.

For behavior (enrollment, state directory, signals, drain semantics), see the
[CLI README](../README.md) and the [host operations guide](../../../docs/guide/hosts.md).

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

Without a list, connect inspects the audited profile-root pool and creates the
project-owned `wssp-pool-marker` filesystem volume once. Restore the original
marker/backing storage after identity failure; the daemon never repairs or deletes
it automatically. Implicit caps use free space, measured charged-root usage,
headroom and a persisted ceiling that can only fall. Only explicit TOML can raise
a cap. Pool drain blocks new roots; retained roots keep their pool and size.
`config show --json` is read-only and reports partial inspection when Incus or
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

### `wssp config`

Inspect the configuration file and resolved paths.

```text
wssp config [OPTIONS] <COMMAND>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-agent-host-commands`

Allow agents to run host commands and use host file tools. The daemon user is an Incus admin: these tools can reach every sandbox on this node, including other users' sandboxes in shared pools. A credential's "own sandboxes only" setting does not limit host commands. Enabling requires local stdin and stderr TTYs, verified process ancestry outside the daemon, and typed confirmation.

```text
wssp config set-agent-host-commands [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-host-command-max-time`

Cap each host command at 1..86400 seconds (default 600). Raising requires local confirmation.

```text
wssp config set-host-command-max-time [OPTIONS] <SECONDS>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SECONDS>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-host-file-roots`

Set up to 32 absolute host file roots (never `/`). Adding roots requires local confirmation.

```text
wssp config set-host-file-roots [OPTIONS] <PATHS>...
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<PATHS>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config clear-host-file-roots`

Disable host file tools by clearing their roots. Never prompts.

```text
wssp config clear-host-file-roots [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-host-terminal`

Enable or disable host terminals locally.

```text
wssp config set-host-terminal [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-host-terminal-totp`

Require TOTP, or permit host terminals without a fresh code.

```text
wssp config set-host-terminal-totp [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `required`, `optional` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-max-lease`

Set this host's sandbox lease ceiling: `6h`, `90m`, `7d` (5m..24d) or `unlimited`. A running daemon reloads it and reports it to the server.

```text
wssp config set-max-lease [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-carry-intent-window`

How long work that never started is carried across a relay outage: `10m` (1m..24h), or `default` (10 minutes). Never past the sandbox lease or `max_carry`. A restart of `wssp connect` applies it.

```text
wssp config set-carry-intent-window [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-max-carry`

How long a running command is carried across a relay outage before the node stops it (`host_disconnect_expired`): `24h`, `7d` (10m..24d), or `default` (24 hours). A restart of `wssp connect` applies it.

```text
wssp config set-max-carry [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-builder`

Run template-build VMs on this host: `on`, `off`, or `default` (on whenever the image cache is enabled). Build steps may run as guest root inside build VMs. A restart of `wssp connect` applies it.

```text
wssp config set-builder [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off`, `default` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-accept-foreign-builds`

Run template builds for other accounts in shared pools (default off; also needs `accept_foreign_images`). A restart applies it.

```text
wssp config set-accept-foreign-builds [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config path`

Print the path to the config file.

```text
wssp config path [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config show`

Print the effective configuration (defaults merged with the file).

```text
wssp config show [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config init`

Create a default config file if one does not already exist.

```text
wssp config init [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-server`

Set the control plane server URL.

```text
wssp config set-server [OPTIONS] <URL>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<URL>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-ca-file`

Save a PEM CA file for HTTPS/WSS (added to webpki roots).

```text
wssp config set-ca-file [OPTIONS] <PATH>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<PATH>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config clear-ca-file`

Clear the saved CA file (WSSP_CA_FILE can still override it).

```text
wssp config clear-ca-file [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-slug`

Store a host slug label (login still requires explicit `--slug`).

```text
wssp config set-slug [OPTIONS] <SLUG>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SLUG>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-open-egress-for-others`

Let sandboxes from other users' pools reach the open internet from this machine (your own sandboxes always can). A running daemon reloads it.

```text
wssp config set-open-egress-for-others [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-allow-guest-sudo-for-others`

Let sandboxes from other users' pools use `sudo` (root inside their own VM) on this machine. Default on; your own sandboxes always can. A running daemon reloads it for the next create or cold reconnect.

```text
wssp config set-allow-guest-sudo-for-others [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off`, `default` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-egress-block-smtp`

Reject outbound SMTP (tcp/25) from sandboxes created afterwards.

```text
wssp config set-egress-block-smtp [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-egress-block-external-dns`

Reject DNS to resolvers other than the sandbox gateway, for sandboxes created afterwards.

```text
wssp config set-egress-block-external-dns [OPTIONS] <VALUE>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<VALUE>` |  | required; one of `on`, `off` |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp config set-egress-dns-upstreams`

Upstream resolvers for open-internet sandboxes created afterwards: up to 4 comma-separated IPv4 addresses, or `--clear` for the host resolvers.

```text
wssp config set-egress-dns-upstreams [OPTIONS] [IP,...]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<IP,...>` |  |  |
| `--clear` | Use the host resolvers again |  |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp completions`

Generate shell completion scripts.

```text
wssp completions [OPTIONS] <SHELL>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<SHELL>` | Shell to generate completions for | required; one of `bash`, `elvish`, `fish`, `powershell`, `zsh` |

### `wssp login`

Device-code login for host enrollment.

```text
wssp login [OPTIONS] --slug <SLUG>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--slug <SLUG>` | Sandbox host slug to enroll (`host-slug:<slug>` scope) | required |
| `--server <SERVER>` | Control plane origin override (defaults to configured `server_url`) |  |
| `--json` | Emit JSON instead of human-readable text |  |
| `--open-egress-for-others <on|off>` | Let sandboxes from other users' pools reach the open internet from this machine. Without it, an interactive login asks once | one of `on`, `off` |

### `wssp logout`

Clear stored device credentials and, best effort, any configured host token binding.

```text
wssp logout [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp token`

Configure dashboard host token environment variables.

```text
wssp token [OPTIONS] <COMMAND>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp token login`

Record the environment variable that contains a dashboard-minted host token.

```text
wssp token login [OPTIONS] <ENV_VAR>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `<ENV_VAR>` |  | required |
| `--json` | Emit JSON instead of human-readable text |  |

### `wssp drain`

Refuse new guest work on this host; running guests keep running.

```text
wssp drain [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--server <SERVER>` | Control plane origin (defaults to the saved selection) |  |
| `--host-token-env <HOST_TOKEN_ENV>` | Environment variable holding a dashboard host token |  |
| `--host-id <HOST_ID>` | Host id (required with a dashboard host token) |  |
| `--json` | Print the committed drain state and live sandbox count as JSON |  |
| `--offload` | Drain only: also offload this host's stopped sandboxes to the image store and free their host copies once another eligible host could restore them. Undrain clears it |  |

### `wssp undrain`

Restore admission on this host.

```text
wssp undrain [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--ca-file <PATH>` | Add PEM CA certificates to webpki roots (default: WSSP_CA_FILE or saved ca_file) |  |
| `--server <SERVER>` | Control plane origin (defaults to the saved selection) |  |
| `--host-token-env <HOST_TOKEN_ENV>` | Environment variable holding a dashboard host token |  |
| `--host-id <HOST_ID>` | Host id (required with a dashboard host token) |  |
| `--json` | Print the committed drain state and live sandbox count as JSON |  |
| `--offload` | Drain only: also offload this host's stopped sandboxes to the image store and free their host copies once another eligible host could restore them. Undrain clears it |  |

### `wssp images`

Inspect or prune the managed template image cache.

```text
wssp images [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp images list`

List managed cached images (fetched, captured, replicas).

```text
wssp images list [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Print JSON |  |

### `wssp images prune`

Evict unpinned images nothing uses (asks the running daemon).

```text
wssp images prune [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--dry-run` | Only list what would be evicted |  |
| `--json` | Print JSON |  |

### `wssp connect`

Connect to the sandbox host relay and execute dispatched operations.

```text
wssp connect [OPTIONS]
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

### `wssp daemon`

Manage the running node daemon (graceful restart for upgrades).

```text
wssp daemon [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp daemon quiesce`

Gracefully restart the running daemon: finish running commands (up to `quiesce_max`, default 10 minutes), then exit for the service manager to restart. Use as the service's `ExecReload`.

```text
wssp daemon quiesce [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--pid <PID>` | The daemon's process id, when not run by systemd (`$MAINPID` unset). Only a daemon whose control file verifies this pid is signalled |  |

### `wssp guard`

Root-owned egress guard: install, status and the service entry point.

```text
wssp guard [OPTIONS] <COMMAND>
```

No command-specific options.

### `wssp guard install`

Install or upgrade the egress guard system service (run with sudo).

```text
wssp guard install [OPTIONS] --daemon-user <USER>
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--daemon-user <USER>` | Unprivileged user that runs `wssp connect`; only it may push the deployment blocklist | required |
| `--configure-ufw` | Also add the minimal ufw rules sandbox bridges need (DHCP, DNS, login proxy in; routing in and out), printing each one |  |
| `--configure-firewalld` | Also add a minimal firewalld zone and policy for the sandbox bridges, printing each command |  |
| `--credential-proxy-port <PORT>` | The daemon's `credential_proxy_port`, opened by `--configure-ufw`/`--configure-firewalld` | default `48080` |

### `wssp guard uninstall`

Remove the egress guard service (run with sudo); keeps /etc/wssp/egress-blocklist.

```text
wssp guard uninstall [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--configure-ufw` | Also remove the ufw rules `install --configure-ufw` added (only those) |  |
| `--configure-firewalld` | Also remove the firewalld zone and policy `install --configure-firewalld` added |  |

### `wssp guard status`

Show the egress guard's health lease, policy sources and bridges.

```text
wssp guard status [OPTIONS]
```

| Argument | Description | Notes |
| --- | --- | --- |
| `--json` | Print the status as JSON |  |

### `wssp guard run`

Service entry point, started by `wssp-guard.service` as root.

```text
wssp guard run [OPTIONS]
```

No command-specific options.

<!-- END GENERATED -->
