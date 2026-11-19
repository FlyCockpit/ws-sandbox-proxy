# Changelog

All notable changes will be documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.0.0 - Unreleased

### Changed

- CLI: every host command moved under `wssp host`, with no aliases for the old names: `wssp connect` is `wssp host run`, `wssp login --slug` is `wssp host enroll --slug`, `wssp token login <ENV>` is `wssp host enroll --token-env <ENV>`, `wssp logout` is `wssp host logout`, and `drain`, `undrain`, `images`, `config`, `daemon quiesce`, `guard` and `tunnel` are `wssp host …`. The guard service entry `wssp-guard guard run` is now the internal `wssp-guard __wssp-guard` (re-run `sudo wssp host guard install --daemon-user <user>` to rewrite the unit; an already installed guard keeps working). On a machine that is not an enrolled host, `wssp host --help` lists only `enroll` (`--help --all` shows everything) and `host run`, `host drain` and `host undrain` exit 6 there unless given an explicit `--host-token-env`. Update systemd units to `ExecStart=%h/.local/bin/wssp host run --runtime incus` and `ExecReload=%h/.local/bin/wssp host daemon quiesce`.

### Added

- CLI user side: `wssp login` (device flow with scope `user-login`; the browser approval chooses the key's name, read or write access, pools, own-sandboxes-only, live sandbox limit and expiry), `wssp logout` (self-revokes with `DELETE /v1/key`; `--local` skips the server), `wssp whoami`, `wssp sandbox create|list|get|exec|ps|logs|stop|start|destroy`, `wssp sandbox files ls|stat|read|write|mkdir|mv|rm`, `wssp sandbox ports get|expose|set|close|link` and `wssp template list|get`, all with `--json`. The login is saved at `<data_dir>/user/login.json` (0600) apart from host state; CI uses `WSSP_API_KEY` with `WSSP_SERVER`. New exit codes: 7 not logged in or 401, 8 forbidden, 9 limit reached, 10 conflict, 11 retryable, and for `sandbox exec` 125 (wssp failure or unknown outcome) and 130 (Ctrl-C); `sandbox exec` otherwise exits with the guest command's exit code. See docs/guide/cli.md.
- Owner-scoped Incus KVM sandboxes on enrolled Linux hosts, with host pools and capacity-aware placement.
- Native HTTP API and TypeScript SDK for commands, streamed output, files and resumable transfers.
- Localized web dashboard with browser terminals and PWA support.
- VM template builds from JSON recipes or a supported Dockerfile subset, plus capture and image distribution.
- Open egress by default behind a node nftables guard, with optional destination allowlists.
- Write-only CLI-login credential vault and signed webhooks.
- Linux CLI and outbound node daemon, shell installation from GitHub Releases, and server and worker images on GHCR.
- Committed schema migrations and a guarded Prisma Migrate runner with delayed removals and backup/restore commands.
- Static musl Linux CLI binaries for x86_64 and ARM64.
- Node 26.13.1 runtime and pnpm 12.18.0 tooling.
