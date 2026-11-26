# Changelog

All notable changes will be documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.0.0 - Unreleased

First release.

### Added

- Owner-scoped Incus KVM sandboxes on enrolled Linux hosts, with host pools and capacity-aware placement.
- Native HTTP API (`/v1`) and TypeScript SDK (`@wssp/sdk`) for commands, streamed output, files and resumable transfers, plus an MCP endpoint for agents.
- Localized web dashboard with browser terminals and PWA support.
- VM template builds from JSON recipes or a supported Dockerfile subset, community base templates, template capture and image distribution.
- Disk offload of stopped sandboxes to the image store.
- Open egress by default behind a node nftables guard, with optional destination allowlists.
- Write-only CLI-login credential vault and signed webhooks.
- Linux CLI (`wssp`) and outbound node daemon (`wssp host …`), installed from GitHub Releases with a shell installer; static musl binaries for x86_64 and ARM64.
- CLI user side: `wssp login` (browser-approved device flow), `wssp sandbox …`, `wssp template …`, all with `--json`. See docs/guide/cli.md.
- Connect plane (`wssp.connect.v1`): `wssp sandbox shell` (interactive or piped, remote signals and exit status) and `wssp sandbox forward` (local TCP ports or a Unix socket to the sandbox's own loopback). See docs/guide/connect.md.
- `ssh <name-or-id>.wssp` with plain OpenSSH (`ssh`, `scp`, `sftp`, `rsync`, `-L`/`-D` forwards, VS Code Remote-SSH, JetBrains Gateway) through `wssp ssh-config`, with no SSH keys or passwords. The CLI's `ssh` feature vendors russh 0.65.4 with a small flow-control patch (`third_party/`). See docs/guide/connect.md#ssh.
- Server and worker images on GHCR with a guarded Prisma Migrate runner (committed migrations, delayed removals) and backup/restore commands.
- Node 26.13.1 runtime and pnpm 12.18.0 tooling.

### Operator notes

- **Upgrades:** update the server before the node daemons, and run server, daemons and CLI from the same release. The relay accepts exactly protocol 1.0 and refuses any other version. See docs/guide/hosts.md.
- **Egress guard:** every node needs the root-owned guard (`sudo wssp host guard install --daemon-user <user>`); without a healthy guard a node takes no new sandboxes. See docs/guide/network.md.
- **Guests:** shells, forwards and SSH need systemd 254 or later in the guest image.
- **Backups** are off by default; `BACKUP_ENABLED=true` needs a usable destination or every migrating start fails. See docs/operations/backup-and-restore.md.
- **Forced 2FA:** the 24-hour enrollment grace counts from account creation, so turning on forced 2FA for non-admin users applies at once to accounts older than a day. See docs/operations/production-hardening.md#forced-two-factor-authentication.
