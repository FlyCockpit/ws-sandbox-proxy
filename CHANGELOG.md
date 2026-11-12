# Changelog

All notable changes will be documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.0.0 - Unreleased

### Added

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
