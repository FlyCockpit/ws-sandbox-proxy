# CLI Agent & Contributor Guide

This file covers the Rust CLI under `apps/cli`. The repo-root `AGENTS.md` still
applies; use this file for CLI-specific conventions.

`CLAUDE.md` and `.cursorrules` are generated mirrors of this file.
Edit `AGENTS.md`, then run `cargo xtask sync-docs`. CI fails if the mirrors drift.

## What This Is

The `wssp` command-line tool and outbound node daemon for WS Sandbox Proxy. The
workspace root `Cargo.toml` also builds `crates/sandbox-protocol` (relay
contract + framing) and `crates/sandbox-runtime` (`SandboxRuntime`, `FakeRuntime`,
Linux `IncusKvmRuntime` via the `incus` CLI, and non-Linux `UnsupportedRuntime`).

`wssp host run` runs the outbound relay (`src/sandbox_relay/`). On Linux the
default runtime is Incus (`--runtime fake` or `WSSP_RUNTIME=fake` for relay-only
work). Every host command lives under `wssp host` (`src/commands/host.rs`);
`completions` is the only other top-level command.

The CLI is not part of the pnpm/Turborepo graph — no `package.json`. All work
here happens with `cargo`, run from the repo root.

## Orientation

| Path                 | What's there                                                                          |
| -------------------- | ------------------------------------------------------------------------------------- |
| `src/lib.rs`         | Shared implementation modules used by the binary and tests.                           |
| `src/main.rs`        | Entry point: parse arguments, initialize logging, dispatch, map errors to exit codes. |
| `src/cli.rs`         | Clap argument definitions. Keep CLI shape here and command logic elsewhere.           |
| `src/commands/`      | One file per subcommand, each exposing `Args` and `run(&Args)`.                       |
| `src/config.rs`      | Local TOML config structs, load/save.                                                 |
| `src/paths.rs`       | Cross-platform config/data directories via `dirs`.                                    |
| `src/logging.rs`     | Tracing setup. Logs go to stderr.                                                     |
| `src/exit.rs`        | Stable process exit codes.                                                            |
| `src/host_role.rs`   | Local-only enrolled-host detection for role-aware `wssp host` help and exit 6.        |
| `src/shutdown.rs`    | SIGTERM/SIGINT graceful shutdown for `wssp host run` (`signal-hook`).                 |
| `src/sandbox_relay/` | Outbound node daemon.                                                                 |
| `tests/cli.rs`       | Black-box tests that run the built binary.                                            |
| `xtask/`             | CLI workspace automation: `sync-docs`.                                                |
| `docs/`              | Error handling and release notes.                                                     |

## Everyday Commands

Run from the repo root:

```sh
cargo build
cargo test
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt
cargo run -p wssp -- host config path
cargo xtask sync-docs
```

Before considering a CLI change done, run:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
# Canonical serial runner
cargo test --workspace --all-targets --locked -- --test-threads=1
# Fast local runner (dev tool; no retries). Nextest excludes doctests.
cargo nextest run --workspace --all-targets --locked -j 6
cargo test --workspace --doc --locked
cargo xtask sync-docs --check
```

`cargo deny check` and `typos` also run in CI.

## Hard Rules

1. Do not weaken lint or CI gates to make a change pass. Fix the issue instead.
2. Do not bypass commit or CI checks with `git commit --no-verify` or force-pushing the default branch.
3. No `unsafe`; the crate forbids it.
4. No secrets in source, tests, fixtures, docs, or commit messages.
5. Do not add dependencies casually. Prefer the standard library and explain new crates.
6. stdout is for command output only. Logs, progress, and diagnostics go to stderr.
7. No `unwrap()`, `panic!`, `todo!`, or `dbg!` in non-test code.
8. Do not run destructive shell commands or `sudo` on the user's behalf.
9. Do not create backup copies such as `.bak`, `.old`, or copied source files.
10. Do not launch live Incus VMs from agent work (`incus-surface`,
    `wssp host run --runtime incus`) unless the user explicitly asks. Tests use
    `FakeRuntime`.

## Conventions

- Application code returns `anyhow::Result<T>`. Add context at file, network, parse, and protocol boundaries.
- Quote identifiers and paths in backticks. Keep error messages lowercase and omit trailing periods.
- Exit codes are public behavior; see `src/exit.rs` before adding or changing one.
- Any command that prints structured data should support `--json` and emit from a typed `Serialize` struct.
- Use `src/output.rs` for stdout writes so output behavior stays deliberate.
- Pure logic tests can live next to code under `#[cfg(test)]`; CLI behavior tests belong in `tests/`.
- Host tokens are `wssp_host_…`. Config stores env-var _names_ for secrets, not values.

## Adding a Command

1. Add `src/commands/<name>.rs` with an `Args` type and `run(&Args) -> anyhow::Result<()>`.
2. Register the module in `src/commands/mod.rs`.
3. Add a variant to `HostCommand` in `src/commands/host.rs` (a host command;
   decide `allowed_without_enrollment`) or to `Command` in `src/cli.rs`.
4. Add the match arm in `commands::host::run` or `src/main.rs`.
5. Add focused black-box tests in `tests/cli.rs` when the command affects user-visible behavior.

## Releasing

Releases are handled by the root `Release` GitHub Actions workflow and `dist` (cargo-dist).

1. Bump `version` in `apps/cli/Cargo.toml`.
2. Merge that change to the default branch.
3. Manually run the root `Release` workflow with the matching tag, for example `v1.0.1`.
4. The supported CLI and node-daemon platform is Linux. The workflow publishes Linux CLI artifacts and a shell installer to GitHub Releases, and containers to GHCR.

Cargo-dist artifact behavior lives in `dist-workspace.toml`; the root release workflow owns monorepo orchestration. See `docs/releasing.md`.
