# Releasing

Releases are automated by the root `Release` GitHub Actions workflow
(`.github/workflows/release.yml`) and
[`dist`](https://opensource.axo.dev/cargo-dist/) (cargo-dist). You bump the CLI
version, merge it to the default branch, then manually run the workflow with
that version tag. The supported CLI targets are Linux x86_64
(`x86_64-unknown-linux-musl`) and Linux ARM64 (`aarch64-unknown-linux-musl`).
Hosts and devices install it from their own server's `/install.sh`, which
downloads the release of that server's version.

The release configuration (`apps/cli/dist-workspace.toml`) builds those two
Linux targets as `wssp-<target>.tar.xz` archives with a `sha256.sum`, and
generates no installer of its own (`installers = []`): the server serves the
only one. GitHub Releases and GHCR are the supported release destinations.

The container images are published to GHCR as:

```text
ghcr.io/flycockpit/ws-sandbox-proxy:vX.Y.Z
ghcr.io/flycockpit/ws-sandbox-proxy:X.Y.Z
ghcr.io/flycockpit/ws-sandbox-proxy:sha-<commit-sha>
ghcr.io/flycockpit/ws-sandbox-proxy:latest   # only when publish_latest is true
```

The worker image uses the same tags on
`ghcr.io/flycockpit/ws-sandbox-proxy-worker`. Both app and worker carry the
Prisma Migrate runner and committed history; the app image runs one-shot
`migrate`, `backup` and `restore` commands.

## Cutting a release

```sh
# 1. Bump the version in apps/cli/Cargo.toml (e.g. 1.0.0 -> 1.0.1) and
#    SERVER_VERSION in apps/server/src/version.ts to the same version.
# 2. Merge that change to the default branch.
# 3. In GitHub Actions, run the root "Release" workflow from the default
#    branch with: version = v1.0.1
```

The workflow validates that it is running from the default branch and that the
requested `vX.Y.Z` tag matches `apps/cli/Cargo.toml` and `SERVER_VERSION`,
runs the release preflight gates, builds the CLI archives and checks them
(`scripts/release/check-cli-artifacts.sh`: both archives present, each named on
exactly one `sha256.sum` line, each holding `wssp-<target>/wssp`, every
checksum matching), and only then publishes the containers to GHCR, so no image
serves an `/install.sh` whose release cannot be published. It then checks the
uploaded files again, signs SLSA build provenance for the archives and
`sha256.sum` with [`actions/attest`](https://github.com/actions/attest)
(keyless: the job's OIDC token and Sigstore, no secret), and creates the GitHub
Release. Watch it in the repo's Actions tab; when it's green, the GitHub
Release has all the artifacts.

Between a version bump and its release, a server built from that commit serves
an `/install.sh` whose download fails ("is wssp X published there yet?") and
names the source build (`cargo install --git … --rev <commit>` when the image
carries its commit in `BUILD_VERSION`). Point `WSSP_CLI_RELEASE_BASE_URL` at a
mirror to install before the release exists.

## One-time setup

1. **Repos must be public** for `/install.sh` downloads, unauthenticated
   container pulls and build provenance attestations (on a private repository
   they need GitHub Enterprise) to work without GitHub tokens.
2. **GHCR package visibility:** after the first release, make the GHCR packages
   public if you want unauthenticated users to pull them.

## Installation after release

```sh
docker pull ghcr.io/flycockpit/ws-sandbox-proxy:latest
# then, on each host or device, from that server:
curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://<your-server>/install.sh | sh
```

The archives come from the GitHub Release of
https://github.com/FlyCockpit/ws-sandbox-proxy. Verify a downloaded archive's
provenance (needs the GitHub CLI):

```sh
gh attestation verify wssp-x86_64-unknown-linux-musl.tar.xz --repo FlyCockpit/ws-sandbox-proxy
```

## Changing release behavior

The root `.github/workflows/release.yml` owns release orchestration and is
hand-maintained — do not overwrite it with `dist generate` output. Cargo-dist
artifact behavior (targets, installers) still comes from
`dist-workspace.toml` here. When you change artifact targets or installers,
edit `dist-workspace.toml`, install `cargo-dist` if needed, then inspect the
generated output before porting the relevant changes into the root workflow:

```sh
cargo install cargo-dist # if `dist` is not already installed
dist init      # interactive; or
dist generate  # emit a reference release.yml from the config
```

CI has no "release drift" check, so review cargo-dist workflow changes
deliberately whenever you change `dist-workspace.toml`.

## Release toolchain

Cargo-dist is pinned to 0.34.0 in both `dist-workspace.toml` and the workflow's
installer URL. Review upstream notes and update both together:

- [0.33.0](https://github.com/axodotdev/cargo-dist/releases/tag/v0.33.0) moves flat-install `env` helpers from the binary directory to the receipt directory (normally `~/.config/<app>`). Its Windows signing support does not affect Linux artifacts.
- [0.33.1](https://github.com/axodotdev/cargo-dist/releases/tag/v0.33.1) refreshes dependencies and certificate trust lists.
- [0.34.0](https://github.com/axodotdev/cargo-dist/releases/tag/v0.34.0) changes the Apple Silicon runner default. This configuration ships only Linux targets and needs no corresponding config change.

Linux binaries use static musl with no glibc requirement. Native x86_64 builds
use ubuntu-latest; native ARM64 uses ubuntu-24.04-arm because GitHub has no
ubuntu-latest arm64 label. CI installs musl-tools, sets target-specific CC/linker
variables, rejects PT_INTERP/NEEDED entries with readelf and smoke-tests --version.
The archives include THIRD-PARTY-LICENSES.md with musl copyright notices.
The [cargo-dist 0.34 configuration reference](https://github.com/axodotdev/cargo-dist/blob/v0.34.0/book/src/reference/config.md#github-custom-runners)
defines the target triple keys and global runner override. Workflow action upgrades use Node 24 internally and require
GitHub-hosted runners or a sufficiently recent self-hosted runner (at least
2.329.0 for authenticated Git inside container actions). The build toolchain
uses Node 26.13.1 and pnpm 12.18.0. Checkout credentials live under `RUNNER_TEMP`; CLI artifact
checkouts disable persistence. Checkout refuses unsafe fork code under
privileged workflow triggers. Labeler keeps the `changed-files` matcher format;
setup-node explicitly caches pnpm where needed and supplies no dummy
registry token. Cache restore/save inputs and artifact archive defaults remain
compatible; artifact downloads enforce digest verification.
