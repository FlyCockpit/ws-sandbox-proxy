/**
 * The installers this server serves, so a new host or device installs the `wssp` that matches it:
 *
 * - `GET /install.sh` (`installScript`): downloads this version's Linux release archive, checks it
 *   against the release's `sha256.sum` (fail closed), installs `wssp` into `~/.local/bin` (where
 *   the hosts guide's systemd unit runs it), and prints the next step for a device
 *   (`wssp login`) and for a host (`wssp host enroll`, the egress guard, `wssp host run`).
 * - `GET /install.ps1` (`windowsExplainer`): wssp has no Windows build (the CLI and daemon are
 *   Linux-only), so `irm … | iex` gets a script that only says to use WSL 2 and stops.
 *
 * Both are static for the life of the process (their inputs are env), use the canonical
 * `BETTER_AUTH_URL` origin (never the request's Host or X-Forwarded-* headers), and touch no
 * database or Redis.
 */

import { env } from "@wssp/env/server";
import type { Env, Hono } from "hono";
import { SERVER_VERSION } from "./version.js";

/** Where the CLI's source and GitHub Releases live. */
export const CLI_REPOSITORY = "https://github.com/FlyCockpit/ws-sandbox-proxy";

/**
 * The release targets (`wssp-<target>.tar.xz`, listed in `sha256.sum`), as
 * `apps/cli/dist-workspace.toml` builds them: static musl builds run on any Linux libc.
 */
export const CLI_RELEASE_TARGETS = [
  "x86_64-unknown-linux-musl",
  "aarch64-unknown-linux-musl",
] as const;

/** The Rust version a source build needs (`apps/cli/Cargo.toml` `rust-version`). */
export const CLI_MIN_RUST = "1.99";

const INSTALL_SCRIPT_PATH = "/install.sh";
const WINDOWS_INSTALL_PATH = "/install.ps1";

/** The GitHub Release of this server's version. */
export function defaultCliReleaseBaseUrl(): string {
  return `${CLI_REPOSITORY}/releases/download/v${SERVER_VERSION}`;
}

/** `WSSP_CLI_RELEASE_BASE_URL` (a mirror) wins; else this version's GitHub Release. */
export function cliReleaseBaseUrl(configured: string | undefined): string {
  return (configured || defaultCliReleaseBaseUrl()).replace(/\/+$/, "");
}

/** The command that installs wssp from `origin` (docs, the dashboard's enrolment card). */
export function installCommand(origin: string): string {
  const url = `${origin.replace(/\/+$/, "")}${INSTALL_SCRIPT_PATH}`;
  return url.startsWith("https://")
    ? `curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 ${url} | sh`
    : `curl -fsSL --max-time 120 ${url} | sh`;
}

// Values are embedded in single quotes; refuse anything that could leave them. `[` and `]` let
// an IPv6 origin through (inert inside single quotes).
function shellQuoted(value: string): string {
  if (!/^[A-Za-z0-9._~%+@:/=[\]-]*$/.test(value)) {
    throw new Error(`install.sh: refusing to embed ${JSON.stringify(value)}`);
  }
  return `'${value}'`;
}

/**
 * The POSIX installer (`curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 <origin>/install.sh | sh`).
 *
 * The whole script is one `{ … }` group closed on the last line: the shell parses the group
 * before running any of it, so a download cut short anywhere is a syntax error and runs nothing.
 * The archive is installed only after its SHA-256 matches exactly one well-formed `sha256.sum`
 * entry, it holds the expected binary and nothing outside its directory, and the binary reports
 * this server's version. `commit` (the server's own 40-hex build commit, when known) names the
 * source build a machine without a release binary can run instead.
 */
export function installScript(
  origin: string,
  releaseBaseUrl: string,
  commit: string | null = null,
): string {
  const releaseUrl = releaseBaseUrl.replace(/\/+$/, "");
  const rev = commit && /^[0-9a-f]{40}$/.test(commit) ? commit : "";
  return `#!/bin/sh
# WS Sandbox Proxy CLI (wssp) installer for ${origin}
#
# Installs the wssp ${SERVER_VERSION} release binary for this Linux machine into ~/.local/bin,
# after checking its SHA-256 against the release's sha256.sum (it stops on any mismatch), then
# prints the next step. Run it as the user who will use wssp (not root):
#
#   curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 ${origin}/install.sh | sh
#
# Options (curl … | sh -s -- <options>): --install-dir <absolute directory>.
{
set -eu
umask 077

WSSP_VERSION=${shellQuoted(SERVER_VERSION)}
WSSP_RELEASE_URL=${shellQuoted(releaseUrl)}
WSSP_ORIGIN=${shellQuoted(origin)}
WSSP_REPOSITORY=${shellQuoted(CLI_REPOSITORY)}
WSSP_SOURCE_REV=${shellQuoted(rev)}
WSSP_MIN_RUST=${shellQuoted(CLI_MIN_RUST)}

say() { printf 'wssp: %s\\n' "$*"; }
die() { printf 'wssp: %s\\n' "$*" >&2; exit 1; }

usage() {
  cat <<'USAGE'
Installs wssp, checksum-verified, into ~/.local/bin.

  curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 <server>/install.sh | sh
  curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 <server>/install.sh | sh -s -- --install-dir /usr/local/bin

  --install-dir <dir>  install into this absolute directory (needed to install as root)
USAGE
}

# The build a machine runs when no release binary fits it or the release is missing.
source_hint() {
  if [ -n "$WSSP_SOURCE_REV" ]; then
    printf 'build it with Rust %s or newer: cargo install --git %s --rev %s --locked wssp' \\
      "$WSSP_MIN_RUST" "$WSSP_REPOSITORY" "$WSSP_SOURCE_REV"
  else
    printf 'build it with Rust %s or newer from a checkout of %s: cargo install --path apps/cli --locked --bin wssp' \\
      "$WSSP_MIN_RUST" "$WSSP_REPOSITORY"
  fi
}

# A value printed inside single quotes in a command to copy; nothing here may leave them.
plain() {
  case "$1" in
    *"'"* | *[[:cntrl:]]*) return 1 ;;
  esac
}

parse_args() {
  install_dir=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --install-dir)
        [ $# -ge 2 ] || die "--install-dir needs a directory."
        install_dir=$2
        shift 2
        ;;
      --install-dir=*)
        install_dir=\${1#--install-dir=}
        shift
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *) die "unknown option $1 (see --help)." ;;
    esac
  done
}

detect_target() {
  [ "$(uname -s)" = Linux ] ||
    die "wssp runs on Linux only. On Windows, run this in a WSL 2 shell."
  machine=$(uname -m)
  case "$machine" in
    x86_64 | amd64) target=x86_64-unknown-linux-musl ;;
    aarch64 | arm64) target=aarch64-unknown-linux-musl ;;
    *) die "there is no wssp release binary for $machine; $(source_hint)." ;;
  esac
}

# The install directory: --install-dir, else ~/.local/bin (never root's: the daemon, wssp login
# and the sandbox commands run as a normal user; the egress guard is the only root step). It must
# be owned by this user and writable by nobody else, since the binary is staged and verified in it.
choose_dir() {
  if [ -n "$install_dir" ]; then
    case "$install_dir" in
      /*) dir=$install_dir ;;
      *) die "--install-dir must be an absolute path." ;;
    esac
  else
    [ "$(id -u)" != 0 ] ||
      die "run this as the user who will run wssp, not as root (wssp prints the one root step, the egress guard). To install for root anyway, pass --install-dir."
    [ -n "\${HOME:-}" ] || die "set HOME, or pass --install-dir."
    case "$HOME" in
      /*) dir="$HOME/.local/bin" ;;
      *) die "HOME is not an absolute path; pass --install-dir." ;;
    esac
  fi
  plain "$dir" || die "the install directory must not contain quotes or control characters."
  requested_dir=$dir
  mkdir -p "$dir" || die "could not create $dir."
  dir=$(CDPATH='' cd -- "$dir" && pwd -P) || die "could not open $requested_dir."
  plain "$dir" || die "the install directory must not contain quotes or control characters."
  owner=$(ls -ldn "$dir" | awk '{ print $3 }')
  [ "$owner" = "$(id -u)" ] ||
    die "$dir belongs to another user; pass --install-dir with a directory you own."
  case "$(ls -ld "$dir" | cut -c6,9)" in
    *w*) die "other users can write to $dir; pass --install-dir with a directory only you can write." ;;
  esac
  # Every directory above it, too: one another user can write to (unless sticky, like /tmp) or
  # owns would let them swap the install directory for theirs while the binary is checked.
  parent=$dir
  while [ "$parent" != / ]; do
    parent=\${parent%/*}
    [ -n "$parent" ] || parent=/
    owner=$(ls -ldn "$parent" | awk '{ print $3 }')
    [ "$owner" = 0 ] || [ "$owner" = "$(id -u)" ] ||
      die "$parent belongs to another user; pass --install-dir with a directory only you or root can change the parents of."
    case "$(ls -ld "$parent" | cut -c6,9,10)" in
      *t | *T) ;;
      *w*) die "other users can write to $parent; pass --install-dir with a directory only you or root can change the parents of." ;;
    esac
  done
}

# curl only: wget cannot refuse a redirect away from https for a single download. Bounded: a
# server that stalls (under 1 KiB/s for a minute) or takes over 15 minutes fails the download.
fetch() {
  curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 30 --speed-limit 1024 --speed-time 60 \\
    --max-time 900 --max-filesize 268435456 --retry 3 -o "$2" "$1"
}

# Hashes stdin, so no file name (escaped by sha256sum when it holds a backslash) reaches the output.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum <"$1"
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 <"$1"
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r <"$1"
  fi
}

check_tools() {
  command -v curl >/dev/null 2>&1 || die "curl is needed to download wssp; install curl."
  command -v tar >/dev/null 2>&1 || die "tar is needed to unpack wssp; install tar."
  command -v xz >/dev/null 2>&1 || command -v unxz >/dev/null 2>&1 ||
    die "xz is needed to unpack wssp; install xz-utils (Debian, Ubuntu) or xz."
  command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 ||
    command -v openssl >/dev/null 2>&1 ||
    die "no SHA-256 tool (sha256sum, shasum or openssl) found; not installing an unverified binary."
}

install_release() {
  archive="wssp-$target.tar.xz"
  # Staged inside the install directory, not /tmp: the binary is test-run before it is installed
  # (a noexec /tmp would refuse that), and the final rename stays on one filesystem.
  tmp=$(mktemp -d "$dir/.wssp-install.XXXXXX") || die "could not create a staging directory in $dir."
  trap 'rm -rf "$tmp"' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  say "downloading wssp $WSSP_VERSION for $target from $WSSP_RELEASE_URL..."
  fetch "$WSSP_RELEASE_URL/sha256.sum" "$tmp/sha256.sum" ||
    die "could not download $WSSP_RELEASE_URL/sha256.sum: is wssp $WSSP_VERSION published there yet? Or $(source_hint)."
  # Exactly one well-formed line names the archive ("<hex>  <name>" or "<hex> *<name>"); a second
  # line, or a malformed one that mentions it, refuses the file.
  expected=$(awk -v f="$archive" '
    { sub(/\\r$/, "") }
    index($0, f) { seen++ }
    NF == 2 && ($2 == f || $2 == "*" f) { found++; hash = tolower($1) }
    END { if (seen == 1 && found == 1) print hash }' "$tmp/sha256.sum")
  case "$expected" in
    "" | *[!0-9a-f]*) die "sha256.sum has no single valid checksum for $archive; not installing it." ;;
  esac
  [ \${#expected} -eq 64 ] || die "sha256.sum has no single valid checksum for $archive; not installing it."
  fetch "$WSSP_RELEASE_URL/$archive" "$tmp/$archive" ||
    die "could not download $WSSP_RELEASE_URL/$archive."
  actual=$(sha256_of "$tmp/$archive" | awk '{ print tolower($1) }')
  [ -n "$actual" ] || die "could not compute the SHA-256 of $archive; not installing it."
  [ "$actual" = "$expected" ] ||
    die "checksum mismatch for $archive (expected $expected, got $actual); not installing it."
  say "checksum verified ($expected)."
  # Only wssp-<target>/ entries, no "..", one binary; then only the binary is unpacked. Listing
  # and unpacking are size-bounded (ulimit -f, 512-byte blocks): 1 MiB of names, a 512 MiB binary.
  (ulimit -f 2048 && exec tar -tJf "$tmp/$archive") >"$tmp/members" 2>/dev/null ||
    die "could not read $archive (tar needs xz)."
  awk -v d="wssp-$target" '
    $0 != d && $0 != d "/" && index($0, d "/") != 1 { bad = 1 }
    $0 ~ /(^|\\/)[.][.](\\/|$)/ { bad = 1 }
    $0 == d "/wssp" { binaries++ }
    END { exit !(binaries == 1 && !bad) }' "$tmp/members" ||
    die "$archive does not have the layout of a wssp release; not installing it."
  mkdir "$tmp/unpacked"
  (cd "$tmp/unpacked" && ulimit -f 1048576 && exec tar -xJf "../$archive" "wssp-$target/wssp") ||
    die "could not unpack $archive."
  unpacked="$tmp/unpacked/wssp-$target"
  [ -d "$unpacked" ] && [ ! -L "$unpacked" ] && [ -f "$unpacked/wssp" ] && [ ! -L "$unpacked/wssp" ] ||
    die "$archive does not contain the wssp binary; not installing it."
  # A new file of ours: owner, mode and type never come from the archive.
  cat "$unpacked/wssp" >"$tmp/wssp" && chmod 755 "$tmp/wssp" || die "could not stage wssp."
  # Bounded: at most 30 s (where timeout(1) exists) and 512 bytes of output (ulimit -f stops a
  # binary that keeps printing), so a broken build cannot hang or fill the install.
  # timeout -k also kills a binary that ignores TERM; an older timeout without -k still bounds it.
  probe=""
  if timeout -k 5 30 true >/dev/null 2>&1; then
    probe="timeout -k 5 30"
  elif command -v timeout >/dev/null 2>&1; then
    probe="timeout 30"
  fi
  (ulimit -f 1 && exec $probe "$tmp/wssp" --version) >"$tmp/version" 2>/dev/null </dev/null ||
    die "the downloaded wssp does not run on this machine; $(source_hint)."
  version=$(sed -n 1p "$tmp/version")
  [ "$version" = "wssp $WSSP_VERSION" ] ||
    die "the downloaded binary reports \\"$version\\", not wssp $WSSP_VERSION; not installing it."
  [ ! -d "$dir/wssp" ] || die "$dir/wssp is a directory; remove it, then run this again."
  # Rename over the old binary: a running daemon keeps its old file.
  mv -f "$tmp/wssp" "$dir/wssp" || die "could not install into $dir."
}

next_steps() {
  installed="$dir/wssp"
  say "installed wssp $WSSP_VERSION at $installed."
  wssp=wssp
  case ":\${PATH:-}:" in
    *":$requested_dir:"* | *":$dir:"*)
      found=$(command -v wssp 2>/dev/null || true)
      if [ -n "$found" ] && [ "$found" != "$installed" ] && [ "$found" != "$requested_dir/wssp" ]; then
        say "warning: $found comes first on your PATH; remove it, or run '$installed'."
        wssp="'$installed'"
      fi
      ;;
    *)
      say "$dir is not on your PATH. Add it (and to your shell profile):"
      say "  export PATH='$dir':\\"\\$PATH\\""
      wssp="'$installed'"
      ;;
  esac
  # The daemon never runs as root (the guard refuses --daemon-user root): as root, the host
  # steps name the normal user that will run it.
  user=$(id -un 2>/dev/null || true)
  if [ "$(id -u)" = 0 ] || [ -z "$user" ] || ! plain "$user"; then user='"$USER"'; else user="'$user'"; fi
  echo
  say "Next, on a computer you use wssp from (sandboxes, shells, files):"
  say "  $wssp login --server '$WSSP_ORIGIN'"
  echo
  say "Or, on a machine that will host sandboxes (replace my-host with a name for it):"
  [ "$(id -u)" != 0 ] ||
    say '  (as the normal user that will run the daemon, not root; the shell fills in $USER)'
  say "  $wssp host enroll --slug my-host --server '$WSSP_ORIGIN'"
  say "  sudo '$installed' host guard install --daemon-user $user"
  say "  $wssp host run"
  say "Then run the daemon as a systemd user service: $WSSP_REPOSITORY/blob/main/docs/guide/hosts.md#run-as-a-service"
}

main() {
  parse_args "$@"
  detect_target
  check_tools
  choose_dir
  install_release
  next_steps
}

main "$@"
}
`;
}

/**
 * `/install.ps1`: wssp has no Windows build. Thrown, never `exit` (which would close the
 * PowerShell window `irm … | iex` runs in).
 */
export function windowsExplainer(origin: string): string {
  const command = installCommand(origin);
  if (!/^[A-Za-z0-9._~%+@:/=[\]' |-]*$/.test(command)) {
    throw new Error(`install.ps1: refusing to embed ${JSON.stringify(origin)}`);
  }
  // PowerShell single-quoted string: a quote is written twice.
  const quoted = `'wssp runs on Linux only: there is no Windows build. In a WSL 2 shell, run: ${command.replaceAll("'", "''")}'`;
  return `# WS Sandbox Proxy CLI (wssp) for ${origin}
# wssp runs on Linux only. In a WSL 2 shell, run:
#   ${command}
throw ${quoted}
`;
}

export function registerInstallRoutes<E extends Env>(
  app: Hono<E>,
  options: { commit?: string | null; releaseBaseUrl?: string } = {},
): Hono<E> {
  const origin = new URL(env.BETTER_AUTH_URL).origin;
  // Rendered once: a bad value fails at startup, not on a node's first install.
  const script = installScript(
    origin,
    cliReleaseBaseUrl(options.releaseBaseUrl ?? env.WSSP_CLI_RELEASE_BASE_URL),
    options.commit ?? null,
  );
  const explainer = windowsExplainer(origin);
  app.get(INSTALL_SCRIPT_PATH, (c) =>
    c.body(script, 200, {
      "Content-Type": "text/x-shellscript; charset=utf-8",
      "Cache-Control": "no-store",
    }),
  );
  app.get(WINDOWS_INSTALL_PATH, (c) =>
    c.body(explainer, 200, {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    }),
  );
  return app;
}
