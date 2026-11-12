#!/usr/bin/env bash
# dev-docker.sh — port-parameterized local docker-compose stack for agents.
#
# Local agent UI-testing stack. This wrapper:
#   1. detects docker/podman (override via CONTAINER_RUNTIME)
#   2. validates the requested port
#   3. sets COMPOSE_PROJECT_NAME=<repo-slug>-<path-hash>-<port> so runs isolate
#      by repo+port
#   4. writes .agent-ports.json with the URL + helper commands
#   5. execs compose up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
# shellcheck source=lib/dev-docker-runtime.sh
. "$SCRIPT_DIR/lib/dev-docker-runtime.sh"

usage() {
  cat >&2 <<'EOF_USAGE'
Usage: pnpm dev:docker <port> [--prod] [--reset] [--rootless-podman]

Start a local dev stack on <port>. Web dev server is published on
127.0.0.1:<port> (loopback only — see BIND_ADDR below); postgres and redis are
internal to the compose network (not exposed on the host).

Flags:
  --prod     Build and run the production Dockerfile instead of `pnpm dev`.
             Slower first run but tests the real production artifact.
             Browsers use the self-signed https front on
             https://localhost:<port+6100> (certificate warning expected);
             CLI uses that same origin with --ca-file (see docs/guide/hosts.md).
  --rootless-podman  Use podman-compose --in-pod false and keep-id for app-dev.
                    Ignored with Docker; saved for logs/down.
  --reset    Tear the stack down (wiping the ephemeral database) before
             starting. Equivalent to running `pnpm dev:docker:down <port>`
             first.
  -h, --help Show this help.

Environment:
  CONTAINER_RUNTIME   Force "docker" or "podman". Default: auto-detect.
  BIND_ADDR           Host interface the published ports bind to. Default
                      127.0.0.1 (loopback only) so the stack is never reachable
                      off-box — important on a shared VPS, where Docker bypasses
                      ufw/firewalld. Set BIND_ADDR=0.0.0.0 to reach it from
                      another device on your LAN (e.g. the PWA on a real phone).

Multi-agent isolation: COMPOSE_PROJECT_NAME=<repo-slug>-<path-hash>-<port>
(the repo directory name + a short hash of its canonical path + the port), so
each project+port gets its own isolated network, containers, and ephemeral
volumes — two different projects on the same host (e.g. a shared VPS) never
collide even if both repos are named the same thing.

Examples:
  pnpm dev:docker 3100
  pnpm dev:docker 3200 --prod
  pnpm dev:docker 3100 --reset
EOF_USAGE
}

# ---------------------------------------------------------------------------
# Parse args
# ---------------------------------------------------------------------------
PORT=""
PROFILE="dev"
RESET=0
PODMAN_ROOTLESS=false

while [ $# -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --prod)    PROFILE="prod"; shift ;;
    --reset)   RESET=1; shift ;;
    --rootless-podman) PODMAN_ROOTLESS=true; shift ;;
    --)        shift; break ;;
    -*)        echo "error: unknown flag: $1" >&2; usage; exit 1 ;;
    *)
      if [ -z "$PORT" ]; then
        PORT="$1"
        shift
      else
        echo "error: unexpected argument: $1" >&2
        usage
        exit 1
      fi
      ;;
  esac
done

if [ -z "$PORT" ]; then
  echo "error: <port> is required" >&2
  usage
  exit 1
fi

case "$PORT" in
  ''|*[!0-9]*)
    echo "error: port must be numeric, got: $PORT" >&2
    exit 1
    ;;
esac

if [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "error: port must be between 1024 and 65535" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Runtime + compose detection
# ---------------------------------------------------------------------------
RUNTIME=$(dev_docker_detect_runtime)
[ "$RUNTIME" = "podman" ] || PODMAN_ROOTLESS=false
COMPOSE=$(dev_docker_pick_compose "$RUNTIME" "$PODMAN_ROOTLESS")

cd "$ROOT_DIR"

dev_docker_export_project_name "$ROOT_DIR" "$PORT"
export WEB_PORT="$PORT"
# Mailpit's web UI / REST API host port. Derived from WEB_PORT with a +5000
# offset so it lands in a separate band (8100..9100 for the default 3100..4100
# web range) and never collides with another instance's web port. Mailpit is
# the dev profile's local SMTP sink — captured signup/verification emails are
# readable at http://localhost:$MAILPIT_PORT (UI) and .../api/v1/messages.
export MAILPIT_PORT="$((PORT + 5000))"
# Prod profile only: host port of the self-signed https front (tls-proxy in
# docker-compose.agent.yml). The production image requires an https
# BETTER_AUTH_URL, so browsers use https://localhost:$TLS_PORT. +6100 lands
# in its own band (9200..10200 for the default 3100..4100 web range), clear of
# both the web and Mailpit bands.
export TLS_PORT="$((PORT + 6100))"
if [ "$PROFILE" = "prod" ] && [ "$TLS_PORT" -gt 65535 ]; then
  echo "error: --prod needs <port> + 6100 <= 65535 for the https front" >&2
  exit 1
fi
# Host interface the published ports bind to. Default 127.0.0.1 (loopback only)
# so the stack is never reachable off-box — critical on a shared VPS, where
# Docker's iptables rules sit ahead of ufw/firewalld and a 0.0.0.0 binding
# would be public even behind a closed host firewall. Opt in for LAN access
# (e.g. testing the PWA on a real phone) with: BIND_ADDR=0.0.0.0 pnpm dev:docker <port>.
export BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
# Pass the host UID/GID through so the dev container runs as the same user
# that owns the bind-mounted repo. Without this, the container runs as root
# and every file it writes inside /app (turbo cache, vite cache, generated
# prisma client, dist output, etc.) lands on the host owned by root.
HOST_UID=$(id -u)
HOST_GID=$(id -g)
export HOST_UID HOST_GID

COMPOSE_FILE="docker-compose.agent.yml"
COMPOSE_FILES=(-f "$COMPOSE_FILE")
if [ "$PODMAN_ROOTLESS" = "true" ]; then
  COMPOSE_FILES+=(-f "$ROOT_DIR/docker-compose.podman-rootless.yml")
fi

# ---------------------------------------------------------------------------
# Per-project node_modules live in a gitignored repo dir instead of Docker
# named volumes (see docker-compose.agent.yml). Export the absolute root for
# compose interpolation and pre-create the subdirs as the host user so the
# container (which runs as HOST_UID:HOST_GID) can write into them — Docker
# would otherwise create missing bind sources as root.
# ---------------------------------------------------------------------------
dev_docker_export_volume_root "$ROOT_DIR"

# node_modules bind-mount helpers (workspace enumeration, nm_<slug> naming and
# the compose coverage guard) live in lib/dev-docker-runtime.sh so
# `pnpm policy:checks` runs the same coverage check without starting a stack.
create_volume_dirs() {
  mkdir -p "$AGENT_VOLUME_ROOT/nm_root"
  while IFS= read -r d; do
    mkdir -p "$AGENT_VOLUME_ROOT/$(dev_docker_nm_slug "$ROOT_DIR" "$d")"
  done < <(dev_docker_workspace_pkg_dirs "$ROOT_DIR")
}

# Per-stack secrets: 32 random bytes as lowercase hex (scripts/generate-secrets.ts'
# secret32 format), generated once per stack into the gitignored volume root
# (0600), so dev:docker:down / --reset removes them with the ephemeral DB.
# Never committed, never printed, never a fixed value.
#   - SANDBOX_REQUEST_HMAC_SECRET is required in every environment and must
#     stay stable for the life of the stack's database (it keys stored
#     idempotency digests). Compose reads AGENT_SANDBOX_REQUEST_HMAC_SECRET.
#   - BETTER_AUTH_SECRET for the --prod image (NODE_ENV=production): the
#     .env.docker.defaults placeholder is weak by design and a developer's .env
#     value is a dev secret, so app-prod takes AGENT_BETTER_AUTH_SECRET instead
#     (docker-compose.agent.yml). Stable across re-runs so sessions survive.
ensure_stack_secret() {
  local file="$AGENT_VOLUME_ROOT/$1" value
  if [ ! -s "$file" ]; then
    mkdir -p "$AGENT_VOLUME_ROOT"
    ( umask 077 && od -An -v -tx1 -N32 /dev/urandom | tr -d ' \n' > "$file" )
  fi
  value="$(cat "$file")"
  case "$value" in
    *[!0-9a-f]*|'')
      echo "error: $file is not lowercase hex; run pnpm dev:docker:down $PORT" >&2
      exit 1
      ;;
  esac
  if [ "${#value}" -ne 64 ]; then
    echo "error: $file is not 32 bytes of hex; run pnpm dev:docker:down $PORT" >&2
    exit 1
  fi
  printf -v "$2" '%s' "$value"
  export "${2?}"
}

ensure_stack_secrets() {
  ensure_stack_secret sandbox-request-hmac-secret AGENT_SANDBOX_REQUEST_HMAC_SECRET
  ensure_stack_secret better-auth-secret AGENT_BETTER_AUTH_SECRET
}

assert_volume_coverage() {
  dev_docker_assert_volume_coverage "$ROOT_DIR" "$COMPOSE_FILE" || exit 1
}

# ---------------------------------------------------------------------------
# --reset: tear the project down first (wipes the ephemeral DB + deps cache)
# ---------------------------------------------------------------------------
if [ "$RESET" = "1" ]; then
  echo "[dev-docker] --reset: tearing down $COMPOSE_PROJECT_NAME…"
  # shellcheck disable=SC2086
  $COMPOSE "${COMPOSE_FILES[@]}" --profile dev --profile prod down -v --remove-orphans || true
  rm -rf "$AGENT_VOLUME_ROOT"
fi

# ---------------------------------------------------------------------------
# Port availability — allow the port if our own project already owns it
# ---------------------------------------------------------------------------
if dev_docker_port_in_use "$PORT"; then
  owner=$("$RUNTIME" ps --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" -q 2>/dev/null || true)
  if [ -z "$owner" ]; then
    echo "error: port $PORT is already in use by another process." >&2
    echo "       Pick a different port, or run: pnpm find-free-port" >&2
    exit 1
  fi
fi
if [ "$PROFILE" = "prod" ] && dev_docker_port_in_use "$TLS_PORT"; then
  owner=$("$RUNTIME" ps --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" -q 2>/dev/null || true)
  if [ -z "$owner" ]; then
    echo "error: https front port $TLS_PORT (<port> + 6100) is already in use by another process." >&2
    exit 1
  fi
fi

if [ "$PROFILE" = "prod" ]; then
  WEB_URL="https://localhost:$TLS_PORT"
  HTTP_URL_JSON="
  \"cliUrl\": \"https://localhost:$TLS_PORT\","
else
  WEB_URL="http://localhost:$PORT"
  HTTP_URL_JSON=""
fi

# ---------------------------------------------------------------------------
# Persist chosen port for agent discovery
# ---------------------------------------------------------------------------
cat > .agent-ports.json <<EOF_JSON
{
  "port": $PORT,
  "project": "$COMPOSE_PROJECT_NAME",
  "volumeRoot": "$AGENT_VOLUME_ROOT",
  "runtime": "$RUNTIME",
  "podmanRootless": "$PODMAN_ROOTLESS",
  "profile": "$PROFILE",
  "url": "$WEB_URL",$HTTP_URL_JSON
  "mailpit": "http://localhost:$MAILPIT_PORT",
  "logs": "pnpm dev:docker:logs $PORT",
  "down": "pnpm dev:docker:down $PORT"
}
EOF_JSON

# ---------------------------------------------------------------------------
# Up
# ---------------------------------------------------------------------------
echo "[dev-docker] runtime=$RUNTIME  compose=\"$COMPOSE\"  project=$COMPOSE_PROJECT_NAME  profile=$PROFILE"
echo "[dev-docker] web will be reachable at: $WEB_URL"
if [ "$PROFILE" = "prod" ]; then
  echo "[dev-docker]   (self-signed certificate: accept the browser warning, or curl -k)"
  echo "[dev-docker] CLI origin: $WEB_URL (use --ca-file; see docs/guide/hosts.md)"
fi
if [ "$BIND_ADDR" != "127.0.0.1" ] && [ "$BIND_ADDR" != "localhost" ]; then
  echo "[dev-docker] WARNING: BIND_ADDR=$BIND_ADDR — ports are published beyond" >&2
  echo "[dev-docker]          loopback. On a public host this exposes the dev" >&2
  echo "[dev-docker]          stack (and its default credentials) to the network." >&2
fi
echo "[dev-docker] tail logs: pnpm dev:docker:logs $PORT"
echo "[dev-docker] tear down: pnpm dev:docker:down $PORT"
echo

assert_volume_coverage
create_volume_dirs
ensure_stack_secrets

# shellcheck disable=SC2086
exec $COMPOSE "${COMPOSE_FILES[@]}" --profile "$PROFILE" up --build
