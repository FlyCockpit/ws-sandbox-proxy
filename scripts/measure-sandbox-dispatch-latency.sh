#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
pnpm exec vitest run apps/server/src/sandbox-relay/outbox-processor.integration.test.ts \
  --maxWorkers=1 --reporter=default --silent=false -t 'measures six concurrent fake clients'
