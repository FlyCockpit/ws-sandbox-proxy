# Sandbox dispatch latency

Reproduce from the repository root:

```sh
bash scripts/measure-sandbox-dispatch-latency.sh
```

The script runs the `measures six concurrent fake clients` integration scenario in
`apps/server/src/sandbox-relay/outbox-processor.integration.test.ts`. It starts
`startSandboxOutboxProcessor` and the production notifier, outbox scanner and
session manager. Six concurrent logical clients each enqueue 20 echo tool cycles
through the production transaction/outbox helper. Each client waits for its host
result to commit before submitting its next cycle. They share one owner, sandbox
and fake host socket, including contention on the sandbox row.

The host performs hello/reconcile, receives real encoded dispatch messages, and
returns successful fake echo results through the production ordered receive queue
after a 1 ms simulated runtime delay. The per-row READ COMMITTED Prisma double
persists attempts, claims, outbox rows and results; the socket checks that each
send observes committed claim/attempt/epoch authority. All 120 results must reach
SUCCEEDED. Only DB/Valkey/worker I/O and the host socket/runtime are faked; neither
the dispatcher drain nor session-manager methods are mocked. No live VM is used.

Timing uses real timers and `performance.now()`. Enqueue-to-send starts immediately
before the enqueue transaction and ends at the socket's dispatch send; cycle
latency ends after the result receive queue (including result commit/confirmation)
finishes. Percentiles use nearest rank over all 120 samples. Setup/hello time is
excluded. This measures the in-memory fake harness, including its assertions and
lock double, and is not a Postgres/network/Incus performance prediction.

Measured on 2026-09-24, one heavy command at a time:

| Metric (ms)                          |   p50 |    p95 |    max |
| ------------------------------------ | ----: | -----: | -----: |
| Enqueue → socket send                | 4.898 |  8.535 | 17.207 |
| Enqueue → committed fake host result | 8.555 | 14.334 | 24.096 |

Recorded script output:

```text
DISPATCH_LATENCY {"clients":6,"cyclesPerClient":20,"samples":120,"enqueueToSendMs":{"p50":4.898,"p95":8.535,"max":17.207},"cycleMs":{"p50":8.555,"p95":14.334,"max":24.096}}
Test Files  1 passed (1)
Tests       1 passed | 20 skipped (21)
```

The script deliberately selects only the measurement; the ordinary test gate runs
all 21 integration scenarios. Separate fake-timer regressions hold commit/send
barriers and exercise expired-create results/receipts, in-scan finalization,
reconciliation, acceptance of waiting stdin/cancel, rollback, restart and shutdown.
Their immediate-dispatch assertions do not advance the 2,000 ms recovery clock.
Startup and periodic recovery still use the same exclusive dispatcher.
