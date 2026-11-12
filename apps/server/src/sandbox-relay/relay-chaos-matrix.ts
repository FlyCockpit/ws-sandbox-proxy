/**
 * WP1 reconnect chaos matrix (reconnect plan rev 4, WP1 "PR subset"). Data
 * only: `relay-chaos.contract.test.ts` holds one case per cell (C13 has two,
 * cap and own timer) against the real debug daemon; a `pending` cell is
 * skipped. A cell's owner is the package whose change makes it pass.
 *
 * Per-cell assertions shared by every cell (plan WP1): the final state is in
 * the allowed set; at most one effect per (op, attempt); no UNKNOWN in a
 * `safe` cell; the daemon is still alive; after quiescence no unconfirmed
 * receipt, no unprocessed outbox row, and output byte-exact or an explicit
 * gap.
 */

type RelayChaosOwner = "WP0" | "WP1" | "WP2" | "WP3" | "WP4" | "WP7" | "P0-1" | "P0-2/WP4";

/** `pr`: `pnpm test:relay-chaos` (PR checks). `full`: nightly only (WP9). */
export type RelayChaosSubset = "pr" | "full";

/**
 * Faults a cell injects:
 * - proxy primitives (`relay-fault-proxy-harness.ts`): `reset`, `blackhole`,
 *   `closeWith`, `dropNext`, `holdThenReset`, `forwardThenReset`,
 *   `dropReplyThenReset`;
 * - `SrvR`: `dispose()`, then a new manager on the same `relayStore`;
 * - `SrvX`: no dispose, no disconnect write, proxy resets both sides;
 * - `DmnR`: SIGKILL, then respawn on the same data dir;
 * - `slowDb`: the fenced-store latency hook;
 * - `intentHold`: the FakeRuntime barrier files;
 * - `outage`: the daemon cannot reach the server for the cell's duration;
 * - `quiesce`: graceful quiesce-then-restart (WP7).
 */
type RelayChaosFault =
  | "reset"
  | "blackhole"
  | "closeWith"
  | "dropNext"
  | "holdThenReset"
  | "forwardThenReset"
  | "dropReplyThenReset"
  | "SrvR"
  | "SrvX"
  | "DmnR"
  | "slowDb"
  | "intentHold"
  | "outage"
  | "quiesce";

export type RelayChaosCell = {
  id: `C${number}`;
  scenario: string;
  /** What the cell proves, as stated in the plan. */
  expect: string;
  owner: RelayChaosOwner;
  subset: RelayChaosSubset;
  faults: readonly RelayChaosFault[];
  /** UNKNOWN_OUTCOME is a failure in this cell. */
  safe: boolean;
  /** `pending` skips the case (e.g. while it exposes an open bug). */
  status: "pending" | "enabled";
};

export const RELAY_CHAOS_MATRIX = [
  {
    id: "C1",
    scenario: "reset during command Effect",
    expect: "command SUCCEEDED",
    owner: "WP1",
    subset: "pr",
    faults: ["reset"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C2",
    scenario: "SrvR with output larger than the stream window",
    expect: "no output gap",
    owner: "WP1",
    subset: "pr",
    faults: ["SrvR"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C3",
    scenario: "server closes with 1000",
    expect: "daemon stays alive and reconnects",
    owner: "P0-1",
    subset: "pr",
    faults: ["closeWith"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C4",
    scenario: "server closes with 1013",
    expect: "daemon backs off before reconnecting",
    owner: "P0-1",
    subset: "pr",
    faults: ["closeWith"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C5",
    scenario: "300-frame adoption burst with a slow DB",
    expect: "no 1008, no false removal",
    owner: "P0-2/WP4",
    subset: "pr",
    faults: ["reset", "slowDb"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C6",
    scenario: "drop s2n operation.dispatch",
    expect: "operation runs exactly once",
    owner: "WP1",
    subset: "pr",
    faults: ["dropNext", "reset"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C7",
    scenario: "drop n2s operation.result",
    expect: "result recovered by receipt replay",
    owner: "WP1",
    subset: "pr",
    faults: ["holdThenReset"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C8",
    scenario: "drop receipt.confirmed",
    expect: "receipt replayed and confirmed once",
    owner: "WP1",
    subset: "pr",
    faults: ["dropReplyThenReset"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C9",
    scenario: "cancel while the daemon is away",
    expect: "cancel reaches the command after reconnect",
    owner: "WP1",
    subset: "pr",
    faults: ["reset", "outage"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C10",
    scenario: "versioned receipt replay",
    expect: "receipt never loops",
    owner: "WP0",
    subset: "pr",
    faults: ["dropReplyThenReset"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C11",
    scenario: "blackhole during census",
    expect: "work detaches on silence",
    owner: "WP2",
    subset: "pr",
    faults: ["blackhole"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C12",
    scenario: "outage longer than 60 s, within the command timeout",
    expect: "command SUCCEEDED",
    owner: "WP3",
    subset: "pr",
    faults: ["outage"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C13",
    scenario: "outage past max_carry; outage past the command timeout",
    expect: "host_disconnect_expired at the cap; timeout past the command timeout",
    owner: "WP3",
    subset: "pr",
    faults: ["outage"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C14",
    scenario: "SrvX",
    expect: "boot sweep, then command SUCCEEDED",
    owner: "WP4",
    subset: "pr",
    faults: ["SrvX"],
    safe: true,
    status: "enabled",
  },
  {
    id: "C15",
    scenario: "quiesce with a running command and a new command",
    expect: "running command finishes; new command is held, then runs on the respawned daemon",
    owner: "WP7",
    subset: "pr",
    faults: ["quiesce", "DmnR"],
    safe: true,
    status: "enabled",
  },
] as const satisfies readonly RelayChaosCell[];

/** Cells a run selects: the PR subset, or every cell for `:full`. */
export function relayChaosCells(subset: RelayChaosSubset): readonly RelayChaosCell[] {
  return subset === "full"
    ? RELAY_CHAOS_MATRIX
    : RELAY_CHAOS_MATRIX.filter((cell) => cell.subset === "pr");
}
