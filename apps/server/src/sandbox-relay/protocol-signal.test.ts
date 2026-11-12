import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { processRefSchema } from "@wssp/sandbox-contracts";
import { expect, it, vi } from "vitest";
import { encodeServerControlMessage, type ServerControlMessage } from "./protocol";

vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

// Shared with `apps/cli/src/sandbox_relay/connect.rs` (E4-01).
type Dispatch = Extract<ServerControlMessage, { type: "operation.dispatch" }>;
const fixture = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../../crates/sandbox-protocol/fixtures/control_process_signal.json",
    ),
    "utf8",
  ),
) as {
  queuedPayload: Record<string, unknown>;
  dispatch: Dispatch & { pid: number };
  refusedDispatch: Dispatch[];
};

it("derives the signal wire pid from the queued qualified target only", async () => {
  const { signalDispatchPid } = await import("./session-manager");
  const payload = fixture.queuedPayload;
  // processes.signal queues the qualified ref and no top-level pid.
  expect(payload.pid).toBeUndefined();
  const process = processRefSchema.parse(payload.process);
  expect(signalDispatchPid({ kind: "process.signal", process })).toBe(fixture.dispatch.pid);
  expect(signalDispatchPid({ kind: "command.run", process })).toBeUndefined();
  expect(signalDispatchPid({ kind: "process.signal" })).toBeUndefined();
});

it("encodes the shared signal frame and refuses one whose pid is not its target's", () => {
  expect(JSON.parse(encodeServerControlMessage(fixture.dispatch, "1.0"))).toEqual(fixture.dispatch);
  for (const message of fixture.refusedDispatch)
    expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow(
      "Invalid process identity field.",
    );
  expect(() =>
    encodeServerControlMessage(
      { ...fixture.dispatch, kind: "file.stat", process: undefined, targetOperationId: undefined },
      "1.0",
    ),
  ).toThrow("Invalid process identity field.");
});
