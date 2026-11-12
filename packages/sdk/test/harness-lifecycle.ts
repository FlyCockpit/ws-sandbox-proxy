/**
 * C57 harness-shaped lifecycle fixture: the sandbox lifecycle an external
 * agent harness drives, written against the PUBLIC SDK surface only (no
 * transport internals, no server imports). The server conformance suite
 * (`apps/server/src/sandbox-relay/lifecycle-conformance.pg.test.ts`) runs it
 * through the real `/v1` adapters; nothing here knows what is behind `fetch`.
 *
 * create → ready → binary seed → long-running script → nonzero result →
 * diagnostics → capture → retain (stop) → cold reconnect → warm reconnect →
 * destroy.
 */
import { createHash } from "node:crypto";
import {
  COMMAND_TIMEOUT_MAX_MS,
  type OutputEvent,
  type SandboxDto,
  type WsspClient,
} from "../src/index";

/** Deterministic bytes that are NOT valid UTF-8 (lone continuations, 0xFF, NULs). */
export function binarySeed(length: number, seed: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let state = seed >>> 0 || 1;
  for (let i = 0; i < length; i++) {
    // xorshift32: seeded, platform-independent.
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    bytes[i] = state & 0xff;
  }
  // Guarantee the invalid-UTF-8 shapes regardless of the PRNG stream.
  bytes.set([0xff, 0xfe, 0x80, 0x00, 0xc3, 0x28, 0xed, 0xa0, 0x80], 0);
  return bytes;
}

export const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");

export type HarnessLifecycleInput = {
  template: string;
  sandboxHostId: string;
  seed: Uint8Array;
  seedPath: string;
  /** A script the fixture's guest keeps running for a long (simulated) time. */
  longScript: string;
  /** A script whose exit status is nonzero. */
  failingScript: string;
  /** Called between steps: lets the suite inject loss or advance a fake clock. */
  between?: (step: HarnessStep, sandbox: SandboxDto | undefined) => Promise<void>;
};

export type HarnessStep =
  | "create"
  | "seed"
  | "long-script"
  | "nonzero"
  | "diagnostics"
  | "capture"
  | "retain"
  | "cold-reconnect"
  | "warm-reconnect"
  | "destroy";

export type HarnessTranscript = {
  sandboxId: string;
  steps: HarnessStep[];
  /** Stable placement: the host every READY read reported. */
  placements: string[];
  seedSha256: string;
  longRun: { operationId: string; exitCode: number; stdout: string; events: number };
  nonzero: { operationId: string; exitCode: number };
  diagnostics: { state: string; exitCode: number | null; complete: boolean; tail: string };
  captureSha256: string;
  captureBytes: number;
  states: Record<string, string>;
};

export async function runHarnessLifecycle(
  client: WsspClient,
  input: HarnessLifecycleInput,
): Promise<HarnessTranscript> {
  const steps: HarnessStep[] = [];
  const placements: string[] = [];
  const states: Record<string, string> = {};
  const step = async (name: HarnessStep, sandbox?: SandboxDto) => {
    steps.push(name);
    if (sandbox) {
      states[name] = sandbox.state;
      if (sandbox.hostId) placements.push(sandbox.hostId);
    }
    await input.between?.(name, sandbox);
  };

  const created = await client.sandboxes.create({
    template: input.template,
    sandboxHostId: input.sandboxHostId,
    timeoutMs: 3_600_000,
    lifecycle: { onTimeout: "stop" },
  });
  await step("create", created);
  const id = created.id;

  const upload = await client.files.writeBytes(id, input.seedPath, input.seed);
  await step("seed");

  let events = 0;
  const long = await client.commands.run(
    id,
    // The 30-minute bootstrap budget: the guest-side maximum, in the command
    // input (waitTimeoutMs separately bounds SDK observation).
    { script: input.longScript, timeoutMs: COMMAND_TIMEOUT_MAX_MS },
    {
      onOutput: (event: OutputEvent) => {
        if (event.kind === "data") events += 1;
      },
    },
  );
  await step("long-script");

  const failing = await client.commands.script(id, input.failingScript, { check: false });
  await step("nonzero");

  // Diagnostics from the operation ID alone, as a detached broker would.
  const stat = await client.commands.stat(failing.operationId);
  const tail = await client.commands.tail(failing.operationId, { maxChars: 4096 });
  await step("diagnostics");

  const captured = await client.files.readBytes(id, input.seedPath);
  await step("capture");

  await step("retain", await client.sandboxes.stop(id));
  const cold = await client.sandboxes.connect(id, { mode: "cold", leaseTimeoutMs: 3_600_000 });
  await step("cold-reconnect", cold);
  const warm = await client.sandboxes.connect(id, { mode: "warm" });
  await step("warm-reconnect", warm);
  await client.sandboxes.destroy(id);
  await step("destroy");

  return {
    sandboxId: id,
    steps,
    placements,
    seedSha256: upload.sha256,
    longRun: {
      operationId: long.operationId,
      exitCode: long.exitCode,
      stdout: long.stdout,
      events,
    },
    nonzero: { operationId: failing.operationId, exitCode: failing.exitCode },
    diagnostics: {
      state: stat.state,
      exitCode: stat.exitCode,
      complete: stat.complete,
      tail: tail.stdout,
    },
    captureSha256: sha256Hex(captured),
    captureBytes: captured.byteLength,
    states,
  };
}
