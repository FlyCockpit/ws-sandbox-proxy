import {
  CREDENTIAL_CHUNK_RAW_BYTES,
  redactCredentialFrame,
  type ServerCredentialMessage,
} from "@wssp/sandbox-contracts";
import { beforeEach, describe, expect, it, vi } from "vitest";

const relay = vi.hoisted(() => ({
  commitCapture: vi.fn(),
  grantInstallBundle: vi.fn(),
  grantRestoreBundle: vi.fn(),
  readOperationSpecChunks: vi.fn(),
  applyCompleteCensus: vi.fn(),
}));
vi.mock("@wssp/api/credentials/relay", async (importActual) => {
  const actual = await importActual<typeof import("@wssp/api/credentials/relay")>();
  return {
    ...relay,
    accumulateCensusPage: actual.accumulateCensusPage,
    newCensusAccumulator: actual.newCensusAccumulator,
    issueCurrentReturnKey: vi.fn(),
    recordInstalled: vi.fn(),
    recordReturnKeyAck: vi.fn(),
    recordScrubbed: vi.fn(),
  };
});
vi.mock("@wssp/db", () => ({ default: {} }));
vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_URL: "https://wssp.example.test/x" } }));

const { CredentialSessionRelay } = await import("./credential-handlers.js");

const SENTINEL = "SENTINEL-credential-plaintext";
const sender = { userId: "owner", hostId: "host-1", connectionEpoch: 3 };

function harness() {
  const sent: ServerCredentialMessage[] = [];
  return { sent, session: new CredentialSessionRelay(sender, (frame) => sent.push(frame)) };
}

function beginFrame(captureId: string, envelopeLen: number) {
  return {
    type: "credential.capture.begin" as const,
    captureId,
    leaseId: "lease-1",
    bindingId: "binding-1",
    kidR: "0123456789abcdef",
    kind: "stop" as const,
    envelopeDigest: "a".repeat(64),
    envelopeLen,
    chunkCount: Math.ceil(envelopeLen / CREDENTIAL_CHUNK_RAW_BYTES),
  };
}

beforeEach(() => vi.clearAllMocks());

describe("credential session relay", () => {
  it("reassembles a capture in order, commits it once and acks the fence outcome", async () => {
    const { sent, session } = harness();
    const envelope = Buffer.alloc(CREDENTIAL_CHUNK_RAW_BYTES + 10, 7);
    let seen: Buffer | null = null;
    relay.commitCapture.mockImplementation(async (s: { envelope: Buffer }) => {
      seen = Buffer.from(s.envelope);
      return { outcome: "committed" };
    });
    await session.handle(beginFrame("cap-1", envelope.byteLength));
    for (let seq = 0; seq < 2; seq++)
      await session.handle({
        type: "credential.capture.chunk",
        captureId: "cap-1",
        seq,
        data: envelope
          .subarray(seq * CREDENTIAL_CHUNK_RAW_BYTES, (seq + 1) * CREDENTIAL_CHUNK_RAW_BYTES)
          .toString("base64url"),
      });
    expect(relay.commitCapture).toHaveBeenCalledTimes(1);
    expect(relay.commitCapture.mock.calls[0]![0]).toMatchObject({
      hostId: "host-1",
      connectionEpoch: 3,
      serverOrigin: "https://wssp.example.test",
      captureId: "cap-1",
    });
    expect(seen!.equals(envelope)).toBe(true);
    // The assembly buffer is zeroed once the fence returns.
    expect(
      (relay.commitCapture.mock.calls[0]![0] as { envelope: Buffer }).envelope.every(
        (b) => b === 0,
      ),
    ).toBe(true);
    expect(sent).toEqual([
      { type: "credential.capture.ack", captureId: "cap-1", outcome: "committed" },
    ]);
  });

  it("drops an out-of-order or mis-sized chunk and never commits it", async () => {
    const { session } = harness();
    await session.handle(beginFrame("cap-2", 100));
    await session.handle({
      type: "credential.capture.chunk",
      captureId: "cap-2",
      seq: 0,
      data: Buffer.alloc(99).toString("base64url"),
    });
    await session.handle({
      type: "credential.capture.chunk",
      captureId: "cap-2",
      seq: 0,
      data: Buffer.alloc(100).toString("base64url"),
    });
    expect(relay.commitCapture).not.toHaveBeenCalled();
  });

  it("over the per-host assembly budget a capture acks DEFERRED (the host retries)", async () => {
    const { sent, session } = harness();
    await session.handle(beginFrame("a", 100));
    await session.handle(beginFrame("b", 100));
    await session.handle(beginFrame("c", 100));
    expect(sent).toEqual([{ type: "credential.capture.ack", captureId: "c", outcome: "deferred" }]);
    session.dispose();
  });

  it("streams a granted bundle as begin + chunks, zeroes it, and keeps the plaintext out of every redacted frame", async () => {
    const { sent, session } = harness();
    const bytes = Buffer.concat([Buffer.alloc(CREDENTIAL_CHUNK_RAW_BYTES), Buffer.from(SENTINEL)]);
    relay.grantInstallBundle.mockResolvedValue({
      kind: "granted",
      bindingId: "binding-9",
      storageSeq: 4,
      fileCount: 1,
      envCount: 0,
      bytes,
    });
    await session.handle({
      type: "credential.bundle.request",
      requestId: "req-1",
      sandboxId: "sbx-1",
      leaseId: "lease-1",
      operationId: "op-1",
      reason: "install",
    });
    expect(sent.map((f) => f.type)).toEqual([
      "credential.bundle.begin",
      "credential.bundle.chunk",
      "credential.bundle.chunk",
    ]);
    expect(sent[0]).toMatchObject({
      bindingId: "binding-9",
      storageSeq: 4,
      bundleLen: bytes.byteLength,
      chunkCount: 2,
    });
    expect(bytes.every((b) => b === 0)).toBe(true);
    const logged = JSON.stringify(sent.map((f) => redactCredentialFrame(f)));
    expect(logged).not.toContain(Buffer.from(SENTINEL).toString("base64url"));
    expect(logged).not.toContain(SENTINEL);
  });

  it("a refused grant is answered with its code; a refused spec request with spec_unavailable", async () => {
    const { sent, session } = harness();
    relay.grantRestoreBundle.mockResolvedValue({ kind: "refused", code: "stale" });
    relay.readOperationSpecChunks.mockResolvedValue(null);
    await session.handle({
      type: "credential.bundle.request",
      requestId: "req-2",
      sandboxId: "sbx-1",
      leaseId: "lease-1",
      bindingId: "binding-1",
      reason: "restore_env",
    });
    await session.handle({
      type: "credential.spec.request",
      operationId: "op-1",
      digest: "b".repeat(64),
    });
    expect(sent).toEqual([
      { type: "credential.bundle.refused", requestId: "req-2", code: "stale" },
      { type: "credential.spec.refused", operationId: "op-1", code: "spec_unavailable" },
    ]);
  });

  it("acks census pages and applies only the complete census", async () => {
    const { sent, session } = harness();
    relay.applyCompleteCensus.mockResolvedValue([{ hostId: "host-1", captureIds: ["q1"] }]);
    const page = (n: number, complete: boolean) => ({
      type: "credential.census" as const,
      page: n,
      complete,
      keyEpoch: 2,
      quarantined: [],
      entries: [],
    });
    await session.handle(page(0, false));
    expect(relay.applyCompleteCensus).not.toHaveBeenCalled();
    await session.handle(page(1, true));
    expect(relay.applyCompleteCensus).toHaveBeenCalledTimes(1);
    expect(sent).toEqual([
      { type: "credential.census.ack", page: 0 },
      { type: "credential.census.ack", page: 1 },
      { type: "credential.quarantine.discard", captureIds: ["q1"], reason: "owner_discard" },
    ]);
  });
});
