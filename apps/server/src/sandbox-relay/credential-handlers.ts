import {
  accumulateCensusPage,
  applyCompleteCensus,
  type CensusAccumulator,
  commitCapture,
  grantInstallBundle,
  grantRestoreBundle,
  issueCurrentReturnKey,
  newCensusAccumulator,
  type QuarantineDiscard,
  readOperationSpecChunks,
  recordInstalled,
  recordReturnKeyAck,
  recordScrubbed,
} from "@wssp/api/credentials/relay";
import prisma from "@wssp/db";
import { env } from "@wssp/env/server";
import {
  CREDENTIAL_CHUNK_RAW_BYTES,
  chunkDataLength,
  type DaemonCredentialMessage,
  type ServerCredentialMessage,
} from "@wssp/sandbox-contracts";
import type { RelaySender } from "./operation-handlers.js";

/**
 * Host-plane credential frames. Thin transport
 * glue: every decision is made by the fenced services in
 * `@wssp/api/credentials/relay` under the sender's relay epoch. This module
 * owns only in-memory transfer state — census pages and capture assemblies —
 * with the §6 server assembly bounds (≤ 2 per host, ≤ 8 global, a 64 MiB
 * byte counter, 60 s idle drop). Bundle plaintext is zeroed once streamed and
 * never logged; chunk frames are redacted by `redactCredentialFrame`.
 */

const ASSEMBLY_PER_HOST = 2;
const ASSEMBLY_GLOBAL = 8;
const ASSEMBLY_BYTES = 64 * 1024 * 1024;
const ASSEMBLY_IDLE_MS = 60_000;

type Assembly = {
  hostId: string;
  begin: Extract<DaemonCredentialMessage, { type: "credential.capture.begin" }>;
  buffer: Buffer;
  received: number;
  nextSeq: number;
  timer: ReturnType<typeof setTimeout>;
};

/** Global transfer accounting shared by every session (captures and bundle grants). */
const budget = { slots: 0, bytes: 0, perHost: new Map<string, number>() };

function acquire(hostId: string, bytes: number): boolean {
  const host = budget.perHost.get(hostId) ?? 0;
  if (
    host >= ASSEMBLY_PER_HOST ||
    budget.slots >= ASSEMBLY_GLOBAL ||
    budget.bytes + bytes > ASSEMBLY_BYTES
  )
    return false;
  budget.slots += 1;
  budget.bytes += bytes;
  budget.perHost.set(hostId, host + 1);
  return true;
}

function release(hostId: string, bytes: number) {
  budget.slots = Math.max(0, budget.slots - 1);
  budget.bytes = Math.max(0, budget.bytes - bytes);
  const host = (budget.perHost.get(hostId) ?? 1) - 1;
  if (host <= 0) budget.perHost.delete(hostId);
  else budget.perHost.set(hostId, host);
}

/** Per-session credential transfer state; disposed with the session. */
export class CredentialSessionRelay {
  private census: CensusAccumulator = newCensusAccumulator();
  private assemblies = new Map<string, Assembly>();

  constructor(
    private readonly sender: RelaySender,
    private readonly send: (frame: ServerCredentialMessage) => void,
  ) {}

  dispose() {
    for (const captureId of [...this.assemblies.keys()]) this.drop(captureId);
  }

  private drop(captureId: string) {
    const assembly = this.assemblies.get(captureId);
    if (!assembly) return;
    clearTimeout(assembly.timer);
    assembly.buffer.fill(0);
    this.assemblies.delete(captureId);
    release(assembly.hostId, assembly.begin.envelopeLen);
  }

  async handle(message: DaemonCredentialMessage): Promise<void> {
    switch (message.type) {
      case "credential.spec.request":
        return this.spec(message);
      case "credential.bundle.request":
        return this.bundle(message);
      case "credential.capture.begin":
        return this.captureBegin(message);
      case "credential.capture.chunk":
        return this.captureChunk(message);
      case "credential.installed":
        await recordInstalled({
          hostId: this.sender.hostId,
          connectionEpoch: this.sender.connectionEpoch,
          leaseId: message.leaseId,
          bindingId: message.bindingId,
          storageSeq: message.storageSeq,
        });
        return;
      case "credential.scrubbed":
        await recordScrubbed({
          hostId: this.sender.hostId,
          connectionEpoch: this.sender.connectionEpoch,
          sandboxId: message.sandboxId,
          bindingIds: message.bindingIds,
          verifiedAbsent: message.verifiedAbsent,
        });
        return;
      case "credential.return.key.ack": {
        const outcome = await recordReturnKeyAck({
          hostId: this.sender.hostId,
          connectionEpoch: this.sender.connectionEpoch,
          ack: message,
        });
        if (outcome === "substitution")
          console.error("[sandbox-relay] host refused a return-key substitution");
        return;
      }
      case "credential.census":
        return this.censusPage(message);
      case "credential.quarantine.discarded":
        // The rejection rows were marked discarded when the discard was sent;
        // the host's confirmation needs no further server state.
        return;
    }
  }

  private async spec(
    message: Extract<DaemonCredentialMessage, { type: "credential.spec.request" }>,
  ) {
    const chunks = await readOperationSpecChunks(prisma, {
      hostId: this.sender.hostId,
      operationId: message.operationId,
      digest: message.digest,
    });
    if (!chunks) {
      this.send({
        type: "credential.spec.refused",
        operationId: message.operationId,
        code: "spec_unavailable",
      });
      return;
    }
    for (const [seq, chunk] of chunks.entries())
      this.send({
        type: "credential.spec.chunk",
        operationId: message.operationId,
        seq,
        data: chunk.toString("base64url"),
      });
  }

  private async bundle(
    message: Extract<DaemonCredentialMessage, { type: "credential.bundle.request" }>,
  ) {
    const reserve = 2 * 4_823_129;
    if (!acquire(this.sender.hostId, reserve)) {
      this.send({ type: "credential.bundle.refused", requestId: message.requestId, code: "busy" });
      return;
    }
    try {
      const base = {
        hostId: this.sender.hostId,
        connectionEpoch: this.sender.connectionEpoch,
        requestId: message.requestId,
        sandboxId: message.sandboxId,
        leaseId: message.leaseId,
      };
      const result =
        message.reason === "install" && message.operationId
          ? await grantInstallBundle({ ...base, operationId: message.operationId })
          : message.reason !== "install" && message.bindingId
            ? await grantRestoreBundle({
                ...base,
                bindingId: message.bindingId,
                reason: message.reason,
              })
            : ({ kind: "refused", code: "not_authorized" } as const);
      if (result.kind === "refused") {
        this.send({
          type: "credential.bundle.refused",
          requestId: message.requestId,
          code: result.code,
        });
        return;
      }
      try {
        const chunkCount = Math.ceil(result.bytes.byteLength / CREDENTIAL_CHUNK_RAW_BYTES);
        this.send({
          type: "credential.bundle.begin",
          requestId: message.requestId,
          bindingId: result.bindingId,
          storageSeq: result.storageSeq,
          fileCount: result.fileCount,
          envCount: result.envCount,
          bundleLen: result.bytes.byteLength,
          chunkCount,
        });
        for (let seq = 0; seq < chunkCount; seq++) {
          const at = seq * CREDENTIAL_CHUNK_RAW_BYTES;
          this.send({
            type: "credential.bundle.chunk",
            requestId: message.requestId,
            seq,
            data: result.bytes.subarray(at, at + CREDENTIAL_CHUNK_RAW_BYTES).toString("base64url"),
          });
        }
      } finally {
        result.bytes.fill(0);
      }
    } finally {
      release(this.sender.hostId, reserve);
    }
  }

  private captureBegin(
    message: Extract<DaemonCredentialMessage, { type: "credential.capture.begin" }>,
  ) {
    this.drop(message.captureId);
    if (!acquire(this.sender.hostId, message.envelopeLen)) {
      // Over the assembly budget: the host keeps the envelope and retries.
      this.send({
        type: "credential.capture.ack",
        captureId: message.captureId,
        outcome: "deferred",
      });
      return;
    }
    const assembly: Assembly = {
      hostId: this.sender.hostId,
      begin: message,
      buffer: Buffer.alloc(message.envelopeLen),
      received: 0,
      nextSeq: 0,
      timer: setTimeout(() => this.drop(message.captureId), ASSEMBLY_IDLE_MS),
    };
    assembly.timer.unref?.();
    this.assemblies.set(message.captureId, assembly);
  }

  private async captureChunk(
    message: Extract<DaemonCredentialMessage, { type: "credential.capture.chunk" }>,
  ) {
    const assembly = this.assemblies.get(message.captureId);
    if (!assembly) return;
    const length = chunkDataLength(message.data) ?? -1;
    const last = message.seq === assembly.begin.chunkCount - 1;
    const expected = last
      ? assembly.begin.envelopeLen - assembly.received
      : CREDENTIAL_CHUNK_RAW_BYTES;
    if (message.seq !== assembly.nextSeq || length !== expected) {
      this.drop(message.captureId);
      return;
    }
    assembly.buffer.write(message.data, assembly.received, "base64url");
    assembly.received += length;
    assembly.nextSeq += 1;
    assembly.timer.refresh();
    if (!last) return;
    const { begin, buffer } = assembly;
    clearTimeout(assembly.timer);
    this.assemblies.delete(message.captureId);
    try {
      const ack = await commitCapture({
        hostId: this.sender.hostId,
        connectionEpoch: this.sender.connectionEpoch,
        serverOrigin: serverOrigin(),
        captureId: begin.captureId,
        leaseId: begin.leaseId,
        bindingId: begin.bindingId,
        kidR: begin.kidR,
        kind: begin.kind,
        envelopeDigest: begin.envelopeDigest,
        envelope: buffer,
      });
      if (ack) this.send({ type: "credential.capture.ack", captureId: begin.captureId, ...ack });
    } finally {
      buffer.fill(0);
      release(assembly.hostId, begin.envelopeLen);
    }
  }

  private async censusPage(
    message: Extract<DaemonCredentialMessage, { type: "credential.census" }>,
  ) {
    if (message.page === 0) this.census = newCensusAccumulator();
    if (!accumulateCensusPage(this.census, message)) {
      this.census = newCensusAccumulator();
      return;
    }
    this.send({ type: "credential.census.ack", page: message.page });
    if (!message.complete) return;
    const census = this.census;
    this.census = newCensusAccumulator();
    const discards = await applyCompleteCensus({
      hostId: this.sender.hostId,
      connectionEpoch: this.sender.connectionEpoch,
      census,
    });
    for (const discard of discards ?? []) this.sendDiscard(discard, "owner_discard");
  }

  sendDiscard(
    discard: QuarantineDiscard,
    reason: "force_released" | "owner_discard" | "host_deleted",
  ) {
    this.send({ type: "credential.quarantine.discard", captureIds: discard.captureIds, reason });
  }
}

function serverOrigin(): string {
  return new URL(env.BETTER_AUTH_URL).origin;
}

/**
 * Hello step (§4.3.0): issue (commit first) and send the current return key
 * when the host's slot epoch is behind. Best-effort: a failure is logged by
 * class and retried at the next hello.
 */
export async function offerReturnKey(
  sender: RelaySender,
  hostSlotEpoch: number,
  send: (frame: ServerCredentialMessage) => void,
): Promise<void> {
  try {
    const frame = await issueCurrentReturnKey({
      hostId: sender.hostId,
      hostSlotEpoch,
      serverOrigin: serverOrigin(),
    });
    if (frame && sender.isCurrent?.() !== false) send(frame);
  } catch (error) {
    console.error(
      `[sandbox-relay] return key issuance failed (${error instanceof Error ? error.constructor.name : typeof error})`,
    );
  }
}
