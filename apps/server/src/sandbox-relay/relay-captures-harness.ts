import { createHash } from "node:crypto";
import { TRANSFER_CHUNK_BYTES } from "@wssp/sandbox-contracts";
import {
  bindRelayCaptures,
  CaptureRefused,
  type RelayCaptures,
} from "../sandbox-transfers/captures.js";

/**
 * Test double for the relay's capture port, used only by the mocked-transaction
 * suites. It mirrors the TransferStore contract (fixed offsets, publish after
 * commit, identical replay, conflicting replay refusal, seal on the final
 * chunk). The real store is exercised by `relay-captures.pg.test.ts`.
 */
export function bindMemoryCaptures() {
  const captures = new Map<string, { parts: Uint8Array[]; size: number; sealed?: string }>();
  const key = (operationId: string, attempt: number) => `${operationId}:${attempt}`;
  const port: RelayCaptures = {
    async admitCapture(_tx, _owner, chunk) {
      const { operationId, attempt, sequence, offset, body, ended } = chunk;
      if (
        offset !== sequence * TRANSFER_CHUNK_BYTES ||
        (!ended && body.byteLength !== TRANSFER_CHUNK_BYTES) ||
        (ended && body.byteLength === 0 && offset !== 0)
      )
        throw new CaptureRefused("protocol_error", "File chunk gap, size or final marker.");
      const entry = captures.get(key(operationId, attempt));
      const previous = entry?.parts[sequence];
      if (previous) {
        if (Buffer.compare(previous, body) === 0 && (!ended || entry?.sealed)) return null;
        throw new CaptureRefused("protocol_error", "Conflicting download replay.");
      }
      if (entry?.sealed || sequence !== (entry?.parts.length ?? 0))
        throw new CaptureRefused("protocol_error", "File chunk gap after the committed tail.");
      const copy = Uint8Array.from(body);
      return async () => {
        const current = captures.get(key(operationId, attempt)) ?? { parts: [], size: 0 };
        current.parts[sequence] = copy;
        current.size += copy.byteLength;
        if (ended)
          current.sealed = createHash("sha256").update(Buffer.concat(current.parts)).digest("hex");
        captures.set(key(operationId, attempt), current);
      };
    },
    async completedCapture(operationId, attempt) {
      const entry = captures.get(key(operationId, attempt));
      return entry?.sealed
        ? { transferId: `capture-${operationId}`, size: entry.size, sha256: entry.sealed }
        : undefined;
    },
    async discardCapture(operationId, attempt) {
      captures.delete(key(operationId, attempt));
    },
  };
  bindRelayCaptures(port);
  return {
    ...port,
    /** Sealed capture metadata, as the result handler compares it. */
    peek(operationId: string, attempt: number) {
      const entry = captures.get(key(operationId, attempt));
      return entry?.sealed ? { size: entry.size, sha256: entry.sealed } : undefined;
    },
    bytes(operationId: string, attempt: number) {
      const entry = captures.get(key(operationId, attempt));
      return entry?.sealed ? new Uint8Array(Buffer.concat(entry.parts)) : undefined;
    },
    async append(
      operationId: string,
      attempt: number,
      sequence: number,
      body: Uint8Array,
      ended: boolean,
    ) {
      const publish = await port.admitCapture({} as never, {} as never, {
        operationId,
        attempt,
        sequence,
        offset: sequence * TRANSFER_CHUNK_BYTES,
        body,
        ended,
      });
      await publish?.();
    },
  };
}
