import type { Prisma } from "@wssp/db";

/** Relay download capture (C28): the owning operation attempt and its identity. */
export type CaptureOwner = {
  userId: string;
  keyId: string | null;
  sandboxId: string;
  generation: number;
  guestPath: string;
};
export type CaptureChunk = {
  operationId: string;
  attempt: number;
  sequence: number;
  offset: number;
  body: Uint8Array;
  ended: boolean;
};
export type CompletedCapture = { transferId: string; size: number; sha256: string };
/** A capture chunk the store will never accept; the operation fails with `code`. */
export class CaptureRefused extends Error {
  constructor(
    readonly code: "protocol_error" | "transfer_quota" | "transfer_expired" | "request_too_large",
    message: string,
  ) {
    super(message);
  }
}
/**
 * The relay's only file-content owner: the C27 TransferStore. There is no
 * second (in-memory or anonymous) store; content, reservations, limits,
 * expiry and shutdown are the transfer store's.
 */
export interface RelayCaptures {
  admitCapture(
    tx: Prisma.TransactionClient,
    owner: CaptureOwner,
    chunk: CaptureChunk,
  ): Promise<(() => Promise<void>) | null>;
  completedCapture(
    operationId: string,
    attempt: number,
    tx?: Prisma.TransactionClient,
  ): Promise<CompletedCapture | undefined>;
  discardCapture(operationId: string, attempt: number): Promise<void>;
}
let bound: RelayCaptures | undefined;
/** Lifecycle binds the started store before the relay accepts hosts. */
export function bindRelayCaptures(store: RelayCaptures) {
  bound = store;
  return () => {
    if (bound === store) bound = undefined;
  };
}
export function relayCaptures(): RelayCaptures {
  if (!bound) throw new Error("Relay file captures are not bound to the transfer store.");
  return bound;
}
