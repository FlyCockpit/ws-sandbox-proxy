import { ORPCError } from "@orpc/server";
import { TRANSFER_CHUNK_BYTES } from "@wssp/sandbox-contracts";

export type TransferLimits = {
  maxBytes: number;
  diskBytes: number;
  ownerActive: number;
  globalActive: number;
  idleMs: number;
  absoluteMs: number;
  /** Delivery grace of a fully delivered capture; defaults to `DELIVERED_GRACE_MS`. */
  deliveredGraceMs?: number;
};
export function transferError(
  code:
    | "FORBIDDEN"
    | "TRANSFER_EXPIRED"
    | "TRANSFER_QUOTA"
    | "TRANSFER_IO"
    | "CONFLICT"
    | "BAD_REQUEST"
    | "NOT_FOUND"
    | "PAYLOAD_TOO_LARGE"
    | "TRANSFER_NOT_READY"
    | "RANGE_NOT_SATISFIABLE",
) {
  return new ORPCError(code, {
    status: {
      FORBIDDEN: 403,
      TRANSFER_EXPIRED: 410,
      TRANSFER_QUOTA: 429,
      TRANSFER_IO: 503,
      CONFLICT: 409,
      BAD_REQUEST: 400,
      NOT_FOUND: 404,
      PAYLOAD_TOO_LARGE: 413,
      TRANSFER_NOT_READY: 409,
      RANGE_NOT_SATISFIABLE: 416,
    }[code],
    data: { code },
  });
}
export function checkReservation(
  total: number,
  limits: TransferLimits,
  used: bigint,
  active: number,
  owned: number,
) {
  if (!Number.isSafeInteger(total) || total < 0) throw transferError("BAD_REQUEST");
  if (total > limits.maxBytes) throw transferError("PAYLOAD_TOO_LARGE");
  if (
    BigInt(total) + used > BigInt(limits.diskBytes) ||
    active >= limits.globalActive ||
    owned >= limits.ownerActive
  )
    throw transferError("TRANSFER_QUOTA");
}
export function checkChunk(total: number, offset: number, bytes: number) {
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    offset % TRANSFER_CHUNK_BYTES !== 0 ||
    bytes <= 0 ||
    bytes !== Math.min(TRANSFER_CHUNK_BYTES, total - offset)
  )
    throw transferError("BAD_REQUEST");
}
