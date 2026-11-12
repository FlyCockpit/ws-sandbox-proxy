import type { Prisma } from "@wssp/db";
/** Relay-affine capability bridge. Absence is unavailable, never an offline policy. */
export type LiveHostTerminalPolicy = {
  hostTerminal: boolean;
  requireHostTerminalTotp: boolean;
  policyRevision: number;
  epoch: number;
};
type Bridge = {
  authorize(
    hostId: string,
    ownerId: string,
    epoch: number,
    db: Prisma.TransactionClient,
  ): Promise<boolean>;
  read(hostId: string, ownerId: string): LiveHostTerminalPolicy | undefined;
  raise(hostId: string, ownerId: string): Promise<boolean>;
  /** In-memory: this process holds the host's current connection at `epoch`. */
  connected?(hostId: string, ownerId: string, epoch: number): boolean;
};
let bridge: Bridge | null = null;
export function bindHostTerminalPolicy(value: Bridge | null) {
  bridge = value;
}
export function readHostTerminalPolicy(hostId: string, ownerId: string) {
  return bridge?.read(hostId, ownerId);
}
export async function raiseLiveHostTerminalTotp(hostId: string, ownerId: string) {
  return bridge?.raise(hostId, ownerId) ?? false;
}

/** Fresh durable credential/transport read; never substitutes a remembered capability. */
export async function authorizeTerminalTransport(
  hostId: string,
  ownerId: string,
  epoch: number,
  db: Prisma.TransactionClient,
) {
  return bridge?.authorize(hostId, ownerId, epoch, db) ?? false;
}

/**
 * WP8: whether a refused transport is only a host connection that ended or
 * moved on (not connected here at that epoch) rather than a revoked one.
 * Classification only: it never grants anything. Without a relay bridge that
 * can tell, a refusal stays a revocation.
 */
export function terminalTransportConnected(hostId: string, ownerId: string, epoch: number) {
  return bridge?.connected?.(hostId, ownerId, epoch) ?? true;
}
