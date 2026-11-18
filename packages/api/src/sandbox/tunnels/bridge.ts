import type { TunnelApplyV11, TunnelClearV11, TunnelPortsV11 } from "@wssp/sandbox-contracts";

/**
 * The relay side of preview tunnels, bound by the server process that holds
 * host sockets (`apps/server/src/lifecycle.ts`). Unbound (tests, the worker):
 * no host is reachable and the controller never applies anything.
 */
export type TunnelHostLink = {
  hostId: string;
  ownerId: string;
  epoch: number;
  /** When this session finished reconciliation (ms since epoch). */
  reconciledAt: number;
  /** The session's hello advertised a verified tunnel client. */
  capable: boolean;
  /** The daemon records tunnel plans (hello `tunnelPorts`): it takes a
   * launch's declared ports and `tunnel.ports`. */
  plan: boolean;
  send(frame: TunnelApplyV11 | TunnelClearV11 | TunnelPortsV11): boolean;
};

export type TunnelBridge = {
  link(hostId: string): TunnelHostLink | null;
};

let bridge: TunnelBridge | null = null;
let wake: (() => void) | null = null;

export function bindTunnelBridge(value: TunnelBridge | null) {
  bridge = value;
}
export function tunnelBridge(): TunnelBridge | null {
  return bridge;
}
/** The controller registers its wake-up; services call it after a change. */
export function bindTunnelWake(value: (() => void) | null) {
  wake = value;
}
export function wakeTunnelController() {
  wake?.();
}
