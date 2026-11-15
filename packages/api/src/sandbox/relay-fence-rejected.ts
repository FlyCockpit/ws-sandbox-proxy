/**
 * The relay fence assertion, import-free. `relay-fence.ts` re-exports it;
 * code that needs only the assertion (the worker's disk-offload maintenance)
 * imports it from here, because `relay-fence.ts` reaches the outbox and the
 * request-MAC module, which validates the server-only environment.
 */
export class RelayFenceRejected extends Error {}
export function requireRelayFence(ok: boolean): asserts ok {
  if (!ok) throw new RelayFenceRejected();
}
