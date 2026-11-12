/** Six missed 5 s heartbeats; shared presentation and admission window. */
export const HOST_HEARTBEAT_STALE_AFTER_MS = 30_000;

export function isHostHeartbeatFresh(heartbeat: Date | null, now: Date): boolean {
  if (heartbeat === null) return false;
  const age = now.getTime() - heartbeat.getTime();
  return age >= 0 && age <= HOST_HEARTBEAT_STALE_AFTER_MS;
}
