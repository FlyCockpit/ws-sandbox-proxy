import prisma from "@wssp/db";
import { disconnectJournalKey } from "./journal-key-ack.js";

/** Rows per page of the boot sweep (bounded query). */
export const HOST_LIVENESS_SWEEP_PAGE = 100;

/**
 * One-time boot sweep (WP4). Runs before the HTTP listener, so no relay socket
 * of this process exists: every host still recorded CONNECTED belongs to a
 * connection that died with the previous process. Each is marked DISCONNECTED
 * with its epoch revoked through the same owner → H epoch CAS as a live
 * session end (`disconnectJournalKey`). A host whose epoch moved since the
 * page was read loses the CAS and is left alone. Any other error propagates:
 * the caller fails boot. There is no periodic sweep.
 */
export async function sweepConnectedHosts(): Promise<{ disconnected: number }> {
  let cursor: string | undefined;
  let disconnected = 0;
  for (;;) {
    const page = await prisma.sandboxHost.findMany({
      where: { status: "CONNECTED", ...(cursor ? { id: { gt: cursor } } : {}) },
      orderBy: { id: "asc" },
      take: HOST_LIVENESS_SWEEP_PAGE,
      select: { id: true, userId: true, connectionEpoch: true },
    });
    for (const row of page) {
      if (
        await disconnectJournalKey(
          { hostId: row.id, userId: row.userId, connectionEpoch: row.connectionEpoch },
          new Date(),
          true,
        )
      )
        disconnected += 1;
    }
    if (page.length < HOST_LIVENESS_SWEEP_PAGE) return { disconnected };
    cursor = page[page.length - 1]!.id;
  }
}
