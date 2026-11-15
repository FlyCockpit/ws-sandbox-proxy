import prisma, { type Prisma } from "@wssp/db";
/** Bounded reaping on the existing cleanup schedule; predicates rechecked at delete. */
export async function sweepHostAccessRetention(now = new Date(), batch = 500) {
  const limit = Math.min(1000, Math.max(1, batch));
  await prisma.hostQueuedCommand.updateMany({
    where: { state: "QUEUED", expiresAt: { lte: now } },
    data: { state: "EXPIRED", decidedAt: now },
  });
  const decidedBefore = new Date(now.getTime() - 7 * 86400000);
  const queuedWhere: Prisma.HostQueuedCommandWhereInput = {
    state: { not: "QUEUED" },
    OR: [{ decidedAt: { lt: decidedBefore } }, { expiresAt: { lt: decidedBefore } }],
  };
  const queued = await prisma.hostQueuedCommand.findMany({
    where: queuedWhere,
    orderBy: { id: "asc" },
    take: limit,
    select: { id: true },
  });
  const queuedDeleted = queued.length
    ? (
        await prisma.hostQueuedCommand.deleteMany({
          where: { AND: [queuedWhere, { id: { in: queued.map((r) => r.id) } }] },
        })
      ).count
    : 0;
  const auditWhere = { createdAt: { lt: new Date(now.getTime() - 90 * 86400000) } };
  const audit = await prisma.hostAuditEvent.findMany({
    where: auditWhere,
    orderBy: { id: "asc" },
    take: limit,
    select: { id: true },
  });
  const auditDeleted = audit.length
    ? (
        await prisma.hostAuditEvent.deleteMany({
          where: { ...auditWhere, id: { in: audit.map((r) => r.id) } },
        })
      ).count
    : 0;
  return { queued: queuedDeleted, audit: auditDeleted };
}
