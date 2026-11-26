import prisma from "@wssp/db";

import { launchableRevisionWhere } from "./template-resolution";

/**
 * Browser plane only: each listed template's launchable live versions (not
 * retired, not an UPSTREAM pin, not awaiting verify) as a count and the
 * newest version number, so the list never badges a template with no usable
 * version as ready. Owner-scoped and bounded by the page's template ids.
 */
export async function templateVersionSummaries(
  ownerId: string,
  templateIds: readonly string[],
): Promise<Map<string, { count: number; latest: number | null }>> {
  const out = new Map<string, { count: number; latest: number | null }>();
  if (templateIds.length === 0) return out;
  const rows = await prisma.sandboxTemplateRevision.groupBy({
    by: ["templateId"],
    where: {
      userId: ownerId,
      templateId: { in: [...templateIds] },
      retiredAt: null,
      ...launchableRevisionWhere(),
    },
    _count: { _all: true },
    _max: { revision: true },
  });
  for (const row of rows ?? [])
    out.set(row.templateId, { count: row._count._all, latest: row._max.revision ?? null });
  return out;
}
