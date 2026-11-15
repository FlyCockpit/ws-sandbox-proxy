import { createHash } from "node:crypto";
import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { metadataSchema, SANDBOX_STATES } from "@wssp/sandbox-contracts";
import { cursorWhere } from "../lib/pagination";
import { serviceResourceFilter } from "../lib/sdk-key-access";
import { type ListSandboxesInput, listSandboxesInput, type Principal } from "./contracts";
import { managedSandboxListFilter } from "./managed-sandbox";
import { recordedKeyIdOf, viewerOf } from "./principal-kinds";

function invalidCursor(): never {
  throw new ORPCError("BAD_REQUEST", { message: "Invalid sandbox pagination cursor." });
}

/** One SQL predicate shared by discovery and the dashboard, before cursor/take. */
function sandboxListQuery(owner: Principal, raw: ListSandboxesInput) {
  const parsed = listSandboxesInput.safeParse(raw);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST");
  const input = parsed.data;
  const states = [...new Set(input.states ?? (input.status ? SANDBOX_STATES : ["READY" as const]))]
    .filter((state) =>
      input.status === "active"
        ? state !== "DELETED"
        : input.status === "deleted"
          ? state === "DELETED"
          : true,
    )
    .sort();
  const metadata = Object.entries(input.metadata ?? {}).sort(([a], [b]) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  const order = input.order ?? "desc";
  const startedAfter = input.startedAfter ? new Date(input.startedAfter).toISOString() : null;
  const viewer = viewerOf(owner);
  const context = createHash("sha256")
    .update(
      JSON.stringify({
        owner: owner.ownerId,
        visibility: {
          creationKey:
            viewer.resourceMode === "ALLOWLIST" || viewer.ownSandboxesOnly
              ? recordedKeyIdOf(owner)
              : null,
          hosts: viewer.allowedHostIds === "allOwned" ? null : [...viewer.allowedHostIds].sort(),
          pools:
            viewer.allowedPoolIds === "allUsable"
              ? null
              : [...(viewer.allowedPoolIds ?? [])].sort(),
          templates:
            viewer.allowedRevisionIds === "allOwned" ? null : [...viewer.allowedRevisionIds].sort(),
        },
        states,
        metadata,
        metadataFilter: input.metadata !== undefined,
        templateId: input.templateId ?? null,
        templateRevisionId: input.templateRevisionId ?? null,
        poolId: input.poolId ?? null,
        startedAfter,
        order,
      }),
    )
    .digest("hex");
  const AND: Prisma.SandboxWhereInput[] = [
    serviceResourceFilter(owner, "sandbox"),
    managedSandboxListFilter(),
    { state: { in: states } },
    ...metadata.map(([key, value]) => ({ metadata: { path: [key], equals: value } })),
  ];
  if (input.poolId) AND.push({ originPoolId: input.poolId });
  if (input.templateId) AND.push({ templateId: input.templateId });
  if (input.templateRevisionId) AND.push({ templateRevisionId: input.templateRevisionId });
  if (startedAfter) AND.push({ startedAt: { gt: new Date(startedAfter) } });
  let position: { createdAt: Date; id: string } | null = null;
  if (input.cursor) {
    const decoded = Buffer.from(input.cursor, "base64url").toString("utf8");
    const [version, iso, id, hash, extra] = decoded.split("|");
    if (
      version !== "s1" ||
      !iso ||
      !id ||
      !/^[A-Za-z0-9_-]{1,64}$/.test(id) ||
      hash !== context ||
      extra !== undefined ||
      Buffer.from(decoded).toString("base64url") !== input.cursor
    )
      invalidCursor();
    const sortValue = new Date(iso);
    if (!Number.isFinite(sortValue.getTime()) || sortValue.toISOString() !== iso) invalidCursor();
    AND.push(cursorWhere("createdAt", { sortValue, id }, order));
    position = { createdAt: sortValue, id };
  }
  return {
    where: { AND } satisfies Prisma.SandboxWhereInput,
    orderBy: [{ createdAt: order }, { id: order }],
    take: input.limit + 1,
    limit: input.limit,
    context,
    filters: {
      states,
      metadata,
      metadataFilter: input.metadata !== undefined,
      templateId: input.templateId ?? null,
      startedAfter,
      order,
      position,
    },
  };
}

/** One Prisma query owns visibility and SQL filtering. Invalid metadata
 * is discarded from the bounded result after take; a page may be short. */
export async function sandboxListReadQuery(owner: Principal, raw: ListSandboxesInput) {
  const query = sandboxListQuery(owner, raw);
  return { ...query, postFilterMetadata: query.filters.metadataFilter };
}

/** Context is a hash of safe query identity, never a map or environment payload. */
export function sandboxListPage<T extends { id: string; createdAt: Date; metadata?: unknown }>(
  rows: T[],
  query: { limit: number; context: string; postFilterMetadata?: boolean },
) {
  // Cursor from the unfiltered SQL page: invalid rows must not hide later pages.
  const positions = rows;
  const selected = positions.slice(0, query.limit);
  const ids = new Set(selected.map((row) => row.id));
  const items = rows.filter(
    (row) =>
      ids.has(row.id) &&
      (!query.postFilterMetadata || metadataSchema.safeParse(row.metadata).success),
  );
  const last = selected.at(-1);
  const nextCursor =
    positions.length > query.limit && last
      ? Buffer.from(`s1|${last.createdAt.toISOString()}|${last.id}|${query.context}`).toString(
          "base64url",
        )
      : null;
  return { items, nextCursor };
}
