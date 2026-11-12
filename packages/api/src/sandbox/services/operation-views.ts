import prisma, { type OperationState, type Prisma } from "@wssp/db";
import {
  failureSchema,
  OPERATION_STATES,
  OUTPUT_RETENTION_MS,
  publicOperationErrorCode,
} from "@wssp/sandbox-contracts";
import { findOwnedOrThrow } from "../../lib/ownership";
import { cursorPage, pageTake, withCursor } from "../../lib/pagination";
import { serviceProcedure } from "../../lib/sdk-key-access";
import type { ListOperationsInput, OperationIdInput, Principal } from "../contracts";
import { safeOperationError } from "../sensitive-errors";
import { ACTIVE_OPERATION_STATES } from "../state-transitions";

/**
 * The dashboard's owner projection of operations (C48), session only.
 *
 * Rows are status metadata: kind, state, generation, timestamps, the stable
 * public error code and — for commands — the exit code. They never carry the
 * request (command text, argv, env, stdin, guest paths), the stored `result`
 * JSON (file sizes/digests/transfer IDs, directory listings), the idempotency
 * key or request hash, or output bytes. The exit code is projected out of a
 * RUN_COMMAND result by a second, kind-restricted read, so the list never even
 * loads another kind's result. The detail adds only catalog error text and the
 * sandbox/host summary the page needs to show a deleted sandbox or an offline host truthfully.
 *
 * The SDK plane keeps `getOperation` and its own DTO; it has no list.
 */

/** Every state that is not in flight (UNKNOWN_OUTCOME included: it never resolves on its own). */
const SETTLED_STATES: OperationState[] = OPERATION_STATES.filter(
  (state) => !ACTIVE_OPERATION_STATES.has(state),
);

// An explicit allowlist: adding a column to SandboxOperation never widens it.
const operationRowSelect = {
  id: true,
  sandboxId: true,
  kind: true,
  state: true,
  generation: true,
  errorCode: true,
  failure: true,
  createdAt: true,
  updatedAt: true,
  dispatchedAt: true,
  completedAt: true,
  progressPhase: true,
  progressBytesDone: true,
  progressBytesTotal: true,
  // The owner's own sandbox name (session only; the /v1 operation DTO has none).
  Sandbox: { select: { state: true, name: true } },
  Capture: { select: { revisionId: true } },
} satisfies Prisma.SandboxOperationSelect;

type OperationRow = Prisma.SandboxOperationGetPayload<{ select: typeof operationRowSelect }>;

function exitCodeOf(result: unknown): number | null {
  if (result === null || typeof result !== "object" || Array.isArray(result)) return null;
  const code = (result as { exitCode?: unknown }).exitCode;
  return typeof code === "number" && Number.isSafeInteger(code) ? code : null;
}

/** Host-reported phase of an image fetch or capture (no paths, no names). */
function progressFields(row: {
  progressPhase?: string | null;
  progressBytesDone?: bigint | null;
  progressBytesTotal?: bigint | null;
  Capture?: { revisionId: string | null } | null;
}) {
  return {
    progress:
      row.progressPhase == null
        ? null
        : {
            phase: row.progressPhase,
            bytesDone: row.progressBytesDone == null ? null : Number(row.progressBytesDone),
            bytesTotal: row.progressBytesTotal == null ? null : Number(row.progressBytesTotal),
          },
    capturedRevisionId: row.Capture?.revisionId ?? null,
  };
}

function toOperationRow(
  {
    Sandbox,
    Capture,
    errorCode,
    progressPhase,
    progressBytesDone,
    progressBytesTotal,
    ...row
  }: OperationRow,
  exitCode: number | null,
) {
  return {
    ...row,
    ...progressFields({ progressPhase, progressBytesDone, progressBytesTotal, Capture }),
    failure: failureSchema.safeParse(row.failure).data ?? null,
    errorCode: publicOperationErrorCode(errorCode),
    exitCode,
    sandboxState: Sandbox.state,
    sandboxName: Sandbox.name,
  };
}

function ownerWhere(ownerId: string) {
  return { userId: ownerId, Sandbox: { userId: ownerId } };
}

function stateWhere(state: ListOperationsInput["state"]): Prisma.SandboxOperationWhereInput {
  if (state === undefined) return {};
  if (state === "active") return { state: { in: [...ACTIVE_OPERATION_STATES] } };
  if (state === "settled") return { state: { in: SETTLED_STATES } };
  return { state };
}

/** Exit codes of the page's RUN_COMMAND rows; no other kind's result is read. */
async function commandExitCodes(ownerId: string, ids: string[]) {
  if (ids.length === 0) return new Map<string, number | null>();
  // pagination:audited — `id in ids`: at most one already-bounded page of rows.
  const rows = await prisma.sandboxOperation.findMany({
    where: { id: { in: ids }, kind: "RUN_COMMAND", ...ownerWhere(ownerId) },
    select: { id: true, result: true },
  });
  return new Map(rows.map((row) => [row.id, exitCodeOf(row.result)]));
}

export const listOperationViews = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: ListOperationsInput) => {
    const rows = await prisma.sandboxOperation.findMany({
      where: withCursor(
        {
          ...ownerWhere(owner.ownerId),
          ...(input.sandboxId === undefined ? {} : { sandboxId: input.sandboxId }),
          ...(input.kind === undefined ? {} : { kind: input.kind }),
          ...stateWhere(input.state),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: operationRowSelect,
    });
    const page = cursorPage(rows, input.limit, "createdAt");
    const exitCodes = await commandExitCodes(
      owner.ownerId,
      page.items.filter((row) => row.kind === "RUN_COMMAND").map((row) => row.id),
    );
    return {
      items: page.items.map((row) => toOperationRow(row, exitCodes.get(row.id) ?? null)),
      nextCursor: page.nextCursor,
    };
  },
);

const operationDetailSelect = {
  ...operationRowSelect,
  Sandbox: {
    select: {
      id: true,
      name: true,
      state: true,
      generation: true,
      hostOwnerId: true,
      SandboxHost: {
        select: {
          id: true,
          slug: true,
          label: true,
          status: true,
          lastConnectedAt: true,
          lastHeartbeatAt: true,
          deletionRequestedAt: true,
        },
      },
    },
  },
} satisfies Prisma.SandboxOperationSelect;

/** One owned operation; another owner's ID is indistinguishable from a missing one (404). */
export const getOperationView = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: OperationIdInput) => {
    const {
      Sandbox,
      errorCode,
      Capture,
      progressPhase,
      progressBytesDone,
      progressBytesTotal,
      ...row
    } = await findOwnedOrThrow({
      find: (args) => prisma.sandboxOperation.findFirst(args),
      args: {
        where: { id: input.operationId, Sandbox: { userId: owner.ownerId } },
        select: operationDetailSelect,
      },
      owner: { field: "userId", id: owner.ownerId },
      notFound: "Operation not found",
    });
    const exitCode =
      row.kind === "RUN_COMMAND"
        ? ((await commandExitCodes(owner.ownerId, [row.id])).get(row.id) ?? null)
        : null;
    const { SandboxHost, hostOwnerId, ...sandbox } = Sandbox;
    // `slug vN` for a captured revision, owner-scoped like the operation.
    const captured = Capture?.revisionId
      ? await prisma.sandboxTemplateRevision.findFirst({
          where: { id: Capture.revisionId, Template: { userId: owner.ownerId } },
          select: {
            revision: true,
            Template: { select: { slug: true } },
          } satisfies Prisma.SandboxTemplateRevisionSelect,
        })
      : null;
    const error =
      errorCode == null && row.state !== "FAILED" && row.state !== "UNKNOWN_OUTCOME"
        ? null
        : safeOperationError(publicOperationErrorCode(errorCode));
    return {
      ...row,
      ...progressFields({ progressPhase, progressBytesDone, progressBytesTotal, Capture }),
      capturedRevision: captured
        ? { slug: captured.Template.slug, revision: captured.revision }
        : null,
      failure: failureSchema.safeParse(row.failure).data ?? null,
      errorCode: error?.code ?? null,
      errorMessage: error?.message ?? null,
      exitCode,
      sandboxState: sandbox.state,
      sandbox: { ...sandbox, host: hostOwnerId === owner.ownerId ? SandboxHost : null },
      /** Output content is deleted this long after completion (status outlives it). */
      outputExpiresAt:
        row.kind === "RUN_COMMAND" && row.completedAt != null
          ? new Date(row.completedAt.getTime() + OUTPUT_RETENTION_MS)
          : null,
    };
  },
);
