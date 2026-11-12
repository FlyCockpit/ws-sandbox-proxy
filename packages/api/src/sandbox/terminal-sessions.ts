/**
 * WP8 (D10): the durable record behind browser terminal reattach.
 *
 * A `SandboxTerminalSession` row is written when a resumable sandbox
 * terminal's PTY first opens (a v2 attachment on a node that negotiated
 * `terminalResume`). It is the only thing a resume ticket can name, and a
 * resume passes only when ALL of these hold against the row (never against
 * anything the browser supplies):
 *
 * - the same owner (`userId`) and the same Better Auth session (`sessionId`;
 *   a revoked or expired session cascades its rows away, so it is refused);
 * - the same sandbox, host and current generation;
 * - `closedAt` is null;
 * - `openedAt` + {@link BROWSER_TERMINAL_MAX_LIFETIME_MS} has not passed.
 *   `openedAt` is written once and never reset, so reattaching never extends
 *   a terminal's lifetime.
 *
 * Host-target terminals never get a row (they are not resumable). Every read
 * is by primary key; the sweep is bounded by `take` batches.
 */
import { ORPCError } from "@orpc/server";
import { BROWSER_TERMINAL_MAX_LIFETIME_MS } from "@wssp/config/browser-terminal";
import prisma, { type Prisma } from "@wssp/db";

/**
 * The named terminal cannot be resumed (closed, past its lifetime, from
 * another auth session or generation, or unknown). One answer for every
 * reason, so it reveals nothing about another session's terminals.
 * Dashboard-only (oRPC), never an SDK code.
 */
export function terminalResumeUnavailable() {
  return new ORPCError("CONFLICT", {
    message: "This terminal can no longer be resumed.",
    data: { code: "sandbox.terminal_resume_unavailable" },
  });
}

/** How long a closed row is kept (observability only; it is never resumable). */
export const TERMINAL_SESSION_CLOSED_RETENTION_MS = 60 * 60_000;
const SWEEP_BATCH = 500;

export type TerminalSessionIdentity = {
  terminalId: string;
  userId: string;
  sessionId: string;
  sandboxId: string;
  hostId: string;
  generation: number;
};

const resumeTargetSelect = {
  userId: true,
  sessionId: true,
  sandboxId: true,
  hostId: true,
  generation: true,
  openedAt: true,
  closedAt: true,
} satisfies Prisma.SandboxTerminalSessionSelect;

/**
 * The resume gate. One primary-key read; every mismatch is the same `false`,
 * so a caller learns nothing about another owner's (or session's) terminal.
 */
export async function terminalResumeTargetOk(
  target: TerminalSessionIdentity,
  now = new Date(),
): Promise<boolean> {
  const row = await prisma.sandboxTerminalSession.findUnique({
    where: { id: target.terminalId },
    select: resumeTargetSelect,
  });
  return (
    row !== null &&
    row.userId === target.userId &&
    row.sessionId === target.sessionId &&
    row.sandboxId === target.sandboxId &&
    row.hostId === target.hostId &&
    row.generation === target.generation &&
    row.closedAt === null &&
    row.openedAt.getTime() + BROWSER_TERMINAL_MAX_LIFETIME_MS > now.getTime()
  );
}

/**
 * The PTY of a resumable terminal opened for the first time. Idempotent
 * (`createMany` + `skipDuplicates`): a duplicate id keeps its original
 * `openedAt`. A failed write leaves the terminal working but not resumable.
 */
export async function recordTerminalSessionOpened(
  identity: TerminalSessionIdentity,
  now = new Date(),
): Promise<void> {
  await prisma.sandboxTerminalSession.createMany({
    data: [
      {
        id: identity.terminalId,
        userId: identity.userId,
        sessionId: identity.sessionId,
        sandboxId: identity.sandboxId,
        hostId: identity.hostId,
        generation: identity.generation,
        openedAt: now,
      },
    ],
    skipDuplicates: true,
  });
}

/** The terminal's PTY was closed (or refused a resume): it is never resumable again. */
export async function closeTerminalSession(terminalId: string, now = new Date()): Promise<void> {
  await prisma.sandboxTerminalSession.updateMany({
    where: { id: terminalId, closedAt: null },
    data: { closedAt: now },
  });
}

/**
 * One bounded pass of `sandbox-terminal-session-sweep`: deletes rows closed
 * longer than the retention, and never-closed rows past the lifetime (a
 * server crash or a missed close leaves those behind; they are unresumable
 * already). Batches of `batch` ids until a short batch, abort or `budgetMs`.
 */
export async function sweepTerminalSessions(
  now = new Date(),
  options: { batch?: number; budgetMs?: number; signal?: AbortSignal } = {},
): Promise<{ deleted: number }> {
  const batch = options.batch ?? SWEEP_BATCH;
  const started = Date.now();
  const where = {
    OR: [
      { closedAt: { lt: new Date(now.getTime() - TERMINAL_SESSION_CLOSED_RETENTION_MS) } },
      { openedAt: { lt: new Date(now.getTime() - BROWSER_TERMINAL_MAX_LIFETIME_MS) } },
    ],
  } satisfies Prisma.SandboxTerminalSessionWhereInput;
  let deleted = 0;
  while (!options.signal?.aborted) {
    const rows = await prisma.sandboxTerminalSession.findMany({
      where,
      select: { id: true },
      take: batch,
    });
    if (rows.length === 0) break;
    const result = await prisma.sandboxTerminalSession.deleteMany({
      where: { id: { in: rows.map((row) => row.id) } },
    });
    deleted += result.count;
    if (rows.length < batch || result.count === 0) break;
    if (options.budgetMs !== undefined && Date.now() - started >= options.budgetMs) break;
  }
  return { deleted };
}
