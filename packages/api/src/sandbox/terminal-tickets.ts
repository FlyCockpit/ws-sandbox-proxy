/**
 * Browser terminal authority (C53): one-use upgrade tickets and the re-read
 * every browser terminal socket repeats (upgrade, post-upgrade, heartbeat,
 * revocation and lifecycle notifications).
 *
 * Ticket: 32 random bytes (base64url), shown to the browser exactly once by
 * `sandboxTerminals.createSession`; only its SHA-256 digest is stored. It is
 * bound to the auth session id, the owner, the sandbox, the sandbox's host and
 * its generation at mint time, and expires after
 * `BROWSER_TERMINAL_TICKET_TTL_MS`. `consumeTerminalTicket` is one atomic
 * `DELETE ... RETURNING`: of any number of concurrent presentations exactly
 * one receives the row, a replay (or any later presentation) receives nothing,
 * and an expired ticket is burned and refused. A detached or closed terminal
 * therefore can never be resumed with the ticket that opened it.
 *
 * Every identity the host later receives comes from these server-side rows,
 * never from the browser (C52 carry-in 1).
 */
import { createHash, randomBytes } from "node:crypto";
import {
  BROWSER_TERMINAL_TICKET_PATTERN,
  BROWSER_TERMINAL_TICKET_TTL_MS,
} from "@wssp/config/browser-terminal";
import prisma, { type Prisma } from "@wssp/db";
import { z } from "zod";
import terminalLimits from "../../../config/src/sandbox-terminal-limits.json";
import { findOwnedOrThrow } from "../lib/ownership";
import { entityId } from "../lib/schemas";
import { isLiveOwnerSessionAuthorized } from "../lib/sensitive-session-two-factor-gate";
import { sessionPrincipal } from "./contracts";
import { sandboxStateConflict } from "./errors";
import { authorizeTerminalTransport, terminalTransportConnected } from "./host-terminal-policy";
import type { HostTerminalBinding } from "./host-terminal-tickets";
import { assertManagedSandboxAccess } from "./managed-sandbox";
import { RelayFenceRejected } from "./relay-fence";
import { currentHostUsability, reconcileSandboxAccess } from "./sharing-access";
import { terminalResumeTargetOk, terminalResumeUnavailable } from "./terminal-sessions";

/** A terminal id the server minted (`t` + 32 hex); never another plane's id. */
const terminalIdInput = z.string().regex(/^t[0-9a-f]{32}$/);

export const createTerminalSessionInput = z
  .object({
    sandboxId: entityId,
    rows: z.number().int().min(1).max(terminalLimits.maxRows),
    cols: z.number().int().min(1).max(terminalLimits.maxCols),
    /** Browser terminal subprotocol the client will offer (absent: v1). */
    version: z.literal(2).optional(),
    /**
     * WP8 reattach: the detached terminal this ticket resumes, and the next
     * output sequence the browser has not displayed. v2 only.
     */
    resume: z
      .object({
        terminalId: terminalIdInput,
        nextOutputSeq: z.number().int().min(0).max(2_147_483_647),
      })
      .strict()
      .optional(),
  })
  .refine((input) => input.resume === undefined || input.version === 2, {
    message: "Resuming a terminal requires terminal protocol v2.",
    path: ["resume"],
  });
export type CreateTerminalSessionInput = z.infer<typeof createTerminalSessionInput>;

/** The server-side identity of one browser terminal (never browser-supplied). */
export type TerminalBinding = {
  hostOwnerId?: string;
  epoch?: number;
  userId: string;
  sessionId: string;
  sandboxId: string;
  hostId: string;
  generation: number;
  rows: number;
  cols: number;
  /**
   * WP8: the detached terminal this attachment resumes (from the ticket row,
   * never the browser's socket). Re-checked against `SandboxTerminalSession`
   * on every re-read.
   */
  resume?: { terminalId: string; nextOutputSeq: number };
};

export type BrowserTerminalBinding = TerminalBinding | HostTerminalBinding;
export type GuestTerminalGrant = {
  creatorId: string;
  hostOwnerId: string;
  hostId: string;
  epoch: number;
  sandboxId: string;
  generation: number;
  /** The revision's default cwd (a built template's WORKDIR), if any. */
  defaultCwd?: string;
};
export function isHostTerminalBinding(
  binding: BrowserTerminalBinding,
): binding is HostTerminalBinding {
  return "kind" in binding && binding.kind === "host";
}
export async function checkBrowserTerminalBinding(
  binding: BrowserTerminalBinding,
  now = new Date(),
): Promise<{ ok: true; grant?: GuestTerminalGrant } | { ok: false; intent: TerminalRevocation }> {
  if (isHostTerminalBinding(binding)) {
    const { checkHostTerminalBinding } = await import("./host-terminal-tickets");
    return checkHostTerminalBinding(binding);
  }
  const checked = await checkTerminalBinding(binding, now);
  if (!checked.ok || !checked.grant) return checked;
  const grant = checked.grant;
  if (!(await authorizeTerminalTransport(grant.hostId, grant.hostOwnerId, grant.epoch, prisma)))
    // WP8: a host whose connection ended or moved on (it is reconnecting,
    // or reconnected elsewhere) is not a revocation: a resume tries again.
    return {
      ok: false,
      intent: terminalTransportConnected(grant.hostId, grant.hostOwnerId, grant.epoch)
        ? "revoked"
        : "host_disconnected",
    };
  return checked;
}

/** Binding refusal reasons; browser-specific reasons map to the relay's revoked intent. */
export type TerminalRevocation =
  | "revoked"
  | "pool_access_removed"
  | "host_terminals_disabled"
  | "sandbox_stopped"
  | "sandbox_destroyed"
  | "superseded"
  | "expired"
  | "lifecycle_unconfirmed"
  /**
   * WP8: the host connection this binding rides ended or moved on (its epoch
   * changed, same host owner; or the host is not connected here). The PTY may
   * outlive it on the node: a resumable terminal reattaches, never final.
   */
  | "host_disconnected"
  /** WP8: the resumed terminal's row no longer passes the resume gate. */
  | "resume_unavailable";

// An OFFLOADED sandbox is stopped with its disk only in the image store
// no guest exists to attach to.
const STOPPED_STATES = new Set(["STOPPING", "STOPPED", "OFFLOADED"]);
const DESTROYED_STATES = new Set(["DELETED", "RECLAIMING", "HOST_LOST"]);

export function terminalTicketDigest(ticket: string): string {
  return createHash("sha256").update(ticket, "utf8").digest("hex");
}

const mintSandboxSelect = {
  id: true,
  state: true,
  hostOwnerId: true,
  usagePoolId: true,
  accessGraceUntil: true,
  generation: true,
  sandboxHostId: true,
  purpose: true,
  buildId: true,
  verifyBuildId: true,
} satisfies Prisma.SandboxSelect;

/**
 * Mint a ticket for the caller's own READY sandbox. Another owner's sandbox
 * is NOT_FOUND (indistinguishable from none).
 */
export async function mintTerminalTicket(
  owner: { userId: string; sessionId: string },
  input: CreateTerminalSessionInput,
  now = new Date(),
): Promise<{ ticket: string; expiresAt: Date }> {
  const sandbox = await findOwnedOrThrow({
    find: (args) => prisma.sandbox.findFirst(args),
    args: { where: { id: input.sandboxId }, select: mintSandboxSelect },
    owner: { field: "userId", id: owner.userId },
    notFound: "Sandbox not found",
  });
  assertManagedSandboxAccess(sessionPrincipal(owner.userId), "terminal.open", sandbox);
  if (sandbox.state !== "READY" || !sandbox.sandboxHostId)
    throw sandboxStateConflict("Sandbox is not running.");
  // WP8 resume gate (same owner, auth session, sandbox, host, generation;
  // open; lifetime from the stored `openedAt`). One answer for every reason.
  if (
    input.resume &&
    !(await terminalResumeTargetOk(
      {
        terminalId: input.resume.terminalId,
        userId: owner.userId,
        sessionId: owner.sessionId,
        sandboxId: sandbox.id,
        hostId: sandbox.sandboxHostId,
        generation: sandbox.generation,
      },
      now,
    ))
  )
    throw terminalResumeUnavailable();
  const checked = await checkTerminalBinding(
    {
      userId: owner.userId,
      sessionId: owner.sessionId,
      sandboxId: sandbox.id,
      hostId: sandbox.sandboxHostId,
      generation: sandbox.generation,
    },
    now,
  );
  if (!checked.ok || !checked.grant)
    throw sandboxStateConflict("Terminal authority is unavailable.");
  const ticket = randomBytes(32).toString("base64url");
  const expiresAt = new Date(now.getTime() + BROWSER_TERMINAL_TICKET_TTL_MS);
  // Hygiene only (no authority): expired tickets are refused at consume anyway.
  await prisma.sandboxTerminalTicket.deleteMany({ where: { expiresAt: { lte: now } } });
  await prisma.sandboxTerminalTicket.create({
    data: {
      hostOwnerId: checked.grant.hostOwnerId,
      epoch: checked.grant.epoch,
      tokenDigest: terminalTicketDigest(ticket),
      expiresAt,
      userId: owner.userId,
      sessionId: owner.sessionId,
      sandboxId: sandbox.id,
      sandboxHostId: sandbox.sandboxHostId,
      generation: sandbox.generation,
      rows: input.rows,
      cols: input.cols,
      ...(input.resume
        ? {
            resumeTerminalId: input.resume.terminalId,
            resumeOutputSeq: input.resume.nextOutputSeq,
          }
        : {}),
    },
    select: { id: true },
  });
  return { ticket, expiresAt };
}

type ConsumedTicketRow = {
  hostOwnerId: string;
  epoch: number;
  userId: string;
  sessionId: string;
  sandboxId: string;
  sandboxHostId: string;
  generation: number;
  rows: number;
  cols: number;
  expiresAt: Date;
  resumeTerminalId: string | null;
  resumeOutputSeq: number | null;
};

/**
 * Atomically take a ticket out of the store. Returns the binding only to the
 * single winner of an unexpired ticket; replay, unknown, malformed and
 * expired tickets all return null (an expired ticket is still burned).
 */
export async function consumeTerminalTicket(
  ticket: string,
  now = new Date(),
): Promise<TerminalBinding | null> {
  if (!BROWSER_TERMINAL_TICKET_PATTERN.test(ticket)) return null;
  const digest = terminalTicketDigest(ticket);
  const rows = await prisma.$queryRaw<ConsumedTicketRow[]>`
    DELETE FROM "sandbox_browser_terminal_ticket" WHERE "tokenDigest" = ${digest}
    RETURNING "hostOwnerId", "epoch", "userId", "sessionId", "sandboxId", "sandboxHostId", "generation", "rows", "cols", "expiresAt", "resumeTerminalId", "resumeOutputSeq"`;
  const row = rows[0];
  if (!row || new Date(row.expiresAt).getTime() <= now.getTime()) return null;
  return {
    hostOwnerId: row.hostOwnerId,
    epoch: Number(row.epoch),
    userId: row.userId,
    sessionId: row.sessionId,
    sandboxId: row.sandboxId,
    hostId: row.sandboxHostId,
    generation: Number(row.generation),
    rows: Number(row.rows),
    cols: Number(row.cols),
    ...(row.resumeTerminalId != null && row.resumeOutputSeq != null
      ? {
          resume: {
            terminalId: row.resumeTerminalId,
            nextOutputSeq: Number(row.resumeOutputSeq),
          },
        }
      : {}),
  };
}

const bindingSandboxSelect = {
  SandboxHost: { select: { userId: true, connectionEpoch: true, deletionRequestedAt: true } },
  CurrentPlacement: {
    select: { userId: true, hostOwnerId: true, originHostId: true, generation: true },
  },
  state: true,
  hostOwnerId: true,
  usagePoolId: true,
  accessGraceUntil: true,
  generation: true,
  sandboxHostId: true,
  leaseExpiresAt: true,
  SandboxTemplateRevision: { select: { defaultCwd: true } },
} satisfies Prisma.SandboxSelect;

/**
 * The re-read behind every terminal decision after mint: the auth session row
 * is live and its owner passes the protected policy (ban, deletion, forced
 * 2FA), and the owner's sandbox is still READY on the same host and
 * generation with an unexpired lease. Fails closed: callers treat a thrown
 * error as `lifecycle_unconfirmed`.
 */
export async function checkTerminalBinding(
  binding: Pick<
    TerminalBinding,
    "userId" | "sessionId" | "sandboxId" | "hostId" | "generation" | "hostOwnerId" | "epoch"
  > & { resume?: TerminalBinding["resume"] },
  now = new Date(),
  reconciled = false,
  reconciliationRaces = 0,
): Promise<{ ok: true; grant?: GuestTerminalGrant } | { ok: false; intent: TerminalRevocation }> {
  if (
    !(await isLiveOwnerSessionAuthorized(
      { user: { id: binding.userId }, session: { id: binding.sessionId } },
      now,
    ))
  )
    return { ok: false, intent: "revoked" };
  // WP8: a resumed terminal re-checks its row on every re-read (upgrade,
  // heartbeat, notifications), so a close, the lifetime or a cascade from a
  // revoked auth session ends it.
  if (
    binding.resume &&
    !(await terminalResumeTargetOk(
      {
        terminalId: binding.resume.terminalId,
        userId: binding.userId,
        sessionId: binding.sessionId,
        sandboxId: binding.sandboxId,
        hostId: binding.hostId,
        generation: binding.generation,
      },
      now,
    ))
  )
    return { ok: false, intent: "resume_unavailable" };
  const sandbox = await prisma.sandbox.findFirst({
    where: { id: binding.sandboxId, userId: binding.userId },
    select: bindingSandboxSelect,
  });
  if (!sandbox) return { ok: false, intent: "sandbox_destroyed" };
  if (sandbox.accessGraceUntil) return { ok: false, intent: "pool_access_removed" };
  if (DESTROYED_STATES.has(sandbox.state)) return { ok: false, intent: "sandbox_destroyed" };
  if (STOPPED_STATES.has(sandbox.state)) return { ok: false, intent: "sandbox_stopped" };
  if (sandbox.generation !== binding.generation || sandbox.sandboxHostId !== binding.hostId)
    return { ok: false, intent: "superseded" };
  if (sandbox.leaseExpiresAt && sandbox.leaseExpiresAt.getTime() <= now.getTime())
    return { ok: false, intent: "expired" };
  if (sandbox.state !== "READY") return { ok: false, intent: "lifecycle_unconfirmed" };
  if (
    sandbox.hostOwnerId != null &&
    (sandbox.hostOwnerId !== binding.userId || sandbox.usagePoolId || sandbox.accessGraceUntil) &&
    !(await currentHostUsability(prisma, binding.userId, binding.sandboxId))
  ) {
    if (!reconciled) {
      // The recorded path may have just disappeared. Resolve cap-fitting alternate
      // authority under the graph/host locks before ending this attachment.
      try {
        await prisma.$transaction((tx) => reconcileSandboxAccess(tx, binding.sandboxId));
      } catch (error) {
        // The scanner may have replaced the discovered attribution while we
        // waited for G/H/S. Its stale-read fence is not a revocation verdict.
        // Re-read every gate; never turn a failed reconciliation into authority.
        if (error instanceof RelayFenceRejected && reconciliationRaces < 2)
          return checkTerminalBinding(binding, now, false, reconciliationRaces + 1);
        throw error;
      }
      if (!(await currentHostUsability(prisma, binding.userId, binding.sandboxId)))
        return { ok: false, intent: "pool_access_removed" };
      return checkTerminalBinding(binding, now, true);
    }
    return { ok: false, intent: "pool_access_removed" };
  }
  const host = sandbox.SandboxHost;
  const placement = sandbox.CurrentPlacement;
  if (host && binding.hostOwnerId !== undefined && binding.hostOwnerId !== host.userId)
    return { ok: false, intent: "superseded" };
  // WP8: only the host's connection moved on (a reconnect, or a restarted
  // server's boot sweep revoking the epoch): the PTY lives on the node across
  // connections, so this is a host disconnect, never a supersession.
  if (host && binding.epoch !== undefined && binding.epoch !== host.connectionEpoch)
    return { ok: false, intent: "host_disconnected" };
  if (
    !host ||
    host.deletionRequestedAt ||
    host.userId !== sandbox.hostOwnerId ||
    (placement &&
      (placement.userId !== binding.userId ||
        placement.hostOwnerId !== host.userId ||
        placement.originHostId !== binding.hostId ||
        placement.generation !== binding.generation)) ||
    (host.userId !== binding.userId && !placement)
  )
    return { ok: false, intent: "revoked" };
  return {
    ok: true,
    grant: {
      creatorId: binding.userId,
      hostOwnerId: host.userId,
      hostId: binding.hostId,
      epoch: host.connectionEpoch,
      sandboxId: binding.sandboxId,
      generation: binding.generation,
      ...(sandbox.SandboxTemplateRevision.defaultCwd
        ? { defaultCwd: sandbox.SandboxTemplateRevision.defaultCwd }
        : {}),
    },
  };
}
