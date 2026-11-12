import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { EGRESS_POLICY_MAX_DOMAINS, templateSelectorSchema } from "@wssp/sandbox-contracts";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../lib/pagination";
import { entityId } from "../lib/schemas";
import { serviceProcedure } from "../lib/sdk-key-access";
import { sandboxStateConflict } from "../sandbox";
import type { Principal } from "../sandbox/contracts";
import { leaseNow } from "../sandbox/lease";
import { operationTransaction } from "../sandbox/operation-transaction";
import { createSandbox, runCommand } from "../sandbox/services/sandboxes";
import { credentialAccessFilter, requireCredentials } from "./access";
import { insertAccount, insertInstance } from "./accounts";
import { consumeCredentialAttach, consumeCredentialLogin } from "./budgets";
import { credentialError } from "./errors";
import { authorizeCredentialClaims } from "./launch";
import { OPEN_LOGIN_SESSION_STATES } from "./leases";
import { assertOwnerCredentialCapacity, lockOwnerCredentialCounts } from "./limits";
import {
  admitAtGeneration,
  dispatchLive,
  lockSandbox,
  recordedOperation,
  requireNoBusyOperation,
} from "./live-ops";
import { destroyLoginSandbox, loginFlowPrincipal } from "./login-relay";
import { credentialPlacementContextFor } from "./placement";
import { claimLoginLease } from "./selection";
import { buildFreeSpec, definitionResiduePaths } from "./specs";
import { type LoadedLogin, loadVerifiedLogin } from "./verified-login";

/**
 * The login sandbox flow.
 *
 * 1. Start: one transaction creates (optionally) the account and instance,
 *    the session, a `purpose=CREDENTIAL_LOGIN` sandbox through the shared
 *    create path and — after S, before O — the LOGIN claim (§7.2 N9: the
 *    instance must have no holder; it sets `loginLeaseId`, so no workload
 *    claim or value write interleaves). No bundle is injected.
 * 2. READY: the LOGIN lease becomes ACTIVE with a LOGIN binding and its
 *    residue row (`activateLoginLease`, in the create's result transaction).
 * 3. Finish: `credential.free` capturing kind `login`; the commit fence makes
 *    the value current (instance READY, `loginLeaseId` cleared, lease
 *    RELEASED, session SAVED) and only then the sandbox is destroyed with
 *    `credentialCapture: skip` (`destroySavedLoginSandbox`). A capture that
 *    is not saved re-arms the lease and fails the session; the sandbox stays
 *    for a retry until cancel or expiry.
 * 4. Cancel / expiry: the sandbox is destroyed; the LOGIN lease is ABANDONED
 *    by the teardown settlement and the session ends.
 *
 * The flow acts on its managed sandbox through the shared services with its
 * own principal (`flow: "credentialLogin"`); the managed-sandbox policy admits
 * exactly its lifecycle actions. Every procedure here is session-only; the
 * relay-side steps (activation, destroy after save) live in login-relay.ts.
 */

type Tx = Prisma.TransactionClient;

/** §11: 30 min by default, ≤ 2 h. */
export const LOGIN_SANDBOX_DEFAULT_MS = 30 * 60_000;
export const LOGIN_SANDBOX_MAX_MS = 2 * 60 * 60_000;

const nameSchema = z.string().trim().min(1).max(80);

export const startLoginInput = z
  .object({
    credentialId: entityId,
    /** An existing account, or `newAccount` (Add account). */
    accountId: entityId.optional(),
    newAccount: z.object({ name: nameSchema.optional() }).strict().optional(),
    /** An existing instance (Re-login), or `newInstance` (Add another instance). */
    instanceId: entityId.optional(),
    newInstance: z
      .object({
        name: nameSchema.optional(),
        maxConcurrent: z.number().int().min(1).max(100_000).optional(),
      })
      .strict()
      .optional(),
    /** Exactly one placement target; a host target must be one of the owner's. */
    sandboxHostId: entityId.optional(),
    poolId: entityId.optional(),
    template: templateSelectorSchema,
    /** Added to the definition's `login.egress.domains`. */
    egressDomains: z.array(z.string().min(1).max(253)).max(32).optional(),
    /** Per-session consent to a foreign pool host (after `login_needs_consent`). */
    allowForeignHost: z.boolean().optional(),
    timeoutMs: z.number().int().min(60_000).max(LOGIN_SANDBOX_MAX_MS).optional(),
  })
  .strict()
  .superRefine((input, ctx) => {
    if ((input.poolId === undefined) === (input.sandboxHostId === undefined))
      ctx.addIssue({ code: "custom", message: "Choose exactly one placement target." });
    if ((input.accountId === undefined) === (input.newAccount === undefined))
      ctx.addIssue({ code: "custom", message: "Choose an account or add one." });
    if ((input.instanceId === undefined) === (input.newInstance === undefined))
      ctx.addIssue({ code: "custom", message: "Choose an instance or add one." });
    if (input.newAccount !== undefined && input.instanceId !== undefined)
      ctx.addIssue({ code: "custom", message: "A new account has no instance yet." });
  });
export type StartLoginInput = z.input<typeof startLoginInput>;

export const loginSessionIdInput = z.object({ id: entityId }).strict();
export const listLoginSessionsInput = cursorPageInput.extend({
  /** Only sessions that still hold their instance (PROVISIONING, READY, SAVING, FAILED). */
  open: z.boolean().optional(),
});

function parse<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid login input." });
  return parsed.data;
}

const sessionSelect = {
  id: true,
  credentialId: true,
  accountId: true,
  instanceId: true,
  sandboxId: true,
  state: true,
  foreignConsentAt: true,
  expiresAt: true,
  createdAt: true,
  updatedAt: true,
} satisfies Prisma.CredentialLoginSessionSelect;
type SessionRow = Prisma.CredentialLoginSessionGetPayload<{ select: typeof sessionSelect }>;

export type LoginSessionDto = {
  id: string;
  credentialId: string;
  accountId: string;
  instanceId: string;
  sandboxId: string | null;
  state: SessionRow["state"];
  foreignConsent: boolean;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
};

function toSessionDto(row: SessionRow): LoginSessionDto {
  return {
    id: row.id,
    credentialId: row.credentialId,
    accountId: row.accountId,
    instanceId: row.instanceId,
    sandboxId: row.sandboxId,
    state: row.state,
    foreignConsent: row.foreignConsentAt !== null,
    expiresAt: row.expiresAt.toISOString(),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

/** The non-secret login instructions the login page shows (§11 step 2). */
function loginInstructions(login: LoadedLogin) {
  const step = login.definition.login;
  return {
    command: step.command,
    method: step.method,
    /** `browser-callback` logins are flagged unsupported (§3). */
    supported: step.method !== "browser-callback",
    doneWhenCommandExits: step.doneWhenCommandExits,
    hasVerifyCommand: step.verifyCommand !== undefined,
  };
}

/**
 * §11 step 1 refusals that need only the login: PROXY delivery and env-only
 * definitions initialize by upload.
 */
function requireLoginSandboxable(login: LoadedLogin): void {
  if (login.delivery === "PROXY" || definitionResiduePaths(login.definition).length === 0)
    throw credentialError("credential.login_requires_upload");
}

/**
 * Required env cannot be typed into a login sandbox: the capture carries files
 * only and keeps the env of the current value (§7.4.3 step 11). A definition
 * with a required env entry therefore needs an instance that already has a
 * value; every stored value was validated against this definition version.
 */
function requireEnvHeld(login: LoadedLogin, currentSeq: number | null): void {
  const requiredEnv = (login.definition.credentials.env ?? []).some((entry) => entry.required);
  if (requiredEnv && currentSeq === null) throw credentialError("credential.login_requires_upload");
}

async function visibleLogin(client: Tx, principal: Principal, credentialId: string) {
  const row = await client.credential.findFirst({
    where: { AND: [credentialAccessFilter(principal), { id: credentialId }] },
    select: { id: true },
  });
  if (!row) throw credentialError("credential.not_found");
  const login = await loadVerifiedLogin(client, credentialId);
  if (!login) throw credentialError("credential.definition_corrupt");
  return login;
}

function egressDomains(login: LoadedLogin, extra: readonly string[]): string[] {
  const domains = [...new Set([...(login.definition.login.egress?.domains ?? []), ...extra])];
  if (domains.length > EGRESS_POLICY_MAX_DOMAINS)
    throw new ORPCError("BAD_REQUEST", { message: "Too many egress domains." });
  return domains;
}

/**
 * The flow's rows, written by the create after S and before O: the account
 * and instance (when added), the session, the LOGIN claim and its event.
 */
async function writeLoginRows(
  tx: Tx,
  owner: Principal,
  input: z.output<typeof startLoginInput>,
  login: LoadedLogin,
  created: { sandboxId: string; operationId: string; hostId: string },
  expiresAt: Date,
): Promise<string> {
  await lockOwnerCredentialCounts(tx, owner.ownerId);
  await assertOwnerCredentialCapacity(tx, owner.ownerId, "loginSessions");
  const accountId =
    input.accountId ??
    (
      await insertAccount(tx, owner.ownerId, {
        credentialId: input.credentialId,
        name: input.newAccount?.name ?? null,
      })
    ).id;
  let instanceId = input.instanceId;
  if (instanceId === undefined)
    instanceId = (
      await insertInstance(tx, owner.ownerId, {
        credentialId: input.credentialId,
        accountId,
        name: input.newInstance?.name ?? null,
        maxConcurrent: input.newInstance?.maxConcurrent ?? null,
      })
    ).id;
  const instance = await tx.credentialInstance.findFirst({
    where: { id: instanceId, credentialId: input.credentialId, userId: owner.ownerId, accountId },
    select: { id: true, currentSeq: true },
  });
  if (!instance) throw credentialError("credential.instance_not_found");
  const sessionId = `ls${randomUUID().replaceAll("-", "")}`;
  // The claim gate (§7.2, §8), as every claim: the feature writable (drain
  // mode refuses), the login visible, the login locked, and the host policy
  // rebuilt under that lock against the placed host — a foreign host only
  // with this session's consent (own-first, D10).
  await authorizeCredentialClaims(tx, {
    principal: owner,
    hostId: created.hostId,
    // The login sandbox installs nothing: no attachment set to validate.
    sandboxId: null,
    claimIds: [input.credentialId],
    foreignConsent: input.poolId !== undefined && input.allowForeignHost === true,
  });
  // The claim's conditional UPDATE re-checks "no holder" (§7.2 N9); the
  // session row is written after it so a refusal leaves nothing behind.
  const lease = await claimLoginLease(tx, {
    ownerId: owner.ownerId,
    credentialId: input.credentialId,
    instanceId: instance.id,
    loginSessionId: sessionId,
    operationId: created.operationId,
    sandboxId: created.sandboxId,
  });
  requireEnvHeld(login, lease.baseSeq);
  await tx.credentialLoginSession.create({
    data: {
      id: sessionId,
      userId: owner.ownerId,
      credentialId: input.credentialId,
      accountId,
      instanceId: instance.id,
      sandboxId: created.sandboxId,
      state: "PROVISIONING",
      foreignConsentAt: input.poolId && input.allowForeignHost ? new Date() : null,
      expiresAt,
    },
    select: { id: true },
  });
  await tx.credentialEvent.create({
    data: {
      userId: owner.ownerId,
      credentialId: input.credentialId,
      accountId,
      instanceId: instance.id,
      leaseId: lease.leaseId,
      sandboxId: created.sandboxId,
      type: "login_started",
    },
    select: { id: true },
  });
  return sessionId;
}

function isCode(error: unknown, code: string): boolean {
  return (
    error instanceof ORPCError &&
    typeof error.data === "object" &&
    error.data !== null &&
    (error.data as { code?: unknown }).code === code
  );
}

export const startLogin = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: StartLoginInput) => {
    const input = parse(startLoginInput, raw);
    requireCredentials("write");
    await consumeCredentialLogin(owner.ownerId);
    // Read-only pre-checks; the create transaction re-reads under its locks.
    const { login, credential } = await prisma.$transaction(async (tx) => {
      const login = await visibleLogin(tx, owner, input.credentialId);
      requireLoginSandboxable(login);
      const context = await credentialPlacementContextFor(tx, [input.credentialId]);
      // Own-first (§8, D10): a host target must be the owner's; a pool target
      // reaches a foreign host only with this session's consent.
      return {
        login,
        credential: {
          ...context,
          requiresOwn: input.sandboxHostId !== undefined || input.allowForeignHost !== true,
        },
      };
    });
    const timeoutMs = input.timeoutMs ?? LOGIN_SANDBOX_DEFAULT_MS;
    const expiresAt = new Date(Date.now() + timeoutMs);
    const domains = egressDomains(login, input.egressDomains ?? []);
    const flow = loginFlowPrincipal(owner.ownerId);
    let sessionId: string | null = null;
    let sandbox: Awaited<ReturnType<typeof createSandbox>>;
    try {
      sandbox = await createSandbox(
        flow,
        {
          template: input.template,
          ...(input.poolId ? { poolId: input.poolId } : { sandboxHostId: input.sandboxHostId }),
          idempotencyKey: `login-start-${randomUUID()}`,
          timeoutMs,
          lifecycle: { onTimeout: "kill", autoResume: false },
          ...(domains.length > 0 ? { egress: { domains } } : {}),
          // DG-6: a CLI-login session never has guestSudo.
          guestSudo: false,
        },
        leaseNow,
        undefined,
        {
          purpose: "CREDENTIAL_LOGIN",
          credential,
          afterSandbox: async (tx, created) => {
            sessionId = await writeLoginRows(tx, owner, input, login, created, expiresAt);
          },
        },
      );
    } catch (error) {
      if (
        input.poolId &&
        input.allowForeignHost !== true &&
        isCode(error, "credential.host_forbidden")
      )
        throw credentialError("credential.login_needs_consent");
      throw error;
    }
    if (!sessionId) throw sandboxStateConflict();
    return {
      sessionId: sessionId as string,
      sandboxId: sandbox.id,
      state: "PROVISIONING" as const,
      expiresAt: expiresAt.toISOString(),
      login: loginInstructions(login),
    };
  },
);

async function ownedSession(owner: Principal, id: string, client: Tx | typeof prisma = prisma) {
  const row = await client.credentialLoginSession.findFirst({
    where: { id, userId: owner.ownerId },
    select: sessionSelect,
  });
  if (!row) throw credentialError("credential.login_session_not_found");
  return row;
}

export const getLoginSession = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof loginSessionIdInput>) => {
    requireCredentials("read");
    const input = parse(loginSessionIdInput, raw);
    const row = await ownedSession(owner, input.id);
    const login = await prisma.$transaction((tx) => loadVerifiedLogin(tx, row.credentialId));
    return {
      ...toSessionDto(row),
      login: login ? loginInstructions(login) : null,
    };
  },
);

export const listLoginSessions = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof listLoginSessionsInput>) => {
    requireCredentials("read");
    const page = parse(listLoginSessionsInput, raw);
    const rows = await prisma.credentialLoginSession.findMany({
      where: withCursor(
        {
          userId: owner.ownerId,
          ...(page.open ? { state: { in: [...OPEN_LOGIN_SESSION_STATES] } } : {}),
        },
        "createdAt",
        page.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: sessionSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return { items: result.items.map(toSessionDto), nextCursor: result.nextCursor };
  },
);

/**
 * Save (§11 step 3): dispatch `credential.free` for the session's ACTIVE
 * LOGIN lease (its LOGIN binding open); the host captures kind `login`.
 * Allowed from READY and, as a retry, from FAILED.
 */
export const finishLogin = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof loginSessionIdInput>) => {
    const input = parse(loginSessionIdInput, raw);
    requireCredentials("settle");
    await consumeCredentialAttach(owner.ownerId);
    const session = await ownedSession(owner, input.id);
    if (!session.sandboxId || (session.state !== "READY" && session.state !== "FAILED"))
      throw credentialError("credential.login_state");
    const sandboxId = session.sandboxId;
    const flow = loginFlowPrincipal(owner.ownerId);
    const idempotencyKey = `login-finish-${randomUUID()}`;
    return operationTransaction(
      flow,
      {
        key: idempotencyKey,
        intent: { sandboxId, credentialId: session.credentialId },
        kind: "CREDENTIAL_FREE",
        action: "sandboxCredentials.free",
        target: { sandboxId },
      },
      async (tx, bodyHash) => {
        const sandbox = await lockSandbox(tx, flow, sandboxId);
        if (sandbox.state !== "READY") throw credentialError("credential.login_state");
        await requireNoBusyOperation(tx, sandbox);
        // S is held: the LOGIN lease FOR UPDATE, then the session.
        const leases = await tx.$queryRaw<{ id: string; state: string; bindingOpen: boolean }[]>`
          SELECT l.id, l.state::text AS state,
            EXISTS (SELECT 1 FROM credential_binding b
              WHERE b.id = l."currentBindingId" AND b."closedAt" IS NULL
                AND b.purpose::text = 'LOGIN') AS "bindingOpen"
          FROM credential_lease l
          WHERE l."sandboxId" = ${sandboxId} AND l."loginSessionId" = ${session.id}
            AND l.kind::text = 'LOGIN'
            AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED')
          FOR UPDATE`;
        const lease = leases[0];
        if (lease?.state !== "ACTIVE" || !lease.bindingOpen)
          throw credentialError("credential.login_state");
        const moved = await tx.credentialLoginSession.updateMany({
          where: { id: session.id, state: { in: ["READY", "FAILED"] } },
          data: { state: "SAVING" },
        });
        if (moved.count !== 1) throw credentialError("credential.login_state");
        await admitAtGeneration(tx, flow, sandbox);
        const operationId = `op${randomUUID().replaceAll("-", "")}`;
        await tx.$executeRaw`UPDATE credential_lease SET state = 'RELEASING',
            "teardownOperationId" = ${operationId}, "endReason" = NULL,
            "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
          WHERE id = ${lease.id}`;
        const op = await recordedOperation(tx, flow, {
          id: operationId,
          sandbox,
          kind: "CREDENTIAL_FREE",
          idempotencyKey,
          bodyHash,
          state: "QUEUED",
        });
        await dispatchLive(tx, flow, {
          sandbox,
          operationId,
          idempotencyKey,
          kind: "CREDENTIAL_FREE",
          spec: await buildFreeSpec(tx, { sandboxId, leaseId: lease.id, skip: false }),
        });
        return { sessionId: session.id, operationId: op.id, state: "SAVING" as const };
      },
      async () => {
        throw sandboxStateConflict();
      },
    );
  },
);

/**
 * Optional `verifyCommand` (§11 step 3): a tracked command in the login
 * sandbox; the page shows its exit code (`operations.get`). Never saves.
 */
export const verifyLogin = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof loginSessionIdInput>) => {
    const input = parse(loginSessionIdInput, raw);
    requireCredentials("settle");
    await consumeCredentialAttach(owner.ownerId);
    const session = await ownedSession(owner, input.id);
    if (!session.sandboxId || (session.state !== "READY" && session.state !== "FAILED"))
      throw credentialError("credential.login_state");
    const login = await prisma.$transaction((tx) => loadVerifiedLogin(tx, session.credentialId));
    if (!login) throw credentialError("credential.definition_corrupt");
    const verify = login.definition.login.verifyCommand;
    if (verify === undefined) throw credentialError("credential.login_state");
    return runCommand(loginFlowPrincipal(owner.ownerId), {
      id: session.sandboxId,
      idempotencyKey: `login-verify-${randomUUID()}`,
      script: verify,
      timeoutMs: 120_000,
    });
  },
);

/**
 * Cancel (§11 step 3): the session is CANCELLED, then its sandbox destroyed;
 * the kill's teardown settlement ABANDONs the LOGIN lease and clears
 * `loginLeaseId`. Repeating a cancel re-requests the destroy.
 */
export const cancelLogin = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof loginSessionIdInput>) => {
    const input = parse(loginSessionIdInput, raw);
    requireCredentials("settle");
    await consumeCredentialAttach(owner.ownerId);
    const session = await prisma.$transaction(async (tx) => {
      const row = await ownedSession(owner, input.id, tx);
      const cancelled = await tx.credentialLoginSession.updateMany({
        where: { id: row.id, state: { in: [...OPEN_LOGIN_SESSION_STATES] } },
        data: { state: "CANCELLED" },
      });
      if (cancelled.count === 1)
        await tx.credentialEvent.create({
          data: {
            userId: owner.ownerId,
            credentialId: row.credentialId,
            accountId: row.accountId,
            instanceId: row.instanceId,
            sandboxId: row.sandboxId,
            type: "login_cancelled",
          },
          select: { id: true },
        });
      return ownedSession(owner, input.id, tx);
    });
    if (session.state === "CANCELLED" && session.sandboxId)
      await destroyLoginSandbox(owner.ownerId, session.sandboxId, `login-cancel-${session.id}`);
    return toSessionDto(session);
  },
);
