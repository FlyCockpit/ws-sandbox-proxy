import { randomUUID } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma, type SandboxState } from "@wssp/db";
import type { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../lib/pagination";
import { entityId } from "../lib/schemas";
import { serviceProcedure } from "../lib/sdk-key-access";
import { sandboxStateConflict } from "../sandbox";
import {
  type AttachSandboxCredentialInput,
  attachSandboxCredentialInput,
  type FreeSandboxCredentialInput,
  freeSandboxCredentialInput,
  type Principal,
} from "../sandbox/contracts";
import { sandboxNotFound } from "../sandbox/errors";
import { operationTransaction } from "../sandbox/operation-transaction";
import { rethrowSensitiveSandboxError } from "../sandbox/sensitive-errors";
import { requireOwnedSandboxPlacement } from "../sandbox/sharing-authority";
import { credentialAccessFilter, requireCredentials } from "./access";
import { consumeCredentialAttach } from "./budgets";
import { credentialError } from "./errors";
import {
  authorizeCredentialClaims,
  requireDisjointAttachmentSet,
  requireUsableLogins,
} from "./launch";
import { detachAttachment } from "./leases";
import {
  admitAtGeneration,
  dispatchLive,
  lockSandbox,
  recordedOperation,
  requireNoBusyOperation,
} from "./live-ops";
import { claimWorkloadLease } from "./selection";
import { buildAttachSpec, buildFreeSpec, preflightCredentialSpec } from "./specs";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Live attach and free.
 *
 * - READY: attach claims a lease (RESERVED) and dispatches `credential.attach`
 *   with a spec of that lease (`inject`) plus residue to scrub; free moves the
 *   ACTIVE lease to RELEASING and dispatches `credential.free` naming its open
 *   binding. Neither changes the sandbox state or generation; a stop or kill
 *   accepted meanwhile supersedes them (`settleCredentialTeardown`).
 * - STOPPED (B1): attach records the attachment only (claimed at the next
 *   start, its account/instance a one-shot hint); free ends an attachment
 *   with no live lease at once, refuses a RELEASING lease `pending_drain` and
 *   a RECOVERY_REQUIRED one `recovery_required`.
 * - Refused `sandbox.state_conflict` while a stop, kill, reconnect, capture or
 *   another attach/free of the sandbox is in flight.
 *
 * Lock order: User → K (operationTransaction) → H → S → credential FOR SHARE →
 * instance → lease (claim) → O; a spec/outbox row last. Every refusal happens
 * before any lease row is written.
 */

type Tx = Prisma.TransactionClient;

const NON_TERMINAL_LEASES = [
  "RESERVED",
  "INSTALLING",
  "ACTIVE",
  "RELEASING",
  "RECOVERY_REQUIRED",
  "RECOVERING",
] as const;

function parse<T extends { safeParse: (value: unknown) => { success: boolean; data?: unknown } }>(
  schema: T,
  input: unknown,
): NonNullable<ReturnType<T["safeParse"]>["data"]> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid login input." });
  return parsed.data as NonNullable<ReturnType<T["safeParse"]>["data"]>;
}

/**
 * §3 / §10.6 admission for one more login on a sandbox: not already
 * attached, ≤ 8 attachments, and a proxy-delivery login only on a sandbox
 * whose `credentialProxyEnabled` was set at create (§9; read under the S lock
 * the caller holds). Returns the other attached logins. Env-name and path
 * disjointness is a property of the whole set, decided by the claim gate
 * (`requireDisjointAttachmentSet`) after the definitions are locked.
 */
async function requireAttachable(
  tx: Tx,
  input: { ownerId: string; sandboxId: string; credentialId: string },
): Promise<string[]> {
  const login = await loadVerifiedLogin(tx, input.credentialId);
  if (!login) throw credentialError("credential.definition_corrupt");
  if (login.delivery === "PROXY") {
    const sandbox = await tx.sandbox.findFirst({
      where: { id: input.sandboxId, userId: input.ownerId },
      select: { credentialProxyEnabled: true },
    });
    if (!sandbox?.credentialProxyEnabled) throw credentialError("credential.proxy_not_enabled");
  }
  const attached = await tx.sandboxCredential.findMany({
    where: { sandboxId: input.sandboxId, detachedAt: null },
    select: { credentialId: true },
    orderBy: { credentialId: "asc" },
    take: 9,
  });
  if (attached.some((row) => row.credentialId === input.credentialId))
    throw credentialError("credential.already_attached");
  if (attached.length >= 8) throw credentialError("credential.limit_reached", { limit: 8 });
  return attached.map((row) => row.credentialId);
}

/** The named account / instance of a STOPPED attach, validated against the login. */
async function recordedChoice(
  tx: Tx,
  ownerId: string,
  input: { credentialId: string; accountId?: string; instanceId?: string },
): Promise<{ accountId: string | null; instanceId: string | null }> {
  if (input.instanceId) {
    const instance = await tx.credentialInstance.findFirst({
      where: {
        id: input.instanceId,
        credentialId: input.credentialId,
        userId: ownerId,
        ...(input.accountId ? { accountId: input.accountId } : {}),
      },
      select: { accountId: true },
    });
    if (!instance) throw credentialError("credential.instance_not_found");
    return { accountId: instance.accountId, instanceId: input.instanceId };
  }
  if (input.accountId) {
    const account = await tx.credentialAccount.findFirst({
      where: { id: input.accountId, credentialId: input.credentialId, userId: ownerId },
      select: { id: true },
    });
    if (!account) throw credentialError("credential.account_not_found");
    return { accountId: account.id, instanceId: null };
  }
  return { accountId: null, instanceId: null };
}

const LIVE_STATES: ReadonlySet<SandboxState> = new Set(["READY"]);
const RECORD_STATES: ReadonlySet<SandboxState> = new Set(["STOPPED"]);

export const attachSandboxCredential = serviceProcedure(
  {
    action: "sandboxCredentials.attach",
    intentOnly: true,
    target: (input: AttachSandboxCredentialInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, raw: AttachSandboxCredentialInput) => {
    const input = parse(attachSandboxCredentialInput, raw);
    requireCredentials("write");
    await consumeCredentialAttach(owner.ownerId);
    const request = {
      credentialId: input.credentialId,
      ...(input.accountId ? { accountId: input.accountId } : {}),
      ...(input.instanceId ? { instanceId: input.instanceId } : {}),
    };
    return operationTransaction(
      owner,
      {
        key: input.idempotencyKey,
        intent: { sandboxId: input.id, ...request },
        kind: "CREDENTIAL_ATTACH",
        action: "sandboxCredentials.attach",
        target: { sandboxId: input.id },
      },
      async (tx, bodyHash) => {
        const sandbox = await lockSandbox(tx, owner, input.id);
        if (!LIVE_STATES.has(sandbox.state) && !RECORD_STATES.has(sandbox.state))
          throw sandboxStateConflict("Logins can be attached to READY or STOPPED sandboxes only.");
        await requireNoBusyOperation(tx, sandbox);
        await requireUsableLogins(tx, owner, [input.credentialId]);
        const attachedIds = await requireAttachable(tx, {
          ownerId: owner.ownerId,
          sandboxId: sandbox.id,
          credentialId: input.credentialId,
        });

        if (RECORD_STATES.has(sandbox.state)) {
          // Nothing is claimed now: refuse a conflicting set early (the
          // resume's claim gate decides again under the definition locks).
          await requireDisjointAttachmentSet(tx, {
            ownerId: owner.ownerId,
            sandboxId: sandbox.id,
            credentialIds: [...attachedIds, input.credentialId],
          });
          // B1: the attachment only; the next start claims it. A named
          // account/instance is recorded as the attachment's last-used one,
          // so the start prefers it and falls back like any resume (§7.2
          // rules 2-3); to force it with no fallback, pin it on the start.
          const recorded = await recordedChoice(tx, owner.ownerId, input);
          await tx.sandboxCredential.create({
            data: {
              sandboxId: sandbox.id,
              userId: owner.ownerId,
              credentialId: input.credentialId,
              accountId: recorded.accountId,
              instanceId: recorded.instanceId,
            },
            select: { id: true },
          });
          const op = await recordedOperation(tx, owner, {
            sandbox,
            kind: "CREDENTIAL_ATTACH",
            idempotencyKey: input.idempotencyKey,
            bodyHash,
            state: "SUCCEEDED",
          });
          return { operationId: op.id, state: op.state };
        }

        if (!sandbox.sandboxHostId) throw sandboxStateConflict("Sandbox placement is missing.");
        await requireOwnedSandboxPlacement(tx, owner.ownerId, sandbox.id);
        // The claim gate: this login claimed, the attached ones in the host
        // policy and the set's env/path disjointness.
        await authorizeCredentialClaims(tx, {
          principal: owner,
          hostId: sandbox.sandboxHostId,
          sandboxId: sandbox.id,
          claimIds: [input.credentialId],
          attachedIds,
        });
        // §6.1: the worst-case spec must fit before any claim.
        await preflightCredentialSpec(tx, {
          sandboxId: sandbox.id,
          credentialIds: [input.credentialId],
        });
        await admitAtGeneration(tx, owner, sandbox);
        const operationId = `op${randomUUID().replaceAll("-", "")}`;
        const lease = await claimWorkloadLease(tx, {
          ownerId: owner.ownerId,
          sandboxId: sandbox.id,
          operationId,
          hostId: sandbox.sandboxHostId,
          request,
        });
        await tx.sandboxCredential.create({
          data: {
            sandboxId: sandbox.id,
            userId: owner.ownerId,
            credentialId: input.credentialId,
            accountId: lease.accountId,
            instanceId: lease.instanceId,
          },
          select: { id: true },
        });
        const op = await recordedOperation(tx, owner, {
          id: operationId,
          sandbox,
          kind: "CREDENTIAL_ATTACH",
          idempotencyKey: input.idempotencyKey,
          bodyHash,
          state: "QUEUED",
        });
        await dispatchLive(tx, owner, {
          sandbox,
          operationId,
          idempotencyKey: input.idempotencyKey,
          kind: "CREDENTIAL_ATTACH",
          spec: await buildAttachSpec(tx, { sandboxId: sandbox.id, leaseId: lease.leaseId }),
        });
        return { operationId: op.id, state: op.state };
      },
      async (_tx, prior) => ({ operationId: prior.id, state: prior.state }),
    ).catch((error: unknown) => rethrowSensitiveSandboxError(error));
  },
);

export const freeSandboxCredential = serviceProcedure(
  {
    action: "sandboxCredentials.free",
    intentOnly: true,
    target: (input: FreeSandboxCredentialInput) => ({ sandboxId: input.id }),
  },
  async (owner: Principal, raw: FreeSandboxCredentialInput) => {
    const input = parse(freeSandboxCredentialInput, raw);
    // Freeing settles exposure: allowed in drain mode too.
    requireCredentials("settle");
    await consumeCredentialAttach(owner.ownerId);
    const skip = input.credentialCapture === "skip";
    return operationTransaction(
      owner,
      {
        key: input.idempotencyKey,
        intent: {
          sandboxId: input.id,
          credentialId: input.credentialId,
          ...(skip ? { credentialCapture: "skip" } : {}),
        },
        kind: "CREDENTIAL_FREE",
        action: "sandboxCredentials.free",
        target: { sandboxId: input.id },
      },
      async (tx, bodyHash) => {
        const sandbox = await lockSandbox(tx, owner, input.id);
        if (!LIVE_STATES.has(sandbox.state) && !RECORD_STATES.has(sandbox.state))
          throw sandboxStateConflict("Logins can be freed on READY or STOPPED sandboxes only.");
        await requireNoBusyOperation(tx, sandbox);
        const visible = await tx.credential.count({
          where: { AND: [credentialAccessFilter(owner), { id: input.credentialId }] },
        });
        const attachment = await tx.sandboxCredential.findFirst({
          where: { sandboxId: sandbox.id, credentialId: input.credentialId, detachedAt: null },
          select: { id: true },
        });
        if (visible === 0 || !attachment) throw credentialError("credential.not_attached");
        // S is held: the sandbox's leases of this login, sorted, FOR UPDATE.
        const leases = await tx.$queryRaw<{ id: string; state: string; bindingOpen: boolean }[]>`
          SELECT l.id, l.state::text AS state,
            EXISTS (SELECT 1 FROM credential_binding b
              WHERE b.id = l."currentBindingId" AND b."closedAt" IS NULL) AS "bindingOpen"
          FROM credential_lease l
          WHERE l."sandboxId" = ${sandbox.id} AND l."credentialId" = ${input.credentialId}
            AND l.state::text = ANY(${[...NON_TERMINAL_LEASES]}::text[])
          ORDER BY l.id
          FOR UPDATE`;
        const lease = leases[0];

        if (!lease) {
          // No live lease: the attachment ends now. A stopped disk's residue
          // (if any) is scrubbed at the next start or listed for a capture.
          await detachAttachment(tx, sandbox.id, input.credentialId);
          const op = await recordedOperation(tx, owner, {
            sandbox,
            kind: "CREDENTIAL_FREE",
            idempotencyKey: input.idempotencyKey,
            bodyHash,
            state: "SUCCEEDED",
          });
          return { operationId: op.id, state: op.state };
        }
        if (RECORD_STATES.has(sandbox.state)) {
          if (lease.state === "RECOVERY_REQUIRED")
            throw credentialError("credential.recovery_required");
          // RELEASING: an envelope is still unresolved (B1 gap).
          throw credentialError("credential.pending_drain");
        }
        // READY: an ACTIVE lease, or a RECOVERY_REQUIRED one whose binding is
        // still open on the running VM (a REJECTED free, §7.1), or one left
        // RELEASING by a free whose outcome was unknown.
        const freeable =
          lease.state === "ACTIVE" ||
          lease.state === "RELEASING" ||
          (lease.state === "RECOVERY_REQUIRED" && lease.bindingOpen);
        if (!freeable) throw sandboxStateConflict("The login is still being installed.");
        if (!sandbox.sandboxHostId) throw sandboxStateConflict("Sandbox placement is missing.");
        await requireOwnedSandboxPlacement(tx, owner.ownerId, sandbox.id);
        await admitAtGeneration(tx, owner, sandbox);
        const operationId = `op${randomUUID().replaceAll("-", "")}`;
        await tx.$executeRaw`UPDATE credential_lease SET state = 'RELEASING',
            "teardownOperationId" = ${operationId}, "endReason" = NULL,
            "updatedAt" = (clock_timestamp() AT TIME ZONE 'UTC')
          WHERE id = ${lease.id}`;
        const op = await recordedOperation(tx, owner, {
          id: operationId,
          sandbox,
          kind: "CREDENTIAL_FREE",
          idempotencyKey: input.idempotencyKey,
          bodyHash,
          state: "QUEUED",
        });
        await dispatchLive(tx, owner, {
          sandbox,
          operationId,
          idempotencyKey: input.idempotencyKey,
          kind: "CREDENTIAL_FREE",
          spec: await buildFreeSpec(tx, { sandboxId: sandbox.id, leaseId: lease.id, skip }),
        });
        return { operationId: op.id, state: op.state };
      },
      async (_tx, prior) => ({ operationId: prior.id, state: prior.state }),
    ).catch((error: unknown) => rethrowSensitiveSandboxError(error));
  },
);

// --- Read: the sandbox detail Credentials panel (§12) -------------------------

export const listSandboxCredentialsInput = cursorPageInput.extend({ id: entityId }).strict();

export type SandboxCredentialDto = {
  credentialId: string;
  name: string;
  mode: "EXCLUSIVE" | "SHAREABLE";
  attachedAt: string;
  account: { id: string; name: string | null; ordinal: number; paused: boolean } | null;
  instance: { id: string; name: string | null; ordinal: number; state: string } | null;
  /** The attachment's live lease, if any (none while STOPPED or before a claim). */
  lease: { id: string; state: (typeof NON_TERMINAL_LEASES)[number] } | null;
};

/**
 * The logins attached to one of the owner's sandboxes (open attachments),
 * oldest first, with their account, instance and live lease state. Metadata
 * only; session-only (the `/v1` sandbox DTO is unchanged).
 */
export const listSandboxCredentials = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, raw: z.input<typeof listSandboxCredentialsInput>) => {
    requireCredentials("read");
    const page = parse(listSandboxCredentialsInput, raw);
    const sandbox = await prisma.sandbox.findFirst({
      where: { id: page.id, userId: owner.ownerId },
      select: { id: true },
    });
    if (!sandbox) throw sandboxNotFound();
    const rows = await prisma.sandboxCredential.findMany({
      where: withCursor(
        { sandboxId: sandbox.id, userId: owner.ownerId, detachedAt: null },
        "attachedAt",
        page.cursor,
        "asc",
      ),
      orderBy: [{ attachedAt: "asc" }, { id: "asc" }],
      take: pageTake(page.limit),
      select: {
        id: true,
        credentialId: true,
        accountId: true,
        instanceId: true,
        attachedAt: true,
        Credential: { select: { name: true, mode: true } },
      } satisfies Prisma.SandboxCredentialSelect,
    });
    const result = cursorPage(rows, page.limit, "attachedAt");
    const credentialIds = result.items.map((row) => row.credentialId);
    const leases = credentialIds.length
      ? await prisma.credentialLease.findMany({
          where: {
            userId: owner.ownerId,
            sandboxId: sandbox.id,
            credentialId: { in: credentialIds },
            state: { in: [...NON_TERMINAL_LEASES] },
          },
          orderBy: [{ createdAt: "desc" }, { id: "desc" }],
          take: credentialIds.length * 4,
          select: {
            id: true,
            credentialId: true,
            accountId: true,
            instanceId: true,
            state: true,
          } satisfies Prisma.CredentialLeaseSelect,
        })
      : [];
    const leaseBy = new Map<string, (typeof leases)[number]>();
    for (const lease of leases)
      if (!leaseBy.has(lease.credentialId)) leaseBy.set(lease.credentialId, lease);
    const accountIds = new Set<string>();
    const instanceIds = new Set<string>();
    for (const row of result.items) {
      const lease = leaseBy.get(row.credentialId);
      const accountId = lease?.accountId ?? row.accountId;
      const instanceId = lease?.instanceId ?? row.instanceId;
      if (accountId) accountIds.add(accountId);
      if (instanceId) instanceIds.add(instanceId);
    }
    const [accounts, instances] = await Promise.all([
      accountIds.size
        ? prisma.credentialAccount.findMany({
            where: { id: { in: [...accountIds] }, userId: owner.ownerId },
            take: accountIds.size,
            select: { id: true, name: true, ordinal: true, pausedAt: true },
          })
        : [],
      instanceIds.size
        ? prisma.credentialInstance.findMany({
            where: { id: { in: [...instanceIds] }, userId: owner.ownerId },
            take: instanceIds.size,
            select: { id: true, name: true, ordinal: true, state: true },
          })
        : [],
    ]);
    const accountBy = new Map(accounts.map((row) => [row.id, row]));
    const instanceBy = new Map(instances.map((row) => [row.id, row]));
    return {
      items: result.items.map((row): SandboxCredentialDto => {
        const lease = leaseBy.get(row.credentialId);
        const account = accountBy.get(lease?.accountId ?? row.accountId ?? "");
        const instance = instanceBy.get(lease?.instanceId ?? row.instanceId ?? "");
        return {
          credentialId: row.credentialId,
          name: row.Credential.name,
          mode: row.Credential.mode,
          attachedAt: row.attachedAt.toISOString(),
          account: account
            ? {
                id: account.id,
                name: account.name,
                ordinal: account.ordinal,
                paused: account.pausedAt !== null,
              }
            : null,
          instance: instance
            ? {
                id: instance.id,
                name: instance.name,
                ordinal: instance.ordinal,
                state: instance.state,
              }
            : null,
          lease: lease
            ? { id: lease.id, state: lease.state as (typeof NON_TERMINAL_LEASES)[number] }
            : null,
        };
      }),
      nextCursor: result.nextCursor,
    };
  },
);
