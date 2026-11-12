import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import {
  canonicalDigestHex,
  type LoginDefinition,
  loadVerifiedDefinition,
  parseLoginDefinition,
  parseLoginDefinitionText,
} from "@wssp/login-definition";
import {
  type CredentialAccountDto,
  type CredentialDefinitionDetailDto,
  type CredentialDefinitionDto,
  type CredentialDto,
  type CredentialEventDto,
  type CredentialInstanceDto,
  type CredentialValueWriteResult,
  createCredentialAccountBodySchema,
  createCredentialBodySchema,
  createCredentialDefinitionBodySchema,
  createCredentialInstanceBodySchema,
  updateCredentialAccountBodySchema,
  updateCredentialBodySchema,
  updateCredentialInstanceBodySchema,
  writeCredentialValueBodySchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { DataKeyStaleWriter, staleWriterError } from "../crypto/data-key-epoch";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../lib/pagination";
import { entityId } from "../lib/schemas";
import { authorizeServiceAction, serviceProcedure } from "../lib/sdk-key-access";
import type { Principal } from "../sandbox/contracts";
import { isBrowserSession, recordedKeyIdOf } from "../sandbox/principal-kinds";
import { credentialAccessFilter, requireCredentials } from "./access";
import { insertAccount, insertInstance, setAccountPaused } from "./accounts";
import { readCredentialsAvailability } from "./availability";
import {
  consumeCredentialRepin,
  consumeCredentialValueWrite,
  consumeCredentialWrite,
} from "./budgets";
import { credentialError } from "./errors";
import { requireDisjointAttachmentSet } from "./launch";
import { assertOwnerCredentialCapacity, lockOwnerCredentialCounts } from "./limits";
import { assertDefinitionSpecContribution } from "./specs";
import {
  CredentialValueInvalid,
  CredentialVaultUnavailable,
  repinInstanceValue,
  type VerifiedLogin,
  writeUploadedValue,
} from "./vault/store";

/**
 * CLI-login control services: the one
 * implementation behind the browser oRPC router and `/v1`. Every export is a
 * `serviceProcedure`; SDK-reachable ones carry a `credentials:*` action,
 * browser-only ones (re-pin, copy-back, foreign opt-in) are `sessionOnly`.
 * Everything is owner-scoped and filtered by {@link credentialAccessFilter};
 * values are write-only and never leave the vault module.
 *
 * Lock order inside writes: User (authorization) → owner credential-count
 * advisory lock (creates) → credential → account → instance (sorted id).
 */

type Tx = Prisma.TransactionClient;

function parse<T extends z.ZodType>(schema: T, input: unknown): z.output<T> {
  const parsed = schema.safeParse(input);
  if (!parsed.success) throw new ORPCError("BAD_REQUEST", { message: "Invalid login input." });
  return parsed.data;
}

const iso = (value: Date) => value.toISOString();
const isoOrNull = (value: Date | null) => (value ? value.toISOString() : null);

// --- Inputs (router and /v1 adapters share these) ---------------------------

export const credentialPageInput = cursorPageInput;
export const credentialIdInput = z.object({ id: entityId });
export const credentialScopedPageInput = cursorPageInput.extend({ credentialId: entityId });
export const accountScopedPageInput = cursorPageInput.extend({
  credentialId: entityId,
  accountId: entityId,
});
export const createDefinitionInput = createCredentialDefinitionBodySchema;
export const createLoginInput = createCredentialBodySchema;
export const updateLoginInput = z.intersection(
  z.object({ id: entityId }),
  updateCredentialBodySchema,
);
export const updateLoginPolicyInput = z
  .object({
    id: entityId,
    copyBack: z.boolean().optional(),
    foreignAllowed: z.boolean().optional(),
  })
  .refine((body) => body.copyBack !== undefined || body.foreignAllowed !== undefined);
export const repinLoginInput = z.object({
  id: entityId,
  definitionId: entityId,
  /** Required (the login's name, typed) when re-pinning erases PROXY values. */
  confirmErase: z.string().max(80).optional(),
});
export const createAccountInput = z.intersection(
  z.object({ credentialId: entityId }),
  createCredentialAccountBodySchema,
);
export const updateAccountInput = z.intersection(
  z.object({ credentialId: entityId, accountId: entityId }),
  updateCredentialAccountBodySchema,
);
export const accountIdInput = z.object({ credentialId: entityId, accountId: entityId });
export const createInstanceInput = z.intersection(
  z.object({ credentialId: entityId, accountId: entityId }),
  createCredentialInstanceBodySchema,
);
export const updateInstanceInput = z.intersection(
  z.object({ credentialId: entityId, instanceId: entityId }),
  updateCredentialInstanceBodySchema,
);
export const instanceIdInput = z.object({ credentialId: entityId, instanceId: entityId });
export const writeValueInput = z.intersection(
  z.object({ credentialId: entityId, instanceId: entityId }),
  writeCredentialValueBodySchema,
);

// --- Projections (disclosure boundaries) ------------------------------------

const definitionSelect = {
  id: true,
  slug: true,
  version: true,
  digest: true,
  displayName: true,
  archivedAt: true,
  createdAt: true,
} satisfies Prisma.CredentialDefinitionSelect;

function toDefinitionDto(
  row: Prisma.CredentialDefinitionGetPayload<{ select: typeof definitionSelect }>,
): CredentialDefinitionDto {
  return {
    id: row.id,
    slug: row.slug,
    version: row.version,
    digest: row.digest,
    displayName: row.displayName,
    archivedAt: isoOrNull(row.archivedAt),
    createdAt: iso(row.createdAt),
  };
}

const loginSelect = {
  id: true,
  name: true,
  definitionDigest: true,
  mode: true,
  delivery: true,
  copyBack: true,
  checkpointIntervalMin: true,
  foreignAllowed: true,
  createdAt: true,
  updatedAt: true,
  Definition: { select: { id: true, slug: true, version: true, displayName: true } },
} satisfies Prisma.CredentialSelect;

function toLoginDto(
  row: Prisma.CredentialGetPayload<{ select: typeof loginSelect }>,
): CredentialDto {
  return {
    id: row.id,
    name: row.name,
    definition: { ...row.Definition },
    definitionDigest: row.definitionDigest,
    mode: row.mode,
    delivery: row.delivery,
    copyBack: row.copyBack,
    checkpointIntervalMin: row.checkpointIntervalMin,
    foreignAllowed: row.foreignAllowed,
    createdAt: iso(row.createdAt),
    updatedAt: iso(row.updatedAt),
  };
}

const accountSelect = {
  id: true,
  credentialId: true,
  ordinal: true,
  name: true,
  pausedAt: true,
  createdAt: true,
} satisfies Prisma.CredentialAccountSelect;

function toAccountDto(
  row: Prisma.CredentialAccountGetPayload<{ select: typeof accountSelect }>,
): CredentialAccountDto {
  return {
    id: row.id,
    credentialId: row.credentialId,
    ordinal: row.ordinal,
    name: row.name,
    paused: row.pausedAt !== null,
    pausedAt: isoOrNull(row.pausedAt),
    createdAt: iso(row.createdAt),
  };
}

const instanceSelect = {
  id: true,
  credentialId: true,
  accountId: true,
  ordinal: true,
  name: true,
  state: true,
  needsLoginReason: true,
  capacity: true,
  activeLeases: true,
  loginLeaseId: true,
  lastCapturedAt: true,
  createdAt: true,
  // The newest dashboard/API upload's timestamp only (never the value). Prune
  // keeps the newest non-checkpoint versions, so a newest upload is never gone.
  Versions: {
    where: { kind: "UPLOAD" },
    orderBy: { storageSeq: "desc" },
    take: 1,
    select: { createdAt: true },
  },
} satisfies Prisma.CredentialInstanceSelect;

function toInstanceDto(
  row: Prisma.CredentialInstanceGetPayload<{ select: typeof instanceSelect }>,
): CredentialInstanceDto {
  return {
    id: row.id,
    credentialId: row.credentialId,
    accountId: row.accountId,
    ordinal: row.ordinal,
    name: row.name,
    state: row.state,
    needsLoginReason: row.needsLoginReason,
    maxConcurrent: row.capacity,
    activeLeases: row.activeLeases,
    loginInProgress: row.loginLeaseId !== null,
    lastCapturedAt: isoOrNull(row.lastCapturedAt),
    lastUploadedAt: isoOrNull(row.Versions[0]?.createdAt ?? null),
    createdAt: iso(row.createdAt),
  };
}

const eventSelect = {
  id: true,
  type: true,
  accountId: true,
  instanceId: true,
  leaseId: true,
  sandboxId: true,
  storageSeq: true,
  sizeBytes: true,
  reason: true,
  at: true,
} satisfies Prisma.CredentialEventSelect;

// --- Shared helpers ----------------------------------------------------------

/** The visible login or NOT_FOUND (a foreign or hidden id is indistinguishable from none). */
async function visibleLogin(client: Tx | typeof prisma, principal: Principal, id: string) {
  const row = await client.credential.findFirst({
    where: { AND: [credentialAccessFilter(principal), { id }] },
    select: { id: true },
  });
  if (!row) throw credentialError("credential.not_found");
  return row;
}

/** Locks a visible login; `share` for value/account work, `update` for settings, re-pin, delete. */
async function lockLogin(tx: Tx, principal: Principal, id: string, mode: "share" | "update") {
  await visibleLogin(tx, principal, id);
  const rows =
    mode === "update"
      ? await tx.$queryRaw<
          { id: string }[]
        >`SELECT id FROM credential WHERE id = ${id} AND "userId" = ${principal.ownerId} AND "deletedAt" IS NULL FOR UPDATE`
      : await tx.$queryRaw<
          { id: string }[]
        >`SELECT id FROM credential WHERE id = ${id} AND "userId" = ${principal.ownerId} AND "deletedAt" IS NULL FOR SHARE`;
  if (rows.length !== 1) throw credentialError("credential.not_found");
  return tx.credential.findUniqueOrThrow({
    where: { id },
    select: {
      id: true,
      name: true,
      mode: true,
      delivery: true,
      copyBack: true,
      definitionDigest: true,
      Definition: { select: { id: true, slug: true, document: true, digest: true } },
    },
  });
}

/** Loads a pinned definition for use: digest recomputed, else `credential.definition_corrupt`. */
async function verified(document: unknown, digest: string): Promise<LoginDefinition> {
  const result = await loadVerifiedDefinition(document, digest);
  if (!result.success) {
    if (result.error.code === "credential.definition_corrupt")
      throw credentialError("credential.definition_corrupt");
    throw credentialError("definition.invalid");
  }
  return result.definition;
}

function hasFiles(definition: LoginDefinition): boolean {
  const files = definition.credentials.files;
  return (files?.required.length ?? 0) + (files?.optional.length ?? 0) > 0;
}

function proxyCapable(definition: LoginDefinition): boolean {
  const env = definition.credentials.env ?? [];
  return !hasFiles(definition) && env.length > 0 && env.every((entry) => entry.proxy !== undefined);
}

function mapValueErrors(error: unknown): never {
  if (error instanceof CredentialValueInvalid)
    throw credentialError("credential.value_invalid", {
      entry: error.entry,
      ...(error.path === undefined ? {} : { path: error.path }),
    });
  if (error instanceof CredentialVaultUnavailable) throw credentialError("credential.unavailable");
  if (error instanceof DataKeyStaleWriter) throw staleWriterError();
  throw error;
}

async function recordEvent(
  tx: Tx,
  principal: Principal,
  event: Omit<Prisma.CredentialEventUncheckedCreateInput, "userId" | "id" | "at">,
) {
  await tx.credentialEvent.create({
    data: { ...event, userId: principal.ownerId },
    select: { id: true },
  });
}

/**
 * Live work that refuses delete and re-pin, in one statement: a non-terminal
 * lease, uncleared residue (only recoverable residue for re-pin), or a pending
 * capture of any lease in scope.
 */
async function liveBlockers(
  tx: Tx,
  where: { credentialId: string; accountId?: string; instanceId?: string },
  options: { recoverableResidueOnly: boolean },
): Promise<boolean> {
  const account = where.accountId ?? null;
  const instance = where.instanceId ?? null;
  const rows = await tx.$queryRaw<{ blocked: boolean }[]>`SELECT (
      EXISTS (SELECT 1 FROM credential_lease l WHERE l."credentialId" = ${where.credentialId}
        AND (${account}::text IS NULL OR l."accountId" = ${account})
        AND (${instance}::text IS NULL OR l."instanceId" = ${instance})
        AND l.state::text IN ('RESERVED', 'INSTALLING', 'ACTIVE', 'RELEASING', 'RECOVERY_REQUIRED', 'RECOVERING'))
      OR EXISTS (SELECT 1 FROM credential_residue r JOIN credential_instance i ON i.id = r."instanceId"
        WHERE r."credentialId" = ${where.credentialId} AND r."clearedAt" IS NULL
        AND (${options.recoverableResidueOnly} = false OR r.recoverable)
        AND (${account}::text IS NULL OR i."accountId" = ${account})
        AND (${instance}::text IS NULL OR r."instanceId" = ${instance}))
      OR EXISTS (SELECT 1 FROM credential_pending_capture p JOIN credential_lease l ON l.id = p."leaseId"
        WHERE l."credentialId" = ${where.credentialId}
        AND (${account}::text IS NULL OR l."accountId" = ${account})
        AND (${instance}::text IS NULL OR l."instanceId" = ${instance}))
    ) AS blocked`;
  return rows[0]?.blocked === true;
}

/** Removes settled lease history (and its bindings/residue by cascade) before instances go. */
async function deleteSettledLeases(tx: Tx, where: Prisma.CredentialLeaseWhereInput) {
  await tx.credentialLease.deleteMany({
    where: { ...where, state: { in: ["RELEASED", "FORCE_RELEASED", "ABANDONED"] } },
  });
}

// --- Status --------------------------------------------------------------------

export const status = serviceProcedure({ sessionOnly: true }, async () => {
  const availability = readCredentialsAvailability();
  return {
    enabled: availability.enabled,
    keyPresent: availability.keyPresent,
    drain: availability.drain,
  };
});

// --- Definitions -------------------------------------------------------------

export const listDefinitions = serviceProcedure(
  { action: "credentialDefinitions.list" },
  async (principal: Principal, input: z.input<typeof credentialPageInput>) => {
    requireCredentials("read");
    const page = parse(credentialPageInput, input);
    const rows = await prisma.credentialDefinition.findMany({
      where: withCursor({ userId: principal.ownerId }, "createdAt", page.cursor, "desc"),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: definitionSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return { items: result.items.map(toDefinitionDto), nextCursor: result.nextCursor };
  },
);

export const getDefinition = serviceProcedure(
  { action: "credentialDefinitions.get" },
  async (
    principal: Principal,
    input: z.input<typeof credentialIdInput>,
  ): Promise<CredentialDefinitionDetailDto> => {
    requireCredentials("read");
    const { id } = parse(credentialIdInput, input);
    const row = await prisma.credentialDefinition.findFirst({
      where: { id, userId: principal.ownerId },
      select: { ...definitionSelect, document: true },
    });
    if (!row) throw credentialError("credential.definition_not_found");
    const result = await loadVerifiedDefinition(row.document, row.digest);
    return {
      ...toDefinitionDto(row),
      document: row.document as Record<string, unknown>,
      warnings: result.success ? result.warnings : [result.error.code],
    };
  },
);

/**
 * Stores a new immutable definition version. The slug is the document's `id`;
 * the version is the next for that slug. Validation is the shared C1 parser;
 * the stored digest is the SHA-256 of the canonical JSON it produced.
 */
export const createDefinition = serviceProcedure(
  { action: "credentialDefinitions.create" },
  async (principal: Principal, input: z.input<typeof createDefinitionInput>) => {
    requireCredentials("write");
    const body = parse(createDefinitionInput, input);
    let parsed: ReturnType<typeof parseLoginDefinition>;
    let document: Record<string, unknown>;
    if ("text" in body) {
      const result = parseLoginDefinitionText(body.text);
      parsed = result;
      document = result.success ? result.document : {};
    } else {
      parsed = parseLoginDefinition(body.document);
      document = body.document;
    }
    if (!parsed.success)
      throw credentialError(parsed.error.code, { issues: parsed.error.issues.slice(0, 20) });
    assertDefinitionSpecContribution(parsed.definition);
    const digest = await canonicalDigestHex(parsed.canonical);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialDefinitions.create", {}, tx);
      await lockOwnerCredentialCounts(tx, principal.ownerId);
      await assertOwnerCredentialCapacity(tx, principal.ownerId, "definitions");
      const last = await tx.credentialDefinition.findFirst({
        where: { userId: principal.ownerId, slug: parsed.definition.id },
        orderBy: { version: "desc" },
        select: { version: true },
      });
      return tx.credentialDefinition.create({
        data: {
          userId: principal.ownerId,
          slug: parsed.definition.id,
          version: (last?.version ?? 0) + 1,
          document: document as Prisma.InputJsonValue,
          digest,
          displayName: parsed.definition.displayName,
        },
        select: definitionSelect,
      });
    });
    return { ...toDefinitionDto(row), warnings: parsed.warnings };
  },
);

export const archiveDefinition = serviceProcedure(
  { action: "credentialDefinitions.archive" },
  async (principal: Principal, input: z.input<typeof credentialIdInput>) => {
    requireCredentials("settle");
    const { id } = parse(credentialIdInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialDefinitions.archive", {}, tx);
      await tx.credentialDefinition.updateMany({
        where: { id, userId: principal.ownerId, archivedAt: null },
        data: { archivedAt: new Date() },
      });
      const found = await tx.credentialDefinition.findFirst({
        where: { id, userId: principal.ownerId },
        select: definitionSelect,
      });
      if (!found) throw credentialError("credential.definition_not_found");
      return found;
    });
    return toDefinitionDto(row);
  },
);

// --- Logins ------------------------------------------------------------------

export const listLogins = serviceProcedure(
  { action: "credentials.list" },
  async (principal: Principal, input: z.input<typeof credentialPageInput>) => {
    requireCredentials("read");
    const page = parse(credentialPageInput, input);
    const rows = await prisma.credential.findMany({
      where: withCursor(credentialAccessFilter(principal), "createdAt", page.cursor, "desc"),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: loginSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return { items: result.items.map(toLoginDto), nextCursor: result.nextCursor };
  },
);

export const getLogin = serviceProcedure(
  { action: "credentials.get" },
  async (principal: Principal, input: z.input<typeof credentialIdInput>) => {
    requireCredentials("read");
    const { id } = parse(credentialIdInput, input);
    const row = await prisma.credential.findFirst({
      where: { AND: [credentialAccessFilter(principal), { id }] },
      select: loginSelect,
    });
    if (!row) throw credentialError("credential.not_found");
    return toLoginDto(row);
  },
);

/**
 * Creates a login pinned to one definition version. Mode follows the
 * definition's `sharing`. Delivery is immutable: PROXY needs a definition that
 * proxies every env entry and has no files, and never copies back. SDK keys
 * can create only GUEST logins without foreign opt-in (§12 whitelist).
 */
export const createLogin = serviceProcedure(
  { action: "credentials.create" },
  async (principal: Principal, input: z.input<typeof createLoginInput>) => {
    requireCredentials("write");
    const body = parse(createLoginInput, input);
    if (
      !isBrowserSession(principal) &&
      (body.delivery === "PROXY" || body.foreignAllowed || body.copyBack !== undefined)
    )
      throw new ORPCError("FORBIDDEN", {
        message: "Delivery, copy-back and foreign hosts are set from the dashboard.",
      });
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentials.create", {}, tx);
      await lockOwnerCredentialCounts(tx, principal.ownerId);
      await assertOwnerCredentialCapacity(tx, principal.ownerId, "logins");
      const definition = await tx.credentialDefinition.findFirst({
        where: { id: body.definitionId, userId: principal.ownerId, archivedAt: null },
        select: { id: true, document: true, digest: true },
      });
      if (!definition) throw credentialError("credential.definition_not_found");
      const verifiedDefinition = await verified(definition.document, definition.digest);
      const mode =
        verifiedDefinition.credentials.sharing === "shareable" ? "SHAREABLE" : "EXCLUSIVE";
      const delivery = body.delivery ?? "GUEST";
      if (delivery === "PROXY" && !proxyCapable(verifiedDefinition))
        throw credentialError("definition.invalid", {
          issues: [
            {
              path: "credentials.env",
              message: "PROXY delivery needs every env entry proxied and no files",
            },
          ],
        });
      const copyBack =
        delivery === "GUEST" && mode === "EXCLUSIVE" ? (body.copyBack ?? true) : false;
      if (body.copyBack && !copyBack)
        throw credentialError("definition.invalid", {
          issues: [
            { path: "copyBack", message: "copy-back applies only to exclusive guest logins" },
          ],
        });
      const checkpointIntervalMin =
        body.checkpointIntervalMin !== undefined
          ? body.checkpointIntervalMin
          : copyBack && hasFiles(verifiedDefinition)
            ? 30
            : null;
      const now = new Date();
      try {
        const created = await tx.credential.create({
          data: {
            userId: principal.ownerId,
            name: body.name,
            definitionId: definition.id,
            definitionDigest: definition.digest,
            mode,
            delivery,
            copyBack,
            checkpointIntervalMin,
            foreignAllowed: body.foreignAllowed ?? false,
            ...(body.foreignAllowed
              ? { foreignAllowedAt: now, foreignAllowedBy: principal.ownerId }
              : {}),
          },
          select: loginSelect,
        });
        await recordEvent(tx, principal, { credentialId: created.id, type: "created" });
        return created;
      } catch (error) {
        if (
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "P2002"
        )
          throw credentialError("credential.name_taken");
        throw error;
      }
    });
    return toLoginDto(row);
  },
);

/** SDK-editable settings: name and checkpoint interval. */
export const updateLogin = serviceProcedure(
  { action: "credentials.update" },
  async (principal: Principal, input: z.input<typeof updateLoginInput>) => {
    requireCredentials("write");
    const body = parse(updateLoginInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentials.update", {}, tx);
      const login = await lockLogin(tx, principal, body.id, "update");
      if (body.checkpointIntervalMin != null && !login.copyBack)
        throw credentialError("definition.invalid", {
          issues: [{ path: "checkpointIntervalMin", message: "checkpoints need copy-back" }],
        });
      try {
        const updated = await tx.credential.update({
          where: { id: login.id },
          data: {
            ...(body.name !== undefined ? { name: body.name } : {}),
            ...(body.checkpointIntervalMin !== undefined
              ? { checkpointIntervalMin: body.checkpointIntervalMin }
              : {}),
          },
          select: loginSelect,
        });
        await recordEvent(tx, principal, { credentialId: login.id, type: "settings_changed" });
        return updated;
      } catch (error) {
        if (
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "P2002"
        )
          throw credentialError("credential.name_taken");
        throw error;
      }
    });
    return toLoginDto(row);
  },
);

/**
 * Browser-only policy: copy-back and foreign-host opt-in. Read inside every
 * claim transaction, so a change applies to the next claim. Copy-back is
 * meaningful only for exclusive guest logins.
 */
export const updateLoginPolicy = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: z.input<typeof updateLoginPolicyInput>) => {
    requireCredentials("write");
    const body = parse(updateLoginPolicyInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentials.update", {}, tx);
      const login = await lockLogin(tx, principal, body.id, "update");
      if (body.copyBack && (login.mode !== "EXCLUSIVE" || login.delivery !== "GUEST"))
        throw credentialError("definition.invalid", {
          issues: [
            { path: "copyBack", message: "copy-back applies only to exclusive guest logins" },
          ],
        });
      const now = new Date();
      const updated = await tx.credential.update({
        where: { id: login.id },
        data: {
          ...(body.copyBack !== undefined
            ? { copyBack: body.copyBack, ...(body.copyBack ? {} : { checkpointIntervalMin: null }) }
            : {}),
          ...(body.foreignAllowed !== undefined
            ? body.foreignAllowed
              ? { foreignAllowed: true, foreignAllowedAt: now, foreignAllowedBy: principal.ownerId }
              : { foreignAllowed: false, foreignAllowedAt: null, foreignAllowedBy: null }
            : {}),
        },
        select: loginSelect,
      });
      await recordEvent(tx, principal, {
        credentialId: login.id,
        type: "policy_changed",
        reason: [
          body.copyBack !== undefined ? `copyBack=${body.copyBack}` : null,
          body.foreignAllowed !== undefined ? `foreignAllowed=${body.foreignAllowed}` : null,
        ]
          .filter(Boolean)
          .join(","),
      });
      return updated;
    });
    return toLoginDto(row);
  },
);

function proxySpec(definition: LoginDefinition): string {
  return JSON.stringify(
    (definition.credentials.env ?? []).map((entry) => [entry.name, entry.proxy ?? null]),
  );
}

/**
 * Re-pin (§4.5): move a login to another version of the same definition.
 * Refused `credential.repin_blocked` while any instance has a non-terminal
 * lease, uncleared recoverable residue or a pending capture; the check runs
 * under the login FOR UPDATE, which blocks new claims (FOR SHARE). Each value
 * (and a newer checkpoint) is re-encrypted under the new policy after
 * validation against the new definition. A PROXY login whose proxy spec
 * changed is erased instead, only with the login's name typed as confirmation.
 */
export const repinLogin = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: z.input<typeof repinLoginInput>) => {
    requireCredentials("write");
    const body = parse(repinLoginInput, input);
    await consumeCredentialRepin(principal.ownerId);
    try {
      const row = await prisma.$transaction(
        async (tx) => {
          await authorizeServiceAction(principal, "credentials.update", {}, tx);
          const login = await lockLogin(tx, principal, body.id, "update");
          const target = await tx.credentialDefinition.findFirst({
            where: { id: body.definitionId, userId: principal.ownerId, archivedAt: null },
            select: { id: true, slug: true, document: true, digest: true },
          });
          if (!target || target.slug !== login.Definition.slug)
            throw credentialError("credential.definition_not_found");
          if (await liveBlockers(tx, { credentialId: login.id }, { recoverableResidueOnly: true }))
            throw credentialError("credential.repin_blocked");
          const fromDefinition = await verified(login.Definition.document, login.definitionDigest);
          const toDefinition = await verified(target.document, target.digest);
          const toMode =
            toDefinition.credentials.sharing === "shareable" ? "SHAREABLE" : "EXCLUSIVE";
          if (toMode !== login.mode || (login.delivery === "PROXY" && !proxyCapable(toDefinition)))
            throw credentialError("credential.repin_blocked", {
              reason: "incompatible_definition",
            });
          const erase =
            login.delivery === "PROXY" && proxySpec(fromDefinition) !== proxySpec(toDefinition);
          if (erase && body.confirmErase !== login.name)
            throw credentialError("credential.repin_confirm_erase");
          const from: VerifiedLogin = {
            userId: principal.ownerId,
            credentialId: login.id,
            definition: fromDefinition,
            definitionDigest: login.definitionDigest,
            delivery: login.delivery,
          };
          const to: VerifiedLogin = {
            ...from,
            definition: toDefinition,
            definitionDigest: target.digest,
          };
          const instances = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
            WHERE "credentialId" = ${login.id} AND "userId" = ${principal.ownerId} ORDER BY id FOR UPDATE`;
          for (const instance of instances)
            await repinInstanceValue(tx, from, to, instance.id, { erase });
          const updated = await tx.credential.update({
            where: { id: login.id },
            data: { definitionId: target.id, definitionDigest: target.digest },
            select: loginSelect,
          });
          // The new definition must not introduce an env/path conflict on any
          // sandbox the login stays attached to (checked against the pin just
          // written; a refusal rolls it back). The claim gate re-decides at
          // every later claim under the definition locks.
          await requireRepinKeepsSetsDisjoint(tx, principal.ownerId, login.id);
          await recordEvent(tx, principal, {
            credentialId: login.id,
            type: "repinned",
            reason: erase ? "erased" : "reencrypted",
          });
          return updated;
        },
        { timeout: 60_000 },
      );
      return toLoginDto(row);
    } catch (error) {
      return mapValueErrors(error);
    }
  },
);

const REPIN_ATTACHMENT_PAGE = 100;

/** Every live attachment set of the login, paged by attachment id. */
async function requireRepinKeepsSetsDisjoint(
  tx: Prisma.TransactionClient,
  ownerId: string,
  credentialId: string,
): Promise<void> {
  let cursor: string | undefined;
  for (;;) {
    const page = await tx.sandboxCredential.findMany({
      where: {
        credentialId,
        userId: ownerId,
        detachedAt: null,
        Sandbox: { state: { not: "DELETED" } },
        ...(cursor ? { id: { gt: cursor } } : {}),
      },
      select: { id: true, sandboxId: true },
      orderBy: { id: "asc" },
      take: REPIN_ATTACHMENT_PAGE,
    });
    for (const attachment of page) {
      const set = await tx.sandboxCredential.findMany({
        where: { sandboxId: attachment.sandboxId, detachedAt: null },
        select: { credentialId: true },
        orderBy: { credentialId: "asc" },
        take: 8,
      });
      await requireDisjointAttachmentSet(tx, {
        ownerId,
        sandboxId: attachment.sandboxId,
        credentialIds: set.map((row) => row.credentialId),
      });
    }
    if (page.length < REPIN_ATTACHMENT_PAGE) return;
    cursor = page[page.length - 1]!.id;
  }
}

export const deleteLogin = serviceProcedure(
  { action: "credentials.delete" },
  async (principal: Principal, input: z.input<typeof credentialIdInput>) => {
    requireCredentials("settle");
    const { id } = parse(credentialIdInput, input);
    await consumeCredentialWrite(principal.ownerId);
    await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentials.delete", {}, tx);
      const login = await lockLogin(tx, principal, id, "update");
      if (await liveBlockers(tx, { credentialId: login.id }, { recoverableResidueOnly: false }))
        throw credentialError("credential.busy");
      // E1-B-04: destroying a sandbox does not detach its logins. Once the
      // sandbox is DELETED with no live resources and every lease, residue
      // and capture has settled (liveBlockers above), its attachment no
      // longer holds the login: detach it here instead of refusing forever.
      await tx.sandboxCredential.updateMany({
        where: {
          credentialId: login.id,
          detachedAt: null,
          Sandbox: { state: "DELETED", liveResourcesHeld: false },
        },
        data: { detachedAt: new Date() },
      });
      const attached = await tx.sandboxCredential.findFirst({
        where: { credentialId: login.id, detachedAt: null },
        select: { id: true },
      });
      const sessions = await tx.credentialLoginSession.findFirst({
        where: { credentialId: login.id, state: { in: ["PROVISIONING", "READY", "SAVING"] } },
        select: { id: true },
      });
      if (attached || sessions) throw credentialError("credential.busy");
      await deleteSettledLeases(tx, { credentialId: login.id });
      await tx.credential.delete({ where: { id: login.id }, select: { id: true } });
      await recordEvent(tx, principal, { credentialId: login.id, type: "deleted" });
    });
    return { deleted: true as const };
  },
);

export const listEvents = serviceProcedure(
  { action: "credentials.events" },
  async (principal: Principal, input: z.input<typeof credentialScopedPageInput>) => {
    requireCredentials("read");
    const page = parse(credentialScopedPageInput, input);
    await visibleLogin(prisma, principal, page.credentialId);
    const rows = await prisma.credentialEvent.findMany({
      where: withCursor(
        { userId: principal.ownerId, credentialId: page.credentialId },
        "at",
        page.cursor,
        "desc",
      ),
      orderBy: [{ at: "desc" }, { id: "desc" }],
      take: pageTake(page.limit),
      select: eventSelect,
    });
    const result = cursorPage(rows, page.limit, "at");
    return {
      items: result.items.map((row): CredentialEventDto => ({ ...row, at: iso(row.at) })),
      nextCursor: result.nextCursor,
    };
  },
);

// --- Accounts ----------------------------------------------------------------

export const listAccounts = serviceProcedure(
  { action: "credentialAccounts.list" },
  async (principal: Principal, input: z.input<typeof credentialScopedPageInput>) => {
    requireCredentials("read");
    const page = parse(credentialScopedPageInput, input);
    await visibleLogin(prisma, principal, page.credentialId);
    const rows = await prisma.credentialAccount.findMany({
      where: withCursor(
        { userId: principal.ownerId, credentialId: page.credentialId },
        "createdAt",
        page.cursor,
        "asc",
      ),
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      take: pageTake(page.limit),
      select: accountSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return { items: result.items.map(toAccountDto), nextCursor: result.nextCursor };
  },
);

export const createAccount = serviceProcedure(
  { action: "credentialAccounts.create" },
  async (principal: Principal, input: z.input<typeof createAccountInput>) => {
    requireCredentials("write");
    const body = parse(createAccountInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialAccounts.create", {}, tx);
      await visibleLogin(tx, principal, body.credentialId);
      const created = await insertAccount(tx, principal.ownerId, {
        credentialId: body.credentialId,
        name: body.name ?? null,
      });
      await recordEvent(tx, principal, {
        credentialId: body.credentialId,
        accountId: created.id,
        type: "account_created",
      });
      return tx.credentialAccount.findUniqueOrThrow({
        where: { id: created.id },
        select: accountSelect,
      });
    });
    return toAccountDto(row);
  },
);

/** Rename and pause/unpause. Pause applies to new claims; running sandboxes keep their leases. */
export const updateAccount = serviceProcedure(
  { action: "credentialAccounts.update" },
  async (principal: Principal, input: z.input<typeof updateAccountInput>) => {
    requireCredentials("write");
    const body = parse(updateAccountInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialAccounts.update", {}, tx);
      await visibleLogin(tx, principal, body.credentialId);
      if (body.paused !== undefined) {
        await setAccountPaused(tx, principal.ownerId, {
          credentialId: body.credentialId,
          accountId: body.accountId,
          paused: body.paused,
          by: isBrowserSession(principal)
            ? principal.ownerId
            : `key:${recordedKeyIdOf(principal) ?? principal.ownerId}`,
        });
        await recordEvent(tx, principal, {
          credentialId: body.credentialId,
          accountId: body.accountId,
          type: body.paused ? "account_paused" : "account_unpaused",
        });
      }
      if (body.name !== undefined) {
        const renamed = await tx.credentialAccount
          .updateMany({
            where: {
              id: body.accountId,
              credentialId: body.credentialId,
              userId: principal.ownerId,
            },
            data: { name: body.name },
          })
          .catch((error: unknown) => {
            if (
              typeof error === "object" &&
              error !== null &&
              "code" in error &&
              error.code === "P2002"
            )
              throw credentialError("credential.name_taken");
            throw error;
          });
        if (renamed.count !== 1) throw credentialError("credential.account_not_found");
      }
      const found = await tx.credentialAccount.findFirst({
        where: { id: body.accountId, credentialId: body.credentialId, userId: principal.ownerId },
        select: accountSelect,
      });
      if (!found) throw credentialError("credential.account_not_found");
      return found;
    });
    return toAccountDto(row);
  },
);

export const deleteAccount = serviceProcedure(
  { action: "credentialAccounts.delete" },
  async (principal: Principal, input: z.input<typeof accountIdInput>) => {
    requireCredentials("settle");
    const body = parse(accountIdInput, input);
    await consumeCredentialWrite(principal.ownerId);
    await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialAccounts.delete", {}, tx);
      await lockLogin(tx, principal, body.credentialId, "share");
      const account = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_account
        WHERE id = ${body.accountId} AND "credentialId" = ${body.credentialId} AND "userId" = ${principal.ownerId} FOR UPDATE`;
      if (account.length !== 1) throw credentialError("credential.account_not_found");
      const held = await tx.credentialInstance.findFirst({
        where: {
          accountId: body.accountId,
          OR: [{ activeLeases: { gt: 0 } }, { loginLeaseId: { not: null } }],
        },
        select: { id: true },
      });
      if (
        held ||
        (await liveBlockers(
          tx,
          { credentialId: body.credentialId, accountId: body.accountId },
          { recoverableResidueOnly: false },
        ))
      )
        throw credentialError("credential.busy");
      await deleteSettledLeases(tx, { accountId: body.accountId });
      await tx.credentialAccount.delete({ where: { id: body.accountId }, select: { id: true } });
      await recordEvent(tx, principal, {
        credentialId: body.credentialId,
        accountId: body.accountId,
        type: "account_deleted",
      });
    });
    return { deleted: true as const };
  },
);

// --- Instances ---------------------------------------------------------------

export const listInstances = serviceProcedure(
  { action: "credentialInstances.list" },
  async (principal: Principal, input: z.input<typeof accountScopedPageInput>) => {
    requireCredentials("read");
    const page = parse(accountScopedPageInput, input);
    await visibleLogin(prisma, principal, page.credentialId);
    const rows = await prisma.credentialInstance.findMany({
      where: withCursor(
        { userId: principal.ownerId, credentialId: page.credentialId, accountId: page.accountId },
        "createdAt",
        page.cursor,
        "asc",
      ),
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      take: pageTake(page.limit),
      select: instanceSelect,
    });
    const result = cursorPage(rows, page.limit, "createdAt");
    return { items: result.items.map(toInstanceDto), nextCursor: result.nextCursor };
  },
);

/** Adds an instance (wssp cannot verify which provider account a token set belongs to). */
export const createInstance = serviceProcedure(
  { action: "credentialInstances.create" },
  async (principal: Principal, input: z.input<typeof createInstanceInput>) => {
    requireCredentials("write");
    const body = parse(createInstanceInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialInstances.create", {}, tx);
      await visibleLogin(tx, principal, body.credentialId);
      const created = await insertInstance(tx, principal.ownerId, {
        credentialId: body.credentialId,
        accountId: body.accountId,
        name: body.name ?? null,
        maxConcurrent: body.maxConcurrent ?? null,
      });
      await recordEvent(tx, principal, {
        credentialId: body.credentialId,
        accountId: body.accountId,
        instanceId: created.id,
        type: "instance_created",
      });
      return tx.credentialInstance.findUniqueOrThrow({
        where: { id: created.id },
        select: instanceSelect,
      });
    });
    return toInstanceDto(row);
  },
);

async function lockInstance(
  tx: Tx,
  principal: Principal,
  credentialId: string,
  instanceId: string,
) {
  const rows = await tx.$queryRaw<{ id: string }[]>`SELECT id FROM credential_instance
    WHERE id = ${instanceId} AND "credentialId" = ${credentialId} AND "userId" = ${principal.ownerId} FOR UPDATE`;
  if (rows.length !== 1) throw credentialError("credential.instance_not_found");
  return tx.credentialInstance.findUniqueOrThrow({
    where: { id: instanceId },
    select: { id: true, accountId: true, capacity: true, activeLeases: true, loginLeaseId: true },
  });
}

/** Name, and `maxConcurrent` for SHAREABLE logins (lowering below use is allowed overcommit). */
export const updateInstance = serviceProcedure(
  { action: "credentialInstances.update" },
  async (principal: Principal, input: z.input<typeof updateInstanceInput>) => {
    requireCredentials("write");
    const body = parse(updateInstanceInput, input);
    await consumeCredentialWrite(principal.ownerId);
    const row = await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialInstances.update", {}, tx);
      const login = await lockLogin(tx, principal, body.credentialId, "share");
      await lockInstance(tx, principal, body.credentialId, body.instanceId);
      if (body.maxConcurrent !== undefined && login.mode !== "SHAREABLE")
        throw credentialError("definition.invalid", {
          issues: [{ path: "maxConcurrent", message: "only shareable logins have maxConcurrent" }],
        });
      try {
        return await tx.credentialInstance.update({
          where: { id: body.instanceId },
          data: {
            ...(body.name !== undefined ? { name: body.name } : {}),
            ...(body.maxConcurrent !== undefined ? { capacity: body.maxConcurrent } : {}),
          },
          select: instanceSelect,
        });
      } catch (error) {
        if (
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "P2002"
        )
          throw credentialError("credential.name_taken");
        throw error;
      }
    });
    return toInstanceDto(row);
  },
);

/** Only with no holder, no non-terminal lease, no uncleared residue and no pending capture. */
export const deleteInstance = serviceProcedure(
  { action: "credentialInstances.delete" },
  async (principal: Principal, input: z.input<typeof instanceIdInput>) => {
    requireCredentials("settle");
    const body = parse(instanceIdInput, input);
    await consumeCredentialWrite(principal.ownerId);
    await prisma.$transaction(async (tx) => {
      await authorizeServiceAction(principal, "credentialInstances.delete", {}, tx);
      await lockLogin(tx, principal, body.credentialId, "share");
      const instance = await lockInstance(tx, principal, body.credentialId, body.instanceId);
      if (
        instance.activeLeases > 0 ||
        instance.loginLeaseId !== null ||
        (await liveBlockers(
          tx,
          { credentialId: body.credentialId, instanceId: instance.id },
          { recoverableResidueOnly: false },
        ))
      )
        throw credentialError("credential.busy");
      await deleteSettledLeases(tx, { instanceId: instance.id });
      await tx.credentialInstance.delete({ where: { id: instance.id }, select: { id: true } });
      await recordEvent(tx, principal, {
        credentialId: body.credentialId,
        accountId: instance.accountId,
        instanceId: instance.id,
        type: "instance_deleted",
      });
    });
    return { deleted: true as const };
  },
);

/**
 * Upload a value (§11.4). Files are base64 on the wire and become the binary
 * bundle inside the vault module; env and proxied header values are checked
 * against the verified definition. An exclusive instance with a holder, or any
 * instance in a login session, refuses (`credential.busy`); shareable instances
 * accept writes while leased (running leases keep their installed value).
 * The response is metadata only.
 */
export const writeValue = serviceProcedure(
  { action: "credentialInstances.writeValue" },
  async (
    principal: Principal,
    input: z.input<typeof writeValueInput>,
  ): Promise<CredentialValueWriteResult> => {
    requireCredentials("write");
    const body = parse(writeValueInput, input);
    await consumeCredentialValueWrite(principal.ownerId);
    try {
      return await prisma.$transaction(
        async (tx) => {
          await authorizeServiceAction(principal, "credentialInstances.writeValue", {}, tx);
          const login = await lockLogin(tx, principal, body.credentialId, "share");
          const instance = await lockInstance(tx, principal, body.credentialId, body.instanceId);
          if (
            instance.loginLeaseId !== null ||
            (login.mode === "EXCLUSIVE" && instance.activeLeases > 0)
          )
            throw credentialError("credential.busy");
          const definition = await verified(login.Definition.document, login.definitionDigest);
          const written = await writeUploadedValue(
            tx,
            {
              userId: principal.ownerId,
              credentialId: login.id,
              definition,
              definitionDigest: login.definitionDigest,
              delivery: login.delivery,
            },
            instance.id,
            {
              files: (body.files ?? []).map((file) => ({
                path: file.path,
                kind: file.kind ?? "file",
                ...(file.mode !== undefined ? { mode: file.mode } : {}),
                ...(file.kind === "dir"
                  ? {}
                  : { data: Buffer.from(file.contentBase64 ?? "", "base64") }),
              })),
              env: Object.entries(body.env ?? {}).map(([name, value]) => ({
                name,
                value: Buffer.from(value, "utf8"),
              })),
            },
          );
          await recordEvent(tx, principal, {
            credentialId: login.id,
            accountId: instance.accountId,
            instanceId: instance.id,
            type: "value_written",
            storageSeq: written.storageSeq,
            sizeBytes: written.sizeBytes,
          });
          return {
            instanceId: instance.id,
            storageSeq: written.storageSeq,
            sizeBytes: written.sizeBytes,
            state: "READY" as const,
          };
        },
        { timeout: 30_000 },
      );
    } catch (error) {
      return mapValueErrors(error);
    }
  },
);

// --- Owner recovery actions (C11) ------------------------------------------------

export {
  discardRejectedCaptures,
  discardRejectedInput,
  forceRelease,
  forceReleaseInput,
  instanceScopedPageInput,
  listInstanceLeases,
  listRejectedCaptures,
} from "./owner-actions";
