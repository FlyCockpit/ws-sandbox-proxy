import { AsyncLocalStorage } from "node:async_hooks";
import { ORPCError } from "@orpc/server";
import {
  AGENT_TOKEN_NO_EXPIRY_BLOCKED_CODE,
  agentTokenBlockedByPolicy,
} from "@wssp/config/agent-token-limits";
import prisma, { type Prisma, type SdkKeyResourceMode } from "@wssp/db";
import { AccountDeletionConflictError, lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { authorityTicket } from "@wssp/db/authority";
import {
  credentialLookupPrefix,
  generateProductCredentialSecret,
  hmacDigestForProductPurpose,
  parseAgentTokenCredentialSecret,
  parseSdkKeyCredentialSecret,
  verifyProductCredentialDigest,
} from "@wssp/db/credential-security";
import { env } from "@wssp/env/server";
import {
  type AuthorizingPrincipal,
  type Principal,
  type SessionPrincipal,
  sessionPrincipal,
} from "../sandbox/contracts";
import {
  hostNotFound,
  poolNotFound,
  sandboxStateConflict,
  templateNotFound,
} from "../sandbox/errors";
import { guardManagedSandboxTarget } from "../sandbox/managed-sandbox";
import { assertNever, isBrowserSession, recordedKeyIdOf } from "../sandbox/principal-kinds";
import { RelayFenceRejected } from "../sandbox/relay-fence";
import { rethrowSensitiveSandboxError } from "../sandbox/sensitive-errors";
import { requireCurrentHostUsability } from "../sandbox/sharing-access";
import { requirePoolUse } from "../sandbox/sharing-authority";
import {
  BUILD_ACTIVE_STATES,
  type BuildRole,
  buildActionClass,
  buildAuthorityLost,
  buildStepAllowed,
  captureOutlivesCancel,
  TEMPLATE_BUILD_SCOPE,
  untargetedCreateRole,
} from "../template-builds/build-authority";
import type { BuildPrincipal } from "../template-builds/principal";
import {
  isOwnerCredentialPolicySatisfied,
  ownerCredentialPolicyUserSelect,
} from "./owner-credential-policy";
import { isPrismaForeignKeyViolation } from "./prisma-errors";
import {
  mutationScopeForOperationKind,
  parseServiceScopeSet,
  SERVICE_ACTION_REQUIREMENTS,
  type ServiceAction,
  type ServiceActionContext,
  type ServiceScope,
} from "./service-scopes";
import { getForcedTwoFactorSettingsRecord } from "./two-factor-policy";

export type { ServiceAction, ServiceActionContext, ServiceScope } from "./service-scopes";
export {
  mutationScopeForOperationKind,
  parseServiceScopeSet,
  SERVICE_ACTION_REQUIREMENTS,
  SERVICE_ACTIONS,
  SERVICE_SCOPES,
  serviceActionForOperationKind,
} from "./service-scopes";

export type ServicePrincipal = {
  kind: "sdkKey";
  credentialKind: "API" | "AGENT_TOKEN" | "OAUTH_GRANT";
  ownSandboxesOnly: boolean;
  expiresAt: Date | null;
  keyId: string;
  ownerId: string;
  resourceMode: SdkKeyResourceMode;
  scopes: ReadonlySet<ServiceScope>;
  allowedHostIds: ReadonlySet<string> | "allOwned";
  allowedRevisionIds: ReadonlySet<string> | "allOwned";
  allowedPoolIds: ReadonlySet<string> | "allUsable";
};

export const sdkKeyListSelect = {
  id: true,
  name: true,
  resourceMode: true,
  kind: true,
  ownSandboxesOnly: true,
  poolMode: true,
  scopes: true,
  lookupPrefix: true,
  lastUsedAt: true,
  revokedAt: true,
  expiresAt: true,
  createdAt: true,
  // Names as well as ids, so the owner can audit a key's reach from the list
  // (M7-S11). Bounded by the mint input (at most 200 of each).
  HostAllowlist: {
    select: { sandboxHostId: true, SandboxHost: { select: { slug: true, label: true } } },
  },
  PoolAllowlist: { select: { poolId: true, Pool: { select: { slug: true, label: true } } } },
  RevisionAllowlist: {
    select: {
      templateRevisionId: true,
      Revision: { select: { revision: true, Template: { select: { label: true } } } },
    },
  },
  CredentialAllowlist: {
    select: { credentialId: true, Credential: { select: { name: true } } },
  },
} satisfies Prisma.SdkKeySelect;

const sdkKeyCredentialSelect = {
  id: true,
  userId: true,
  resourceMode: true,
  kind: true,
  ownSandboxesOnly: true,
  poolMode: true,
  scopes: true,
  lookupPrefix: true,
  secretDigest: true,
  revokedAt: true,
  expiresAt: true,
  HostAllowlist: { select: { sandboxHostId: true, SandboxHost: { select: { userId: true } } } },
  RevisionAllowlist: { select: { templateRevisionId: true } },
  PoolAllowlist: { select: { poolId: true } },
  User: {
    select: ownerCredentialPolicyUserSelect,
  },
} satisfies Prisma.SdkKeySelect;

type SdkKeyCredentialRow = Prisma.SdkKeyGetPayload<{ select: typeof sdkKeyCredentialSelect }>;

// First lookup on every /v1 request: only what the pre-digest gates read. The
// allowlists come from revalidateSdkKey's full select after the ticket.
const sdkKeyLookupSelect = {
  kind: true,
  ownSandboxesOnly: true,
  id: true,
  userId: true,
  scopes: true,
  secretDigest: true,
  revokedAt: true,
  expiresAt: true,
  User: { select: ownerCredentialPolicyUserSelect },
} satisfies Prisma.SdkKeySelect;

/** `lastUsedAt` is advisory: written at most once per this window per key so
 * steady /v1 traffic does not write (and row-lock) the key on every request. */
export const SDK_KEY_LAST_USED_PRECISION_MS = 60_000;

export function sdkKeyLookupPrefix(raw: string): string | null {
  const parsed = parseSdkKeyCredentialSecret(raw);
  return parsed ? credentialLookupPrefix(parsed) : null;
}

export function digestSdkKeySecret(raw: string): string {
  return hmacDigestForProductPurpose({ purpose: "sdkKey", value: raw });
}

export function generateSdkKeySecret() {
  return generateProductCredentialSecret("sdkKey");
}

function isExpired(expiresAt: Date | null | undefined, now: Date): boolean {
  return Boolean(expiresAt && expiresAt <= now);
}

function principalFromRow(
  row: Pick<
    SdkKeyCredentialRow,
    | "id"
    | "userId"
    | "expiresAt"
    | "kind"
    | "ownSandboxesOnly"
    | "resourceMode"
    | "poolMode"
    | "HostAllowlist"
    | "RevisionAllowlist"
    | "PoolAllowlist"
  >,
  scopes: ReadonlySet<ServiceScope>,
): ServicePrincipal {
  const allowedHostIds =
    row.resourceMode === "ALL_OWNED"
      ? ("allOwned" as const)
      : new Set(
          row.HostAllowlist.filter((entry) => entry.SandboxHost.userId === row.userId).map(
            (entry) => entry.sandboxHostId,
          ),
        );
  const allowedRevisionIds =
    row.resourceMode === "ALL_OWNED"
      ? ("allOwned" as const)
      : new Set(row.RevisionAllowlist.map((entry) => entry.templateRevisionId));

  return {
    kind: "sdkKey",
    credentialKind: row.kind,
    ownSandboxesOnly: row.ownSandboxesOnly,
    expiresAt: row.expiresAt,
    keyId: row.id,
    ownerId: row.userId,
    resourceMode: row.resourceMode,
    scopes,
    allowedHostIds,
    allowedRevisionIds,
    allowedPoolIds:
      row.poolMode === "ALL_USABLE"
        ? "allUsable"
        : new Set((row.PoolAllowlist ?? []).map((entry) => entry.poolId)),
  };
}

function hostAllowed(principal: ServicePrincipal, hostId: string | null | undefined): boolean {
  if (!hostId) return false;
  if (principal.allowedHostIds === "allOwned") return true;
  if (principal.allowedHostIds.size === 0) return false;
  return principal.allowedHostIds.has(hostId);
}

function templateAllowed(
  principal: ServicePrincipal,
  templateId: string | null | undefined,
): boolean {
  if (!templateId) return false;
  if (principal.allowedRevisionIds === "allOwned") return true;
  if (principal.allowedRevisionIds.size === 0) return false;
  return principal.allowedRevisionIds.has(templateId);
}

function hasScopes(principal: ServicePrincipal, required: readonly ServiceScope[]): boolean {
  return required.every((scope) => principal.scopes.has(scope));
}

function forbidden(message = "Insufficient scope.") {
  return new ORPCError("FORBIDDEN", { message });
}

/** The refusal of a principal that lacks a scope a service step needs (403 FORBIDDEN). */
export function insufficientScope(): ORPCError<"FORBIDDEN", unknown> {
  return forbidden();
}

/**
 * Shared SDK authorization gate for HTTP adapters and idempotency replay.
 * Throws `FORBIDDEN` when scope or resource restrictions fail.
 */
/** The same exact retained-grant predicate is used by accept and dispatch.
 * An undefined pool context refuses; explicit null is a direct placement.
 *
 * The retained-creator shortcut (an ALL_OWNED key,
 * or the key of the CREATE) keeps its meaning only for
 * `RETAINED_CREATOR_ACTIONS` (history reads and cleanup). Every other action
 * on a stored sandbox context, and every non-cleanup dispatch, first needs
 * `currentCustodyAllowed` for the sandbox's current host and pool. */
function storedGrantsAllowed(
  principal: ServicePrincipal,
  context: ServiceActionContext,
  action: ServiceAction | "dispatch" | "createDispatch",
): boolean {
  if (storedContexts.has(context) && "authorizingKeyId" in context) {
    if (!(!createdOnly(principal) || context.authorizingKeyId === principal.keyId)) return false;
    // A same-key replay returns the stored receipt (history), never new
    // work; a CREATE's own dispatch launches what its acceptance placed
    // (custody governs use of an existing sandbox).
    if (context.retainedReplay || action === "createDispatch") return true;
    if (action !== "dispatch" && RETAINED_CREATOR_ACTIONS.has(action)) return true;
    const custody = custodies.get(context);
    // No sandbox, no custody to hold; a sandbox without one fails closed.
    if (custody === undefined) return !context.sandboxId;
    return currentCustodyAllowed(principal, custody);
  }
  return (
    poolAllowed(principal, context.originPoolId) &&
    (foreignPoolContexts.has(context) || hostAllowed(principal, context.sandboxHostId)) &&
    templateAllowed(principal, context.templateRevisionId)
  );
}

/**
 * Where a sandbox is now: its
 * bound host, else (hostless `OFFLOADED`) the host of its latest placement by
 * generation, the host its disk last lived on. The pool is the current usage pool (the
 * last placement's pool while hostless); null is a direct placement.
 */
export type SandboxCustody = {
  hostId: string | null;
  hostOwnerId: string | null;
  poolId: string | null;
};

const custodySelect = {
  sandboxHostId: true,
  hostOwnerId: true,
  usagePoolId: true,
  originHostId: true,
  originPoolId: true,
  CurrentPlacement: { select: { originHostId: true, originPoolId: true, hostOwnerId: true } },
} satisfies Prisma.SandboxSelect;

export async function readSandboxCustody(
  client: Prisma.TransactionClient,
  ownerId: string,
  sandboxId: string,
): Promise<SandboxCustody | null> {
  const sandbox = await client.sandbox.findFirst({
    where: { id: sandboxId, userId: ownerId },
    select: custodySelect,
  });
  return sandbox ? custodyOf(client, ownerId, sandboxId, sandbox) : null;
}

/** Custody from an already-read sandbox row (`custodySelect` fields). */
async function custodyOf(
  client: Prisma.TransactionClient,
  ownerId: string,
  sandboxId: string,
  sandbox: Partial<Prisma.SandboxGetPayload<{ select: typeof custodySelect }>>,
): Promise<SandboxCustody> {
  // Only a hostless sandbox (OFFLOADED, or never placed) reads its latest
  // placement.
  const placement =
    sandbox.CurrentPlacement ??
    (sandbox.sandboxHostId
      ? null
      : await client.sandboxPlacement.findFirst({
          where: { sandboxId, userId: ownerId },
          orderBy: [{ generation: "desc" }, { acceptedAt: "desc" }],
          select: { originHostId: true, originPoolId: true, hostOwnerId: true },
        }));
  return {
    hostId: sandbox.sandboxHostId ?? placement?.originHostId ?? null,
    hostOwnerId: sandbox.hostOwnerId ?? placement?.hostOwnerId ?? null,
    // Hosted: the current usage pool (null = direct, or an own host's
    // cleared attribution). Hostless: the last placement's pool.
    poolId: sandbox.sandboxHostId
      ? (sandbox.usagePoolId ?? null)
      : placement
        ? placement.originPoolId
        : null,
  };
}

/**
 * §5a (W1): a key's use of a sandbox needs the sandbox's current custody,
 * evaluated as two independent legs:
 * - host leg, only for `resourceMode = ALLOWLIST`: the current host is in the
 *   key's host allowlist. A host owned by another account is reachable only
 *   through a pool (as at create), so there it needs a current pool.
 * - pool leg, whenever `poolMode = SELECTED` (an ALL_OWNED key included): the
 *   current pool is selected; null (a direct placement) is allowed.
 */
export function currentCustodyAllowed(
  principal: ServicePrincipal,
  custody: SandboxCustody,
): boolean {
  if (principal.resourceMode === "ALLOWLIST") {
    const foreign = custody.hostOwnerId !== null && custody.hostOwnerId !== principal.ownerId;
    if (foreign ? custody.poolId === null : !hostAllowed(principal, custody.hostId)) return false;
  }
  return principal.allowedPoolIds === "allUsable" || poolAllowed(principal, custody.poolId);
}

/** Per stored context: the custody it was authorized against. */
const custodies = new WeakMap<ServiceActionContext, SandboxCustody>();

function poolAllowed(principal: ServicePrincipal, poolId: string | null | undefined): boolean {
  if (poolId === undefined) return false;
  return (
    poolId === null ||
    principal.allowedPoolIds === "allUsable" ||
    Boolean(principal.allowedPoolIds?.has(poolId))
  );
}

const storedContexts = new WeakSet<ServiceActionContext>();
const foreignPoolContexts = new WeakSet<ServiceActionContext>();
/**
 * Capacity-queue ENTRY only: a pool create that found no fitting host and
 * enters the queue has no host to check yet. Marked solely by the queued
 * branch of `createSandbox`; honoured solely for `sandboxes.create` with a
 * pool and a null host. Scopes, pool selection/use and the revision grant are
 * still checked here, and the placer re-runs the complete
 * `sandboxes.create` authorization against the chosen host before any hold.
 */
const queuedPoolContexts = new WeakSet<ServiceActionContext>();
/**
 * Community verify (review4 U1): the build role an in-transaction build
 * authorization derived for its context. Keyed by the context's identity,
 * like the marks above, so the queued/foreign/stored marks survive (the
 * context is never copied to carry it). Read with `buildRoleOf`.
 */
const buildRoles = new WeakMap<ServiceActionContext, BuildRole>();
/** The build role `authorizeServiceAction` derived for this exact context. */
export function buildRoleOf(context: ServiceActionContext): BuildRole | null {
  return buildRoles.get(context) ?? null;
}
export function queuedPoolContext(context: {
  sandboxHostId: null;
  templateRevisionId: string;
  originPoolId: string;
}): ServiceActionContext {
  queuedPoolContexts.add(context);
  return context;
}
function queuedEntry(action: ServiceAction, context: ServiceActionContext): boolean {
  return (
    action === "sandboxes.create" &&
    queuedPoolContexts.has(context) &&
    !storedContexts.has(context) &&
    context.sandboxHostId === null &&
    typeof context.originPoolId === "string" &&
    context.originPoolId.length > 0
  );
}
type ResultGuard = {
  checks: Map<string, () => Promise<void>>;
  checking: boolean;
  retainedWork: boolean;
};
const resultGuards = new AsyncLocalStorage<ResultGuard>();

function checkServiceAction(
  principal: ServicePrincipal,
  action: ServiceAction,
  context: ServiceActionContext = {},
): void {
  const requirement = SERVICE_ACTION_REQUIREMENTS[action];
  if (!hasScopes(principal, requirement.scopes)) {
    throw forbidden();
  }

  const retained = storedContexts.has(context) && storedGrantsAllowed(principal, context, action);
  if (
    requirement.requiresHost &&
    !retained &&
    !foreignPoolContexts.has(context) &&
    !queuedEntry(action, context) &&
    !hostAllowed(principal, context.sandboxHostId)
  ) {
    throw forbidden("Host is not allowed for this key.");
  }
  if (
    !retained &&
    (requirement.requiresTemplate ||
      (action === "operations.getReceipt" && context.templateRevisionId)) &&
    !templateAllowed(principal, context.templateRevisionId)
  ) {
    if (action.startsWith("templates.")) throw templateNotFound();
    throw forbidden("Template is not allowed for this key.");
  }

  if (
    (requirement.requiresSandbox || storedContexts.has(context)) &&
    !storedGrantsAllowed(principal, context, action)
  ) {
    throw forbidden("Sandbox resource grants are required.");
  }
  if (
    requirement.requiresPoolWhenPooled &&
    !retained &&
    !poolAllowed(principal, context.originPoolId)
  )
    throw forbidden("Placement context is required.");

  if (requirement.cancelMutationScope) {
    const kind = context.operationKind;
    if (!kind) {
      throw forbidden("Operation kind is required to cancel.");
    }
    const mutationScope = mutationScopeForOperationKind(kind);
    if (!mutationScope || !principal.scopes.has(mutationScope)) {
      throw forbidden("Missing mutation scope for cancellation.");
    }
  }
}

/** SDK keys can never administer enrollment or credentials, even with every scope. */
export function authorizeSessionManagement(principal: Principal): void {
  if (!isBrowserSession(principal)) throw forbidden("A browser session is required.");
}

/**
 * The shared service boundary. Scope checks precede even authorization-context
 * reads; only owner/immutable grant IDs and operation kind are loaded here.
 * Data queries, side effects and receipt lookups must follow this awaited gate.
 * Sessions already passed browser authentication and have all owner capabilities.
 */
const HOST_USABILITY_ACTIONS: ReadonlySet<ServiceAction> = new Set([
  "sandboxes.probe",
  "sandboxes.reconnect",
  "sandboxes.setTimeout",
  "commands.run",
  "commands.writeStdin",
  "files.read",
  "files.write",
  "files.listDir",
  "files.stat",
  "files.mkdir",
  "files.remove",
  "files.move",
  "processes.connect",
  "processes.list",
  "processes.signal",
]);
async function requireGuestAccess(
  client: Prisma.TransactionClient,
  creatorId: string,
  action: ServiceAction,
  target: ServiceActionContext,
): Promise<() => boolean> {
  if (
    target.retainedReplay ||
    !HOST_USABILITY_ACTIONS.has(action) ||
    (!target.sandboxId && !target.operationId)
  )
    return () => true;
  const sandbox = await client.sandbox.findFirst({
    where: {
      userId: creatorId,
      ...(target.sandboxId
        ? { id: target.sandboxId }
        : { Operations: { some: { id: target.operationId, userId: creatorId } } }),
    },
    select: {
      id: true,
      sandboxHostId: true,
      hostOwnerId: true,
      usagePoolId: true,
      accessGraceUntil: true,
    },
  });
  if (
    sandbox?.sandboxHostId &&
    sandbox.hostOwnerId != null &&
    (sandbox.hostOwnerId !== creatorId || sandbox.usagePoolId || sandbox.accessGraceUntil)
  )
    return requireCurrentHostUsability(client, creatorId, sandbox.id);
  return () => true;
}

async function authorizeAction(
  principal: Principal,
  action: ServiceAction,
  target: ServiceActionContext = {},
  client: Prisma.TransactionClient = prisma,
  intentOnly = false,
): Promise<ServiceActionContext> {
  if (client !== prisma) {
    // C21-13: every service transaction serializes with account finalization.
    await lockOwnerForAdmission(client, principal.ownerId);
  }
  // MS0: managed sandboxes admit only what their purpose policy allows, for
  // every principal, before any other target-specific work.
  if (!intentOnly) await guardManagedSandboxTarget(client, principal, action, target);
  switch (principal.kind) {
    case "session":
    case "sdkKey":
      return authorizeCredential(principal, principal, action, target, client, intentOnly, null);
    case "build":
      return authorizeBuildAction(principal, action, target, client, intentOnly);
    default:
      return assertNever(principal, forbidden());
  }
}

/**
 * Template-build action classes. Runs after owner admission and
 * the managed-sandbox guard. The build row is read WITHOUT a lock: a FOR SHARE
 * here would precede owner placement and invert the lock order (§3.4); the
 * create-side state check after owner placement closes the create race.
 *
 * A step re-checks, every time, the same rules a session or the accepting key
 * gets for the action: the owner's credential policy, guest access / host
 * usability, and for a keyed build the key itself (`FOR SHARE`, revalidation,
 * `templates:build`) with its host/pool/revision allowlists. The build's
 * `templates:build` grant replaces the user's write scopes (r1 B-2). Every
 * refusal of a step is `build.authority_lost` (r2 N12).
 */
async function authorizeBuildAction(
  build: BuildPrincipal,
  action: ServiceAction,
  target: ServiceActionContext,
  client: Prisma.TransactionClient,
  intentOnly: boolean,
): Promise<ServiceActionContext> {
  const actionClass = buildActionClass(action, target.retainedReplay === true);
  if (!actionClass) throw forbidden();
  const row = await client.sandboxTemplateBuild.findFirst({
    where: { id: build.buildId, userId: build.ownerId },
    select: {
      state: true,
      cancelRequestedAt: true,
      authorizingKeyId: true,
      verifyRequired: true,
      captureAttempt: true,
    },
  });
  if (!row || (row.authorizingKeyId || null) !== build.keyId) throw buildAuthorityLost();
  // Community verify (I4b): the role is derived from durable facts, never
  // from the caller. (a) a sandbox/operation target names the VM, and the
  // column that matched (`buildId` or `verifyBuildId`) is the role; (b) an
  // untargeted create or create intent is a verify create iff the build is
  // CAPTURING (the two step-state sets are disjoint); (c) an intent-only
  // check admits when either role's table does, and the in-transaction
  // targeted check stays authoritative.
  let role: BuildRole | null = null;
  if (!intentOnly) {
    if (target.sandboxId || target.operationId) {
      // Only the build's own VMs (the immutable `Sandbox.buildId` or
      // `verifyBuildId`), never another sandbox of the owner.
      const vm = await client.sandbox.findFirst({
        where: {
          userId: build.ownerId,
          OR: [{ buildId: build.buildId }, { verifyBuildId: build.buildId }],
          ...(target.sandboxId
            ? { id: target.sandboxId }
            : { Operations: { some: { id: target.operationId, userId: build.ownerId } } }),
        },
        select: { id: true, verifyBuildId: true },
      });
      if (!vm) throw forbidden();
      role = vm.verifyBuildId === build.buildId ? "verify" : "build";
    } else if (action === "sandboxes.create" || action === "sandboxes.createIntent")
      role = untargetedCreateRole(row.state);
    else throw forbidden();
  }
  const captureFinalized =
    row.verifyRequired &&
    row.state === "CAPTURING" &&
    (await client.sandboxTemplateCapture.findFirst({
      where: {
        buildId: build.buildId,
        userId: build.ownerId,
        buildAttempt: row.captureAttempt,
        state: "FINALIZED",
      },
      select: { operationId: true },
    })) !== null;
  const facts = { ...row, captureFinalized };
  const remember = (context: ServiceActionContext) => {
    if (role !== null) buildRoles.set(context, role);
    return context;
  };
  if (actionClass !== "step") return intentOnly ? {} : remember(target);
  const allowed =
    role === null
      ? buildStepAllowed(action, facts, "build") || buildStepAllowed(action, facts, "verify")
      : buildStepAllowed(action, facts, role);
  if (!allowed) throw buildAuthorityLost();
  const owner = await client.user.findUnique({
    where: { id: build.ownerId },
    select: ownerCredentialPolicyUserSelect,
  });
  const settings = client === prisma ? undefined : await getForcedTwoFactorSettingsRecord(client);
  if (!owner || !(await isOwnerCredentialPolicySatisfied(owner, new Date(), settings)))
    throw buildAuthorityLost();
  try {
    if (build.keyId === null)
      return remember(
        await authorizeCredential(
          sessionPrincipal(build.ownerId),
          build,
          action,
          target,
          client,
          intentOnly,
          null,
        ),
      );
    if (client !== prisma)
      await client.$queryRaw`SELECT id FROM sdk_key WHERE id = ${build.keyId} FOR SHARE`;
    const fresh = await revalidateSdkKey(build.keyId, build.ownerId, client);
    build.key = fresh;
    const held: ReadonlySet<string> | undefined = fresh?.scopes;
    if (!fresh || !held?.has(TEMPLATE_BUILD_SCOPE)) throw buildAuthorityLost();
    const grant: ReadonlySet<ServiceScope> = new Set(SERVICE_ACTION_REQUIREMENTS[action].scopes);
    return remember(
      await authorizeCredential(
        { ...fresh, scopes: grant },
        build,
        action,
        target,
        client,
        intentOnly,
        grant,
      ),
    );
  } catch (error) {
    if (error instanceof ORPCError && error.code === "FORBIDDEN") throw buildAuthorityLost();
    throw error;
  }
}

/**
 * The session / SDK-key rules for one credential. `bindAs` is the principal
 * whose result guard re-authorizes later (the build itself when a build step
 * borrows these rules); `buildGrant` replaces a key's scopes with the build
 * grant after every revalidation, so the build never needs user write scopes.
 */
async function authorizeCredential(
  principal: SessionPrincipal | ServicePrincipal,
  bindAs: Principal,
  action: ServiceAction,
  target: ServiceActionContext,
  client: Prisma.TransactionClient,
  intentOnly: boolean,
  buildGrant: ReadonlySet<ServiceScope> | null,
): Promise<ServiceActionContext> {
  switch (principal.kind) {
    case "session": {
      if (!intentOnly) {
        const pathCurrent = await requireGuestAccess(client, principal.ownerId, action, target);
        if (HOST_USABILITY_ACTIONS.has(action) && (target.sandboxId || target.operationId))
          bindResolvedResultGuard(bindAs, action, target, pathCurrent);
      }
      return target;
    }
    case "sdkKey":
      break;
    default:
      return assertNever(principal, forbidden());
  }
  const current = authorityTicket({ ownerId: principal.ownerId, credentialId: principal.keyId });
  if (client !== prisma) {
    await client.$queryRaw`SELECT id FROM sdk_key WHERE id = ${principal.keyId} FOR SHARE`;
  }
  const fresh = await revalidateSdkKey(principal.keyId, principal.ownerId, client);
  if (!fresh || !current()) throw forbidden("Credential is inactive.");
  // OAuth access tokens can carry fewer scopes than their backing grant.
  // Revalidation may narrow that request ceiling, but must never widen it.
  const oauthScopes = principal.credentialKind === "OAUTH_GRANT" ? principal.scopes : null;
  Object.assign(principal, fresh);
  if (oauthScopes)
    principal.scopes = new Set([...fresh.scopes].filter((scope) => oauthScopes.has(scope)));
  if (buildGrant) principal.scopes = buildGrant;
  if (!hasScopes(principal, SERVICE_ACTION_REQUIREMENTS[action].scopes)) throw forbidden();
  if (intentOnly) return {};
  if (SERVICE_ACTION_REQUIREMENTS[action].requiresPool) {
    const poolId = target.poolId;
    if (!poolId || !poolAllowed(principal, poolId)) throw poolNotFound();
    const pool = await client.sandboxPool.findFirst({
      where: {
        id: poolId,
        deletedAt: null,
        OR: [
          { userId: principal.ownerId },
          { Shares: { some: { granteeUserId: principal.ownerId, canUse: true } } },
        ],
      },
      select: { id: true },
    });
    if (!pool) throw poolNotFound();
  }
  let context = target;
  let custody: SandboxCustody | null = null;
  if (target.operationId) {
    const operation = await client.sandboxOperation.findFirst({
      where: {
        id: target.operationId,
        userId: principal.ownerId,
        Sandbox: { userId: principal.ownerId },
      },
      select: {
        kind: true,
        Sandbox: {
          select: { id: true, templateRevisionId: true, ...custodySelect },
        },
      },
    });
    if (!operation) throw new ORPCError("NOT_FOUND", { message: "Operation not found." });
    custody = await custodyOf(client, principal.ownerId, operation.Sandbox.id, operation.Sandbox);
    context = {
      operationId: target.operationId,
      originPoolId: operation.Sandbox.originPoolId,
      sandboxId: operation.Sandbox.id,
      // §5a: host-allowlist checks use the CURRENT host (the last placement's
      // while offloaded).
      sandboxHostId: custody.hostId,
      templateRevisionId: operation.Sandbox.templateRevisionId,
      operationKind: operation.kind,
    };
  } else if (target.sandboxId) {
    const sandbox = await client.sandbox.findFirst({
      where: { id: target.sandboxId, userId: principal.ownerId },
      select: { templateRevisionId: true, ...custodySelect },
    });
    if (!sandbox) throw new ORPCError("NOT_FOUND", { message: "Sandbox not found." });
    custody = await custodyOf(client, principal.ownerId, target.sandboxId, sandbox);
    context = {
      originPoolId: sandbox.originPoolId,
      sandboxId: target.sandboxId,
      sandboxHostId: custody.hostId,
      templateRevisionId: sandbox.templateRevisionId,
    };
  }
  foreignPoolContexts.delete(context);
  if (!target.sandboxId && !target.operationId && context.originPoolId && context.sandboxHostId) {
    await requirePoolUse(client, principal, context.originPoolId);
    const member = await client.sandboxPoolMember.findFirst({
      where: {
        poolId: context.originPoolId,
        sandboxHostId: context.sandboxHostId,
        enabled: true,
        removedAt: null,
        Host: { userId: { not: principal.ownerId }, deletionRequestedAt: null },
      },
      select: { id: true },
    });
    if (member) foreignPoolContexts.add(context);
  }
  const hostFence = context.sandboxHostId
    ? authorityTicket({ ownerId: principal.ownerId, hostId: context.sandboxHostId })
    : null;
  if (context.logicalTemplateId) {
    const logical = await client.sandboxTemplate.findFirst({
      where: {
        AND: [serviceResourceFilter(principal, "template"), { id: context.logicalTemplateId }],
      },
      select: { id: true },
    });
    if (!logical) throw templateNotFound();
  }
  if (target.operationId || target.sandboxId) {
    const creation = await client.sandboxOperation.findFirst({
      where: {
        sandboxId: context.sandboxId ?? "",
        userId: principal.ownerId,
        kind: "CREATE_SANDBOX",
      },
      orderBy: [{ createdAt: "asc" }, { id: "asc" }],
      select: { authorizingKeyId: true },
    });
    context.authorizingKeyId = creation?.authorizingKeyId ?? null;
    if (custody) custodies.set(context, custody);
    storedContexts.add(context);
  }
  if (target.retainedReplay) context.retainedReplay = true;
  const retained = storedContexts.has(context) && storedGrantsAllowed(principal, context, action);
  checkServiceAction(principal, action, context);
  if (SERVICE_ACTION_REQUIREMENTS[action].requiresOwnedHost) {
    const host =
      context.sandboxHostId &&
      (await client.sandboxHost.findFirst({
        where: { id: context.sandboxHostId, userId: principal.ownerId },
        select: { id: true },
      }));
    if (!host || !hostAllowed(principal, context.sandboxHostId))
      throw new ORPCError("FORBIDDEN", {
        message: "Host is not owned by this credential's owner.",
        data: { code: "host.not_owned" },
      });
  }
  // Host authority is owner/credential-scoped above, which a host revision
  // bump does not move; fence the host scope itself from before the existence
  // check to the end of authorization. Otherwise a request resuming after a
  // committed host deletion (whose allowlist cascade raced this lookup) would
  // pass the final ticket check and read with the revoked grant (C23).
  if (context.sandboxHostId && !retained) {
    const host = await client.sandboxHost.findFirst({
      where: {
        id: context.sandboxHostId,
        ...(foreignPoolContexts.has(context) ? {} : { userId: principal.ownerId }),
      },
      select: { id: true },
    });
    if (!host) {
      const retainedRead =
        !createdOnly(principal) &&
        (action === "sandboxes.replayCreate" ||
          action === "operations.getReceipt" ||
          (context.sandboxId &&
            [
              "sandboxes.get",
              "sandboxes.capabilities",
              "processes.connect",
              "operations.get",
              "operations.getCommandOutput",
              "operations.downloadFile",
              "operations.getFileResult",
              "operations.getFileMutationResult",
              "operations.getRenameResult",
              "operations.getCommandResult",
              "operations.getSignalResult",
            ].includes(action)));
      if (action === "sandboxes.create" && principal.resourceMode === "ALL_OWNED")
        throw hostNotFound();
      if (!retainedRead) throw forbidden("Host is no longer owned or active.");
    }
  }
  if (
    !retained &&
    context.templateRevisionId &&
    !(await client.sandboxTemplateRevision.findFirst({
      where: { id: context.templateRevisionId, userId: principal.ownerId },
      select: { id: true },
    }))
  ) {
    if (action.startsWith("templates.")) throw templateNotFound();
    throw forbidden("Template is no longer owned.");
  }
  if (!retained && context.originPoolId)
    await requirePoolUse(client, principal, context.originPoolId);
  if (!current() || (hostFence !== null && !hostFence()) || isExpired(fresh.expiresAt, new Date()))
    throw forbidden("Authority changed during authorization.");
  if (
    context.sandboxId &&
    !context.retainedReplay &&
    action === "sandboxes.reconnect" &&
    (await isOffloadedRestoreTarget(client, principal.ownerId, context.sandboxId))
  ) {
    // §8.3b (V2): a restore of a hostless OFFLOADED sandbox is authorized as
    // a restore intent, never by the guest-access usability check (which
    // refuses a sandbox without a host). Every other action, and reconnect
    // of a hosted sandbox, keeps the usability check below.
    await requireRestoreIntentGrants(client, principal, context);
    if (!current() || (hostFence !== null && !hostFence()))
      throw forbidden("Authority changed during authorization.");
  } else if (context.sandboxId && !context.retainedReplay && needsCurrentUsability(action)) {
    await requireCurrentSandboxUsability(client, principal, context.sandboxId);
    if (!current() || (hostFence !== null && !hostFence()))
      throw forbidden("Authority changed during authorization.");
  }
  const pathCurrent = await requireGuestAccess(client, principal.ownerId, action, context);
  if (!current() || !pathCurrent() || (hostFence !== null && !hostFence()))
    throw forbidden("Authority changed during authorization.");
  bindResolvedResultGuard(bindAs, action, context, pathCurrent);
  return context;
}

export function authorizeServiceAction(
  principal: Principal,
  action: ServiceAction,
  target: ServiceActionContext = {},
  client: Prisma.TransactionClient = prisma,
): Promise<ServiceActionContext> {
  return authorizeAction(principal, action, target, client);
}

/** Replay entry checks current credentials and scopes before looking up identity. */
export function authorizeServiceIntent(
  principal: Principal,
  action: ServiceAction,
  client: Prisma.TransactionClient = prisma,
): Promise<ServiceActionContext> {
  return authorizeAction(principal, action, {}, client, true);
}

function bindResolvedResultGuard(
  principal: Principal,
  action: ServiceAction,
  context: ServiceActionContext,
  pathCurrent: () => boolean = () => true,
) {
  const guard = resultGuards.getStore();
  if (!guard || guard.checking) return;
  // Receipt recovery supersedes tentative admission checks from the rolled-back attempt.
  if (context.retainedReplay) guard.checks.clear();
  if (retainedKeyWork(principal, context, action)) guard.retainedWork = true;
  const ticket = serviceReadTicket(principal, { hostId: context.sandboxHostId ?? undefined });
  const key = JSON.stringify([action, context]);
  if (guard.checks.has(key)) return;
  guard.checks.set(key, async () => {
    if (!pathCurrent()) throw forbidden("Authority changed during request.");
    ticket();
    await authorizeServiceAction(principal, action, context);
    if (!pathCurrent()) throw forbidden("Authority changed during request.");
    ticket();
  });
}

/** Work an SDK key retains through its stored (creation-time) grants. A
 * build re-authorizes its own steps in its result guard instead. */
function retainedKeyWork(
  principal: Principal,
  context: ServiceActionContext,
  action: ServiceAction,
): boolean {
  switch (principal.kind) {
    case "session":
    case "build":
      return false;
    case "sdkKey":
      return storedContexts.has(context) && storedGrantsAllowed(principal, context, action);
    default:
      return assertNever(principal);
  }
}

/** A result must not disclose data fetched using grants that changed while it awaited IO. */
function serviceReadTicket(principal: Principal, scope: { hostId?: string }): () => void {
  switch (principal.kind) {
    // A build step's bound result guard re-runs the whole step authorization
    // (key, state, policy); cleanup and reads hold no key authority to fence.
    case "session":
    case "build":
      return () => undefined;
    case "sdkKey":
      break;
    default:
      return assertNever(principal);
  }
  const current = authorityTicket({
    ownerId: principal.ownerId,
    credentialId: principal.keyId,
    ...(scope.hostId ? { hostId: scope.hostId } : {}),
  });
  const signature = () =>
    JSON.stringify([
      principal.ownSandboxesOnly,
      principal.credentialKind,
      [...principal.scopes].sort(),
      principal.allowedPoolIds === "allUsable"
        ? "allUsable"
        : [...(principal.allowedPoolIds ?? [])].sort(),
      principal.allowedHostIds === "allOwned" ? "allOwned" : [...principal.allowedHostIds].sort(),
      principal.allowedRevisionIds === "allOwned"
        ? "allOwned"
        : [...principal.allowedRevisionIds].sort(),
    ]);
  const before = signature();
  const identity = () =>
    JSON.stringify([
      principal.keyId,
      principal.resourceMode,
      principal.ownSandboxesOnly,
      principal.credentialKind,
      [...principal.scopes].sort(),
    ]);
  const identityBefore = identity();
  return () => {
    const changed = resultGuards.getStore()?.retainedWork
      ? identity() !== identityBefore
      : signature() !== before;
    if (!current() || isExpired(principal.expiresAt, new Date()) || changed)
      throw forbidden("Authority changed during request.");
  };
}

/** Admission races surface as domain conflicts, never raw database errors (C21-13). */
export function serviceAdmissionError(error: unknown): unknown {
  if (error instanceof AccountDeletionConflictError)
    return new ORPCError("CONFLICT", { message: "Account deletion is in progress." });
  if (error instanceof RelayFenceRejected) return sandboxStateConflict();
  if (isPrismaForeignKeyViolation(error))
    return new ORPCError("CONFLICT", {
      message: "A referenced resource was removed concurrently.",
    });
  if (error instanceof ORPCError) return error;
  rethrowSensitiveSandboxError(error);
}

/** How a service procedure authorizes at entry: an SDK-scoped action, or browser-only. */
export type ServiceEntry<I> =
  | { action: ServiceAction; target?: (input: I) => ServiceActionContext; intentOnly?: true }
  | { sessionOnly: true };

const serviceProcedures = new WeakSet<object>();

/** True only for functions built by `serviceProcedure` (inventory test hook). */
export function isServiceProcedure(fn: unknown): boolean {
  return typeof fn === "function" && serviceProcedures.has(fn);
}

/**
 * THE service boundary (C21-15). Every exported service function is built here:
 * entry authorization, then the scoped read ticket is sampled, then the body runs,
 * and the ticket is checked on BOTH its resolve and reject paths. A stale ticket
 * replaces the result or error with FORBIDDEN "Authority changed during request.",
 * so replays, owned-row NOT_FOUNDs and kind conflicts disclose nothing post-revoke.
 */
export function serviceProcedure<I, R, Rest extends unknown[] = []>(
  entry: ServiceEntry<I>,
  body: (principal: Principal, input: I, ...rest: Rest) => Promise<R>,
): (principal: Principal, input: I, ...rest: Rest) => Promise<R> {
  const procedure = async (principal: Principal, input: I, ...rest: Rest): Promise<R> => {
    const guard: ResultGuard = { checks: new Map(), checking: false, retainedWork: false };
    return resultGuards.run(guard, async () => {
      let context: ServiceActionContext = {};
      if ("sessionOnly" in entry) authorizeSessionManagement(principal);
      else {
        const target = entry.target?.(input);
        context = entry.intentOnly
          ? await authorizeServiceIntent(principal, entry.action)
          : await authorizeServiceAction(principal, entry.action, target);
      }
      const ticket = serviceReadTicket(principal, { hostId: context.sandboxHostId ?? undefined });
      const check = async () => {
        ticket();
        guard.checking = true;
        try {
          for (const verify of guard.checks.values()) await verify();
        } finally {
          guard.checking = false;
        }
        ticket();
      };
      let value: R;
      try {
        value = await body(principal, input, ...rest);
      } catch (error) {
        await check();
        throw serviceAdmissionError(error);
      }
      await check();
      return value;
    });
  };
  serviceProcedures.add(procedure);
  return procedure;
}

/** Mandatory collection restriction, composed into WHERE before cursor/take. */
export function serviceResourceFilter(
  principal: Principal,
  resource: "host",
): Prisma.SandboxHostWhereInput;
export function serviceResourceFilter(
  principal: Principal,
  resource: "template",
): Prisma.SandboxTemplateWhereInput;
export function serviceResourceFilter(
  principal: Principal,
  resource: "revision",
): Prisma.SandboxTemplateRevisionWhereInput;
export function serviceResourceFilter(
  principal: Principal,
  resource: "sandbox",
): Prisma.SandboxWhereInput;
export function serviceResourceFilter(
  principal: Principal,
  resource: "pool",
): Prisma.SandboxPoolWhereInput;
export function serviceResourceFilter(
  principal: Principal,
  resource: "member",
): Prisma.SandboxPoolMemberWhereInput;
export function serviceResourceFilter(
  principal: Principal,
  resource: "host" | "template" | "revision" | "sandbox" | "pool" | "member",
):
  | Prisma.SandboxHostWhereInput
  | Prisma.SandboxTemplateWhereInput
  | Prisma.SandboxTemplateRevisionWhereInput
  | Prisma.SandboxWhereInput
  | Prisma.SandboxPoolWhereInput
  | Prisma.SandboxPoolMemberWhereInput {
  const owner = { userId: principal.ownerId };
  let key: ServicePrincipal;
  switch (principal.kind) {
    case "session":
      return owner;
    case "sdkKey":
      key = principal;
      break;
    // A build sees what its accepting key sees (its owner's session view when
    // keyless); a keyed build whose key no longer revalidates sees nothing.
    case "build":
      if (principal.keyId === null) return owner;
      if (!principal.key) return { ...owner, id: { in: [] } };
      key = principal.key;
      break;
    default:
      return assertNever(principal);
  }
  // Omit unrestricted predicates: an empty scalar filter inside OR is not
  // an identity in Prisma, particularly for nullable originPoolId.
  const hosts = key.allowedHostIds === "allOwned" ? undefined : { in: [...key.allowedHostIds] };
  const templates =
    key.allowedRevisionIds === "allOwned" ? undefined : { in: [...key.allowedRevisionIds] };
  const pools =
    key.allowedPoolIds === "allUsable" ? undefined : { in: [...(key.allowedPoolIds ?? [])] };
  if (resource === "pool") return { ...owner, ...(pools ? { id: pools } : {}) };
  if (resource === "member")
    return {
      ...owner,
      ...(hosts ? { sandboxHostId: hosts } : {}),
      ...(pools ? { poolId: pools } : {}),
      Host: owner,
      Pool: owner,
    };
  if (resource === "host") return { ...owner, ...(hosts ? { id: hosts } : {}) };
  if (resource === "revision") return { ...owner, ...(templates ? { id: templates } : {}) };
  // A template is visible to a key that may see all owned revisions, or that
  // holds a granted revision of it, or that accepted a build into it. The
  // last arm keeps a template whose first build failed (no revision yet)
  // reachable by the key that created it, without granting any revision.
  if (resource === "template") {
    if (!templates) return owner;
    return {
      ...owner,
      OR: [
        { Revisions: { some: { ...owner, id: templates } } },
        { Builds: { some: { ...owner, authorizingKeyId: key.keyId } } },
      ],
    };
  }
  if (!createdOnly(key)) return owner;
  return {
    ...owner,
    Operations: {
      some: {
        kind: "CREATE_SANDBOX",
        authorizingKeyId: key.keyId,
        userId: key.ownerId,
      },
    },
  };
}

async function authenticateCredentialSecret(
  rawSecret: string,
  kind: "API" | "AGENT_TOKEN",
  now = new Date(),
): Promise<ServicePrincipal | null> {
  const startedAt = Date.now();
  const credential =
    kind === "API"
      ? parseSdkKeyCredentialSecret(rawSecret)
      : parseAgentTokenCredentialSecret(rawSecret);
  if (!credential) {
    return null;
  }

  const lookupPrefix = credentialLookupPrefix(credential);
  const row = await prisma.sdkKey.findUnique({
    where: { lookupPrefix },
    select: sdkKeyLookupSelect,
  });
  if (
    !row ||
    row.kind !== kind ||
    !row.secretDigest ||
    row.revokedAt ||
    isExpired(row.expiresAt, now)
  )
    return null;
  const current = authorityTicket({ ownerId: row.userId, credentialId: row.id });
  if (!(await isOwnerCredentialPolicySatisfied(row.User, now))) return null;
  try {
    parseServiceScopeSet(row.scopes);
  } catch {
    return null;
  }
  if (
    !verifyProductCredentialDigest({
      purpose: kind === "API" ? "sdkKey" : "agentToken",
      value: credential.raw,
      digest: row.secretDigest,
    })
  ) {
    return null;
  }

  // Throttled and tolerant of a concurrently deleted key: a missing row matches
  // nothing here and revalidateSdkKey below refuses it. A token the no-expiry policy
  // blocks is not stamped as used (the refusal itself is still decided below).
  if (!agentTokenBlockedByPolicy(row, env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY))
    await prisma.sdkKey.updateMany({
      where: {
        id: row.id,
        OR: [
          { lastUsedAt: null },
          { lastUsedAt: { lt: new Date(now.getTime() - SDK_KEY_LAST_USED_PRECISION_MS) } },
        ],
      },
      data: { lastUsedAt: now },
    });

  // Durable read AFTER the scoped ticket: a revoke/ban committed between the lookup
  // and the ticket sample is observed here; one racing this read fails the ticket.
  // It is also the only no-expiry policy decision on this path (no earlier read is reused).
  const outcome = await revalidateSdkKeyOutcome(row.id, row.userId);
  if (outcome === POLICY_BLOCKED) {
    if (row.kind === "AGENT_TOKEN" && current()) throw new AgentTokenPolicyBlockedError();
    return null;
  }
  const fresh = outcome;
  if (
    !fresh ||
    fresh.credentialKind !== kind ||
    !current() ||
    isExpired(fresh.expiresAt, new Date(now.getTime() + Date.now() - startedAt))
  )
    return null;
  return fresh;
}

/** An existing no-expiry agent token presented while the deployment disallows
 * no-expiry tokens. Thrown only after the secret verified and every other gate
 * passed, so it never reveals a token the caller does not hold. */
export class AgentTokenPolicyBlockedError extends Error {
  readonly code = AGENT_TOKEN_NO_EXPIRY_BLOCKED_CODE;
  constructor() {
    super("No-expiry agent tokens are disabled on this deployment.");
    this.name = "AgentTokenPolicyBlockedError";
  }
}

const POLICY_BLOCKED = Symbol("credential-policy-blocked");

/** Every credential (re)validation runs through here, so the no-expiry policy
 * is applied on first authentication, in-flight dispatch checks, stored
 * principals and build principals alike. The policy is read once, beside the
 * row, and the result is returned without any later re-read. */
async function revalidateSdkKeyOutcome(
  keyId: string,
  ownerId: string,
  client: Prisma.TransactionClient = prisma,
): Promise<ServicePrincipal | typeof POLICY_BLOCKED | null> {
  const current = authorityTicket({ ownerId, credentialId: keyId });
  const row = await client.sdkKey.findUnique({
    where: { id: keyId },
    select: sdkKeyCredentialSelect,
  });
  const now = new Date();
  const settings = client === prisma ? undefined : await getForcedTwoFactorSettingsRecord(client);
  if (
    !row ||
    row.userId !== ownerId ||
    row.revokedAt ||
    isExpired(row.expiresAt, now) ||
    !(await isOwnerCredentialPolicySatisfied(row.User, now, settings))
  )
    return null;
  if (agentTokenBlockedByPolicy(row, env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY))
    return current() ? POLICY_BLOCKED : null;
  try {
    const principal = principalFromRow(row, new Set(parseServiceScopeSet(row.scopes)));
    return current() && !isExpired(row.expiresAt, new Date()) ? principal : null;
  } catch {
    return null;
  }
}

export async function revalidateSdkKey(
  keyId: string,
  ownerId: string,
  client: Prisma.TransactionClient = prisma,
): Promise<ServicePrincipal | null> {
  const outcome = await revalidateSdkKeyOutcome(keyId, ownerId, client);
  return outcome === POLICY_BLOCKED ? null : outcome;
}

/** Caller locks SDK K before H/S. No owner admission, mutation, scheduling or
 * scope check belongs here. Ticket movement/read failures never prove revocation. */
export async function checkAcceptedDispatchAuthority(
  input: {
    ownerId: string;
    principal: AuthorizingPrincipal;
    context: ServiceActionContext;
    onActive?: (expiresAt: Date | null) => void;
    onActiveAuthority?: (current: () => boolean) => void;
    cleanup?: boolean;
    /** The dispatched operation (row kind or dispatch kind), when known: a
     * CREATE's own launch is not use of an existing sandbox (§5a). */
    operationKind?: string;
  },
  client: Prisma.TransactionClient = prisma,
): Promise<"active" | "inactive" | "indeterminate"> {
  const { ownerId, principal, context } = input;
  const credentialId = recordedKeyIdOf(principal);
  const principalCurrent = authorityTicket({
    ownerId,
    ...(context.sandboxHostId ? { hostId: context.sandboxHostId } : {}),
    ...(credentialId !== null ? { credentialId } : {}),
  });
  let pathCurrent = () => true;
  const current = () => principalCurrent() && pathCurrent();
  try {
    switch (principal.kind) {
      case "system":
        return current() ? "active" : "indeterminate";
      case "build": {
        // Plan §3.1 "Dispatch": the build row exists and the target is the
        // build's own VM. Cleanup (stop, kill) needs nothing more, so it
        // dispatches after revocation, ban or deletion blocking; any other
        // kind is a step and also needs an active build plus the session /
        // accepting-key rules below.
        const build = await client.sandboxTemplateBuild.findFirst({
          where: { id: principal.buildId, userId: ownerId },
          select: {
            state: true,
            cancelRequestedAt: true,
            authorizingKeyId: true,
            captureAttempt: true,
            verifyRequired: true,
          },
        });
        // The build's own VMs: its build VM or its community verify VM
        // (community-base I4c). Dispatch re-checks liveness and the key, not
        // the action table: the action was authorized at enqueue.
        const vm = context.sandboxId
          ? await client.sandbox.findFirst({
              where: {
                id: context.sandboxId,
                userId: ownerId,
                OR: [{ buildId: principal.buildId }, { verifyBuildId: principal.buildId }],
              },
              select: { id: true },
            })
          : null;
        if (!build || !vm || (build.authorizingKeyId || null) !== principal.keyId)
          return current() ? "inactive" : "indeterminate";
        if (input.cleanup) return current() ? "active" : "indeterminate";
        if (build.cancelRequestedAt !== null || !BUILD_ACTIVE_STATES.has(build.state)) {
          // A user build's capture recorded before the cancel wins over it
          // (§3.3; a community build's never does, S9): only that capture's
          // own operation (its image upload) keeps authority
          // until the capture is stored; every other dispatch is refused.
          const capture =
            input.operationKind === "CAPTURE_TEMPLATE" && context.operationId && context.sandboxId
              ? await client.sandboxTemplateCapture.findFirst({
                  where: {
                    operationId: context.operationId,
                    buildId: principal.buildId,
                    userId: ownerId,
                    sandboxId: context.sandboxId,
                  },
                  select: { state: true, buildAttempt: true, buildCancelledAt: true },
                })
              : null;
          if (!captureOutlivesCancel({ operationKind: input.operationKind, build, capture }))
            return current() ? "inactive" : "indeterminate";
        }
        break;
      }
      case "session":
      case "sdkKey":
        break;
      default:
        return assertNever(principal);
    }
    if (!input.cleanup) {
      const creator = await client.user.findUnique({
        where: { id: ownerId },
        select: ownerCredentialPolicyUserSelect,
      });
      if (
        !creator ||
        !(await isOwnerCredentialPolicySatisfied(
          creator,
          new Date(),
          await getForcedTwoFactorSettingsRecord(client),
        ))
      )
        return "inactive";
      if (context.sandboxId) {
        // Attribution is stable under the caller's H/S fence. Sample its pool
        // owner before the policy reads, and retain that proof through socket
        // IO: a pool can belong to neither the creator nor the host owner.
        const path = await client.sandbox.findFirst({
          where: { id: context.sandboxId, userId: ownerId },
          select: { hostOwnerId: true, usagePoolId: true },
        });
        if (path?.hostOwnerId && path.hostOwnerId !== ownerId && path.usagePoolId) {
          const pool = await client.sandboxPool.findUnique({
            where: { id: path.usagePoolId },
            select: { userId: true },
          });
          if (!pool) return "inactive";
          pathCurrent = authorityTicket({ ownerId: pool.userId });
        }
        try {
          await requireCurrentSandboxUsability(client, { ownerId }, context.sandboxId);
        } catch {
          return "inactive";
        }
      }
    }
    let keyId: string;
    let buildScope = false;
    switch (principal.kind) {
      case "session":
        if (!current()) return "indeterminate";
        input.onActiveAuthority?.(current);
        return "active";
      case "sdkKey":
        keyId = principal.keyId;
        break;
      // A keyless build step has its owner's session rules (checked above); a
      // keyed one needs the accepting key, its grants and `templates:build`.
      case "build":
        if (principal.keyId === null) {
          if (!current()) return "indeterminate";
          input.onActiveAuthority?.(current);
          return "active";
        }
        keyId = principal.keyId;
        buildScope = true;
        break;
      default:
        return assertNever(principal);
    }
    // §5a (V1): non-cleanup dispatch revalidation checks the sandbox's
    // CURRENT custody before the retained-creator shortcut.
    const custody = context.sandboxId
      ? await readSandboxCustody(client, ownerId, context.sandboxId)
      : null;
    const hostIds = [
      ...new Set([context.sandboxHostId ?? "", ...(custody?.hostId ? [custody.hostId] : [])]),
    ];
    const poolIds = [
      ...new Set([context.originPoolId ?? "", ...(custody?.poolId ? [custody.poolId] : [])]),
    ];
    const row = await client.sdkKey.findUnique({
      where: { id: keyId, userId: ownerId },
      select: {
        id: true,
        scopes: true,
        userId: true,
        expiresAt: true,
        revokedAt: true,
        resourceMode: true,
        kind: true,
        ownSandboxesOnly: true,
        poolMode: true,
        HostAllowlist: {
          where: { sandboxHostId: { in: hostIds }, SandboxHost: { userId: ownerId } },
          take: 2,
          select: { sandboxHostId: true, SandboxHost: { select: { userId: true } } },
        },
        RevisionAllowlist: {
          where: {
            templateRevisionId: context.templateRevisionId ?? "",
            Revision: { userId: ownerId },
          },
          take: 1,
          select: { templateRevisionId: true },
        },
        // No pool-owner filter (as `principalFromRow` at request time): a
        // SELECTED key may name a pool shared with its owner, which current
        // custody checks; an unowned origin pool is still refused below.
        PoolAllowlist: {
          where: { poolId: { in: poolIds } },
          take: 2,
          select: { poolId: true },
        },
        User: { select: ownerCredentialPolicyUserSelect },
      },
    });
    const settings = await getForcedTwoFactorSettingsRecord(client);
    let active = Boolean(
      row &&
        (!buildScope || row.scopes.includes(TEMPLATE_BUILD_SCOPE)) &&
        !row.revokedAt &&
        !isExpired(row.expiresAt, new Date()) &&
        // Accepted work authorized by a no-expiry agent token stops while the
        // deployment disallows those tokens, like any other lost authority.
        !agentTokenBlockedByPolicy(row, env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY) &&
        (await isOwnerCredentialPolicySatisfied(row.User, new Date(), settings)),
    );
    if (row && active) {
      const creation = context.sandboxId
        ? await client.sandboxOperation.findFirst({
            where: { sandboxId: context.sandboxId, userId: ownerId, kind: "CREATE_SANDBOX" },
            orderBy: [{ createdAt: "asc" }, { id: "asc" }],
            select: { authorizingKeyId: true },
          })
        : null;
      const retainedContext = { ...context, authorizingKeyId: creation?.authorizingKeyId ?? null };
      if (custody) custodies.set(retainedContext, custody);
      storedContexts.add(retainedContext);
      active = storedGrantsAllowed(
        principalFromRow(row, new Set()),
        retainedContext,
        input.cleanup
          ? "sandboxes.kill"
          : input.operationKind === "CREATE_SANDBOX" || input.operationKind === "sandbox.create"
            ? "createDispatch"
            : "dispatch",
      );
      if (active) {
        // ALL_OWNED grants creator-owned retained work, including a foreign
        // transport. The durable CREATE row proves that ownership; host/pool
        // custody is not an extra creator grant. Selected keys still require
        // that exact initial key. Current usability was checked above.
        const retained =
          creation != null &&
          (!createdOnly({
            resourceMode: row.resourceMode,
            ownSandboxesOnly: row.ownSandboxesOnly,
          }) ||
            retainedContext.authorizingKeyId === row.id);
        const host =
          retained ||
          (await client.sandboxHost.findFirst({
            where: { id: context.sandboxHostId ?? "", userId: ownerId },
            select: { id: true },
          }));
        const revision =
          retained ||
          (await client.sandboxTemplateRevision.findFirst({
            where: { id: context.templateRevisionId ?? "", userId: ownerId },
            select: { id: true },
          }));
        const pool =
          !retained && context.originPoolId
            ? await client.sandboxPool.findFirst({
                where: { id: context.originPoolId, userId: ownerId },
                select: { id: true },
              })
            : true;
        active = Boolean(host && revision && pool);
      }
    }
    // Final verdict after every read: expiry and the no-expiry policy are judged here, so a
    // policy read never precedes an await that the verdict then trusts.
    const policyBlocked = () =>
      row !== null && agentTokenBlockedByPolicy(row, env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY);
    if (active && row && (isExpired(row.expiresAt, new Date()) || policyBlocked())) active = false;
    if (!current()) return "indeterminate";
    if (active) {
      input.onActive?.(row?.expiresAt ?? null);
      // The synchronous gate a relay send consults also re-judges the policy.
      input.onActiveAuthority?.(() => current() && !policyBlocked());
    }
    return active ? "active" : "inactive";
  } catch {
    return "indeterminate";
  }
}

/**
 * How each action treats the retained-creator
 * shortcut. `retained`: history reads and cleanup, which a creating (or
 * ALL_OWNED) key keeps after the sandbox moves off its allowlists. `custody`:
 * everything else, which needs `currentCustodyAllowed` first on a stored
 * sandbox context. A new action does not compile until it is classified.
 */
export const SERVICE_ACTION_CUSTODY: Readonly<Record<ServiceAction, "retained" | "custody">> = {
  "capabilities.get": "custody",
  "hosts.list": "custody",
  "hosts.get": "custody",
  "hostCommands.run": "custody",
  "hostCommands.get": "custody",
  "hostCommands.writeStdin": "custody",
  "hostCommands.cancel": "custody",
  "hostCommands.queue": "custody",
  "hostFiles.read": "custody",
  "hostFiles.list": "custody",
  "hostFiles.write": "custody",
  "hostFiles.edit": "custody",

  "hosts.storagePools": "custody",
  "pools.list": "custody",
  "pools.get": "custody",
  "pools.members": "custody",
  "pools.capacity": "custody",
  "templates.list": "custody",
  "templates.create": "custody",
  "templates.retire": "custody",
  "templates.revisions": "custody",
  "templates.availability": "custody",
  "templates.append": "custody",
  "templates.associate": "custody",
  "templates.build": "custody",
  "sandboxes.list": "retained",
  "sandboxes.get": "retained",
  "sandboxes.probe": "custody",
  "sandboxes.createIntent": "custody",
  "sandboxes.replayCreate": "retained",
  "sandboxes.create": "custody",
  "sandboxes.kill": "retained",
  "sandboxes.stop": "retained",
  "sandboxes.reconnect": "custody",
  "sandboxes.setTimeout": "custody",
  "sandboxes.update": "custody",
  "sandboxes.capture": "custody",
  "operations.get": "retained",
  "operations.getFileResult": "retained",
  "operations.getFileMutationResult": "retained",
  "operations.getRenameResult": "retained",
  "operations.getCommandResult": "retained",
  "operations.getSignalResult": "retained",
  "operations.getReceipt": "retained",
  "operations.getCommandOutput": "retained",
  "operations.downloadFile": "retained",
  "operations.cancel": "retained",
  "commands.run": "custody",
  "commands.writeStdin": "custody",
  "files.read": "custody",
  "files.write": "custody",
  "files.listDir": "custody",
  "files.stat": "custody",
  "files.mkdir": "custody",
  "files.remove": "custody",
  "files.move": "custody",
  "processes.connect": "custody",
  "sandboxes.capabilities": "retained",
  "processes.list": "custody",
  "processes.signal": "custody",
  "webhooks.list": "custody",
  "webhooks.get": "custody",
  "webhooks.create": "custody",
  "webhooks.update": "custody",
  "webhooks.delete": "custody",
  "webhooks.rotateSecret": "custody",
  "webhooks.test": "custody",
  "webhooks.listDeliveries": "custody",
  "webhooks.getDelivery": "custody",
  "webhooks.redeliver": "custody",
  "credentialDefinitions.list": "custody",
  "credentialDefinitions.get": "custody",
  "credentialDefinitions.create": "custody",
  "credentialDefinitions.archive": "custody",
  "credentials.list": "custody",
  "credentials.get": "custody",
  "credentials.create": "custody",
  "credentials.update": "custody",
  "credentials.delete": "custody",
  "credentials.events": "custody",
  "credentialAccounts.list": "custody",
  "credentialAccounts.create": "custody",
  "credentialAccounts.update": "custody",
  "credentialAccounts.delete": "custody",
  "credentialInstances.list": "custody",
  "credentialInstances.create": "custody",
  "credentialInstances.update": "custody",
  "credentialInstances.delete": "custody",
  "credentialInstances.writeValue": "custody",
  "sandboxCredentials.attach": "custody",
  "sandboxCredentials.free": "custody",
  "credentialInstances.listLeases": "custody",
  "credentialInstances.forceRelease": "custody",
};

/** History reads and cleanup (stop, kill, cancel): the retained-creator
 * shortcut applies to these only (§5a). */
export const RETAINED_CREATOR_ACTIONS: ReadonlySet<ServiceAction> = new Set(
  (Object.keys(SERVICE_ACTION_CUSTODY) as ServiceAction[]).filter(
    (action) => SERVICE_ACTION_CUSTODY[action] === "retained",
  ),
);

/** A reconnect target that resumes only through restore admission (§8.3b). */
async function isOffloadedRestoreTarget(
  client: Prisma.TransactionClient,
  ownerId: string,
  sandboxId: string,
): Promise<boolean> {
  const row = await client.sandbox.findFirst({
    where: { id: sandboxId, userId: ownerId, state: "OFFLOADED", diskOffloadId: { not: null } },
    select: { id: true },
  });
  return row !== null;
}

/**
 * §8.3b (V2): the grants a restore intent of an OFFLOADED sandbox needs from
 * an SDK key, in place of the guest-access usability check: the revision
 * grant, the origin-pool grant and the last host (current custody, §5a),
 * plus the owner's credential policy. The scope (`sandboxes:manage`) and the
 * owner-scoped lookup were checked by the caller; the creating-key
 * placement rule and the destination are checked at placement.
 */
async function requireRestoreIntentGrants(
  client: Prisma.TransactionClient,
  principal: ServicePrincipal,
  context: ServiceActionContext,
): Promise<void> {
  if (!templateAllowed(principal, context.templateRevisionId))
    throw forbidden("Template is not allowed for this key.");
  if (!poolAllowed(principal, context.originPoolId))
    throw forbidden("Placement context is required.");
  const custody = custodies.get(context);
  if (!custody || !currentCustodyAllowed(principal, custody))
    throw forbidden("Host is not allowed for this key.");
  const owner = await client.user.findUnique({
    where: { id: principal.ownerId },
    select: ownerCredentialPolicyUserSelect,
  });
  const settings = client === prisma ? undefined : await getForcedTwoFactorSettingsRecord(client);
  if (!owner || !(await isOwnerCredentialPolicySatisfied(owner, new Date(), settings)))
    throw forbidden("Sandbox access is unavailable.");
}

/** The normalized restore intent (§8.3a/§8.3b) the restore admission checks. */
export type RestoreIntentShape = {
  target: { hostId: string } | { poolId: string } | null;
  overrideCreatorAllowlist: boolean;
};

/**
 * §8.3b: the intent half of restore authorization. The override of the
 * creating key's allowlists is the owner's dashboard choice only: any SDK
 * principal sending it (an unrestricted key included) and any build is
 * refused `forbidden`. A target hint names at most one host or pool.
 */
export function authorizeRestoreIntent(principal: Principal, intent: RestoreIntentShape): void {
  if (intent.overrideCreatorAllowlist && !isBrowserSession(principal))
    throw forbidden("Only the owner can restore outside the creating key's allowlists.");
  if (intent.target && "hostId" in intent.target && "poolId" in intent.target)
    throw new ORPCError("BAD_REQUEST", { message: "Choose exactly one placement target." });
}

function needsCurrentUsability(action: ServiceAction) {
  return (
    action.startsWith("files.") ||
    action.startsWith("commands.") ||
    ["processes.list", "processes.signal", "sandboxes.reconnect", "sandboxes.setTimeout"].includes(
      action,
    )
  );
}

/** Request/final-read fence. The shared guest-access check also samples the
 * pinned transport and pool owner's authority; attribution writers hold G/H/S. */
async function requireCurrentSandboxUsability(
  client: Prisma.TransactionClient,
  principal: { ownerId: string },
  sandboxId: string,
) {
  const policy = {
    deletionRequestedAt: null,
    OR: [{ banned: { not: true } }, { banned: null }, { banExpires: { lte: new Date() } }],
  };
  const owned = await client.sandbox.findFirst({
    where: {
      id: sandboxId,
      userId: principal.ownerId,
      accessGraceUntil: null,
      SandboxHost: { userId: principal.ownerId, deletionRequestedAt: null, User: policy },
    },
    select: { id: true },
  });
  if (owned) return;
  const sandbox = await client.sandbox.findFirst({
    where: { id: sandboxId, userId: principal.ownerId },
    select: {
      sandboxHostId: true,
      hostOwnerId: true,
      usagePoolId: true,
      usageMemberId: true,
      accessGraceUntil: true,
      SandboxHost: {
        select: {
          userId: true,
          deletionRequestedAt: true,
          User: { select: ownerCredentialPolicyUserSelect },
        },
      },
    },
  });
  if (
    !sandbox?.SandboxHost ||
    sandbox.accessGraceUntil ||
    sandbox.SandboxHost.deletionRequestedAt ||
    sandbox.hostOwnerId !== sandbox.SandboxHost.userId ||
    !(await isOwnerCredentialPolicySatisfied(
      sandbox.SandboxHost.User,
      new Date(),
      await getForcedTwoFactorSettingsRecord(client),
    ))
  )
    throw forbidden("Sandbox access is unavailable.");
  if (sandbox.hostOwnerId === principal.ownerId) return;
  if (!sandbox.usagePoolId || !sandbox.usageMemberId)
    throw forbidden("Sandbox access is unavailable.");
  const member = await client.sandboxPoolMember.findFirst({
    where: {
      id: sandbox.usageMemberId,
      poolId: sandbox.usagePoolId,
      sandboxHostId: sandbox.sandboxHostId ?? "",
      hostOwnerId: sandbox.hostOwnerId,
      removedAt: null,
      Pool: {
        deletedAt: null,
        OR: [
          { userId: principal.ownerId },
          { Shares: { some: { granteeUserId: principal.ownerId, canUse: true } } },
        ],
      },
    },
    select: { Pool: { select: { User: { select: ownerCredentialPolicyUserSelect } } } },
  });
  if (
    !member ||
    !(await isOwnerCredentialPolicySatisfied(
      member.Pool.User,
      new Date(),
      await getForcedTwoFactorSettingsRecord(client),
    ))
  )
    throw forbidden("Sandbox access is unavailable.");
  // The active member's RI witness proves current contribution. enabled gates new placement only.
}

/** Creator restriction applies even to an all-owned resource grant. */
export function createdOnly(key: {
  resourceMode: SdkKeyResourceMode;
  ownSandboxesOnly: boolean;
}): boolean {
  return key.resourceMode === "ALLOWLIST" || key.ownSandboxesOnly;
}

export function authenticateSdkKeySecret(raw: string, now = new Date()) {
  return authenticateCredentialSecret(raw, "API", now);
}
export function authenticateAgentTokenSecret(raw: string, now = new Date()) {
  return authenticateCredentialSecret(raw, "AGENT_TOKEN", now);
}
export async function principalForMcpGrant(
  grantId: string,
  userId: string,
  clientId: string,
): Promise<ServicePrincipal | null> {
  const current = authorityTicket({ ownerId: userId });
  const grant = await prisma.mcpGrant.findFirst({
    where: { id: grantId, userId, clientId, revokedAt: null },
    select: { sdkKeyId: true },
  });
  if (!grant) return null;
  const principal = await revalidateSdkKey(grant.sdkKeyId, userId);
  // Re-read the grant after credential validation; a racing revoke must not authenticate.
  const active = await prisma.mcpGrant.findFirst({
    where: { id: grantId, userId, clientId, sdkKeyId: grant.sdkKeyId, revokedAt: null },
    select: { id: true },
  });
  return active && current() && principal?.credentialKind === "OAUTH_GRANT" ? principal : null;
}
