import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import type { AuthorityChangeHold } from "@wssp/db/authority";
import { pinnedAllocationV11Schema, validBuildId } from "@wssp/sandbox-contracts";
import { type CapacityHint, notifyCapacityChanged, takeCapacityHints } from "./capacity-queue-wake";
import { type AuthorizingPrincipal, KEY_FREE_CLEANUP_KINDS } from "./contracts";
import { commandRunDispatchFitsControlLimit } from "./dispatch-control-envelope";
import { loadExecutionConfig, validateCommandEnvironmentUnion } from "./execution-config";
import { finalizeReleasedHosts } from "./host-admission";
import { isLeasePolicyIdempotencyKey } from "./idempotency-key-reserved";
import { LEASE_DISPATCH_KINDS, leaseDispatchPayload, leaseWireSchema } from "./lease-wire";
import {
  notifyOperationsChanged,
  type OperationChange,
  operationChange,
} from "./operation-waiters";
import { outboxOperationIdOf } from "./outbox-operation";
import { dispatchClassOf } from "./principal-kinds";
import { finalizeTerminalResultHolds } from "./result-finalization";
import { pinnedLaunchSource, templateDispatchPayload } from "./template-dispatch";
import {
  notifySandboxTerminalLifecycle,
  type SandboxTerminalLifecycleChange,
  sandboxTerminalWrite,
} from "./terminal-lifecycle";

type SandboxDispatchWake = () => void;

let dispatchWake: SandboxDispatchWake | null = null;

/** Server runtime binds the in-process dispatch notifier (no-op until bound). */
export function bindSandboxDispatchWake(wake: SandboxDispatchWake | null): void {
  dispatchWake = wake;
}

export function notifySandboxDispatchPending(): void {
  try {
    dispatchWake?.();
  } catch {
    // Durable outbox has committed; the recovery scan will wake it. A notifier
    // failure must never turn a known accepted mutation into an HTTP failure.
    console.error("[sandbox-outbox] dispatch wake failed; recovery scan pending");
  }
}

/**
 * Owns post-commit invalidation for both service and relay transactions. Observe
 * the actual delegate writes so nested finalizers/settlement cannot omit a wake.
 * Claim bookkeeping and no-op row locks do not invalidate eligibility; otherwise
 * the scanner would wake itself forever on offline/ineligible rows.
 */
export async function sandboxOutboxTransaction<T>(
  work: (tx: Prisma.TransactionClient) => Promise<T>,
): Promise<T> {
  let changed = false;
  // C53: terminal-relevant sandbox writes, announced only after the commit.
  let terminalChange: SandboxTerminalLifecycleChange | null = null;
  // Operation long-polls: operation/result rows written, announced post-commit.
  let operationTouched: OperationChange | null = null;
  // Host-finalization authority holds stay in flight for the WHOLE transaction:
  // they settle only after its commit or rollback, so a ticket sampled between
  // the finalizer's statements and the commit can never authorize against
  // pre-commit grant state.
  const finalizationHolds: AuthorityChangeHold[] = [];
  // Capacity-queue wakes recorded on this transaction, delivered post-commit.
  let capacity: CapacityHint | null = null;
  try {
    const result = await prisma.$transaction((tx) => {
      const observe = <TModel extends object>(model: TModel, name: string): TModel =>
        new Proxy(model, {
          get(target, method, receiver) {
            const value: unknown = Reflect.get(target, method, receiver);
            if (typeof value !== "function") return value;
            return (...args: unknown[]) => {
              const result: unknown = Reflect.apply(value, target, args);
              const wakes = changesDispatchEligibility(name, String(method), args[0]);
              const terminal =
                name === "sandbox" ? sandboxTerminalWrite(String(method), args[0]) : null;
              const operation = operationWrite(name, String(method), args[0]);
              if (!wakes && !terminal && !operation) return result;
              return Promise.resolve(result).then((written: unknown) => {
                if (!(isRecord(written) && written.count === 0)) {
                  if (wakes) changed = true;
                  if (terminal) terminalChange = mergeTerminalChange(terminalChange, terminal);
                  if (operation)
                    operationTouched = mergeOperationChange(operationTouched, operation);
                }
                return written;
              });
            };
          },
        });
      const observed = new Proxy(tx, {
        get(target, model, receiver) {
          if (
            model === "outboxEvent" ||
            model === "sandboxOperation" ||
            model === "sandboxOperationResult" ||
            model === "sandbox"
          )
            return observe(target[model], model);
          return Reflect.get(target, model, receiver);
        },
      });
      return work(observed).then(async (value) => {
        // C21-11 finalizes host authority after handler work. Only the
        // result release suffix follows; it acquires no prefix rows.
        await finalizeReleasedHosts(observed, finalizationHolds);
        await finalizeTerminalResultHolds(observed);
        capacity = mergeCapacityHints(takeCapacityHints(observed), takeCapacityHints(tx));
        return value;
      });
    });
    if (changed) notifySandboxDispatchPending();
    if (terminalChange) notifySandboxTerminalLifecycle(terminalChange);
    // Never before the commit: a woken long-poll must read the committed row.
    if (operationTouched) notifyOperationsChanged(operationTouched);
    if (capacity) notifyCapacityChanged(capacity);
    return result;
  } finally {
    // After commit the invalidation is durable; after rollback it is spurious
    // and fails closed, healing on the next sample.
    for (const hold of finalizationHolds) hold.settle();
  }
}

function mergeCapacityHints(a: CapacityHint | null, b: CapacityHint | null): CapacityHint | null {
  if (!a || !b) return a ?? b;
  if (a === "all" || b === "all") return "all";
  return {
    poolIds: [...(a.poolIds ?? []), ...(b.poolIds ?? [])],
    hostIds: [...(a.hostIds ?? []), ...(b.hostIds ?? [])],
  };
}

function mergeTerminalChange(
  current: SandboxTerminalLifecycleChange | null,
  next: SandboxTerminalLifecycleChange,
): SandboxTerminalLifecycleChange {
  if (current === "all" || next === "all") return "all";
  if (!current) return next;
  return { sandboxIds: new Set([...current.sandboxIds, ...next.sandboxIds]) };
}

function mergeOperationChange(
  current: OperationChange | null,
  next: OperationChange,
): OperationChange {
  if (current === "all" || next === "all") return "all";
  if (!current) return next;
  return operationChange(
    [...current.operationIds, ...next.operationIds],
    [...current.ownerIds, ...next.ownerIds],
  );
}

const OPERATION_WRITES = new Set(["update", "updateMany", "upsert", "delete", "deleteMany"]);

/**
 * Which operations a `sandboxOperation` / `sandboxOperationResult` write can
 * change for a long-poll reader: the ids in `where.id` / `where.operationId`
 * (a string or `{ in: [...] }`, also inside `AND`); otherwise the owner in
 * `where.userId` (also inside `AND`), which wakes only that owner's waiters;
 * "all" only for a write naming neither. Creating an operation needs no wake:
 * nobody can hold its id yet. Exported for tests.
 */
export function operationWrite(
  model: string,
  method: string,
  args: unknown,
): OperationChange | null {
  if (model === "sandboxOperation") {
    if (!OPERATION_WRITES.has(method)) return null;
    return writeScope(isRecord(args) ? args.where : undefined, "id");
  }
  if (model === "sandboxOperationResult") {
    if (method === "create" && isRecord(args) && isRecord(args.data))
      return writeScope(args.data, "operationId");
    if (!OPERATION_WRITES.has(method)) return null;
    return writeScope(isRecord(args) ? args.where : undefined, "operationId");
  }
  return null;
}

function writeScope(where: unknown, field: "id" | "operationId"): OperationChange {
  const ids = keyedValues(where, field);
  if (ids) return operationChange(ids);
  const owners = keyedValues(where, "userId");
  return owners ? operationChange([], owners) : "all";
}

/** Values of `field` (string or `{ in }`) on `where` or any `AND` member. */
function keyedValues(where: unknown, field: string): string[] | null {
  if (!isRecord(where)) return null;
  const key = where[field];
  if (typeof key === "string") return [key];
  if (
    isRecord(key) &&
    Object.keys(key).length === 1 &&
    Array.isArray(key.in) &&
    key.in.every((id): id is string => typeof id === "string")
  )
    return key.in;
  const and = Array.isArray(where.AND) ? where.AND : isRecord(where.AND) ? [where.AND] : [];
  for (const member of and) {
    const found = keyedValues(member, field);
    if (found) return found;
  }
  return null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function changesDispatchEligibility(model: string, method: string, args: unknown): boolean {
  if (model === "outboxEvent" && (method === "create" || method === "createMany")) return true;
  if (method !== "update" && method !== "updateMany") return false;
  if (!isRecord(args) || !isRecord(args.data)) return false;
  const data = args.data;
  if (model === "outboxEvent") return data.sentAt === null || "processedAt" in data;
  // Acceptance unlocks pending stdin/cancel; settlement and lifecycle transitions
  // can release waiting work. DISPATCHED is the scanner's own claim, not a wake.
  if (model === "sandboxOperation") {
    // A proven pre-frame refusal restores the original claim for a later wake
    // or recovery scan. Waking here would immediately repeat the same refusal.
    if (
      data.state === "QUEUED" &&
      data.dispatchAttempt === 0 &&
      data.dispatchedAt === null &&
      data.dispatchedHostId === null &&
      data.dispatchedConnectionEpoch === null
    )
      return false;
    return (
      ("state" in data && data.state !== "DISPATCHED" && data.state !== "CANCEL_REQUESTED") ||
      ("acceptedAttempt" in data && data.acceptedAttempt !== null)
    );
  }
  return model === "sandbox" && (data.state === "READY" || data.state === "STOPPED");
}

export type SandboxOutboxEventCreate = {
  authorizingPrincipal: AuthorizingPrincipal;
  userId: string;
  aggregateId: string;
  eventType: string;
  payload: Prisma.InputJsonObject;
};

export async function createSandboxOutboxEvent(
  tx: Prisma.TransactionClient,
  data: SandboxOutboxEventCreate,
): Promise<void> {
  const instanceOperation =
    typeof data.payload.kind === "string" &&
    !["operation.cancel", "process.stdin"].includes(data.payload.kind);
  let templatePayload = {};
  let privatePayload: { privateConfig?: import("./execution-config").PrivateConfigReference } = {};
  let defaults: [string, string][] = [];
  let leasePayload = {};
  if (instanceOperation) {
    const sandbox = await tx.sandbox.findFirst({
      where: { id: data.aggregateId, userId: data.userId },
      select: {
        templateId: true,
        templateRevisionId: true,
        sandboxHostId: true,
        leaseRevision: true,
        leaseExpiresAt: true,
        leaseExpireAction: true,
        leasePendingReady: true,
      },
    });
    if (!sandbox?.sandboxHostId) throw new Error("Sandbox host missing");
    // Retirement blocks fresh placement, not work on an existing VM/disk.
    // Every instance operation uses its owner-scoped boot placement identity;
    // commands, files, lease changes and cleanup never re-resolve a live revision.
    const template = await pinnedLaunchSource(
      tx,
      data.aggregateId,
      data.userId,
      ["sandbox.create", "sandbox.reconnect"].includes(String(data.payload.kind)),
    );
    if (!template) throw new Error("Sandbox template identity missing");
    const allocation = pinnedAllocationV11Schema.safeParse({
      cpuCount: template.cpuCount,
      memoryMiB: template.memoryMiB,
      diskGiB: template.diskGiB,
      storagePoolName: template.storagePoolName,
      storageMarker: template.storageMarker,
      chargedMemoryMiB: template.chargedMemoryMiB,
      chargedVcpu: template.chargedVcpu,
      rootChargeGiB: template.rootChargeGiB,
    });
    templatePayload = {
      ...templateDispatchPayload(template),
      ...(["sandbox.create", "sandbox.reconnect", "sandbox.stop", "sandbox.kill"].includes(
        String(data.payload.kind),
      ) && allocation.success
        ? { allocation: allocation.data }
        : {}),
      ...(["sandbox.create", "sandbox.reconnect"].includes(String(data.payload.kind))
        ? {
            cpuCount: template.cpuCount,
            memoryMiB: template.memoryMiB,
          }
        : {}),
      ...(data.payload.kind === "sandbox.create"
        ? { templateRevisionId: sandbox.templateRevisionId }
        : {}),
    };
    if (
      ["sandbox.create", "sandbox.reconnect", "command.run"].includes(String(data.payload.kind))
    ) {
      const config = await loadExecutionConfig(tx, data.aggregateId, data.userId);
      if (config) {
        privatePayload = { privateConfig: config.reference };
        defaults = config.env;
      }
    }
    if (LEASE_DISPATCH_KINDS.has(String(data.payload.kind)))
      leasePayload = {
        lease: leaseDispatchPayload(
          sandbox,
          // The keyless system pull-in is shorten-only at the host.
          data.payload.kind === "sandbox.lease.renew" &&
            dispatchClassOf(data.authorizingPrincipal, String(data.payload.kind)) === "system" &&
            isLeasePolicyIdempotencyKey(data.payload.idempotencyKey),
          // Lease from READY: only the create carries the relative timeout.
          data.payload.kind === "sandbox.create" &&
            sandbox.leasePendingReady &&
            typeof data.payload.leaseFromReadyMs === "number"
            ? data.payload.leaseFromReadyMs
            : undefined,
        ),
      };
  }
  const payload: Prisma.InputJsonObject = {
    ...data.payload,
    ...templatePayload,
    ...leasePayload,
    ...privatePayload,
    authorizingPrincipal: data.authorizingPrincipal,
  };
  if (payload.kind === "command.run") {
    if (!commandRunDispatchFitsControlLimit(payload, data.aggregateId)) {
      throw new ORPCError("BAD_REQUEST", { message: "Encoded command dispatch exceeds 64 KiB." });
    }
    const union = validateCommandEnvironmentUnion(payload, defaults);
    if (!commandRunDispatchFitsControlLimit({ ...payload, env: union }, data.aggregateId)) {
      throw new ORPCError("BAD_REQUEST", { message: "Encoded command dispatch exceeds 64 KiB." });
    }
  }
  await tx.outboxEvent.create({
    data: {
      userId: data.userId,
      aggregateType: "sandbox",
      aggregateId: data.aggregateId,
      eventType: data.eventType,
      operationId: outboxOperationIdOf(payload),
      payload,
    },
  });
}

/** Decode the explicit, closed acceptance attribution. */
export function decodeOutboxPrincipal(
  payload: Record<string, unknown>,
): AuthorizingPrincipal | null {
  const value = payload.authorizingPrincipal;
  if (!isRecord(value)) return null;
  if (
    value.kind === "sdkKey" &&
    typeof value.keyId === "string" &&
    value.keyId.length > 0 &&
    Object.keys(value).length === 2
  )
    return { kind: "sdkKey", keyId: value.keyId };
  if ((value.kind === "session" || value.kind === "system") && Object.keys(value).length === 1)
    return { kind: value.kind };
  // Exactly {kind, buildId, keyId}; keyId is the real accepting key or null.
  if (
    value.kind === "build" &&
    typeof value.buildId === "string" &&
    validBuildId(value.buildId) &&
    (value.keyId === null || (typeof value.keyId === "string" && value.keyId.length > 0)) &&
    Object.keys(value).length === 3 &&
    "keyId" in value
  )
    return { kind: "build", buildId: value.buildId, keyId: value.keyId };
  return null;
}

/** Closed payloads for system cleanup; rejecting extra keys also rejects nested
 * env/private-config/stdin smuggling before the system authorization bypass. */
export function systemDispatchAllowed(
  kind: string,
  payload: Record<string, unknown>,
  prepared = false,
): boolean {
  const fields = new Set([
    "sandboxId",
    "sandboxHostId",
    "operationId",
    "kind",
    "generation",
    "dispatchAttempt",
    "idempotencyKey",
    "incusName",
    "templateId",
    "templateDigest",
    "incusFingerprint",
    "architecture",
    "guestUid",
    "guestGid",
    "guestHome",
    "guestShell",
    "authorizingPrincipal",
  ]);
  if (prepared)
    for (const key of [
      "connectionEpoch",
      "attempt",
      "bodyHash",
      "digestScheme",
      "digestKeyId",
      "onPossibleDispatchFrame",
    ])
      fields.add(key);
  // M4: the system lease pull-in is the one non-cleanup system dispatch. It
  // gains exactly one extra field, a valid `lease`, and only under its
  // reserved key; renew is NOT a key-free cleanup kind for the host.
  const leasePolicyRenew =
    kind === "sandbox.lease.renew" && isLeasePolicyIdempotencyKey(payload.idempotencyKey);
  return (
    (KEY_FREE_CLEANUP_KINDS.has(kind) || leasePolicyRenew) &&
    Object.entries(payload).every(
      ([key, value]) =>
        (key === "allocation" && pinnedAllocationV11Schema.safeParse(value).success) ||
        // CLI logins (§10.3): the one credential field a system stop/kill
        // carries, with its single exact value (never `credentialCapture`).
        (key === "credentialTeardown" &&
          value === "system" &&
          (kind === "sandbox.stop" || kind === "sandbox.kill")) ||
        (leasePolicyRenew &&
          key === "lease" &&
          leaseWireSchema.safeParse(value).data?.shortenOnly === true) ||
        (prepared && value === undefined) ||
        (prepared && key === "recursive" && value === false) ||
        // The restored lineage's base image, built
        // from the worker-verified offload row in the dispatch transaction.
        // Without it a system stop/kill (restore exit SYSTEM_DETACH, lease
        // expiry, readiness cleanup) of a restored sandbox never dispatches.
        (prepared &&
          key === "diskBaseFingerprint" &&
          typeof value === "string" &&
          /^sha256:[0-9a-f]{64}$/.test(value)) ||
        (prepared && key === "onPossibleDispatchFrame" && typeof value === "function") ||
        (fields.has(key) &&
          (key === "authorizingPrincipal" ||
            value === null ||
            ["string", "number", "boolean"].includes(typeof value))),
    )
  );
}
