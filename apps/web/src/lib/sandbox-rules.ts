import {
  createSandboxInput,
  idempotencyKey,
  sandboxNameSchema,
  setSandboxTimeoutInput,
  TRANSFER_MAX_BYTES,
} from "@wssp/api/sandbox/contracts";
import {
  isUnlimitedLeaseEnd,
  LEASE_DEFAULT_MS,
  LEASE_MAX_MS,
} from "@wssp/api/sandbox/lease-limits";
import { TRANSIENT_RESTORE_LOGIN_CODES } from "@wssp/api/sandbox/restore-login-codes";
import {
  ACTIVE_OPERATION_STATES,
  HEALTHY_GUEST_STATES,
  KILLABLE_SANDBOX_STATES,
  STOPPABLE_SANDBOX_STATES,
} from "@wssp/api/sandbox/state-transitions";

import { type HostConnectionFields, hostConnectionState } from "@/lib/host-status";

/**
 * Pure rules for the Sandboxes dashboard (C47). The page shows only what the
 * server reported: a lifecycle action never flips a sandbox to READY, STOPPED
 * or DELETED in the browser — the next read does. Which controls are offered
 * follows the server's own state sets (imported, not copied); the server
 * still decides every mutation.
 */

export { isUnlimitedLeaseEnd, LEASE_DEFAULT_MS, LEASE_MAX_MS, TRANSFER_MAX_BYTES };

export type SandboxState =
  | "REQUESTED"
  | "SCHEDULED"
  | "PROVISIONING"
  | "READY"
  | "STOPPING"
  | "STOPPED"
  | "RECLAIMING"
  | "DELETED"
  | "UNREACHABLE"
  | "RECOVERED"
  | "HOST_LOST"
  | "ERROR"
  | "WAITING_FOR_CAPACITY"
  | "OFFLOADED";

export type OperationState =
  | "QUEUED"
  | "DISPATCHED"
  | "ACCEPTED"
  | "RUNNING"
  | "CANCEL_REQUESTED"
  | "SUCCEEDED"
  | "FAILED"
  | "CANCELLED"
  | "UNKNOWN_OUTCOME";

/** How the page groups the server's lifecycle states (every state keeps its own label). */
export type SandboxPhase =
  | "waiting"
  | "starting"
  | "ready"
  | "stopping"
  | "stopped"
  | "deleted"
  | "problem";

const PHASE: Record<SandboxState, SandboxPhase> = {
  // Its own phase, polled slowly: a wait can last hours (never isTransitional).
  WAITING_FOR_CAPACITY: "waiting",
  REQUESTED: "starting",
  SCHEDULED: "starting",
  PROVISIONING: "starting",
  RECOVERED: "starting",
  READY: "ready",
  STOPPING: "stopping",
  RECLAIMING: "stopping",
  STOPPED: "stopped",
  // Hostless: the stopped disk lives only in the image store.
  OFFLOADED: "stopped",
  DELETED: "deleted",
  UNREACHABLE: "problem",
  HOST_LOST: "problem",
  ERROR: "problem",
};

export function sandboxPhase(state: SandboxState): SandboxPhase {
  return PHASE[state];
}

/** A state the server is still moving toward a result: the page polls quickly while it lasts. */
export function isTransitional(state: SandboxState): boolean {
  const phase = PHASE[state];
  return phase === "starting" || phase === "stopping";
}

export function isOperationActive(state: OperationState): boolean {
  return ACTIVE_OPERATION_STATES.has(state);
}

export type SandboxAction = "stop" | "destroy" | "reconnectWarm" | "startCold" | "renew" | "files";

/**
 * Controls offered for a sandbox in `state`, mirroring the server's own
 * guards: stop can interrupt boot; renew/files need a healthy guest (READY), warm reconnect needs
 * READY, a cold start needs STOPPED (or OFFLOADED: the start restores the
 * stored disk onto an eligible host), destroy follows the server's killable
 * set. Nothing is offered for a DELETED sandbox. The server re-checks all of it.
 */
export function sandboxActions(
  state: SandboxState,
  latest?: { kind: string; state: string } | null,
): ReadonlySet<SandboxAction> {
  const actions = new Set<SandboxAction>();
  if (STOPPABLE_SANDBOX_STATES.has(state)) actions.add("stop");
  if (HEALTHY_GUEST_STATES.has(state)) {
    actions.add("reconnectWarm");
    actions.add("renew");
    actions.add("files");
  }
  if (state === "STOPPED" || state === "OFFLOADED") actions.add("startCold");
  // Destroying a waiting create cancels it (the server's dedicated branch).
  if (state === "WAITING_FOR_CAPACITY") actions.add("destroy");
  if (
    KILLABLE_SANDBOX_STATES.has(state) ||
    (state === "STOPPING" &&
      latest?.state === "UNKNOWN_OUTCOME" &&
      ["KILL_SANDBOX", "STOP_SANDBOX"].includes(latest.kind)) ||
    (state === "STOPPING" &&
      latest?.kind === "STOP_SANDBOX" &&
      ACTIVE_OPERATION_STATES.has(latest.state as OperationState))
  )
    actions.add("destroy");
  return actions;
}

/** The server's disk projection (`disk` on the sandbox DTO and dashboard view). */
export type DiskView = {
  location: "host" | "host_and_store" | "store";
  offloadState:
    | "none"
    | "pending"
    | "exporting"
    | "uploading"
    | "verifying"
    | "stored"
    | "evicting"
    | "failed";
  offloadFailure: "quota_exceeded" | "size_exceeded" | "staging_full" | "other" | null;
  offloadedAt: string | null;
  sizeBytes: number | null;
  eligibility: "any_host" | "own_hosts" | "never";
  offloadPin: "ANY" | "OWN_HOSTS";
};

/** The image store holds a copy of this disk that a destroy also deletes. */
export function hasStoredCopy(disk: DiskView | null): boolean {
  return disk != null && disk.location !== "host";
}

/**
 * Offer the dashboard-only override of the creating SDK key's allowlists
 * once a restore of an OFFLOADED sandbox found no allowed
 * host: refused at once, or the restore's wait ended without room.
 */
export function offersRestoreOverride(
  state: SandboxState,
  problem: SandboxProblem | null,
  latest?: { kind: string; state: string; errorCode: string | null } | null,
): boolean {
  if (state !== "OFFLOADED") return false;
  if (problem === "restoreNoAllowedHost") return true;
  return (
    latest?.kind === "RECONNECT_SANDBOX" &&
    latest.state === "FAILED" &&
    latest.errorCode === "restore_no_allowed_host"
  );
}

/**
 * Message key per login refusal that kept a restore waiting until its
 * deadline (§8.3c): the server's transient list, so a new code there fails
 * type checking here until it has a message.
 */
const RESTORE_LOGIN_WAIT = {
  "credential.in_use": "inUse",
  "credential.busy": "busy",
  "credential.pending_drain": "pendingDrain",
  "credential.needs_login": "needsLogin",
  "credential.account_paused": "accountPaused",
  "credential.limit_reached": "limitReached",
  "credential.host_forbidden": "hostForbidden",
  "credential.recovery_required": "recoveryRequired",
} as const satisfies Record<(typeof TRANSIENT_RESTORE_LOGIN_CODES)[number], string>;

export type RestoreLoginWait = (typeof RESTORE_LOGIN_WAIT)[keyof typeof RESTORE_LOGIN_WAIT];

/**
 * Why the latest restore of this OFFLOADED sandbox failed, when its wait
 * reached the deadline while an attached login was busy or unavailable, so
 * the page can explain it and point to the login; otherwise null.
 */
export function restoreLoginWait(
  state: SandboxState,
  latest?: { kind: string; state: string; errorCode: string | null } | null,
): RestoreLoginWait | null {
  if (state !== "OFFLOADED") return null;
  if (latest?.kind !== "RECONNECT_SANDBOX" || latest.state !== "FAILED") return null;
  const code = TRANSIENT_RESTORE_LOGIN_CODES.find((known) => known === latest.errorCode);
  return code ? RESTORE_LOGIN_WAIT[code] : null;
}

/**
 * The sandbox's host as the page should describe it. `offline` covers every
 * host that is not heartbeating now (stale, disconnected, revoked, pending
 * deletion): the stored lifecycle state may be out of date, and queued work
 * waits for the host.
 */
export type SandboxHostView = "online" | "offline" | "none";

export function sandboxHostView(host: HostConnectionFields | null, now: number): SandboxHostView {
  if (host == null) return "none";
  return hostConnectionState(host, now) === "ready" ? "online" : "offline";
}

/** `unlimited`: the far-future "no time limit" end (9999-12-31), never a date to show. */
export type LeaseTerm = { expiresAt: number; onExpire: "stop" | "destroy"; unlimited?: boolean };

function term(at: Date | string | null, action: "STOP" | "DESTROY" | null): LeaseTerm | null {
  if (at == null || action == null) return null;
  const ms = at instanceof Date ? at.getTime() : Date.parse(at);
  if (!Number.isFinite(ms)) return null;
  return {
    expiresAt: ms,
    onExpire: action === "DESTROY" ? "destroy" : "stop",
    unlimited: isUnlimitedLeaseEnd(ms),
  };
}

export type LeaseFields = {
  leaseRevision: number;
  leaseExpiresAtRequested: Date | string | null;
  leaseExpireActionRequested: "STOP" | "DESTROY" | null;
  leaseExpiresAtEffective: Date | string | null;
  leaseExpireActionEffective: "STOP" | "DESTROY" | null;
};

/**
 * Requested versus host-acknowledged lifetime. `pending` means the host has
 * not acknowledged the latest request (so the extension is not promised);
 * `acknowledged` means the host holds exactly what was requested; `differs`
 * means the host holds another term (for example an older one).
 */
export type LeaseAck = "pending" | "acknowledged" | "differs";

export function leaseView(sandbox: LeaseFields): {
  revision: number;
  requested: LeaseTerm | null;
  effective: LeaseTerm | null;
  ack: LeaseAck;
} {
  const requested = term(sandbox.leaseExpiresAtRequested, sandbox.leaseExpireActionRequested);
  const effective = term(sandbox.leaseExpiresAtEffective, sandbox.leaseExpireActionEffective);
  const ack: LeaseAck =
    effective == null
      ? "pending"
      : requested != null &&
          requested.expiresAt === effective.expiresAt &&
          requested.onExpire === effective.onExpire
        ? "acknowledged"
        : "differs";
  return { revision: sandbox.leaseRevision, requested, effective, ack };
}

/** String labels validated at the read boundary, in a stable order. */
export function sandboxLabels(metadata: Record<string, string>): [string, string][] {
  return Object.entries(metadata).sort(([a], [b]) => a.localeCompare(b));
}

/**
 * Lifetime presets, filtered by the effective maximum for the target (the
 * deployment, host, pool and membership limits). `0` is "no time limit" and is
 * offered only where the target allows it.
 */
const LIFETIME_MINUTES = [
  5, 15, 30, 60, 120, 240, 480, 720, 1440, 2880, 4320, 10080, 20160,
] as const;
const UNLIMITED_LIFETIME = "0";
export function lifetimeOptions(maxTimeoutMs: number, allowUnlimited = false): number[] {
  return [
    ...LIFETIME_MINUTES.filter((minutes) => minutes * 60_000 <= maxTimeoutMs),
    ...(allowUnlimited ? [0] : []),
  ];
}
/** The effective lease limit the form validates against before the server re-checks. */
export type LifetimeLimit = { maxTimeoutMs: number; allowUnlimited: boolean };
export const DEFAULT_LIFETIME_MINUTES = LEASE_DEFAULT_MS / 60_000;

export type SandboxDraft = {
  /** Blank lets the server pick a free adjective-noun name. */
  name: string;
  hostId: string;
  poolId?: string;
  expectedDisconnectGraceSeconds?: number;
  templateId: string;
  /** Logical identity selects its explicit latest tag at acceptance; revision pins an exact ID. */
  templateMode?: "logical" | "revision";
  cpuCount: string;
  memoryMiB: string;
  diskGiB: string;
  lifetimeMinutes: string;
  onExpire: "stop" | "destroy";
  labels: string;
  envs: string;
  /**
   * Open internet (the default) or an allowlist. The grants below are the
   * allowlist when off, and fallback grants when on (used only if the node
   * allows only listed destinations for other users' sandboxes).
   */
  internetAccess: boolean;
  /** Immutable egress grants (C34): one entry per line. */
  egressDomains: string;
  egressCidrs: string;
  /**
   * Passwordless `sudo` for the guest user (default on, fixed at creation).
   * The dashboard always sends it, so the idempotency intent is explicit.
   */
  guestSudo: boolean;
  /** Pool creates only: wait in the pool's FIFO queue when it is full. */
  capacityWait?: CapacityWaitChoice;
  /** CLI logins (≤ 8, one per login); empty account/instance mean "Any available". */
  credentials?: readonly { credentialId: string; accountId: string; instanceId: string }[];
};

/** "If the pool is full" choices; `none` fails at once (today's behavior). */
const CAPACITY_WAIT_CHOICES = {
  none: null,
  "15m": 15 * 60_000,
  "1h": 60 * 60_000,
  "4h": 4 * 60 * 60_000,
  "24h": 24 * 60 * 60_000,
  unlimited: "unlimited",
} as const;
export type CapacityWaitChoice = keyof typeof CAPACITY_WAIT_CHOICES;

/** Choices the effective limit allows (`null` = no limit; 0 = waits disabled). */
export function capacityWaitChoices(maxWaitMs: number | null): CapacityWaitChoice[] {
  return (Object.keys(CAPACITY_WAIT_CHOICES) as CapacityWaitChoice[]).filter((choice) => {
    const value = CAPACITY_WAIT_CHOICES[choice];
    if (value === null) return true;
    if (value === "unlimited") return maxWaitMs === null;
    return maxWaitMs === null || value <= maxWaitMs;
  });
}

export const DEFAULT_SANDBOX_DRAFT: SandboxDraft = {
  name: "",
  hostId: "",
  templateId: "",
  cpuCount: "",
  memoryMiB: "",
  diskGiB: "",
  lifetimeMinutes: String(DEFAULT_LIFETIME_MINUTES),
  onExpire: "destroy",
  labels: "",
  envs: "",
  internetAccess: true,
  egressDomains: "",
  egressCidrs: "",
  guestSudo: true,
};

export type SandboxDraftProblem =
  | "name"
  | "noHost"
  | "noTemplate"
  | "unknownHost"
  | "unknownPool"
  | "templateOffHost"
  | "lifetime"
  | "labelsSyntax"
  | "labels"
  | "envs"
  | "egress"
  | "cpuCount"
  | "memoryMiB"
  | "diskGiB"
  | "credentials";

/** `key=value` per line; blank lines are ignored. Values stay strings. */
export function parseLabels(text: string): Record<string, string> | null {
  // Null prototype: a `__proto__` key stays an own key (the server schema refuses it).
  const labels = Object.create(null) as Record<string, string>;
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line) continue;
    const at = line.indexOf("=");
    if (at <= 0) return null;
    const key = line.slice(0, at).trim();
    if (!key || Object.hasOwn(labels, key)) return null;
    labels[key] = line.slice(at + 1).trim();
  }
  return labels;
}

/** Relative lease of a draft: `0` only for an explicit, allowed "no time limit". */
export function lifetimeMs(
  minutesText: string,
  limit: LifetimeLimit = { maxTimeoutMs: LEASE_MAX_MS, allowUnlimited: false },
): number | null {
  if (minutesText === UNLIMITED_LIFETIME) return limit.allowUnlimited ? 0 : null;
  const minutes = Number(minutesText);
  if (!Number.isInteger(minutes) || minutes < 1) return null;
  const ms = minutes * 60_000;
  return ms > limit.maxTimeoutMs ? null : ms;
}

/** One entry per line, trimmed; blank lines are ignored. */
function parseLines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/**
 * The draft's egress request as the create input's `egress`, always with an
 * explicit mode: `open` (grants are fallback grants) or `allowlist` (no grants
 * is deny-all). Null when the entries fail the server's own input-schema
 * shape (the C34 catalog). The server still normalizes and re-validates.
 */
function egressInput(draft: SandboxDraft): {
  mode: "open" | "allowlist";
  domains: string[];
  cidrs: string[];
} | null {
  const egress = {
    mode: draft.internetAccess ? ("open" as const) : ("allowlist" as const),
    domains: parseLines(draft.egressDomains),
    cidrs: parseLines(draft.egressCidrs),
  };
  if (!createSandboxInput.shape.egress?.safeParse(egress).success) return null;
  return egress;
}

/** JSON preserves whitespace and multiline values; diagnostics never echo input. */
function parseSandboxEnvs(text: string): Record<string, string> | null {
  try {
    const value: unknown = text.trim() ? JSON.parse(text) : {};
    const parsed = createSandboxInput.shape.envs.safeParse(value);
    return parsed.success ? (parsed.data ?? {}) : null;
  } catch {
    return null;
  }
}

/** Blank independently inherits the accepted revision; never coerce blank to zero. */
function sizeOverrides(draft: SandboxDraft) {
  const numeric = (value: string) =>
    /^\d{1,10}$/.test(value.trim()) ? Number(value.trim()) : Number.NaN;
  return {
    ...(draft.cpuCount.trim() ? { cpuCount: numeric(draft.cpuCount) } : {}),
    ...(draft.memoryMiB.trim() ? { memoryMiB: numeric(draft.memoryMiB) } : {}),
    ...(draft.diskGiB.trim() ? { diskGiB: numeric(draft.diskGiB) } : {}),
  };
}

/** The exact `createSandbox` input for this draft, with a relative lifetime for server acceptance. */
export function sandboxDraftInput(draft: SandboxDraft, key: string, limit?: LifetimeLimit) {
  const labels = parseLabels(draft.labels);
  if (labels === null) throw new Error("sandbox.metadata_invalid");
  const egress = egressInput(draft);
  if (egress === null) throw new Error("sandbox.egress_policy_invalid");
  // 0 means "no time limit": an invalid draft must never fall back to it.
  const timeoutMs = lifetimeMs(draft.lifetimeMinutes, limit);
  if (timeoutMs === null) throw new RangeError("Lifetime exceeds the allowed maximum.");
  return createSandboxInput.parse({
    template: `${draft.templateMode === "logical" ? "template" : "revision"}/${draft.templateId}`,
    ...(draft.name ? { name: draft.name } : {}),
    ...(draft.poolId
      ? {
          poolId: draft.poolId,
          ...(draft.expectedDisconnectGraceSeconds !== undefined
            ? { expectedDisconnectGraceSeconds: draft.expectedDisconnectGraceSeconds }
            : {}),
          ...(draft.capacityWait && CAPACITY_WAIT_CHOICES[draft.capacityWait] !== null
            ? { waitForCapacityMs: CAPACITY_WAIT_CHOICES[draft.capacityWait] ?? undefined }
            : {}),
        }
      : { sandboxHostId: draft.hostId }),
    idempotencyKey: key,
    ...sizeOverrides(draft),
    envs: parseSandboxEnvs(draft.envs) ?? {},
    ...(Object.keys(labels).length > 0 ? { metadata: labels } : {}),
    egress,
    guestSudo: draft.guestSudo,
    timeoutMs,
    lifecycle: { onTimeout: draft.onExpire === "destroy" ? ("kill" as const) : ("stop" as const) },
    ...(draft.credentials && draft.credentials.length > 0
      ? {
          credentials: draft.credentials.map((choice) => ({
            credentialId: choice.credentialId,
            ...(choice.accountId ? { accountId: choice.accountId } : {}),
            ...(choice.instanceId ? { instanceId: choice.instanceId } : {}),
          })),
        }
      : {}),
  });
}

/**
 * Every reason the draft cannot be sent: placement and an active logical
 * template or exact revision must be chosen, lifetime must be bounded, and the
 * labels must parse and pass the server's own metadata schema.
 */
export function sandboxDraftProblems(
  draft: SandboxDraft,
  templates: readonly {
    id: string;
    availability?: readonly { hostId: string; status?: string }[];
    retiredAt?: Date | string | null;
    archivedAt?: Date | string | null;
  }[],
  maxTimeoutMs = LEASE_MAX_MS,
  allowUnlimited = false,
): SandboxDraftProblem[] {
  const problems: SandboxDraftProblem[] = [];
  if (draft.name && !sandboxNameSchema.safeParse(draft.name).success) problems.push("name");
  if (!draft.hostId && !draft.poolId) problems.push("noHost");
  if (!draft.templateId) problems.push("noTemplate");
  else {
    const template = templates.find((candidate) => candidate.id === draft.templateId);
    if (!template || template.retiredAt != null || template.archivedAt != null)
      problems.push("templateOffHost");
  }
  if (lifetimeMs(draft.lifetimeMinutes, { maxTimeoutMs, allowUnlimited }) == null)
    problems.push("lifetime");
  const size = sizeOverrides(draft);
  for (const field of ["cpuCount", "memoryMiB", "diskGiB"] as const) {
    if (!createSandboxInput.shape[field].safeParse(size[field]).success) problems.push(field);
  }
  const labels = parseLabels(draft.labels);
  if (labels == null) problems.push("labelsSyntax");
  else if (
    !createSandboxInput.safeParse({
      template: "revision/t",
      sandboxHostId: "h",
      idempotencyKey: "k",
      metadata: labels,
    }).success
  )
    problems.push("labels");
  if (parseSandboxEnvs(draft.envs) == null) problems.push("envs");
  if (egressInput(draft) == null) problems.push("egress");
  const logins = draft.credentials ?? [];
  if (
    logins.length > 8 ||
    logins.some((choice) => !choice.credentialId) ||
    new Set(logins.map((choice) => choice.credentialId)).size !== logins.length
  )
    problems.push("credentials");
  return problems;
}

/** Renewal input: a relative lifetime; the stored expiry action is unchanged. */
/** Relative renewal bounded by the caller's effective limit; never clamped. */
export function renewalInput(
  sandboxId: string,
  minutes: string,
  key: string,
  limit: LifetimeLimit = { maxTimeoutMs: LEASE_MAX_MS, allowUnlimited: false },
) {
  const timeoutMs = lifetimeMs(minutes, limit);
  if (timeoutMs === null) throw new RangeError("Lifetime exceeds the allowed maximum.");
  return setSandboxTimeoutInput.parse({ id: sandboxId, idempotencyKey: key, timeoutMs });
}

/** A fresh idempotency key for one browser intent (valid for the server schema). */
export function newIntentKey(action: string, random: () => string = () => crypto.randomUUID()) {
  return idempotencyKey.parse(`web.${action}.${random()}`);
}

/**
 * One idempotency key per intent: a retry of the same intent (same action,
 * target and body) reuses the key — and the exact input first sent, so a
 * double submit or a retry after a lost response replays the first request
 * instead of creating a second sandbox or a second receipt. A different
 * intent gets a fresh key. `settle` forgets the intent once the server
 * answered, so the next click is a new intent.
 */
export class IntentKeys {
  private current: { signature: string; key: string; input: unknown } | null = null;

  constructor(private readonly random: () => string = () => crypto.randomUUID()) {}

  /**
   * The input for this intent. The stored input was built by the same
   * `action`'s builder (the action is part of the signature), so it has
   * the builder's type.
   */
  for<TInput>(action: string, signature: string, build: (key: string) => TInput): TInput {
    const full = `${action}\n${signature}`;
    if (this.current?.signature !== full) {
      const key = newIntentKey(action, this.random);
      this.current = { signature: full, key, input: build(key) };
    }
    return this.current.input as TInput;
  }

  settle() {
    this.current = null;
  }
}

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

function shapeOf(error: unknown): ErrorShape {
  return (error && typeof error === "object" ? error : {}) as ErrorShape;
}

function domainField(error: unknown, field: "code" | "capability" | "reason"): string | null {
  const data = shapeOf(error).data;
  if (data && typeof data === "object" && field in data) {
    const value = (data as Record<string, unknown>)[field];
    return typeof value === "string" ? value : null;
  }
  return null;
}

function domainCode(error: unknown): string | null {
  return domainField(error, "code");
}

export type SandboxProblem =
  | "poolPolicyChanged"
  | "shareQuota"
  | "memberQuota"
  | "notFound"
  | "stateChanged"
  | "keyReused"
  | "poolFull"
  | "poolUnavailable"
  | "poolIncompatible"
  | "poolMissing"
  | "hostCapacity"
  | "capacityRam"
  | "capacityVcpu"
  | "capacityDisk"
  | "capacityStorage"
  | "capacityCeiling"
  | "sizeInvalid"
  | "diskBelowImage"
  | "sizeUnsupported"
  | "sizeMismatch"
  | "hostUnavailable"
  | "hostDraining"
  | "diskEvicting"
  | "restoring"
  | "restoreNoAllowedHost"
  | "diskUnavailable"
  | "hostDeleting"
  | "templateMissing"
  | "labels"
  | "nameTaken"
  | "nameInvalid"
  | "egress"
  | "hostNoEgress"
  | "egressGuardUnavailable"
  | "openEgressNotPermitted"
  | "invalid"
  | "forbidden"
  | "imageMissing"
  | "leaseExceedsPolicy"
  | "capacityReserved"
  | "templateUnavailable"
  | "queueFull"
  | "waitExceedsPolicy"
  | "generic";

/**
 * Map a refused sandbox mutation to its explanation. Every problem except
 * `generic` and `invalid` means the page's data is stale, so the caller
 * refetches after showing it.
 */
export function sandboxProblem(error: unknown): SandboxProblem {
  const code = domainCode(error);
  if (code === "sandbox.host_capacity" || code === "sandbox.pool_full") {
    const reason = domainField(error, "reason");
    switch (reason) {
      case "ram":
        return "capacityRam";
      case "vcpu":
        return "capacityVcpu";
      case "disk":
        return "capacityDisk";
      case "storage":
        return "capacityStorage";
      case "ceiling":
        return "capacityCeiling";
    }
  }
  if (code === "sandbox.pool_full" && domainField(error, "reason") === "reserved")
    return "capacityReserved";
  switch (domainCode(error)) {
    case "sandbox.template_unavailable":
      return "templateUnavailable";
    case "sandbox.capacity_queue_full":
      return "queueFull";
    case "capacity_wait_exceeds_policy":
      return "waitExceedsPolicy";
    case "sandbox.vm_size_invalid":
      return "sizeInvalid";
    case "sandbox.disk_below_image":
      return "diskBelowImage";
    case "sandbox.vm_size_unsupported":
      return "sizeUnsupported";
    case "sandbox.vm_size_mismatch":
      return "sizeMismatch";
    case "sandbox.template_image_missing":
      return "imageMissing";
    case "sandbox.not_found":
      return "notFound";
    case "sandbox.state_conflict":
    case "sandbox.invalid_transition":
      return "stateChanged";
    case "sandbox.idempotency_conflict":
      return "keyReused";
    case "sandbox.pool_policy_changed":
      return "poolPolicyChanged";
    case "lease_exceeds_policy":
      return "leaseExceedsPolicy";
    case "sandbox.share_quota":
      return "shareQuota";
    case "sandbox.member_quota":
      return "memberQuota";
    case "sandbox.pool_full":
      return "poolFull";
    case "sandbox.pool_unavailable":
      return "poolUnavailable";
    case "sandbox.pool_no_compatible_host":
      return "poolIncompatible";
    case "sandbox.pool_not_found":
      return "poolMissing";
    case "sandbox.host_unavailable":
    case "sandbox.host_reconnecting":
      return "hostUnavailable";
    case "sandbox.host_capacity":
      return "hostCapacity";
    case "sandbox.host_draining":
      return "hostDraining";
    case "sandbox.disk_evicting":
      return "diskEvicting";
    case "sandbox.restoring":
      return "restoring";
    case "restore_no_allowed_host":
      return "restoreNoAllowedHost";
    case "sandbox.disk_unavailable":
      return "diskUnavailable";
    case "sandbox.host_delete_conflict":
      return "hostDeleting";
    case "sandbox.host_not_found":
    case "sandbox.template_not_found":
      return "templateMissing";
    case "sandbox.metadata_invalid":
      return "labels";
    case "sandbox.name_taken":
      return "nameTaken";
    case "sandbox.name_invalid":
      return "nameInvalid";
    case "sandbox.egress_policy_invalid":
      return "egress";
    case "UNSUPPORTED_CAPABILITY":
      // Egress refusals carry a typed reason (default-open egress §1.3-1.5):
      // the node's guard is not running (retryable), or the node owner does
      // not allow open internet for other users' sandboxes. Without a reason
      // the host never advertised egress enforcement, so it refuses every
      // create and cold start (E-07). Other capabilities stay `invalid`.
      if (domainField(error, "capability") === "egress") {
        const reason = domainField(error, "reason");
        if (reason === "egress_guard_unavailable") return "egressGuardUnavailable";
        if (reason === "open_egress_not_permitted") return "openEgressNotPermitted";
        return "hostNoEgress";
      }
      break;
  }
  const shape = shapeOf(error);
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "CONFLICT" || shape.status === 409) return "stateChanged";
  if (shape.code === "BAD_REQUEST" || shape.status === 400) return "invalid";
  if (shape.code === "FORBIDDEN" || shape.status === 403) return "forbidden";
  return "generic";
}

/**
 * Create validation refusals that happen before dispatch. Use catalog codes,
 * not HTTP 400 alone: a host image/runtime refusal can also be a 400, and an
 * unfamiliar domain code must keep the existing clearing behavior.
 */
export function isCreateInputMistake(error: unknown): boolean {
  const domain = domainCode(error);
  if (domain !== null) {
    return (
      domain === "sandbox.vm_size_invalid" ||
      domain === "sandbox.disk_below_image" ||
      domain === "sandbox.metadata_invalid" ||
      domain === "sandbox.name_invalid" ||
      domain === "sandbox.name_taken" ||
      domain === "sandbox.egress_policy_invalid" ||
      domain === "UNSUPPORTED_CAPABILITY"
    );
  }
  const code = shapeOf(error).code;
  return (
    code === "BAD_REQUEST" || code === "PAYLOAD_TOO_LARGE" || code === "UNSUPPORTED_MEDIA_TYPE"
  );
}

/** A NOT_FOUND read (missing, or another owner's sandbox: indistinguishable by design). */
export function isNotFound(error: unknown): boolean {
  const shape = shapeOf(error);
  return shape.code === "NOT_FOUND" || shape.status === 404;
}

/** Byte sizes use the dashboard's one format (binary units, "1 GiB"). */
export { formatBytes } from "./format-bytes";

/**
 * File paths the server accepts for an upload or download: a browser copy of
 * `guestFilePathSchema` (packages/sandbox-contracts/src/guest-path.ts), which
 * mirrors the guest's own rules (E-28). The server checks again.
 */
export function isGuestPath(path: string): boolean {
  const parts = path.split("/");
  return (
    // Never trimmed: `/data/report ` is a different file (G4R1-1).
    path === path.trim() &&
    path.startsWith("/") &&
    new TextEncoder().encode(path).byteLength <= 4096 &&
    !parts.includes("..") &&
    !parts.includes(".") &&
    parts.some(Boolean) &&
    [...path].every((char) => {
      const code = char.codePointAt(0)!;
      return code >= 32 && code !== 127 && (code < 0xd800 || code > 0xdfff);
    })
  );
}

/**
 * The one place a sandbox's display title is chosen (list heading, detail H1,
 * operation links): its name. The id stays copyable under Advanced.
 */
export function sandboxTitle(sandbox: { name: string }): string {
  return sandbox.name;
}

const SANDBOX_STATUS_FILTERS = ["active", "deleted", "all"] as const;
export type SandboxStatusFilter = (typeof SANDBOX_STATUS_FILTERS)[number];
export type SandboxesSearch = { status?: Exclude<SandboxStatusFilter, "active"> };

/**
 * `?status=` on Sandboxes. Active (every sandbox that is not DELETED) is the
 * default and is never written to the URL; anything unknown reads as Active.
 */
export function parseSandboxesSearch(search: Record<string, unknown>): SandboxesSearch {
  return search.status === "deleted" || search.status === "all" ? { status: search.status } : {};
}
