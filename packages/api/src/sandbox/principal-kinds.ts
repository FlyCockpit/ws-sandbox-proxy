/**
 * The only place (with `stored-principal.ts`) that branches on or constructs a
 * `Principal` / `AuthorizingPrincipal` kind. Every helper is a `switch` ending in
 * `assertNever`, so adding a kind is a compile error here and nowhere else; no
 * caller carries an implicit else-branch over the open union.
 * `principal-kinds.lint.test.ts` keeps the other encodings out of the codebase.
 */
import type { SdkKeyResourceMode } from "@wssp/db";
import { SERVICE_SCOPES, type ServiceScope } from "../lib/service-scopes";
import {
  type AuthorizingPrincipal,
  KEY_FREE_CLEANUP_KINDS,
  type Principal,
  type SessionPrincipal,
} from "./contracts";

/** Exhaustiveness guard. `error` keeps a caller's runtime refusal unchanged. */
export function assertNever(value: never, error?: Error): never {
  throw (
    error ?? new Error(`Unhandled principal kind: ${String((value as { kind?: unknown })?.kind)}`)
  );
}

/** Who placement and list predicates are evaluated for. A session sees every
 * owned/usable resource; an SDK key sees its own allowlists (the live principal
 * object, so a revalidation that refreshes the key is observed). */
export type PlacementViewer = {
  readonly ownerId: string;
  readonly resourceMode: SdkKeyResourceMode;
  readonly ownSandboxesOnly: boolean;
  readonly allowedHostIds: "allOwned" | ReadonlySet<string>;
  readonly allowedPoolIds: "allUsable" | ReadonlySet<string>;
  readonly allowedRevisionIds: "allOwned" | ReadonlySet<string>;
};

/** `principal`: the recorded session/key rules; `system`: the closed-payload
 * keyless rules; `build`: the build step rules. */
export type DispatchClass = "principal" | "system" | "build";

/** Who a per-owner budget is charged to; null is exempt. */
export type BudgetSubject = { readonly ownerId: string };

const ALL_SCOPES: ReadonlySet<ServiceScope> = new Set(SERVICE_SCOPES);
/** A build's own scope grant: read-class scopes only. Its steps are authorized
 * by the build action classes (`templates:build`), never by user write scopes. */
const BUILD_SCOPES: ReadonlySet<ServiceScope> = new Set(
  SERVICE_SCOPES.filter((scope) => scope.endsWith(":read")),
);

function sessionViewer(ownerId: string): PlacementViewer {
  return {
    ownerId,
    resourceMode: "ALL_OWNED",
    ownSandboxesOnly: false,
    allowedHostIds: "allOwned",
    allowedPoolIds: "allUsable",
    allowedRevisionIds: "allOwned",
  };
}

/** A keyed build whose key no longer revalidates sees nothing (never the
 * session view: that would widen a revoked ALLOWLIST key to the whole owner). */
function closedViewer(ownerId: string): PlacementViewer {
  return {
    ownerId,
    resourceMode: "ALLOWLIST",
    ownSandboxesOnly: true,
    allowedHostIds: new Set(),
    allowedPoolIds: new Set(),
    allowedRevisionIds: new Set(),
  };
}

/** The immutable accept attribution recorded with new work. */
export function attributionOf(p: Principal): AuthorizingPrincipal {
  switch (p.kind) {
    case "session":
      return { kind: "session" };
    case "sdkKey":
      return { kind: "sdkKey", keyId: p.keyId };
    case "build":
      return { kind: "build", buildId: p.buildId, keyId: p.keyId };
    default:
      return assertNever(p);
  }
}

/** The keyless attribution of server-initiated work (lease-policy pull-in). */
export function systemAttribution(): AuthorizingPrincipal {
  return { kind: "system" };
}

/** The SDK key stored with (or fencing) work: `authorizingKeyId`, transfer
 * `keyId`, credential tickets and K locks. Absent attribution records none. */
export function recordedKeyIdOf(
  p: Principal | AuthorizingPrincipal | null | undefined,
): string | null {
  if (p == null) return null;
  switch (p.kind) {
    case "sdkKey":
      return p.keyId;
    // r4 (N16): keyed build work records the REAL accepting key, so K locks,
    // creation-key and dispatch key comparisons need no build branch.
    case "build":
      return p.keyId;
    case "session":
    case "system":
      return null;
    default:
      return assertNever(p);
  }
}

export function viewerOf(p: Principal): PlacementViewer {
  switch (p.kind) {
    case "session":
      return sessionViewer(p.ownerId);
    case "sdkKey":
      return p;
    // A keyed build places under its key's revalidated allowlists (r2 N1);
    // a session or system build sees what its owner's session sees.
    case "build":
      if (p.keyId === null) return sessionViewer(p.ownerId);
      return p.key && p.key.keyId === p.keyId ? p.key : closedViewer(p.ownerId);
    default:
      return assertNever(p);
  }
}

/** The scopes a principal holds: a browser session holds every scope. */
export function grantOf(p: Principal): ReadonlySet<ServiceScope> {
  switch (p.kind) {
    case "session":
      return ALL_SCOPES;
    case "sdkKey":
      return p.scopes;
    case "build":
      return BUILD_SCOPES;
    default:
      return assertNever(p);
  }
}

/** Browser-only surfaces (credential management, live-session rechecks). */
export function isBrowserSession(p: Principal): boolean {
  switch (p.kind) {
    case "session":
      return true;
    case "sdkKey":
    case "build":
      return false;
    default:
      return assertNever(p);
  }
}

/** The wssp-managed flow a session principal acts for (CLI logins, §11), or
 * null. Only wssp's own flows set it; no key or build principal carries one. */
export function managedFlowOf(p: Principal): "credentialLogin" | null {
  switch (p.kind) {
    case "session":
      return p.flow ?? null;
    case "sdkKey":
    case "build":
      return null;
    default:
      return assertNever(p);
  }
}

/** The principal of wssp's own CLI-login flow for one owner (§11): a browser
 * session marked with its managed flow. Built only by wssp, never from a request. */
export function credentialLoginFlowPrincipal(ownerId: string): SessionPrincipal {
  return { kind: "session", ownerId, flow: "credentialLogin" };
}

/** Which CLI logins a principal sees: every login of the owner, only the
 * logins allowlisted for one SDK key, or none (a build never touches logins). */
export function credentialVisibilityOf(
  p: Principal,
): "allOwned" | "none" | { readonly allowlistKeyId: string } {
  switch (p.kind) {
    case "session":
      return "allOwned";
    case "sdkKey":
      return p.resourceMode === "ALL_OWNED" ? "allOwned" : { allowlistKeyId: p.keyId };
    case "build":
      return "none";
    default:
      return assertNever(p);
  }
}

/** A clock deadline on the credential itself (no authority revision moves at it). */
export function credentialExpiryOf(p: Principal): Date | null {
  switch (p.kind) {
    case "session":
      return null;
    case "sdkKey":
      return p.expiresAt;
    // A keyed build lives no longer than its key; an invalid key is expired.
    case "build":
      if (p.keyId === null) return null;
      return p.key ? p.key.expiresAt : new Date(0);
    default:
      return assertNever(p);
  }
}

/** Relay controls (stdin, cancel) are never system work, and builds use no
 * relay control at all: they end a step by killing the VM (r2 N2). */
export function controlAllowed(p: AuthorizingPrincipal): boolean {
  switch (p.kind) {
    case "session":
    case "sdkKey":
      return true;
    case "system":
    case "build":
      return false;
    default:
      return assertNever(p);
  }
}

/** Which dispatch rules apply: `system` work must pass the closed-payload
 * check. A build's key-free cleanup (stop, kill) is dispatched exactly like a
 * system kill, closed payload included (r3 N23); its other work is `build`. */
export function dispatchClassOf(p: AuthorizingPrincipal, kind: string): DispatchClass {
  switch (p.kind) {
    case "session":
    case "sdkKey":
      return "principal";
    case "system":
      return "system";
    case "build":
      return KEY_FREE_CLEANUP_KINDS.has(kind) ? "system" : "build";
    default:
      return assertNever(p);
  }
}

/** The per-owner budget subject; a build is exempt (it is paced per build by
 * the orchestrator and charged in build minutes). Budget helpers themselves
 * stay principal-agnostic: callers skip them on a null subject. */
export function budgetSubjectOf(p: Principal): BudgetSubject | null {
  switch (p.kind) {
    case "session":
    case "sdkKey":
      return { ownerId: p.ownerId };
    case "build":
      return null;
    default:
      return assertNever(p);
  }
}

/** The template build a principal or attribution acts for, or null. */
export function buildIdOf(p: Principal | AuthorizingPrincipal): string | null {
  switch (p.kind) {
    case "build":
      return p.buildId;
    case "session":
    case "sdkKey":
    case "system":
      return null;
    default:
      return assertNever(p);
  }
}
