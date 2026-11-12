import { ORPCError } from "@orpc/server";
import type { Prisma, SandboxPurpose } from "@wssp/db";
import type { ServiceAction } from "../lib/service-scopes";
import { BUILD_ACTIONS, VERIFY_ACTIONS } from "../template-builds/build-authority";
import type { Principal } from "./contracts";
import { buildIdOf, isBrowserSession, managedFlowOf } from "./principal-kinds";

/**
 * MS0: managed sandboxes. A sandbox's `purpose` is set at insert and never changes. WORKLOAD
 * sandboxes behave exactly as before. Managed purposes (CREDENTIAL_LOGIN,
 * TEMPLATE_BUILD) are created only by wssp itself, are hidden from every
 * sandbox list and emit no webhooks (the hardening triggers check the same
 * purpose), and admit an action only when their policy predicate does.
 *
 * One policy table, one list filter, one guard. The guard runs inside
 * `authorizeServiceAction` for every sandbox- or operation-targeted service
 * action (operation targets resolve to their sandbox), and at terminal ticket
 * mint. Feature code widens a purpose's predicate here, never at a call site.
 *
 * Guest root (DG-6): only a WORKLOAD sandbox may carry `guestSudo`. Build and
 * CLI-login creates pass `guestSudo: false`, `createSandbox` refuses an
 * explicit true for them, the `sandbox_instance_guest_sudo` CHECK requires
 * WORKLOAD, and the daemon refuses `guest_sudo` with a build binding. Their
 * `guestRoot` still follows the revision's root taint, so a managed sandbox
 * from a tainted base retires UNKNOWN commands on host proof only.
 */

/** Guarded actions: every service action plus the non-service entry points. */
export type ManagedSandboxAction =
  | ServiceAction
  | "terminal.open"
  | "credentials.attach"
  | "credentials.free"
  | "sharing"
  | "env.private";

/** The immutable facts a purpose predicate may read (set at insert). */
type ManagedSandboxFacts = {
  purpose: SandboxPurpose;
  buildId: string | null;
  verifyBuildId: string | null;
};

type PurposePolicy = {
  /** Shown in sandbox lists (dashboard, `/v1`). */
  listed: boolean;
  /** Emits webhook events (mirrored by the webhook triggers in the committed 0_init migration). */
  webhooks: boolean;
  /** Its stopped disk may be offloaded, evicted and restored: a system action, so it is a policy fact
   * here and never a call-site check. */
  diskOffload: boolean;
  allow(principal: Principal, action: ManagedSandboxAction, sandbox: ManagedSandboxFacts): boolean;
};

/**
 * The login flow's own lifecycle actions (§11): its finish (`credential.free`
 * capture), the optional `verifyCommand`, and the destroy after save or
 * cancel. Only the flow principal (`flow: "credentialLogin"`, built by
 * credentials/login-sessions.ts) carries them; a plain session never does.
 */
const LOGIN_FLOW_ACTIONS: ReadonlySet<ManagedSandboxAction> = new Set([
  "sandboxCredentials.free",
  "commands.run",
  "sandboxes.kill",
]);

/** Owner metadata reads allowed on every managed sandbox. */
const METADATA_READS: ReadonlySet<ManagedSandboxAction> = new Set([
  "sandboxes.get",
  "operations.get",
]);

/** The login page reaches its sandbox only through the browser session. */
const LOGIN_SESSION_ACTIONS: ReadonlySet<ManagedSandboxAction> = new Set([
  ...METADATA_READS,
  "terminal.open",
]);

export const MANAGED_PURPOSE_POLICY: Readonly<Record<SandboxPurpose, PurposePolicy>> = {
  WORKLOAD: { listed: true, webhooks: true, diskOffload: true, allow: () => true },
  // CLI logins (§11): no /v1 commands, files or terminal, no capture, attach,
  // sharing or private env. The session login-page terminal is allowed; the
  // login flow's own principal also finishes, verifies and destroys it.
  CREDENTIAL_LOGIN: {
    listed: false,
    webhooks: false,
    diskOffload: false,
    allow: (principal, action) =>
      isBrowserSession(principal) &&
      (LOGIN_SESSION_ACTIONS.has(action) ||
        (managedFlowOf(principal) === "credentialLogin" && LOGIN_FLOW_ACTIONS.has(action))),
  },
  // Template builds (§3.1): only the build principal whose buildId matches
  // the VM's acts on it, within the build action classes (authorizeAction
  // then applies the class rules); owners read its metadata. Every session
  // or SDK-key action beyond that is `sandbox.managed`.
  TEMPLATE_BUILD: {
    listed: false,
    webhooks: false,
    diskOffload: false,
    allow: (principal, action, sandbox) => {
      if (METADATA_READS.has(action)) return true;
      const buildId = buildIdOf(principal);
      return (
        buildId !== null &&
        sandbox.buildId !== null &&
        buildId === sandbox.buildId &&
        (BUILD_ACTIONS as ReadonlySet<string>).has(action)
      );
    },
  },
  // Community verify VMs (community-base I4b, review4 U3): only the build
  // principal of the build it verifies, within the verify set (its create,
  // the smoke command, the key-free cleanup kill and reads). Files, capture,
  // lease changes, reconnect, signals and terminals are refused for everyone;
  // owners read metadata only.
  TEMPLATE_VERIFY: {
    listed: false,
    webhooks: false,
    diskOffload: false,
    allow: (principal, action, sandbox) => {
      if (METADATA_READS.has(action)) return true;
      const buildId = buildIdOf(principal);
      return (
        buildId !== null &&
        sandbox.verifyBuildId !== null &&
        buildId === sandbox.verifyBuildId &&
        (VERIFY_ACTIONS as ReadonlySet<string>).has(action)
      );
    },
  },
};

const MANAGED_PURPOSES: ReadonlySet<string> = new Set(
  (Object.keys(MANAGED_PURPOSE_POLICY) as SandboxPurpose[]).filter((p) => p !== "WORKLOAD"),
);

/** Purposes that sandbox lists include. Compose into every list WHERE before cursor/take. */
export const LISTED_SANDBOX_PURPOSES = (
  Object.keys(MANAGED_PURPOSE_POLICY) as SandboxPurpose[]
).filter((purpose) => MANAGED_PURPOSE_POLICY[purpose]?.listed);

/** Purposes whose stopped disks may be offloaded, evicted or restored (R15.1).
 * Compose into every offload, evict and restore candidate filter. */
export const OFFLOADABLE_SANDBOX_PURPOSES = (
  Object.keys(MANAGED_PURPOSE_POLICY) as SandboxPurpose[]
).filter((purpose) => MANAGED_PURPOSE_POLICY[purpose]?.diskOffload);

export function managedSandboxListFilter(): Prisma.SandboxWhereInput {
  return { purpose: { in: LISTED_SANDBOX_PURPOSES } };
}

function managedSandboxRefused(purpose: SandboxPurpose): ORPCError<"CONFLICT", unknown> {
  return new ORPCError("CONFLICT", {
    message: "This sandbox is managed by wssp and cannot be used for this action.",
    data: { code: "sandbox.managed", purpose: purpose.toLowerCase() },
  });
}

/** Throws `sandbox.managed` unless the sandbox's purpose policy admits the action. */
export function assertManagedSandboxAccess(
  principal: Principal,
  action: ManagedSandboxAction,
  sandbox: { purpose: SandboxPurpose; buildId?: string | null; verifyBuildId?: string | null },
): void {
  const policy = MANAGED_PURPOSE_POLICY[sandbox.purpose];
  if (
    !policy?.allow(principal, action, {
      purpose: sandbox.purpose,
      buildId: sandbox.buildId ?? null,
      verifyBuildId: sandbox.verifyBuildId ?? null,
    })
  )
    throw managedSandboxRefused(sandbox.purpose);
}

/**
 * Resolve the target's purpose (a sandbox, or an operation's sandbox) for the
 * owner and apply the guard. The SQL returns a row only for a MANAGED sandbox
 * of this owner, so the WORKLOAD path costs one indexed probe and nothing else.
 * Unknown or foreign targets pass through: the caller's own owner-scoped
 * lookup reports NOT_FOUND, so this adds no oracle.
 */
export async function guardManagedSandboxTarget(
  client: Pick<Prisma.TransactionClient, "$queryRaw">,
  principal: Principal,
  action: ManagedSandboxAction,
  target: { sandboxId?: string | null; operationId?: string },
): Promise<void> {
  if (!target.sandboxId && !target.operationId) return;
  type Row = { purpose: string; buildId: string | null; verifyBuildId: string | null };
  const rows = target.sandboxId
    ? await client.$queryRaw<Row[]>`SELECT s.purpose::text AS purpose, s."buildId" AS "buildId",
        s."verifyBuildId" AS "verifyBuildId"
        FROM sandbox_instance s WHERE s.id = ${target.sandboxId} AND s."userId" = ${principal.ownerId}
        AND s.purpose::text <> 'WORKLOAD'`
    : await client.$queryRaw<Row[]>`SELECT s.purpose::text AS purpose, s."buildId" AS "buildId",
        s."verifyBuildId" AS "verifyBuildId"
        FROM sandbox_mutation_operation o JOIN sandbox_instance s ON s.id = o."sandboxId" AND s."userId" = o."userId"
        WHERE o.id = ${target.operationId} AND o."userId" = ${principal.ownerId}
        AND s.purpose::text <> 'WORKLOAD'`;
  const row = Array.isArray(rows) ? rows[0] : undefined;
  if (row?.purpose && MANAGED_PURPOSES.has(row.purpose))
    assertManagedSandboxAccess(principal, action, {
      purpose: row.purpose as SandboxPurpose,
      buildId: row.buildId ?? null,
      verifyBuildId: row.verifyBuildId ?? null,
    });
}
