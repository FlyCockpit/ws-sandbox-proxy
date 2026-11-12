import { createHash } from "node:crypto";
import type { Prisma } from "@wssp/db";
import {
  CanonicalJsonError,
  canonicalJsonBytes,
  type LoginDefinition,
} from "@wssp/login-definition";
import {
  CREDENTIAL_CHUNK_RAW_BYTES,
  CREDENTIAL_PROTOCOL_LIMITS,
  CREDENTIAL_SPEC_MAX_BYTES,
  type CredentialSpecV11,
  credentialSpecV11Schema,
} from "@wssp/sandbox-contracts";
import { credentialError } from "./errors";
import { loadVerifiedLogin } from "./verified-login";

/**
 * Operation credential specs: the non-secret,
 * canonical-JSON list of leases and residue rows a dispatch refers to by
 * `{digest, bytes}`. One encoded-byte cap (`specMaxBytes` in
 * credential-protocol-limits.json) governs admission, the
 * `credential_operation_spec` CHECK, host reassembly and both parsers. Nothing
 * is ever truncated: admission serializes the actual spec BEFORE any lease
 * claim, binding or residue write and refuses `credential.spec_too_large`.
 */

type Tx = Prisma.TransactionClient;
export type SpecLease = CredentialSpecV11["leases"][number];
type SpecResidue = CredentialSpecV11["residue"][number];

/** Per-definition worst-case contribution bounds (§3 spec contribution check, R3-5). */
export const SPEC_LEASE_ENTRY_MAX_BYTES = 106_496;
export const SPEC_RESIDUE_ENTRY_MAX_BYTES = 18_432;
/** Longest entity id the wire accepts; the contribution check measures with it. */
const MAX_ID = "x".repeat(64);
const MAX_DIGEST = "f".repeat(64);

export type SpecLeaseInput = {
  leaseId: string;
  bindingId?: string | null;
  credentialId: string;
  instanceId: string;
  definitionDigest: string;
  definition: LoginDefinition;
  delivery: "GUEST" | "PROXY";
  exclusive: boolean;
  copyBack: boolean;
  kind: "WORKLOAD" | "LOGIN";
  action: SpecLease["action"];
  checkpointIntervalMin?: number | null;
};

/** One lease entry, derived only from the verified definition and lease rows. */
export function specLeaseEntry(input: SpecLeaseInput): SpecLease {
  const files = input.definition.credentials.files;
  const env = input.definition.credentials.env ?? [];
  return {
    leaseId: input.leaseId,
    ...(input.bindingId ? { bindingId: input.bindingId } : {}),
    credentialId: input.credentialId,
    instanceId: input.instanceId,
    definitionDigest: input.definitionDigest,
    maxBytes: input.definition.credentials.maxBytes,
    delivery: input.delivery === "PROXY" ? "proxy" : "guest",
    exclusive: input.exclusive,
    copyBack: input.copyBack,
    rotates: input.definition.credentials.rotates,
    kind: input.kind === "LOGIN" ? "login" : "workload",
    action: input.action,
    files: {
      required: [...(files?.required ?? [])],
      optional: [...(files?.optional ?? [])],
      exclude: [...(files?.exclude ?? [])],
    },
    env: env.map((entry) => entry.name),
    proxy:
      input.delivery === "PROXY"
        ? env.flatMap((entry) =>
            entry.proxy
              ? [
                  {
                    name: entry.name,
                    upstream: entry.proxy.upstream,
                    header: entry.proxy.header,
                    format: entry.proxy.format,
                    baseUrlEnv: entry.proxy.baseUrlEnv,
                    ...(entry.proxy.placeholderEnv
                      ? { placeholderEnv: entry.proxy.placeholderEnv }
                      : {}),
                  },
                ]
              : [],
          )
        : [],
    ...(input.checkpointIntervalMin ? { checkpointIntervalMin: input.checkpointIntervalMin } : {}),
  };
}

/** Home-relative paths a binding of this definition may leave on a disk (residue). */
export function definitionResiduePaths(definition: LoginDefinition): string[] {
  const files = definition.credentials.files;
  return [...(files?.required ?? []), ...(files?.optional ?? [])];
}

/**
 * Whether a teardown or checkpoint of this definition's binding has anything
 * to capture: it declares a file path (required or optional). An env-only
 * login has none — its env value comes only from the vault, never back from
 * the guest. The node daemon decides the same from the spec
 * (`SpecFilesV11::includes_paths`), so the server never waits for a capture
 * the daemon will not produce.
 */
export function definitionCapturesFiles(definition: LoginDefinition): boolean {
  return definitionResiduePaths(definition).length > 0;
}

function canonical(value: unknown, maxBytes: number): Uint8Array {
  try {
    return canonicalJsonBytes(value, { maxBytes, maxDepth: 16 });
  } catch (error) {
    if (error instanceof CanonicalJsonError) throw credentialError("credential.spec_too_large");
    throw error;
  }
}

/**
 * The §3 spec contribution check, run at definition write: the definition's
 * worst-case lease entry (maximum-length ids, every string at its actual value
 * so JSON escaping is measured) and residue entry must fit their bounds, which
 * is what makes the one spec cap hold for any 8 leases + 16 residue rows.
 */
export function assertDefinitionSpecContribution(definition: LoginDefinition): void {
  const measure = (value: unknown, max: number) => {
    try {
      return canonicalJsonBytes(value, { maxBytes: max + 1, maxDepth: 16 }).byteLength;
    } catch (error) {
      if (error instanceof CanonicalJsonError) return max + 1;
      throw error;
    }
  };
  const proxied = (definition.credentials.env ?? []).some((entry) => entry.proxy);
  const lease = specLeaseEntry({
    leaseId: MAX_ID,
    bindingId: MAX_ID,
    credentialId: MAX_ID,
    instanceId: MAX_ID,
    definitionDigest: MAX_DIGEST,
    definition,
    delivery: proxied ? "PROXY" : "GUEST",
    exclusive: true,
    copyBack: !proxied,
    kind: "WORKLOAD",
    action: "recover",
    checkpointIntervalMin: 240,
  });
  const residue: SpecResidue = {
    residueId: MAX_ID,
    bindingId: MAX_ID,
    leaseId: MAX_ID,
    action: "recover",
    paths: definitionResiduePaths(definition),
  };
  if (
    measure(lease, SPEC_LEASE_ENTRY_MAX_BYTES) > SPEC_LEASE_ENTRY_MAX_BYTES ||
    measure(residue, SPEC_RESIDUE_ENTRY_MAX_BYTES) > SPEC_RESIDUE_ENTRY_MAX_BYTES
  )
    throw credentialError("definition.spec_too_large");
}

export type EncodedSpec = { bytes: Uint8Array; digest: Buffer; digestHex: string };

/**
 * Admission: validate and serialize the actual spec under the single cap.
 * Callers run this BEFORE any lease claim, binding or residue write, so a
 * refusal leaves nothing to clean up.
 */
export function encodeCredentialSpec(spec: CredentialSpecV11): EncodedSpec {
  const bytes = canonical(spec, CREDENTIAL_SPEC_MAX_BYTES);
  if (bytes.byteLength > CREDENTIAL_SPEC_MAX_BYTES)
    throw credentialError("credential.spec_too_large");
  if (!credentialSpecV11Schema.safeParse(spec).success)
    throw new Error("credential spec failed its own schema");
  const digest = createHash("sha256").update(bytes).digest();
  return { bytes, digest, digestHex: digest.toString("hex") };
}

/** A distinct maximum-length placeholder id (upper-bound measurements). */
function maxId(index: number): string {
  return MAX_ID.slice(0, 60) + String(index).padStart(4, "0");
}

/**
 * Admission preflight (§6.1, R3-5): the WORST-CASE spec a launch of these
 * logins could produce on this sandbox — every lease entry with
 * maximum-length ids, a binding id and the longer `recover` action, every
 * uncleared residue row of the sandbox as `recover` — must fit the one cap.
 * Runs BEFORE any lease claim, binding or residue write, so a refusal
 * (`credential.spec_too_large`) leaves nothing to clean up; the real spec
 * built after the claims is never larger.
 */
export async function preflightCredentialSpec(
  tx: Tx,
  input: { sandboxId: string | null; credentialIds: readonly string[] },
): Promise<void> {
  if (input.credentialIds.length === 0) return;
  const leases: SpecLease[] = [];
  for (const [index, credentialId] of [...input.credentialIds].sort().entries()) {
    const login = await loadVerifiedLogin(tx, credentialId);
    if (!login) throw credentialError("credential.definition_corrupt");
    leases.push(
      specLeaseEntry({
        leaseId: maxId(index),
        bindingId: maxId(100 + index),
        credentialId: maxId(200 + index),
        instanceId: maxId(300 + index),
        definitionDigest: login.definitionDigest,
        definition: login.definition,
        delivery: login.delivery,
        exclusive: true,
        copyBack: login.copyBack,
        kind: "WORKLOAD",
        action: "recover",
        checkpointIntervalMin: login.checkpointIntervalMin,
      }),
    );
  }
  const residue = input.sandboxId
    ? await tx.credentialResidue.findMany({
        where: { sandboxId: input.sandboxId, clearedAt: null },
        select: { paths: true },
        orderBy: { createdAt: "asc" },
        take: 16,
      })
    : [];
  const bound = {
    version: 1,
    sandboxId: MAX_ID.repeat(2),
    sandboxOwnerId: MAX_ID.repeat(2),
    hostOwnerId: MAX_ID.repeat(2),
    leases,
    residue: residue.map((row, index) => ({
      residueId: maxId(400 + index),
      bindingId: maxId(500 + index),
      leaseId: maxId(600 + index),
      action: "recover",
      paths: Array.isArray(row.paths) ? row.paths : [],
    })),
  };
  const bytes = canonical(bound, CREDENTIAL_SPEC_MAX_BYTES);
  if (bytes.byteLength > CREDENTIAL_SPEC_MAX_BYTES)
    throw credentialError("credential.spec_too_large");
}

/**
 * Stores the spec bytes with the operation (same transaction). Any byte string
 * up to the cap is stored as-is; over the cap is refused before the CHECK.
 */
export async function writeOperationSpec(
  tx: Tx,
  operationId: string,
  bytes: Uint8Array,
): Promise<{ digest: string; bytes: number }> {
  if (bytes.byteLength > CREDENTIAL_SPEC_MAX_BYTES)
    throw credentialError("credential.spec_too_large");
  const digest = createHash("sha256").update(bytes).digest();
  await tx.credentialOperationSpec.create({
    data: { operationId, digest: new Uint8Array(digest), bytes: new Uint8Array(bytes) },
    select: { operationId: true },
  });
  return { digest: digest.toString("hex"), bytes: bytes.byteLength };
}

const TERMINAL_OPERATION_STATES = new Set(["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"]);

/**
 * `credential.spec.request`: the stored spec as ≤ 32 KiB raw chunks, only
 * for a non-terminal operation dispatched to the requesting host whose stored
 * digest equals the requested one. Null means refuse (`spec_unavailable`).
 */
export async function readOperationSpecChunks(
  client: Pick<Tx, "credentialOperationSpec">,
  input: { hostId: string; operationId: string; digest: string },
): Promise<Buffer[] | null> {
  const row = await client.credentialOperationSpec.findUnique({
    where: { operationId: input.operationId },
    select: {
      digest: true,
      bytes: true,
      Operation: {
        select: {
          state: true,
          dispatchedHostId: true,
          Sandbox: { select: { sandboxHostId: true } },
        },
      },
    },
  });
  if (!row) return null;
  const op = row.Operation;
  const host = op.dispatchedHostId ?? op.Sandbox.sandboxHostId;
  if (host !== input.hostId || TERMINAL_OPERATION_STATES.has(op.state)) return null;
  if (Buffer.from(row.digest).toString("hex") !== input.digest) return null;
  const bytes = Buffer.from(row.bytes);
  const chunks: Buffer[] = [];
  for (let at = 0; at < bytes.byteLength; at += CREDENTIAL_CHUNK_RAW_BYTES)
    chunks.push(bytes.subarray(at, at + CREDENTIAL_CHUNK_RAW_BYTES));
  return chunks;
}

/**
 * The spec a create / cold reconnect dispatch carries (§6.1, §7.6): every
 * RESERVED lease is `inject`, every RECOVERING lease is `recover` (naming its
 * RECOVER binding); every uncleared residue row is `recover` only when a
 * RECOVERING lease's RECOVER binding supersedes exactly that row's binding,
 * otherwise `scrub`. Built from rows inside the caller's transaction.
 */
export async function buildSandboxCredentialSpec(
  tx: Tx,
  sandboxId: string,
): Promise<CredentialSpecV11> {
  const sandbox = await tx.sandbox.findUniqueOrThrow({
    where: { id: sandboxId },
    select: { userId: true, hostOwnerId: true },
  });
  // A LOGIN lease is never injected (§11: a login sandbox starts clean); it
  // becomes ACTIVE with its LOGIN binding when the sandbox is READY.
  const leases = await tx.credentialLease.findMany({
    where: { sandboxId, kind: "WORKLOAD", state: { in: ["RESERVED", "RECOVERING"] } },
    select: {
      id: true,
      credentialId: true,
      instanceId: true,
      exclusive: true,
      kind: true,
      state: true,
      currentBindingId: true,
    },
    orderBy: { credentialId: "asc" },
    take: 8,
  });
  const recovering = new Map<string, string>();
  const entries: SpecLease[] = [];
  for (const lease of leases) {
    const login = await loadVerifiedLogin(tx, lease.credentialId);
    if (!login) throw credentialError("credential.definition_corrupt");
    let bindingId: string | null = null;
    if (lease.state === "RECOVERING" && lease.currentBindingId) {
      const binding = await tx.credentialBinding.findUnique({
        where: { id: lease.currentBindingId },
        select: { id: true, recoveryOfBindingId: true },
      });
      bindingId = binding?.id ?? null;
      if (binding?.recoveryOfBindingId) recovering.set(binding.recoveryOfBindingId, lease.id);
    }
    entries.push(
      specLeaseEntry({
        leaseId: lease.id,
        bindingId,
        credentialId: lease.credentialId,
        instanceId: lease.instanceId,
        definitionDigest: login.definitionDigest,
        definition: login.definition,
        delivery: login.delivery,
        exclusive: lease.exclusive,
        copyBack: login.copyBack,
        kind: lease.kind,
        action: lease.state === "RECOVERING" ? "recover" : "inject",
        checkpointIntervalMin: login.checkpointIntervalMin,
      }),
    );
  }
  const residue = await tx.credentialResidue.findMany({
    where: { sandboxId, clearedAt: null },
    select: { id: true, bindingId: true, leaseId: true, paths: true },
    orderBy: { createdAt: "asc" },
    take: 16,
  });
  return {
    version: 1,
    sandboxId,
    sandboxOwnerId: sandbox.userId,
    hostOwnerId: sandbox.hostOwnerId ?? sandbox.userId,
    leases: entries,
    residue: residue.map((row) => {
      const recoverLease = recovering.get(row.bindingId);
      return {
        residueId: row.id,
        bindingId: row.bindingId,
        leaseId: recoverLease ?? row.leaseId,
        action: recoverLease ? ("recover" as const) : ("scrub" as const),
        paths: Array.isArray(row.paths)
          ? row.paths.filter((p): p is string => typeof p === "string")
          : [],
      };
    }),
  };
}

/**
 * safeguard 2: the sandbox once had a login delivered (any
 * delivery: GUEST files, GUEST env or PROXY), so its disk may hold login
 * values and an offloaded copy resumes only on its owner's own hosts
 * (`restoreHostEligibility`). Set in every login binding grant transaction;
 * never cleared (it survives the login-deletion cascade); never an offload
 * blocker. One idempotent statement.
 */
export async function markCredentialFilesEver(tx: Tx, sandboxId: string): Promise<void> {
  await tx.$executeRaw`UPDATE sandbox_instance SET "credentialFilesEver" = true
    WHERE id = ${sandboxId} AND NOT "credentialFilesEver"`;
}

/** Most login paths a template capture's scrub spec can carry (every residue entry full). */
const CREDENTIAL_SCRUB_PATHS_MAX =
  CREDENTIAL_PROTOCOL_LIMITS.specResiduesMax * CREDENTIAL_PROTOCOL_LIMITS.specPathsMax;

/**
 * Appends a new binding's declared paths to the sandbox's login path history
 * (`Sandbox.credentialPathHistory`, §7.6), in the grant's transaction. One
 * atomic statement: concurrent grants on the same sandbox never lose a path.
 */
export async function recordCredentialPathHistory(
  tx: Tx,
  sandboxId: string,
  paths: readonly string[],
): Promise<void> {
  if (paths.length === 0) return;
  await tx.$executeRaw`UPDATE sandbox_instance SET "credentialPathHistory" = ARRAY(
      SELECT DISTINCT p FROM unnest("credentialPathHistory" || ${[...paths]}::text[]) AS p
      ORDER BY p)
    WHERE id = ${sandboxId}`;
}

/**
 * Template capture (§6.1, §7.6): the spec a `sandbox.capture` carries so the
 * capture VM scrubs every login file the copied disk may hold. It lists NO
 * leases. Its residue entries carry the union of EVERY path any binding of
 * this sandbox ever declared: the sandbox's path history plus every residue
 * row, cleared or not (E1-B-01). A stop that reported a path scrubbed (and so
 * cleared its residue) is no proof for a capture: the report may have come
 * from a page cache a forced power-off then discarded. The union is chunked
 * into `specPathsMax`-sized entries under capture-only ids (the host reads
 * only their paths); the sandbox's own disk is untouched. Null when no login
 * file was ever installed in the sandbox.
 */
export async function buildCaptureScrubSpec(
  tx: Tx,
  sandboxId: string,
): Promise<CredentialSpecV11 | null> {
  const sandbox = await tx.sandbox.findUniqueOrThrow({
    where: { id: sandboxId },
    select: { userId: true, hostOwnerId: true, credentialPathHistory: true },
  });
  // Deduplicated in SQL and bounded by distinct paths, not by row count. A
  // malformed stored value is never filtered out: the capture is refused
  // instead of publishing a template that may hold the file it names (an
  // invalid path string fails the spec's own schema in encodeCredentialSpec).
  const rows = await tx.$queryRaw<{ path: unknown }[]>`SELECT DISTINCT e.value AS path
    FROM credential_residue r
    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(r.paths) = 'array'
      THEN r.paths ELSE jsonb_build_array(r.paths) END) AS e(value)
    WHERE r."sandboxId" = ${sandboxId}
    LIMIT ${CREDENTIAL_SCRUB_PATHS_MAX + 1}`;
  const union = new Set<string>(sandbox.credentialPathHistory);
  for (const row of rows) {
    if (typeof row.path !== "string")
      throw new Error("stored credential residue path is malformed");
    union.add(row.path);
  }
  if (union.size === 0) return null;
  if (union.size > CREDENTIAL_SCRUB_PATHS_MAX) throw credentialError("credential.spec_too_large");
  const paths = [...union].sort();
  const residue: SpecResidue[] = [];
  for (let i = 0; i < paths.length; i += CREDENTIAL_PROTOCOL_LIMITS.specPathsMax) {
    residue.push({
      residueId: `capture-scrub-${residue.length}`,
      bindingId: `capture-scrub-${residue.length}`,
      leaseId: "capture-scrub",
      action: "scrub",
      paths: paths.slice(i, i + CREDENTIAL_PROTOCOL_LIMITS.specPathsMax),
    });
  }
  return {
    version: 1,
    sandboxId,
    sandboxOwnerId: sandbox.userId,
    hostOwnerId: sandbox.hostOwnerId ?? sandbox.userId,
    leases: [],
    residue,
  };
}

async function specOwners(tx: Tx, sandboxId: string) {
  const sandbox = await tx.sandbox.findUniqueOrThrow({
    where: { id: sandboxId },
    select: { userId: true, hostOwnerId: true },
  });
  return { sandboxOwnerId: sandbox.userId, hostOwnerId: sandbox.hostOwnerId ?? sandbox.userId };
}

async function leaseEntry(
  tx: Tx,
  leaseId: string,
  action: SpecLease["action"],
  withBinding: boolean,
): Promise<SpecLease> {
  const lease = await tx.credentialLease.findUniqueOrThrow({
    where: { id: leaseId },
    select: {
      id: true,
      credentialId: true,
      instanceId: true,
      exclusive: true,
      kind: true,
      currentBindingId: true,
    },
  });
  const login = await loadVerifiedLogin(tx, lease.credentialId);
  if (!login) throw credentialError("credential.definition_corrupt");
  return specLeaseEntry({
    leaseId: lease.id,
    bindingId: withBinding ? lease.currentBindingId : null,
    credentialId: lease.credentialId,
    instanceId: lease.instanceId,
    definitionDigest: login.definitionDigest,
    definition: login.definition,
    delivery: login.delivery,
    exclusive: lease.exclusive,
    copyBack: login.copyBack,
    kind: lease.kind,
    action,
    checkpointIntervalMin: login.checkpointIntervalMin,
  });
}

/**
 * Live attach (§10.4): the attach's RESERVED lease as `inject`, plus every
 * uncleared residue row the grant fence would refuse on (§7.4.1 step 4) as
 * `scrub` — residue of a closed binding or of a lease that is terminal or not
 * on this sandbox. Residue of an open binding of a live lease of this sandbox
 * is a sibling's installed files and is never listed.
 */
export async function buildAttachSpec(
  tx: Tx,
  input: { sandboxId: string; leaseId: string },
): Promise<CredentialSpecV11> {
  const owners = await specOwners(tx, input.sandboxId);
  const entry = await leaseEntry(tx, input.leaseId, "inject", false);
  const residue = await tx.$queryRaw<
    { id: string; bindingId: string; leaseId: string; paths: unknown }[]
  >`SELECT r.id, r."bindingId", r."leaseId", r.paths
    FROM credential_residue r
    LEFT JOIN credential_binding b ON b.id = r."bindingId"
    LEFT JOIN credential_lease l ON l.id = r."leaseId"
    WHERE r."sandboxId" = ${input.sandboxId} AND r."clearedAt" IS NULL
      AND NOT (b."closedAt" IS NULL AND l."sandboxId" = r."sandboxId"
        AND l.state::text NOT IN ('RELEASED', 'FORCE_RELEASED', 'ABANDONED'))
    ORDER BY r."createdAt", r.id
    LIMIT 16`;
  return {
    version: 1,
    sandboxId: input.sandboxId,
    ...owners,
    leases: [entry],
    residue: residue.map((row) => ({
      residueId: row.id,
      bindingId: row.bindingId,
      leaseId: row.leaseId,
      action: "scrub" as const,
      paths: Array.isArray(row.paths)
        ? row.paths.filter((p): p is string => typeof p === "string")
        : [],
    })),
  };
}

/**
 * Free (§10.4): exactly the freed lease, naming its open binding. `none` =
 * capture per policy, then revoke, close terminals and scrub; `scrub_only`
 * (`credentialCapture: "skip"`) = no capture, revoke, close and scrub.
 */
export async function buildFreeSpec(
  tx: Tx,
  input: { sandboxId: string; leaseId: string; skip: boolean },
): Promise<CredentialSpecV11> {
  const owners = await specOwners(tx, input.sandboxId);
  const entry = await leaseEntry(tx, input.leaseId, input.skip ? "scrub_only" : "none", true);
  return { version: 1, sandboxId: input.sandboxId, ...owners, leases: [entry], residue: [] };
}

/** Whether a stored free spec asked for `skip` (its lease entry is `scrub_only`). */
export async function freeSpecSkips(tx: Tx, operationId: string): Promise<boolean> {
  const row = await tx.credentialOperationSpec.findUnique({
    where: { operationId },
    select: { bytes: true },
  });
  if (!row) return false;
  try {
    const parsed = credentialSpecV11Schema.safeParse(
      JSON.parse(Buffer.from(row.bytes).toString("utf8")),
    );
    return parsed.success && parsed.data.leases.some((lease) => lease.action === "scrub_only");
  } catch {
    return false;
  }
}
