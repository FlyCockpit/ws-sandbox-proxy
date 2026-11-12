import { z } from "zod";
import limits from "../../config/src/credential-protocol-limits.json";

/**
 * Relay 1.0 additive CLI-login credential frames (). Mirrors
 * `crates/sandbox-protocol/src/credentials.rs`; the shared fixture is
 * `crates/sandbox-protocol/fixtures/control_credentials.json` and the bounds
 * come from `packages/config/src/credential-protocol-limits.json`.
 */
export const CREDENTIAL_PROTOCOL_LIMITS = limits;
export const CREDENTIAL_SPEC_MAX_BYTES = limits.specMaxBytes;
export const CREDENTIAL_CHUNK_RAW_BYTES = limits.chunkRawBytes;
const CHUNK_TEXT_MAX = Math.ceil((limits.chunkRawBytes * 4) / 3);
const BUNDLE_MIN_BYTES = 41;

const idSchema = z.string().regex(new RegExp(`^[A-Za-z0-9_-]{1,${limits.idMaxBytes}}$`));
/** Sandbox ids (`valid_inventory_sandbox_id`). */
const sandboxIdSchema = z.string().regex(/^[A-Za-z0-9_-]{1,128}$/);
/** Operation and owner ids (`valid_terminal_id`). */
const relayIdSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/);
const sha256HexSchema = z.string().regex(/^[0-9a-f]{64}$/);
const kidSchema = z.string().regex(/^[0-9a-f]{16}$/);
const epochSchema = z.number().int().min(1).max(limits.returnKeyEpochMax);
const codeSchema = z.string().regex(/^[a-z_.]{1,64}$/);
const countSchema = (max: number) => z.number().int().min(0).max(max);
const unique = (values: readonly string[]) => new Set(values).size === values.length;

const B64URL = /^[A-Za-z0-9_-]*$/;
const B64_VALUE = (c: string) =>
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".indexOf(c);

/** Decoded length of canonical unpadded base64url, or null. */
export function chunkDataLength(text: string): number | null {
  const rem = text.length % 4;
  if (rem === 1 || !B64URL.test(text)) return null;
  const len = Math.floor(text.length / 4) * 3 + Math.max(0, rem - 1);
  if (rem === 0) return len;
  // Non-canonical trailing bits are refused, like the Rust decoder.
  const last = B64_VALUE(text[text.length - 1] ?? "A");
  const mask = rem === 2 ? 0x0f : 0x03;
  return (last & mask) === 0 ? len : null;
}

export const chunkDataSchema = z
  .string()
  .min(1)
  .max(CHUNK_TEXT_MAX)
  .refine((text) => {
    const len = chunkDataLength(text);
    return len !== null && len >= 1 && len <= limits.chunkRawBytes;
  });

/** Home-relative credential path (definition §3). */
export function validCredentialPath(path: string): boolean {
  if (path.length === 0 || new TextEncoder().encode(path).byteLength > 255) return false;
  if (path.startsWith("/")) return false;
  for (let i = 0; i < path.length; i++) {
    const c = path.charCodeAt(i);
    if (c < 0x20 || c === 0x7f || c === 0x5c || c === 0x3a) return false;
  }
  const segments = path.split("/");
  if (segments.some((s) => s === "" || s === "." || s === "..")) return false;
  return !(segments[0] ?? "").startsWith(".wssp");
}
const credentialPathSchema = z.string().refine(validCredentialPath);
const envNameSchema = z.string().regex(/^[A-Za-z_][A-Za-z0-9_]{0,127}$/);

function validOrigin(value: string): boolean {
  if (value.length > 256) return false;
  let rest: string;
  if (value.startsWith("https://")) rest = value.slice(8);
  else if (value.startsWith("http://")) {
    rest = value.slice(7);
    const host = rest.split(":")[0];
    if (host !== "localhost" && host !== "127.0.0.1" && host !== "[::1]") return false;
  } else return false;
  return rest.length > 0 && /^[A-Za-z0-9.\-:[\]]+$/.test(rest);
}

// --- capability and dispatch ----------------------------------------------------

export const credentialCapabilitiesV11Schema = z.strictObject({
  files: z.boolean(),
  env: z.boolean(),
  proxy: z.boolean(),
  sealedReturn: z.boolean(),
  checkpoint: z.boolean(),
  specTransfer: z.boolean(),
  maxBundleBytes: z.number().int().min(BUNDLE_MIN_BYTES).max(limits.bundleMaxBytes),
  returnKeyEpoch: z.number().int().min(0).max(limits.returnKeyEpochMax),
});
export type CredentialCapabilitiesV11 = z.infer<typeof credentialCapabilitiesV11Schema>;

export const credentialSpecRefV11Schema = z.strictObject({
  digest: sha256HexSchema,
  bytes: z.number().int().min(2).max(limits.specMaxBytes),
});
export type CredentialSpecRefV11 = z.infer<typeof credentialSpecRefV11Schema>;
export const CREDENTIAL_SPEC_DISPATCH_KINDS = new Set([
  "sandbox.create",
  "sandbox.reconnect",
  "credential.attach",
  "credential.free",
  "sandbox.stop",
  "sandbox.kill",
  "sandbox.capture",
]);
export const CREDENTIAL_CAPTURE_DISPATCH_KINDS = new Set(["sandbox.stop", "sandbox.kill"]);
/**
 * `credentialTeardown` on a stop/kill dispatch (same kinds as
 * `credentialCapture`): `"system"` for the expiry, access and readiness
 * writers, which never fail on a capture failure; absent is a user stop/kill.
 */
export const credentialTeardownOriginSchema = z.enum(["system"]);

// --- spec content (§6.1) --------------------------------------------------------

const specFilesSchema = z
  .strictObject({
    required: z.array(credentialPathSchema),
    optional: z.array(credentialPathSchema),
    exclude: z.array(credentialPathSchema),
  })
  .refine((f) => {
    const all = [...f.required, ...f.optional, ...f.exclude];
    return all.length <= limits.specPathsMax && unique(all);
  });

const specProxySchema = z.strictObject({
  name: envNameSchema,
  upstream: z.string().max(512).startsWith("https://"),
  header: z.string().regex(/^[A-Za-z0-9!#$%&'*+\-.^_`|~]{1,64}$/),
  format: z
    .string()
    .max(256)
    .refine((f) => f.split("{value}").length === 2),
  baseUrlEnv: envNameSchema,
  placeholderEnv: envNameSchema.optional(),
});

const specLeaseSchema = z
  .strictObject({
    leaseId: idSchema,
    bindingId: idSchema.optional(),
    credentialId: idSchema,
    instanceId: idSchema,
    definitionDigest: sha256HexSchema,
    maxBytes: z.number().int().min(1).max(4_194_304),
    delivery: z.enum(["guest", "proxy"]),
    exclusive: z.boolean(),
    copyBack: z.boolean(),
    rotates: z.enum(["yes", "no", "unknown"]),
    kind: z.enum(["workload", "login"]),
    action: z.enum(["inject", "recover", "scrub_only", "none"]),
    files: specFilesSchema,
    env: z.array(envNameSchema).max(limits.specEnvMax).refine(unique),
    proxy: z.array(specProxySchema).max(limits.specEnvMax),
    checkpointIntervalMin: z.number().int().min(5).max(240).optional(),
  })
  .refine((l) => {
    const fileCount = l.files.required.length + l.files.optional.length + l.files.exclude.length;
    const deliveryOk =
      l.delivery === "proxy"
        ? fileCount === 0 &&
          !l.copyBack &&
          l.proxy.length === l.env.length &&
          l.proxy.every((p) => l.env.includes(p.name))
        : l.proxy.length === 0;
    return (
      deliveryOk &&
      (l.kind === "workload" || l.delivery === "guest") &&
      (!l.copyBack || l.exclusive) &&
      (l.action !== "recover" || l.bindingId !== undefined)
    );
  });

const specResidueSchema = z.strictObject({
  residueId: idSchema,
  bindingId: idSchema,
  leaseId: idSchema,
  action: z.enum(["recover", "scrub"]),
  paths: z.array(credentialPathSchema).min(1).max(limits.specPathsMax).refine(unique),
});

export const credentialSpecV11Schema = z
  .strictObject({
    version: z.literal(1),
    sandboxId: sandboxIdSchema,
    sandboxOwnerId: relayIdSchema,
    hostOwnerId: relayIdSchema,
    leases: z.array(specLeaseSchema).max(limits.specLeasesMax),
    residue: z.array(specResidueSchema).max(limits.specResiduesMax),
  })
  .refine(
    (s) =>
      unique(s.leases.map((l) => l.leaseId)) &&
      unique(s.leases.map((l) => l.credentialId)) &&
      unique(s.residue.map((r) => r.residueId)) &&
      unique(s.residue.map((r) => r.bindingId)) &&
      s.residue.every(
        (r) =>
          r.action === "scrub" ||
          s.leases.some((l) => l.leaseId === r.leaseId && l.action === "recover"),
      ),
  );
export type CredentialSpecV11 = z.infer<typeof credentialSpecV11Schema>;

/** Parse spec bytes under the single cap (never truncated). */
export function parseCredentialSpec(bytes: Uint8Array): CredentialSpecV11 {
  if (bytes.byteLength > limits.specMaxBytes) throw new Error("credential spec exceeds the cap");
  return credentialSpecV11Schema.parse(
    JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
  );
}

// --- daemon → server -------------------------------------------------------------

const captureKindSchema = z.enum([
  "stop",
  "kill",
  "free",
  "expiry",
  "checkpoint",
  "recovery",
  "login",
]);
export type CredentialCaptureKind = z.infer<typeof captureKindSchema>;

const censusEntrySchema = z.strictObject({
  leaseId: idSchema,
  bindingId: idSchema,
  sandboxId: sandboxIdSchema,
  state: z.enum(["installing", "active", "teardown", "stopped"]),
  teardownAttemptId: idSchema.optional(),
  scrubbedVerified: z.boolean(),
  pending: z
    .array(z.strictObject({ captureId: idSchema, kidR: kidSchema, kind: captureKindSchema }))
    .max(limits.censusPendingMax),
});

const captureIdsSchema = z.array(idSchema).min(1).max(limits.quarantineDiscardMax).refine(unique);

export const daemonCredentialMessageSchemas = [
  z.strictObject({
    type: z.literal("credential.spec.request"),
    operationId: relayIdSchema,
    digest: sha256HexSchema,
  }),
  // Two variants (P3-4/R3-4): install carries operationId and no bindingId;
  // restore_env/proxy carry the open bindingId and no operationId.
  z
    .strictObject({
      type: z.literal("credential.bundle.request"),
      requestId: idSchema,
      sandboxId: sandboxIdSchema,
      leaseId: idSchema,
      operationId: relayIdSchema.optional(),
      bindingId: idSchema.optional(),
      reason: z.enum(["install", "restore_env", "proxy"]),
    })
    .refine((r) =>
      r.reason === "install"
        ? r.operationId !== undefined && r.bindingId === undefined
        : r.bindingId !== undefined && r.operationId === undefined,
    ),
  z
    .strictObject({
      type: z.literal("credential.capture.begin"),
      captureId: idSchema,
      leaseId: idSchema,
      bindingId: idSchema,
      kidR: kidSchema,
      kind: captureKindSchema,
      envelopeDigest: sha256HexSchema,
      envelopeLen: z.number().int().min(70).max(limits.envelopeMaxBytes),
      chunkCount: z.number().int().min(1).max(limits.captureChunksMax),
    })
    .refine((b) => b.chunkCount === Math.ceil(b.envelopeLen / limits.chunkRawBytes)),
  z.strictObject({
    type: z.literal("credential.capture.chunk"),
    captureId: idSchema,
    seq: countSchema(limits.captureChunksMax - 1),
    data: chunkDataSchema,
  }),
  z.strictObject({
    type: z.literal("credential.installed"),
    leaseId: idSchema,
    bindingId: idSchema,
    storageSeq: epochSchema,
    fileCount: countSchema(4096),
    envCount: countSchema(16),
  }),
  z.strictObject({
    type: z.literal("credential.scrubbed"),
    sandboxId: sandboxIdSchema,
    bindingIds: z.array(idSchema).min(1).max(limits.scrubbedBindingsMax).refine(unique),
    verifiedAbsent: z.boolean(),
  }),
  z
    .strictObject({
      type: z.literal("credential.return.key.ack"),
      kidR: kidSchema,
      epoch: epochSchema,
      currentEpoch: epochSchema,
      retiredKids: z.array(kidSchema).max(limits.retiredKidsMax).refine(unique),
      pendingUnderRetired: z.number().int().min(0).max(4_294_967_295),
      refused: z.enum(["stale", "substitution"]).optional(),
    })
    .refine((a) =>
      a.refused === undefined
        ? a.currentEpoch === a.epoch
        : a.refused === "stale"
          ? a.epoch < a.currentEpoch
          : a.epoch === a.currentEpoch,
    ),
  z
    .strictObject({
      type: z.literal("credential.census"),
      page: countSchema(limits.censusPagesMax - 1),
      complete: z.boolean(),
      keyEpoch: z.number().int().min(0).max(limits.returnKeyEpochMax),
      quarantined: z
        .array(z.strictObject({ captureId: idSchema, leaseId: idSchema, kidR: kidSchema }))
        .max(limits.censusQuarantinedMax),
      entries: z.array(censusEntrySchema).max(limits.censusEntriesMax),
    })
    .refine(
      (c) =>
        (c.page === 0 || c.quarantined.length === 0) && unique(c.entries.map((e) => e.bindingId)),
    ),
  z.strictObject({
    type: z.literal("credential.quarantine.discarded"),
    captureIds: captureIdsSchema,
  }),
] as const;
export type DaemonCredentialMessage = z.infer<(typeof daemonCredentialMessageSchemas)[number]>;

// --- server → daemon -------------------------------------------------------------

const DISCARD_REASONS = [
  "force_released",
  "copy_back_disabled",
  "superseded",
  "incomplete",
  "account_deleted",
] as const;
const REJECT_REASONS = [
  "context_mismatch",
  "decrypt_failed",
  "invalid_bundle",
  "unknown_kid",
  "unknown_lease",
  "binding_closed",
] as const;

export const serverCredentialMessageSchema = z.union([
  z.strictObject({
    type: z.literal("credential.return.key"),
    kidR: kidSchema,
    epoch: epochSchema,
    publicKey: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
    serverOrigin: z.string().refine(validOrigin),
  }),
  z.strictObject({
    type: z.literal("credential.spec.chunk"),
    operationId: relayIdSchema,
    seq: countSchema(limits.specChunksMax - 1),
    data: chunkDataSchema,
  }),
  z.strictObject({
    type: z.literal("credential.spec.refused"),
    operationId: relayIdSchema,
    code: codeSchema,
  }),
  z
    .strictObject({
      type: z.literal("credential.bundle.begin"),
      requestId: idSchema,
      bindingId: idSchema,
      storageSeq: epochSchema,
      fileCount: countSchema(4096),
      envCount: countSchema(16),
      bundleLen: z.number().int().min(BUNDLE_MIN_BYTES).max(limits.bundleMaxBytes),
      chunkCount: z.number().int().min(1).max(limits.bundleChunksMax),
    })
    .refine((b) => b.chunkCount === Math.ceil(b.bundleLen / limits.chunkRawBytes)),
  z.strictObject({
    type: z.literal("credential.bundle.chunk"),
    requestId: idSchema,
    seq: countSchema(limits.bundleChunksMax - 1),
    data: chunkDataSchema,
  }),
  z.strictObject({
    type: z.literal("credential.bundle.refused"),
    requestId: idSchema,
    code: codeSchema,
  }),
  z.strictObject({
    type: z.literal("credential.quarantine.discard"),
    captureIds: captureIdsSchema,
    reason: z.enum(["force_released", "owner_discard", "host_deleted"]),
  }),
  z.strictObject({
    type: z.literal("credential.capture.ack"),
    captureId: idSchema,
    outcome: z.enum(["committed", "unchanged", "deferred"]),
  }),
  z.strictObject({
    type: z.literal("credential.capture.ack"),
    captureId: idSchema,
    outcome: z.literal("discarded"),
    reason: z.enum(DISCARD_REASONS),
  }),
  z.strictObject({
    type: z.literal("credential.capture.ack"),
    captureId: idSchema,
    outcome: z.literal("rejected"),
    reason: z.enum(REJECT_REASONS),
  }),
  z.strictObject({
    type: z.literal("credential.revoke"),
    leaseId: idSchema,
    reason: codeSchema,
  }),
  z.strictObject({
    type: z.literal("credential.census.ack"),
    page: countSchema(limits.censusPagesMax - 1),
  }),
]);
export type ServerCredentialMessage = z.infer<typeof serverCredentialMessageSchema>;

export const SERVER_CREDENTIAL_MESSAGE_TYPES = new Set<string>([
  "credential.return.key",
  "credential.spec.chunk",
  "credential.spec.refused",
  "credential.bundle.begin",
  "credential.bundle.chunk",
  "credential.bundle.refused",
  "credential.quarantine.discard",
  "credential.capture.ack",
  "credential.revoke",
  "credential.census.ack",
]);

// --- teardown receipt outcomes (wired into stop/kill/free results in C8b) ------

export const credentialTeardownOutcomeV11Schema = z.strictObject({
  leaseId: idSchema.optional(),
  bindingId: idSchema,
  capture: z.discriminatedUnion("status", [
    z.strictObject({
      status: z.literal("acked"),
      captureId: idSchema,
      outcome: z.enum(["committed", "unchanged", "discarded", "rejected", "deferred"]),
    }),
    z.strictObject({ status: z.literal("durable"), captureId: idSchema }),
    z.strictObject({ status: z.literal("none") }),
    z.strictObject({ status: z.literal("failed"), reason: codeSchema }),
  ]),
  scrub: z.enum(["verified", "not_run", "failed"]),
});
export const credentialTeardownOutcomesV11Schema = z
  .array(credentialTeardownOutcomeV11Schema)
  .max(limits.teardownOutcomesMax)
  .refine((outcomes) => unique(outcomes.map((o) => o.bindingId)));
export type CredentialTeardownOutcomeV11 = z.infer<typeof credentialTeardownOutcomeV11Schema>;
/**
 * Where the receipt travels: the untyped lifecycle result record of a
 * `sandbox.stop` / `sandbox.kill` (and later `credential.free`)
 * `operation.result` / `operation.receipt`, on success AND failure, as
 * `result.credentialOutcomes`. The server never stores it on the operation.
 */
export const CREDENTIAL_TEARDOWN_RESULT_KEY = "credentialOutcomes" as const;

/**
 * Chunk frames carry credential plaintext (bundles) or sealed captures:
 * never log one verbatim. Every other frame is returned unchanged.
 */
export function redactCredentialFrame(frame: { type: string } & Record<string, unknown>): unknown {
  if (!frame.type.startsWith("credential.") || !frame.type.endsWith(".chunk")) return frame;
  const data = frame.data;
  return {
    ...frame,
    data: typeof data === "string" ? `<redacted ${data.length} chars>` : "<redacted>",
  };
}
