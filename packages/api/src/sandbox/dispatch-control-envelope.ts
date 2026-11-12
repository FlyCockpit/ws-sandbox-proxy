import {
  type BuildCopyV11,
  buildCopyV11Schema,
  type RunAsV11,
  runAsV11Schema,
} from "@wssp/sandbox-contracts";
import receiptLimits from "../../../config/src/sandbox-receipt-limits.json";
import { type CommandRunPayloadParts, SANDBOX_JSON_CONTROL_MAX_BYTES } from "./command-payload";
import { effectiveCommandTimeoutMs, encodeCommandTimeoutMs } from "./contracts";

// Prisma Int / PostgreSQL integer bounds, including future retries and stdin appends.
const DISPATCH_INT32_MAX = 2_147_483_647;
const BODY_HASH_PLACEHOLDER = "f".repeat(receiptLimits.bodyHashBytes);

export type CommandRunOperationDispatchMessage = {
  type: "operation.dispatch";
  operationId: string;
  sandboxOwnerId: string;
  sandboxId: string;
  idempotencyKey: string;
  kind: "command.run";
  generation: number;
  attempt: number;
  templateDigest?: string;
  incusFingerprint?: string;
  templateRevisionId?: string;
  verificationConnectionEpoch?: number;
  architecture?: string;
  guestUid?: number;
  guestGid?: number;
  guestHome?: string;
  guestShell?: string;
  incusName?: string;
  argv?: string[];
  script?: string;
  cwd?: string;
  timeoutMs?: number;
  stdinSequence?: number;
  recursive?: boolean;
  env?: Array<[string, string]>;
  bodyHash?: string;
  digestScheme?: string;
  digestKeyId?: string | null;
  privateConfig?: import("./execution-config").PrivateConfigReference;
  /** Template-build step fields (D1), carried only from the outbox payload. */
  runAs?: RunAsV11;
  buildCopy?: BuildCopyV11;
};

export type CommandRunDispatchBuildInput = {
  operationId: string;
  sandboxOwnerId: string;
  sandboxId: string;
  idempotencyKey: string;
  generation: number;
  attempt: number;
  bodyHash: string;
  digestScheme?: string;
  digestKeyId?: string | null;
  privateConfig?: import("./execution-config").PrivateConfigReference;
  templateDigest: string;
  incusFingerprint: string;
  architecture: string;
  guestUid?: number;
  guestGid?: number;
  guestHome?: string;
  guestShell?: string;
  incusName?: string;
  timeoutMs: number;
  stdinSequence: number;
  recursive: boolean;
  argv?: string[];
  script?: string;
  cwd?: string;
  env?: Array<[string, string]>;
  runAs?: RunAsV11;
  buildCopy?: BuildCopyV11;
};

/**
 * The build step fields of a stored command payload (plan template-builds
 * §3.1 "Persistence, not context"): only `runCommand` writes them, inside the
 * enqueue transaction, for a build principal on its own build VM. A malformed
 * value is a producer bug and throws instead of being dropped silently.
 */
export function commandRunBuildFieldsFromPayload(payload: Record<string, unknown>): {
  runAs?: RunAsV11;
  buildCopy?: BuildCopyV11;
} {
  return {
    ...(payload.runAs !== undefined ? { runAs: runAsV11Schema.parse(payload.runAs) } : {}),
    ...(payload.buildCopy !== undefined
      ? { buildCopy: buildCopyV11Schema.parse(payload.buildCopy) }
      : {}),
  };
}

function commandPartsFromPayload(payload: Record<string, unknown>): CommandRunPayloadParts {
  const argv = Array.isArray(payload.argv)
    ? payload.argv.filter((v): v is string => typeof v === "string")
    : undefined;
  const script = typeof payload.script === "string" ? payload.script : undefined;
  const cwd = typeof payload.cwd === "string" ? payload.cwd : undefined;
  const env = parseCommandRunDispatchEnvPairs(payload.env);
  return { argv, script, cwd, env };
}

export function parseCommandRunDispatchEnvPairs(
  value: unknown,
): Array<[string, string]> | undefined {
  if (!Array.isArray(value)) return undefined;
  const pairs: Array<[string, string]> = [];
  for (const item of value) {
    if (Array.isArray(item) && typeof item[0] === "string" && typeof item[1] === "string") {
      pairs.push([item[0], item[1]]);
    }
  }
  return pairs.length > 0 ? pairs : undefined;
}

/** Shared wire projection for relay `operation.dispatch` (`command.run`). */
export function buildCommandRunOperationDispatchMessage(
  input: CommandRunDispatchBuildInput,
): CommandRunOperationDispatchMessage {
  const message: CommandRunOperationDispatchMessage = {
    type: "operation.dispatch",
    operationId: input.operationId,
    sandboxOwnerId: input.sandboxOwnerId,
    sandboxId: input.sandboxId,
    idempotencyKey: input.idempotencyKey,
    kind: "command.run",
    generation: input.generation,
    attempt: input.attempt,
    templateDigest: input.templateDigest,
    incusFingerprint: input.incusFingerprint,
    architecture: input.architecture,
    guestUid: input.guestUid,
    guestGid: input.guestGid,
    guestHome: input.guestHome,
    guestShell: input.guestShell,
    incusName: input.incusName,
    timeoutMs: encodeCommandTimeoutMs(effectiveCommandTimeoutMs(input.timeoutMs)),
    stdinSequence: input.stdinSequence,
    recursive: input.recursive,
    bodyHash: input.bodyHash,
    digestScheme: input.digestScheme,
    digestKeyId: input.digestKeyId,
    privateConfig: input.privateConfig,
  };
  if (input.script != null) message.script = input.script;
  else if (input.argv != null) message.argv = input.argv;
  if (input.cwd != null) message.cwd = input.cwd;
  if (input.env != null && input.env.length > 0) message.env = input.env;
  if (input.runAs !== undefined) message.runAs = input.runAs;
  if (input.buildCopy !== undefined) message.buildCopy = input.buildCopy;
  return message;
}

export function commandRunDispatchBuildInputFromOutboxPayload(
  payload: Record<string, unknown>,
  sandboxId: string,
  dispatch: { sandboxOwnerId: string; attempt: number; bodyHash: string; stdinSequence: number },
): CommandRunDispatchBuildInput {
  const parts = commandPartsFromPayload(payload);
  const generation =
    typeof payload.generation === "number" && Number.isFinite(payload.generation)
      ? payload.generation
      : 1;
  return {
    operationId: String(payload.operationId ?? ""),
    sandboxOwnerId: dispatch.sandboxOwnerId,
    sandboxId,
    idempotencyKey: String(payload.idempotencyKey ?? ""),
    generation,
    attempt: dispatch.attempt,
    bodyHash: dispatch.bodyHash,
    templateDigest: typeof payload.templateDigest === "string" ? payload.templateDigest : "",
    incusFingerprint: typeof payload.incusFingerprint === "string" ? payload.incusFingerprint : "",
    architecture: typeof payload.architecture === "string" ? payload.architecture : "",
    guestUid: typeof payload.guestUid === "number" ? payload.guestUid : undefined,
    guestGid: typeof payload.guestGid === "number" ? payload.guestGid : undefined,
    guestHome: typeof payload.guestHome === "string" ? payload.guestHome : undefined,
    guestShell: typeof payload.guestShell === "string" ? payload.guestShell : undefined,
    incusName: typeof payload.incusName === "string" ? payload.incusName : undefined,
    timeoutMs: encodeCommandTimeoutMs(effectiveCommandTimeoutMs(payload.timeoutMs)),
    stdinSequence: dispatch.stdinSequence,
    recursive: payload.recursive === true,
    argv: parts.argv,
    script: parts.script,
    cwd: parts.cwd,
    env: parts.env,
    privateConfig: payload.privateConfig as
      | import("./execution-config").PrivateConfigReference
      | undefined,
    ...commandRunBuildFieldsFromPayload(payload),
  };
}

/** Worst-case dispatch variables for enqueue sizing (real stored template + command fields). */
export function commandRunDispatchBuildInputForEnqueueGuard(
  payload: Record<string, unknown>,
  sandboxId: string,
): CommandRunDispatchBuildInput {
  const input = commandRunDispatchBuildInputFromOutboxPayload(payload, sandboxId, {
    sandboxOwnerId: "f".repeat(receiptLimits.identityBytes),
    attempt: DISPATCH_INT32_MAX,
    bodyHash: BODY_HASH_PLACEHOLDER,
    stdinSequence: DISPATCH_INT32_MAX,
  });
  // Sizing placeholders only: wire omission leaves identity/name derivation to
  // the host. Six JSON bytes per source byte conservatively covers escaping.
  return {
    ...input,
    generation: DISPATCH_INT32_MAX,
    digestScheme: "hmac-sha256-v1",
    digestKeyId: "f".repeat(32),
    guestUid: input.guestUid ?? receiptLimits.guestIdMax,
    guestGid: input.guestGid ?? receiptLimits.guestIdMax,
    guestHome: input.guestHome ?? "\0".repeat(receiptLimits.guestPathBytes),
    guestShell: input.guestShell ?? "\0".repeat(receiptLimits.guestPathBytes),
    incusName: input.incusName ?? "\0".repeat(receiptLimits.identityBytes),
  };
}

export function encodedCommandRunDispatchControlBytes(input: CommandRunDispatchBuildInput): number {
  return new TextEncoder().encode(JSON.stringify(buildCommandRunOperationDispatchMessage(input)))
    .byteLength;
}

export function commandRunDispatchFitsControlLimit(
  payload: Record<string, unknown>,
  sandboxId: string,
): boolean {
  return (
    encodedCommandRunDispatchControlBytes(
      commandRunDispatchBuildInputForEnqueueGuard(payload, sandboxId),
    ) <= SANDBOX_JSON_CONTROL_MAX_BYTES
  );
}
