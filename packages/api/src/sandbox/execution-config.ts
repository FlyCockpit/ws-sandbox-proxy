import { ORPCError } from "@orpc/server";
import type { Prisma } from "@wssp/db";
import { commandBodySchema, defaultEnvSchema, envSchema } from "@wssp/sandbox-contracts";
import { privateConfigBinding, requestDigestMetadata } from "./idempotency";
import { rethrowSensitiveSandboxError } from "./sensitive-errors";

// These are private projections. Never spread them into a public DTO or error.
const configSelect = {
  id: true,
  userId: true,
  sandboxId: true,
  generation: true,
  hostId: true,
  authorizingKeyId: true,
  templateDefaults: true,
  sandboxOverrides: true,
  mergedDefaults: true,
  bindingScheme: true,
  bindingKeyId: true,
  bindingMac: true,
  acknowledgedEpoch: true,
  Sandbox: {
    select: {
      userId: true,
      hostOwnerId: true,
      sandboxHostId: true,
      CurrentPlacement: {
        select: { hostOwnerId: true, originHostId: true, userId: true, sandboxId: true },
      },
      SandboxHost: { select: { userId: true } },
    },
  },
} satisfies Prisma.SandboxExecutionConfigSelect;

export type PrivateConfigReference = {
  configId: string;
  bindingScheme: "hmac-sha256-v1";
  bindingKeyId: string;
  bindingMac: string;
};

function invalid(): never {
  throw new ORPCError("BAD_REQUEST", { message: "Invalid private execution config." });
}

export function executionEnvPairs(value: unknown): [string, string][] {
  const parsed = defaultEnvSchema.safeParse(value);
  if (!parsed.success) return invalid();
  return Object.keys(parsed.data)
    .sort()
    .map((key) => [key, parsed.data[key]!]);
}

export function mergeCommandEnvironment(defaults: [string, string][], command: unknown) {
  // Do not silently discard malformed stored tuples, duplicate keys or values.
  if (
    command !== undefined &&
    (!Array.isArray(command) ||
      command.some(
        (p: unknown) =>
          !Array.isArray(p) ||
          p.length !== 2 ||
          typeof p[0] !== "string" ||
          typeof p[1] !== "string",
      ))
  )
    invalid();
  const pairs = (command ?? []) as [string, string][];
  if (new Set(pairs.map(([key]) => key)).size !== pairs.length) invalid();
  const overrides = envSchema.safeParse(Object.fromEntries(pairs));
  if (!overrides.success) invalid();
  const merged = envSchema.safeParse({ ...Object.fromEntries(defaults), ...overrides.data });
  if (!merged.success) invalid();
  return Object.keys(merged.data)
    .sort()
    .map((key): [string, string] => [key, merged.data[key]!]);
}

export function validateCommandEnvironmentUnion(
  payload: Record<string, unknown>,
  defaults: [string, string][],
) {
  const env = mergeCommandEnvironment(defaults, payload.env);
  if (
    defaults.length > 0 &&
    !commandBodySchema.safeParse({
      argv: payload.argv,
      script: payload.script,
      cwd: payload.cwd,
      envs: Object.fromEntries(env),
      timeoutMs: payload.timeoutMs,
    }).success
  )
    invalid();
  return env;
}

async function readExecutionConfig(
  tx: Prisma.TransactionClient,
  sandboxId: string,
  ownerId: string,
) {
  const row = await tx.sandboxExecutionConfig.findFirst({
    where: { sandboxId, userId: ownerId, Sandbox: { userId: ownerId } },
    select: configSelect,
  });
  if (!row) return null;
  const defaults = executionEnvPairs(row.templateDefaults);
  const overrides = executionEnvPairs(row.sandboxOverrides);
  const env = executionEnvPairs(row.mergedDefaults);
  const merged = mergeCommandEnvironment(defaults, overrides);
  if (JSON.stringify(merged) !== JSON.stringify(env)) invalid();
  if (row.bindingKeyId !== requestDigestMetadata().requestDigestKeyId)
    throw new ORPCError("CONFLICT", {
      message: "Digest key changed.",
      data: { code: "digest_key_changed" },
    });
  const pin = row.Sandbox.CurrentPlacement;
  // During initial acceptance the config precedes the placement pointer in the
  // same transaction. The live sandbox/host binding is already fixed there.
  // Retained reads after host retirement use the immutable placement evidence.
  const hostOwnerId = pin?.hostOwnerId ?? row.Sandbox.hostOwnerId;
  if (
    !hostOwnerId ||
    row.Sandbox.userId !== ownerId ||
    (pin &&
      (pin.userId !== ownerId || pin.sandboxId !== sandboxId || pin.originHostId !== row.hostId)) ||
    (!pin && row.Sandbox.sandboxHostId !== row.hostId) ||
    (row.Sandbox.hostOwnerId !== null && row.Sandbox.hostOwnerId !== hostOwnerId) ||
    (row.Sandbox.SandboxHost && row.Sandbox.SandboxHost.userId !== hostOwnerId)
  )
    invalid();
  const expected = privateConfigBinding(
    { configId: row.id, sandboxId, generation: row.generation, env },
    {
      ownerId,
      hostOwnerId,
      hostId: row.hostId,
      authorizingKeyId: row.authorizingKeyId,
    },
  );
  if (
    row.bindingScheme !== expected.bindingScheme ||
    row.bindingKeyId !== expected.bindingKeyId ||
    row.bindingMac !== expected.bindingMac
  )
    invalid();
  return {
    env,
    generation: row.generation,
    hostId: row.hostId,
    acknowledgedEpoch: row.acknowledgedEpoch,
    reference: {
      configId: row.id,
      bindingScheme: "hmac-sha256-v1" as const,
      bindingKeyId: row.bindingKeyId,
      bindingMac: row.bindingMac,
    },
  };
}

/** Nearest enclosing boundary also strips Prisma invocation and driver causes. */
export async function loadExecutionConfig(
  tx: Prisma.TransactionClient,
  sandboxId: string,
  ownerId: string,
) {
  try {
    return await readExecutionConfig(tx, sandboxId, ownerId);
  } catch (error) {
    if (error instanceof ORPCError && error.code === "BAD_REQUEST") invalid();
    return rethrowSensitiveSandboxError(error);
  }
}
