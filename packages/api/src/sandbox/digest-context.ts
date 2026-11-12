import type { Prisma } from "@wssp/db";
import { z } from "zod";

import { idempotencyConflict } from "./errors";

/**
 * Operation identity independent of later movement. Every accepted operation and action receipt stores the
 * digest inputs it was hashed with in `digestContext`, and a same-key replay
 * recomputes against that snapshot, never against the sandbox's later
 * placement (a cold restore can rebind the host, host owner and pool).
 *
 * Owner and authorizing key are already immutable columns of the row
 * (`userId`, `authorizingKeyId`, checked by `requireReplayPrincipal`); the
 * snapshot holds the transport half and the provenance of the acceptance.
 */
const DIGEST_CONTEXT_VERSION = 1;

/** Default request MAC domain (`hashRequestBody` without a domain). */
export const REQUEST_DIGEST_DOMAIN = "wssp-request-v2";
/** Recorded only: KILL/STOP hash env-free bodies with no transport input. */
export const ENV_FREE_DIGEST_DOMAIN = "env-free";
/**
 * Hostless restore intent (§8.3a): an operation accepted while its sandbox is
 * `OFFLOADED` has no host, host owner or placement. It hashes with this
 * domain and empty transport fields; the body is the restore intent
 * (sandbox, acceptance generation, timeout, credential pins, target hint,
 * capacity wait and override flag, chosen by C6b `acceptRestore`).
 */
export const RESTORE_INTENT_DIGEST_DOMAIN = "restore-intent:v1";
/** Non-dispatch action receipts (`action-receipts.ts`). */
export const ACTION_DIGEST_DOMAIN = "wssp-action-v2";

const snapshotSchema = z
  .object({
    version: z.literal(DIGEST_CONTEXT_VERSION),
    domain: z.string().min(1).max(64),
    hostId: z.string().max(128),
    hostOwnerId: z.string().max(128),
    /** The acceptance generation (operation generation, receipt generation). */
    generation: z.number().int().nullable(),
    /** The execution-config binding the acceptance bound, when one exists. */
    configId: z.string().max(128).nullable(),
    usagePoolId: z.string().max(128).nullable(),
    usageMemberId: z.string().max(128).nullable(),
  })
  .strict();

export type DigestContextSnapshot = z.infer<typeof snapshotSchema>;

/** The transport half every replay hashes with. */
export type DigestTransport = { domain: string; hostId: string; hostOwnerId: string };
type LooseTransport = { domain: string; hostId?: string | null; hostOwnerId?: string | null };

export function digestContextSnapshot(
  transport: LooseTransport,
  acceptance: {
    generation?: number | null;
    configId?: string | null;
    usagePoolId?: string | null;
    usageMemberId?: string | null;
  } = {},
): DigestContextSnapshot {
  return snapshotSchema.parse({
    version: DIGEST_CONTEXT_VERSION,
    domain: transport.domain,
    // Exactly as hashed: `hashRequestBody` reads an absent field as "".
    hostId: transport.hostId ?? "",
    hostOwnerId: transport.hostOwnerId ?? "",
    generation: acceptance.generation ?? null,
    configId: acceptance.configId ?? null,
    usagePoolId: acceptance.usagePoolId ?? null,
    usageMemberId: acceptance.usageMemberId ?? null,
  });
}

/** A malformed snapshot fails closed; replay never derives it from current state. */
export function parseDigestContext(
  value: Prisma.JsonValue | null | undefined,
): DigestContextSnapshot {
  const parsed = snapshotSchema.safeParse(value);
  if (!parsed.success) throw idempotencyConflict();
  return parsed.data;
}

// Admission writers share the transport snapshot chosen before their work.
const operationContexts = new WeakMap<Prisma.TransactionClient, DigestContextSnapshot>();
export function bindOperationDigestContext(
  tx: Prisma.TransactionClient,
  context: DigestContextSnapshot,
): void {
  operationContexts.set(tx, context);
}
export function operationDigestContext(tx: Prisma.TransactionClient): DigestContextSnapshot {
  const context = operationContexts.get(tx);
  if (!context) throw new Error("Operation admission has no digest context.");
  return context;
}
