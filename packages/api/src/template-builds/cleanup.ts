import type { SandboxState, TemplateBuildState, TemplateCaptureState } from "@wssp/db";
import { Prisma as PrismaValue } from "@wssp/db/client";
import { CAPTURE_RESULT_RECORDED } from "./decide";

/**
 * The cleanup invariant:
 *
 * > Every non-DELETED sandbox with `buildId IS NOT NULL` is killed (cleanup
 * > class, key-free) when its build is missing, CANCELLING, terminal, or
 * > CAPTURING with the current capture attempt's host result recorded.
 *
 * Cleanup is a property of state, not a step of any path: deadline, step
 * failure, cancel and capture success only change the build state, and this
 * one rule (one indexed query) does the rest. It is the only place that
 * issues `tb:…:kill` keys.
 *
 * The SQL fragment and the TypeScript predicate are generated from the same
 * two tables below, and the unit test enumerates every state × capture case.
 */

/** Build states whose VM is never needed again. */
export const BUILD_VM_DEAD_STATES: readonly TemplateBuildState[] = [
  "CANCELLING",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
];

/** Must the VM of a build in this state (null: the build row is gone) die? */
export function buildVmMustDie(
  build: { state: TemplateBuildState; captureState: TemplateCaptureState | null } | null,
): boolean {
  if (build === null) return true;
  if (BUILD_VM_DEAD_STATES.includes(build.state)) return true;
  return (
    build.state === "CAPTURING" &&
    build.captureState !== null &&
    CAPTURE_RESULT_RECORDED.includes(build.captureState)
  );
}

/**
 * Must a community build's VERIFY VM die (community-base T2, review4 U2)?
 * Its own rule, never the build VM's: verification runs exactly while the
 * build is CAPTURING with its capture FINALIZED, when the build VM must die
 * and the verify VM must live. It dies when the build is gone, cancelling
 * or terminal (SUCCEEDED included: a passed verify VM is cleaned up too).
 */
export function verifyVmMustDie(build: { state: TemplateBuildState } | null): boolean {
  return build === null || BUILD_VM_DEAD_STATES.includes(build.state);
}

/**
 * The same predicate over `b` (a LEFT JOINed `sandbox_template_build`) for
 * one sandbox row. States compare as text (the applier adds enum values in
 * the same transaction as CHECKs that name them).
 */
export function buildVmMustDieSql() {
  return PrismaValue.sql`(b.id IS NULL
    OR b.state::text IN (${PrismaValue.join(BUILD_VM_DEAD_STATES)})
    OR (b.state::text = 'CAPTURING' AND EXISTS (
      SELECT 1 FROM sandbox_template_capture c
      WHERE (c."operationId" = b."captureOperationId"
          OR (c."buildId" = b.id AND c."buildAttempt" = b."captureAttempt"))
        AND c."userId" = b."userId"
        AND c.state::text IN (${PrismaValue.join(CAPTURE_RESULT_RECORDED)}))))`;
}

/** Sandbox states a kill can be accepted in (plus a capacity wait, which a
 * kill cancels). Others (STOPPING, RECLAIMING, HOST_LOST) settle first.
 * OFFLOADED never appears: build and verify VMs are managed purposes, never
 * offloaded (offload plan R15.1, §10 C7; asserted in cleanup.test.ts). */
const CLEANUP_KILLABLE_SANDBOX_STATES = [
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPED",
  "UNREACHABLE",
  "RECOVERED",
  "ERROR",
  "WAITING_FOR_CAPACITY",
] as const satisfies readonly Exclude<SandboxState, "OFFLOADED">[];

/** Per-pass bound of the invariant query (§3.10 `LIMIT 32`). */
const CLEANUP_BATCH = 32;

/**
 * Keyset bounds of one cleanup page: rows with id > `after` (exclusive) and,
 * on the wrap-around page, id <= `upTo` (inclusive). See `rotatingPage`.
 */
export type CleanupPageBounds = { after: string | null; upTo: string | null; take: number };

/** `verifyVmMustDie` over `b` (the verify VM's build). */
function verifyVmMustDieSql() {
  return PrismaValue.sql`(b.id IS NULL OR b.state::text IN (${PrismaValue.join(BUILD_VM_DEAD_STATES)}))`;
}

/** One page of live build and verify VMs that must die. Served by the
 * partial indexes `sandbox_instance(state) WHERE "buildId" IS NOT NULL` and
 * `… WHERE "verifyBuildId" IS NOT NULL`. `buildId` is the VM's build either
 * way; `verify` says which rule (and key namespace) applies. */
export function cleanupCandidatesSql(
  bounds: CleanupPageBounds = { after: null, upTo: null, take: CLEANUP_BATCH },
) {
  return PrismaValue.sql`
    SELECT s.id, s."userId", COALESCE(s."buildId", s."verifyBuildId") AS "buildId",
      s.state::text AS state, b.id AS "liveBuildId", (s."verifyBuildId" IS NOT NULL) AS verify
    FROM sandbox_instance s
    LEFT JOIN sandbox_template_build b
      ON b.id = COALESCE(s."buildId", s."verifyBuildId") AND b."userId" = s."userId"
    WHERE (s."buildId" IS NOT NULL OR s."verifyBuildId" IS NOT NULL)
      AND s.state::text <> 'DELETED'
      AND s.state::text IN (${PrismaValue.join(CLEANUP_KILLABLE_SANDBOX_STATES)})
      AND ((s."verifyBuildId" IS NULL AND ${buildVmMustDieSql()})
        OR (s."verifyBuildId" IS NOT NULL AND ${verifyVmMustDieSql()}))
      ${bounds.after === null ? PrismaValue.empty : PrismaValue.sql`AND s.id > ${bounds.after}`}
      ${bounds.upTo === null ? PrismaValue.empty : PrismaValue.sql`AND s.id <= ${bounds.upTo}`}
    ORDER BY s.id
    LIMIT ${bounds.take}`;
}

/** Where the next cleanup page starts (per process; a restart starts over). */
export type CleanupCursor = { after: string | null };

/**
 * A bounded page that rotates through every candidate (§3.10 fairness): it
 * continues after the previous page's last id and, when that tail is shorter
 * than `take`, wraps to the start for the rest. Rows that stay blocked
 * (a VM whose kill is in flight, a build whose context cannot be aborted yet)
 * therefore never hold the page: each pass moves past them, and every
 * candidate is visited within ceil(candidates / take) passes. When there are
 * at most `take` candidates, every pass visits all of them.
 */
export async function rotatingPage<T extends { id: string }>(
  cursor: CleanupCursor,
  take: number,
  fetch: (bounds: CleanupPageBounds) => Promise<T[]>,
): Promise<T[]> {
  const start = cursor.after;
  const tail = await fetch({ after: start, upTo: null, take });
  const head =
    tail.length < take && start !== null
      ? await fetch({ after: null, upTo: start, take: take - tail.length })
      : [];
  const rows = [...tail, ...head];
  cursor.after = rows.at(-1)?.id ?? null;
  return rows;
}
