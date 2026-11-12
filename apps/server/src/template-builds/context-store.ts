import { lstat, opendir, unlink } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { ORPCError } from "@orpc/server";
import type { Principal } from "@wssp/api/sandbox/contracts";
import {
  credentialExpiryOf,
  isBrowserSession,
  recordedKeyIdOf,
} from "@wssp/api/sandbox/principal-kinds";
import { TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS } from "@wssp/api/template-builds/config";
import {
  BuildContextPortError,
  buildContextGuestPath,
  buildContextImportKey,
  notifyBuildContextChanged,
} from "@wssp/api/template-builds/context-port";
import prisma, { type Prisma } from "@wssp/db";
import { authorityTicket } from "@wssp/db/authority";
import { TRANSFER_CHUNK_BYTES } from "@wssp/sandbox-contracts";
import { checkChunk, transferError } from "../sandbox-transfers/limits.js";
import {
  checkSpoolRoot,
  checkSpoolStat,
  createSpoolRoot,
  digest,
  hashSpoolFile,
  ImportSourceError,
  missing,
  openSpoolFile,
  storageFailure,
  syncSpoolRoot,
  verifyAcknowledged,
  writeFully,
} from "../sandbox-transfers/spool-io.js";
import type { TransferStore } from "../sandbox-transfers/store.js";

/**
 * Build-context staging. A COPY
 * build's context is uploaded and sealed here BEFORE any VM exists, then
 * adopted into an ordinary transfer by `TransferStore.importSealed` once the
 * build sandbox is READY. One owner per directory and per table: this store
 * alone writes its root (a sibling of the transfer spool root, which the
 * transfer store's `recover` never scans) and `sandbox_build_context*`; it
 * never writes a transfer row or a file in the transfer root.
 *
 * Budgets: every context reserves its declared `totalBytes` against a
 * per-account share and a global cap, decided under one advisory lock at
 * `open`, until its staged name is durably unlinked (`reservationHeld`, like
 * the transfer store): an ended or adopted context whose file is not yet
 * gone stays charged, and the sweep retries the deletion. Staged contexts
 * never count toward transfer slots or disk.
 *
 * Lifecycle (coordinator ruling on §3.7): OPEN is bounded by progress, not
 * by a fixed window from acceptance: it expires after `idleMs` without a
 * chunk, and at most `TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS` after it opened
 * (`build_context_timeout` either way), so a slow but steady upload of a large
 * context completes. SEALED has no idle expiry but a finite absolute one,
 * anchored at the seal: `seal + 15 min + min(wait, 6 h)`
 * (`build_context_expired`). A seal whose sha256 differs ends the context
 * (`build_context_mismatch`). The store never touches the build row: each
 * change wakes the orchestrator, which reads the context row.
 */

/** Global context admission rank. Taken alone, in its own transaction. */
const CONTEXT_ADMISSION_LOCK = 270029;
/** Slack after the seal for placement and readiness, before any capacity
 * wait (§3.7: the plan's "+ 15 min"). */
export const CONTEXT_PLACEMENT_GRACE_MS = 15 * 60 * 1000;
const SCAN_BATCH = 32;
const CONTEXT_FILE = /^([a-z0-9]{1,64})\.context$/;
const LIVE_STATES = ["OPEN", "SEALED"] as const;

export type BuildContextLimits = {
  /** Largest single context (TEMPLATE_BUILD_CONTEXT_MAX_BYTES after clamps). */
  maxBytes: number;
  /** Per-account staged share (TEMPLATE_BUILD_CONTEXT_STAGED_BYTES_PER_ACCOUNT). */
  stagedBytesPerAccount: number;
  /** Global staged cap (TEMPLATE_BUILD_CONTEXT_STAGED_BYTES). */
  stagedBytes: number;
  /** OPEN idle timeout between chunks (TRANSFER_IDLE_SECONDS). */
  idleMs: number;
  /** In-flight exclusive tasks across all contexts. */
  globalActive: number;
};

export type BuildContextBudgetScope = "account" | "global";

/** `<dirname(spool)>/<basename(spool)>.build-context` (derived, no env var). */
export function buildContextRoot(transferSpoolDir: string): string {
  const root = resolve(transferSpoolDir);
  return join(dirname(root), `${basename(root)}.build-context`);
}

/**
 * Budget arithmetic at `open` (r3 N21). The account share is checked first:
 * an account at its share waits for its own builds even when the global cap
 * still has room. Null admits.
 */
export function contextBudgetRefusal(input: {
  requested: bigint;
  accountUsed: bigint;
  globalUsed: bigint;
  perAccount: number;
  global: number;
}): BuildContextBudgetScope | null {
  if (input.requested + input.accountUsed > BigInt(input.perAccount)) return "account";
  if (input.requested + input.globalUsed > BigInt(input.global)) return "global";
  return null;
}

/** The absolute ceiling of the OPEN upload phase (the idle timeout aside):
 * `opened + 6 h`. Steady progress is never cut off before it. */
export function contextOpenExpiresAt(openedAt: Date): Date {
  return new Date(openedAt.getTime() + TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS);
}

/**
 * SEALED expiry: `seal + 15 min + min(waitForCapacityMs, 6 h)`. `null` is a
 * build that does not wait for capacity (only the placement grace). Acceptance
 * already clamps a COPY build's wait to the ceiling; this clamps again, and an
 * invalid value fails closed to the ceiling.
 */
export function contextSealedExpiresAt(sealedAt: Date, waitForCapacityMs: number | null): Date {
  const wait =
    waitForCapacityMs === null
      ? 0
      : !Number.isFinite(waitForCapacityMs) || waitForCapacityMs < 0
        ? TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS
        : Math.min(waitForCapacityMs, TEMPLATE_BUILD_CONTEXT_SEALED_MAX_MS);
  return new Date(sealedAt.getTime() + CONTEXT_PLACEMENT_GRACE_MS + wait);
}

/** `template.build_context_busy{scope}` (429: retry after the account's or
 * everyone's staged contexts drain). */
function buildContextBusy(scope: BuildContextBudgetScope) {
  return new ORPCError("TOO_MANY_REQUESTS", {
    status: 429,
    data: { code: "template.build_context_busy", scope },
  });
}

/**
 * Who may act on a build's context through the routes: exactly the accepting
 * principal (§3.7 "Routes"): the session for a session build, the accepting
 * key for a keyed build. The build row's CHECK-bound `principalKey` encodes
 * it; system builds ("sys") have no context route. Null: nobody.
 */
function acceptingPrincipalKey(owner: Principal): string | null {
  if (isBrowserSession(owner)) return "s";
  const key = recordedKeyIdOf(owner);
  return key === null ? null : `k:${key}`;
}

const handleSelect = {
  id: true,
  buildId: true,
  userId: true,
  state: true,
  totalBytes: true,
  receivedBytes: true,
  expectedSha256: true,
  idleExpiresAt: true,
  expiresAt: true,
  importAttempt: true,
  transferId: true,
  errorCode: true,
} satisfies Prisma.SandboxBuildContextSelect;
type ContextRow = Prisma.SandboxBuildContextGetPayload<{ select: typeof handleSelect }>;

/** The upload handle a client sees (no internal ids). */
function contextHandle(row: ContextRow) {
  return {
    buildId: row.buildId,
    state: row.state,
    totalBytes: Number(row.totalBytes),
    receivedBytes: Number(row.receivedBytes),
    chunkBytes: TRANSFER_CHUNK_BYTES,
    idleExpiresAt: row.state === "OPEN" ? row.idleExpiresAt.toISOString() : null,
    expiresAt: row.expiresAt.toISOString(),
    errorCode: row.errorCode,
  };
}
export type BuildContextHandle = ReturnType<typeof contextHandle>;

export class BuildContextStore {
  readonly root: string;
  private readonly transferRoot: string;
  private identity = "";
  private closed = true;
  private readonly work = new Map<string, Promise<unknown>>();
  private timer?: ReturnType<typeof setInterval>;
  private sweeping?: Promise<void>;
  /** True when the context and transfer roots are different filesystems
   * (`importSealed` then copies instead of linking). */
  crossDevice = false;

  constructor(
    transferSpoolDir: string,
    private readonly limits: BuildContextLimits,
    private readonly wake: (buildId: string) => void = notifyBuildContextChanged,
    private readonly now: () => number = Date.now,
  ) {
    if (Object.values(limits).some((v) => !Number.isSafeInteger(v) || v <= 0))
      throw new Error("Invalid build-context limits");
    this.transferRoot = resolve(transferSpoolDir);
    this.root = buildContextRoot(transferSpoolDir);
  }

  /** File name of a context inside `root` (only ids this store minted). */
  fileName(contextId: string) {
    if (!/^[a-z0-9]{1,64}$/.test(contextId)) throw transferError("TRANSFER_IO");
    return `${contextId}.context`;
  }
  private path(contextId: string) {
    return join(this.root, this.fileName(contextId));
  }

  /**
   * Startup: root checks, then recovery. MUST complete before the transfer
   * store starts: it unlinks the staged name of every adopted context, so the
   * transfer store's `recover()` never sees a spool with a second name.
   */
  async start() {
    if (!this.closed || this.identity) throw new Error("Build-context store already started");
    this.identity = await createSpoolRoot(this.root);
    const own = await lstat(this.root);
    // The transfer root may not exist yet on first boot; its parent decides.
    const peer = await lstat(this.transferRoot).catch(() => lstat(dirname(this.transferRoot)));
    this.crossDevice = own.dev !== peer.dev;
    if (this.crossDevice)
      console.warn(
        "[template-builds] Build-context root and transfer spool root are on different filesystems; context imports copy instead of linking.",
      );
    await this.recover();
    this.closed = false;
    this.timer = setInterval(() => {
      void this.sweep().catch(() =>
        console.error("[template-builds] Context cleanup incomplete; retried next sweep."),
      );
    }, 60_000);
    this.timer.unref();
  }

  async close() {
    this.closed = true;
    clearInterval(this.timer);
    await Promise.allSettled([...this.work.values(), this.sweeping]);
  }

  private run<T>(id: string, body: () => Promise<T>): Promise<T> {
    if (this.closed) return Promise.reject(transferError("TRANSFER_IO"));
    if (this.work.has(id)) return Promise.reject(transferError("CONFLICT"));
    if (this.work.size >= this.limits.globalActive)
      return Promise.reject(transferError("TRANSFER_QUOTA"));
    const task = Promise.resolve()
      .then(body)
      .finally(() => {
        this.work.delete(id);
      });
    this.work.set(id, task);
    return task;
  }

  /** Authority ticket around a route task (same fence as transfer uploads). */
  private authorized<T>(owner: Principal, body: () => Promise<T>): Promise<T> {
    const credentialId = recordedKeyIdOf(owner);
    const current = authorityTicket({
      ownerId: owner.ownerId,
      ...(credentialId !== null ? { credentialId } : {}),
    });
    const check = () => {
      if (!current()) throw transferError("FORBIDDEN");
      const expiresAt = credentialExpiryOf(owner);
      if (expiresAt && expiresAt.getTime() <= this.now()) throw transferError("FORBIDDEN");
    };
    return body().then(
      (value) => {
        check();
        return value;
      },
      (error: unknown) => {
        check();
        if (storageFailure(error)) throw transferError("TRANSFER_IO");
        throw error;
      },
    );
  }

  /**
   * The context of a build the caller accepted. Anything else — another
   * owner's build, another key's build, a session acting on a keyed build, a
   * build without a context row — is NOT_FOUND (§3.1, pg 8b).
   */
  private async owned(owner: Principal, buildId: string, tx: Prisma.TransactionClient = prisma) {
    const principalKey = acceptingPrincipalKey(owner);
    if (!principalKey || typeof buildId !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(buildId))
      throw transferError("NOT_FOUND");
    const build = await tx.sandboxTemplateBuild.findFirst({
      where: { id: buildId, userId: owner.ownerId, principalKey },
      select: { id: true, Context: { select: handleSelect } },
    });
    if (!build?.Context) throw transferError("NOT_FOUND");
    return build.Context;
  }

  private expired(row: ContextRow) {
    const now = this.now();
    return (
      row.expiresAt.getTime() <= now || (row.state === "OPEN" && row.idleExpiresAt.getTime() <= now)
    );
  }

  /**
   * Opens (or re-opens) the context of a COPY build the caller accepted.
   * Idempotent by `buildId`: a second call returns the existing handle in
   * whatever state it is.
   */
  async open(owner: Principal, buildId: string): Promise<BuildContextHandle> {
    if (this.closed) throw transferError("TRANSFER_IO");
    return this.authorized(owner, async () => {
      const principalKey = acceptingPrincipalKey(owner);
      if (!principalKey || !/^[A-Za-z0-9_-]{1,64}$/.test(buildId)) throw transferError("NOT_FOUND");
      const build = await prisma.sandboxTemplateBuild.findFirst({
        where: { id: buildId, userId: owner.ownerId, principalKey },
        select: {
          id: true,
          userId: true,
          authorizingKeyId: true,
          state: true,
          contextSha256: true,
          contextBytes: true,
          Context: { select: handleSelect },
        },
      });
      if (!build) throw transferError("NOT_FOUND");
      if (build.Context) return contextHandle(build.Context);
      if (!build.contextSha256 || build.contextBytes == null) throw transferError("NOT_FOUND");
      if (build.state !== "AWAITING_CONTEXT") throw transferError("CONFLICT");
      const total = build.contextBytes;
      if (total <= 0n || total > BigInt(this.limits.maxBytes))
        throw transferError("PAYLOAD_TOO_LARGE");
      const expiresAt = contextOpenExpiresAt(new Date(this.now()));
      try {
        const row = await prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT 1 FROM pg_advisory_xact_lock(${CONTEXT_ADMISSION_LOCK}::bigint)`;
          const prior = await tx.sandboxBuildContext.findUnique({
            where: { buildId },
            select: handleSelect,
          });
          if (prior) return prior;
          const [used] = await tx.$queryRaw<{ account: bigint; global: bigint }[]>`
            SELECT coalesce(sum("totalBytes") FILTER (WHERE "userId" = ${owner.ownerId}), 0)::bigint AS account,
                   coalesce(sum("totalBytes"), 0)::bigint AS global
            FROM sandbox_build_context
            WHERE "reservationHeld"`;
          const scope = contextBudgetRefusal({
            requested: total,
            accountUsed: used?.account ?? 0n,
            globalUsed: used?.global ?? 0n,
            perAccount: this.limits.stagedBytesPerAccount,
            global: this.limits.stagedBytes,
          });
          if (scope) throw buildContextBusy(scope);
          return tx.sandboxBuildContext.create({
            data: {
              buildId,
              userId: build.userId,
              keyId: build.authorizingKeyId,
              totalBytes: total,
              expectedSha256: build.contextSha256 as string,
              idleExpiresAt: new Date(
                Math.min(this.now() + this.limits.idleMs, expiresAt.getTime()),
              ),
              expiresAt,
            },
            select: handleSelect,
          });
        });
        return contextHandle(row);
      } catch (error) {
        // A concurrent open of the same build won the unique buildId.
        if (error instanceof Error && "code" in error && error.code === "P2002")
          return contextHandle(await this.owned(owner, buildId));
        throw error;
      }
    });
  }

  /** Metadata read; holds no permit. */
  async status(owner: Principal, buildId: string): Promise<BuildContextHandle> {
    if (this.closed) throw transferError("TRANSFER_IO");
    return this.authorized(owner, async () => contextHandle(await this.owned(owner, buildId)));
  }

  /** One fixed-grid chunk at the committed tail. Disk first (fsync), then the
   * chunk row; an identical replay of a committed chunk returns the handle. */
  async write(
    owner: Principal,
    buildId: string,
    offset: number,
    bytes: Uint8Array,
  ): Promise<BuildContextHandle> {
    if (bytes.byteLength > TRANSFER_CHUNK_BYTES) throw transferError("PAYLOAD_TOO_LARGE");
    const prior = await this.owned(owner, buildId);
    return this.run(prior.id, () =>
      this.authorized(owner, async () => {
        const copy = Buffer.from(bytes);
        const row = await this.owned(owner, buildId);
        checkChunk(Number(row.totalBytes), offset, copy.byteLength);
        const chunkDigest = digest(copy);
        const old = await prisma.sandboxBuildContextChunk.findUnique({
          where: { contextId_offset: { contextId: row.id, offset: BigInt(offset) } },
        });
        if (old) {
          if (old.digest !== chunkDigest || old.length !== copy.byteLength)
            throw transferError("CONFLICT");
          return contextHandle(row);
        }
        if (row.state !== "OPEN" || this.expired(row)) throw transferError("TRANSFER_EXPIRED");
        if (BigInt(offset) !== row.receivedBytes) throw transferError("CONFLICT");
        const file = await openSpoolFile(
          this.root,
          this.identity,
          this.path(row.id),
          offset === 0 ? "allow" : false,
        );
        try {
          // A prior rollback or crash may have left an unacknowledged tail.
          await file.truncate(offset);
          await writeFully(file, copy, offset);
          await file.sync();
        } finally {
          await file.close();
        }
        if (offset === 0) await syncSpoolRoot(this.root, this.identity);
        const updated = await prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM sandbox_build_context WHERE id = ${row.id} FOR UPDATE`;
          const latest = await tx.sandboxBuildContext.findUniqueOrThrow({
            where: { id: row.id },
            select: handleSelect,
          });
          if (latest.state !== "OPEN" || this.expired(latest))
            throw transferError("TRANSFER_EXPIRED");
          if (latest.receivedBytes !== BigInt(offset)) throw transferError("CONFLICT");
          await tx.sandboxBuildContextChunk.create({
            data: {
              contextId: row.id,
              offset: BigInt(offset),
              length: copy.byteLength,
              digest: chunkDigest,
            },
          });
          return tx.sandboxBuildContext.update({
            where: { id: row.id },
            data: {
              receivedBytes: BigInt(offset + copy.byteLength),
              idleExpiresAt: new Date(
                Math.min(this.now() + this.limits.idleMs, latest.expiresAt.getTime()),
              ),
            },
            select: handleSelect,
          });
        });
        return contextHandle(updated);
      }),
    );
  }

  /** Hashes the complete staged file; a match seals, a mismatch ends the
   * context as `build_context_mismatch`. Replays of a sealed context return. */
  async seal(owner: Principal, buildId: string): Promise<BuildContextHandle> {
    const prior = await this.owned(owner, buildId);
    return this.run(prior.id, () =>
      this.authorized(owner, async () => {
        const row = await this.owned(owner, buildId);
        if (row.state === "SEALED" || row.state === "ADOPTED") return contextHandle(row);
        if (row.state !== "OPEN" || this.expired(row)) throw transferError("TRANSFER_EXPIRED");
        if (row.receivedBytes !== row.totalBytes) throw transferError("CONFLICT");
        const file = await openSpoolFile(this.root, this.identity, this.path(row.id));
        let whole: string;
        try {
          whole = await hashSpoolFile(file, Number(row.totalBytes));
        } finally {
          await file.close();
        }
        if (whole !== row.expectedSha256) {
          await this.end(row, "OPEN", "ABORTED", "build_context_mismatch");
          throw new ORPCError("BAD_REQUEST", {
            data: { code: "template.build_context_mismatch" },
          });
        }
        const sealed = await prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM sandbox_build_context WHERE id = ${row.id} FOR UPDATE`;
          const latest = await tx.sandboxBuildContext.findUniqueOrThrow({
            where: { id: row.id },
            select: handleSelect,
          });
          if (latest.state !== "OPEN" || this.expired(latest))
            throw transferError("TRANSFER_EXPIRED");
          if (latest.receivedBytes !== latest.totalBytes) throw transferError("CONFLICT");
          // The sealed lifetime starts now, from the build's own (clamped)
          // capacity wait; the upload phase's ceiling no longer applies.
          const build = await tx.sandboxTemplateBuild.findUniqueOrThrow({
            where: { id: latest.buildId },
            select: { waitForCapacityMs: true },
          });
          return tx.sandboxBuildContext.update({
            where: { id: row.id },
            data: {
              state: "SEALED",
              expiresAt: contextSealedExpiresAt(new Date(this.now()), build.waitForCapacityMs),
            },
            select: handleSelect,
          });
        });
        this.wake(buildId);
        return contextHandle(sealed);
      }),
    );
  }

  /**
   * Durable terminal intent first (only from the observed live state), then
   * the file goes (releasing the reservation only once that is durable) and
   * the orchestrator wakes. False: the row had moved on.
   */
  private async end(
    row: Pick<ContextRow, "id" | "buildId">,
    from: "OPEN" | "SEALED" | readonly ("OPEN" | "SEALED")[],
    state: "ABORTED" | "EXPIRED",
    errorCode: string | null,
  ) {
    const { count } = await prisma.sandboxBuildContext.updateMany({
      where: { id: row.id, state: typeof from === "string" ? from : { in: [...from] } },
      data: { state, errorCode },
    });
    try {
      await this.release(row.id);
    } finally {
      if (count) this.wake(row.buildId);
    }
    return count > 0;
  }

  /**
   * Unlink the staged name and sync the root; only then, and only for a
   * context that is no longer OPEN or SEALED, drop its reservation. A failed
   * unlink or sync keeps the reservation (the sweep retries).
   */
  private async release(contextId: string) {
    await checkSpoolRoot(this.root, this.identity);
    try {
      await unlink(this.path(contextId));
    } catch (error) {
      if (!missing(error)) throw error;
    }
    // Also after a missing name: a prior unlink may not have been synced.
    await syncSpoolRoot(this.root, this.identity);
    await prisma.sandboxBuildContext.updateMany({
      where: { id: contextId, reservationHeld: true, state: { notIn: [...LIVE_STATES] } },
      data: { reservationHeld: false },
    });
  }

  private async contextOf(principal: Principal, buildId: string) {
    return prisma.sandboxBuildContext.findFirst({
      where: { buildId, userId: principal.ownerId },
      select: { ...handleSelect, Build: { select: { buildSandboxId: true } } },
    });
  }

  /**
   * Port `abortContext` (cleanup class): an OPEN or SEALED context ends
   * ABORTED and its file goes. Adopted (the transfer owns it), ended or absent
   * contexts are a no-op. A busy context refuses retryably.
   */
  async abort(principal: Principal, buildId: string): Promise<void> {
    const row = await this.contextOf(principal, buildId);
    if (!row || !LIVE_STATES.some((state) => state === row.state)) return;
    await this.run(row.id, () => this.end(row, LIVE_STATES, "ABORTED", null)).catch(
      (error: unknown) => {
        throw portError(error);
      },
    );
  }

  /**
   * Port `importContext`: the sealed context becomes an ordinary SEALED upload
   * of the build's READY sandbox through `TransferStore.importSealed`. The
   * import key carries `importAttempt`; a spent prior (crash after tx1) raises
   * the attempt under the context row lock and imports again.
   */
  async importContext(
    transfers: TransferStore,
    principal: Principal,
    buildId: string,
  ): Promise<{ transferId: string }> {
    for (let round = 0; round < 3; round++) {
      const row = await this.contextOf(principal, buildId);
      if (!row) throw new BuildContextPortError("state", false);
      if (row.state === "ADOPTED" && row.transferId) {
        // Step 4 of a crashed import: the staged name must be gone.
        await this.run(row.id, () => this.release(row.id)).catch((error: unknown) => {
          throw portError(error);
        });
        return { transferId: row.transferId };
      }
      if (row.state !== "SEALED") throw new BuildContextPortError("state", false, row.errorCode);
      if (this.expired(row)) {
        await this.run(row.id, () =>
          this.end(row, "SEALED", "EXPIRED", "build_context_expired"),
        ).catch(() => undefined);
        throw new BuildContextPortError("state", false, "build_context_expired");
      }
      const sandboxId = row.Build.buildSandboxId;
      const sandbox = sandboxId
        ? await prisma.sandbox.findFirst({
            where: { id: sandboxId, userId: principal.ownerId },
            select: { id: true, generation: true },
          })
        : null;
      if (!sandbox) throw new BuildContextPortError("state", false);
      const chunks = await prisma.sandboxBuildContextChunk.findMany({
        where: { contextId: row.id },
        orderBy: { offset: "asc" },
        take: Math.ceil(Number(row.totalBytes) / TRANSFER_CHUNK_BYTES) + 1,
        select: { offset: true, length: true, digest: true },
      });
      const attempt = row.importAttempt;
      let result: Awaited<ReturnType<TransferStore["importSealed"]>>;
      try {
        result = await this.run(row.id, () =>
          transfers.importSealed(principal, {
            sandboxId: sandbox.id,
            generation: sandbox.generation,
            idempotencyKey: buildContextImportKey(buildId, attempt),
            guestPath: buildContextGuestPath(buildId),
            sha256: row.expectedSha256,
            totalBytes: Number(row.totalBytes),
            chunks: chunks.map((chunk) => ({
              offset: Number(chunk.offset),
              length: chunk.length,
              digest: chunk.digest,
            })),
            source: { root: this.root, name: this.fileName(row.id) },
            onSealed: async (tx, transferId) => {
              // The context row is a leaf lock, taken last (§3.4).
              await tx.$queryRaw`SELECT id FROM sandbox_build_context WHERE id = ${row.id} FOR UPDATE`;
              const adopted = await tx.sandboxBuildContext.updateMany({
                where: { id: row.id, state: "SEALED", importAttempt: attempt },
                data: { state: "ADOPTED", transferId },
              });
              if (adopted.count !== 1) throw transferError("CONFLICT");
            },
          }),
        );
      } catch (error) {
        if (
          error instanceof ImportSourceError &&
          (error.reason === "missing" || error.reason === "invalid")
        ) {
          await this.run(row.id, () =>
            this.end(row, "SEALED", "ABORTED", "build_context_failed"),
          ).catch(() => undefined);
        }
        throw portError(error);
      }
      if (!result.stale) return { transferId: result.transferId };
      await prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_build_context WHERE id = ${row.id} FOR UPDATE`;
        await tx.sandboxBuildContext.updateMany({
          where: { id: row.id, state: "SEALED", importAttempt: attempt },
          data: { importAttempt: attempt + 1 },
        });
      });
    }
    throw new BuildContextPortError("busy", true);
  }

  /** Port `commitContext`: the existing transfer commit (PUT_FILE) of the
   * adopted context, with the orchestrator's reserved `tb:` key. */
  async commitContext(
    transfers: TransferStore,
    principal: Principal,
    buildId: string,
    transferId: string,
    idempotencyKey: string,
  ): Promise<{ operationId: string }> {
    const row = await this.contextOf(principal, buildId);
    if (row?.state !== "ADOPTED" || row.transferId !== transferId)
      throw new BuildContextPortError("state", false, row?.errorCode ?? null);
    try {
      // A crashed import may have left the staged name (nlink 2).
      await this.run(row.id, () => this.release(row.id));
      const receipt = await transfers.commit(
        principal,
        transferId,
        idempotencyKey,
        row.expectedSha256,
        true,
      );
      return { operationId: receipt.operationId };
    } catch (error) {
      throw portError(error);
    }
  }

  /** Expiry and orphan cleanup (also at runtime for the after-tx2 window). */
  async sweep() {
    if (this.sweeping) return this.sweeping;
    if (this.closed) return;
    this.sweeping = this.expire()
      .then(() => this.cleanDirectory())
      .then(() => this.releaseEnded())
      .finally(() => {
        this.sweeping = undefined;
      });
    return this.sweeping;
  }

  private async scanLive(
    visit: (row: ContextRow) => Promise<void>,
    where: Prisma.SandboxBuildContextWhereInput,
  ) {
    let cursor: string | undefined;
    let failed = false;
    for (;;) {
      const rows = await prisma.sandboxBuildContext.findMany({
        where: { ...where, ...(cursor ? { id: { gt: cursor } } : {}) },
        orderBy: { id: "asc" },
        take: SCAN_BATCH,
        select: handleSelect,
      });
      if (!rows.length) {
        if (failed) throw transferError("TRANSFER_IO");
        return;
      }
      for (const row of rows) {
        try {
          await visit(row);
        } catch {
          failed = true;
        }
      }
      cursor = rows.at(-1)?.id;
    }
  }

  private async expire() {
    const now = new Date(this.now());
    await this.scanLive(
      async (row) => {
        if (this.work.has(row.id)) return;
        await this.run(row.id, () =>
          row.state === "OPEN"
            ? this.end(row, "OPEN", "EXPIRED", "build_context_timeout")
            : this.end(row, "SEALED", "EXPIRED", "build_context_expired"),
        );
      },
      {
        OR: [
          { state: "OPEN", OR: [{ idleExpiresAt: { lte: now } }, { expiresAt: { lte: now } }] },
          { state: "SEALED", expiresAt: { lte: now } },
        ],
      },
    );
  }

  /** Every ended or adopted context still holding its reservation: its
   * staged name goes (again, idempotently) and the reservation is released.
   * Recovery runs before the store opens, so it releases directly. */
  private async releaseEnded(recovering = false) {
    await this.scanLive(
      async (row) => {
        if (recovering) return this.release(row.id);
        if (this.work.has(row.id)) return;
        await this.run(row.id, () => this.release(row.id));
      },
      { reservationHeld: true, state: { notIn: [...LIVE_STATES] } },
    );
  }

  /**
   * Unlinks every staged name whose context is not OPEN or SEALED: adopted
   * (the crash window after `importSealed`'s tx2), ended, or cascaded away by
   * account deletion. Names this store never mints are left alone.
   */
  private async cleanDirectory() {
    await checkSpoolRoot(this.root, this.identity);
    let removed = false;
    for await (const entry of await opendir(this.root)) {
      const id = CONTEXT_FILE.exec(entry.name)?.[1];
      if (!id) {
        console.warn("[template-builds] Ignoring an unexpected entry in the build-context root.");
        continue;
      }
      if (this.work.has(id)) continue;
      const row = await prisma.sandboxBuildContext.findUnique({
        where: { id },
        select: { state: true },
      });
      if (row && LIVE_STATES.some((state) => state === row.state)) continue;
      try {
        await unlink(this.path(id));
        removed = true;
      } catch (error) {
        if (!missing(error)) throw error;
      }
    }
    if (removed) await syncSpoolRoot(this.root, this.identity);
  }

  /**
   * Restart recovery, before the transfer store starts: staged names of
   * adopted/ended contexts go first; then each OPEN context's acknowledged
   * bytes are verified against its chunk digests (the transfer store's
   * algorithm) and its unacknowledged tail is cut; a SEALED context's file
   * must exist with its full size. A context whose bytes are gone or corrupt
   * ends as `build_context_failed`.
   */
  private async recover() {
    await this.cleanDirectory();
    await this.releaseEnded(true);
    await this.scanLive(
      async (row) => {
        try {
          if (row.state === "OPEN") {
            if (row.receivedBytes === 0n) return;
            const file = await openSpoolFile(this.root, this.identity, this.path(row.id));
            try {
              await verifyAcknowledged(
                file,
                Number(row.receivedBytes),
                Number(row.totalBytes),
                (offset) =>
                  prisma.sandboxBuildContextChunk.findUnique({
                    where: { contextId_offset: { contextId: row.id, offset: BigInt(offset) } },
                  }),
              );
            } finally {
              await file.close();
            }
          } else {
            // A SEALED file may briefly have a second name: an import that
            // crashed after linking, before tx2. The transfer store's own
            // recovery (next) retires that row and unlinks its name.
            const stat = await lstat(this.path(row.id));
            if (stat.isSymbolicLink()) throw transferError("TRANSFER_IO");
            checkSpoolStat(stat, stat.nlink === 2 ? 2 : 1);
            if (stat.size !== Number(row.totalBytes)) throw transferError("TRANSFER_IO");
          }
        } catch (error) {
          if (!storageFailure(error)) throw error;
          await this.end(row, row.state as "OPEN" | "SEALED", "ABORTED", "build_context_failed");
        }
      },
      { state: { in: [...LIVE_STATES] } },
    );
  }
}

/** Store and transfer refusals as typed port errors (§3.3 retry table). */
function portError(error: unknown): unknown {
  if (error instanceof BuildContextPortError) return error;
  if (error instanceof ImportSourceError)
    return new BuildContextPortError(
      error.reason === "linked" ? "busy" : error.reason,
      error.reason === "linked",
      error.reason === "linked" ? null : "build_context_failed",
    );
  if (error instanceof ORPCError) {
    const code = (error.data as { code?: unknown } | undefined)?.code ?? error.code;
    if (code === "TRANSFER_QUOTA" || code === "TRANSFER_IO" || code === "CONFLICT")
      return new BuildContextPortError("busy", true);
    if (code === "TRANSFER_EXPIRED") return new BuildContextPortError("state", false);
  }
  return error;
}
