import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Principal } from "@wssp/api/sandbox/contracts";
import { BuildContextPortError } from "@wssp/api/template-builds/context-port";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { TRANSFER_CHUNK_BYTES as CHUNK } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";
import {
  seedLaunchHost,
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";
import type { SandboxApiEnv } from "../sandbox-api/auth.js";
import { sdkErrorResponse } from "../sandbox-api/errors.js";
import type { TransferLimits } from "../sandbox-transfers/limits.js";

vi.mock("@wssp/api/sandbox/budgets", () => ({ consumeSandboxWriteBudget: async () => {} }));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    TRANSFER_GLOBAL_ACTIVE: 16,
    TRANSFER_OWNER_ACTIVE: 4,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));

const db = await pgTestDatabase();
const { TransferStore } = await import("../sandbox-transfers/store.js");
const { BuildContextStore, buildContextRoot } = await import("./context-store.js");
const { registerBuildContextRoutes } = await import("./context-routes.js");
const { hashLegacyEnvFreeBody } = await import("@wssp/api/sandbox/idempotency");

const transferLimits: TransferLimits = {
  maxBytes: CHUNK * 4,
  diskBytes: CHUNK * 8,
  ownerActive: 4,
  globalActive: 16,
  idleMs: 900_000,
  absoluteMs: 3_600_000,
};
const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const HOUR = 3_600_000;
type Stores = {
  contexts: InstanceType<typeof BuildContextStore>;
  transfers: InstanceType<typeof TransferStore>;
};
const open: { close(): Promise<void> }[] = [];
const dirs: string[] = [];
const clock = { offset: 0 };
const wake = vi.fn();

async function spool() {
  const base = await fs.mkdtemp(join(tmpdir(), "wssp-b5c-"));
  dirs.push(base);
  return join(base, "spool");
}
async function startContexts(
  transferRoot: string,
  overrides: Partial<{ perAccount: number; global: number }> = {},
) {
  const contexts = new BuildContextStore(
    transferRoot,
    {
      maxBytes: CHUNK * 4,
      stagedBytesPerAccount: overrides.perAccount ?? CHUNK * 8,
      stagedBytes: overrides.global ?? CHUNK * 32,
      idleMs: 900_000,
      globalActive: 16,
    },
    wake,
    () => Date.now() + clock.offset,
  );
  await contexts.start();
  open.push(contexts);
  return contexts;
}
async function startTransfers(transferRoot: string, limits = transferLimits) {
  const transfers = new TransferStore(transferRoot, limits);
  await transfers.start();
  open.push(transfers);
  return transfers;
}
async function stop(...stores: { close(): Promise<void> }[]) {
  for (const store of stores) await store.close();
}

async function owner() {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const host = await seedLaunchHost(db.inspect, {
    data: { userId: id, slug: "host", label: "host" },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "image",
      label: "image",
      imageRef: "image",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const session: Principal = { kind: "session", ownerId: id };
  const key = async (): Promise<Principal> => {
    const row = await db.inspect.sdkKey.create({
      data: {
        userId: id,
        name: "key",
        lookupPrefix: randomUUID(),
        secretDigest: randomUUID(),
        resourceMode: "ALLOWLIST",
        scopes: ["files:read", "files:write"],
      },
    });
    return {
      kind: "sdkKey",
      keyId: row.id,
      ownerId: id,
      expiresAt: null,
      resourceMode: "ALLOWLIST",
      scopes: new Set(["files:read", "files:write"]),
      allowedHostIds: new Set([host.id]),
      allowedRevisionIds: new Set([revision.id]),
      allowedPoolIds: new Set(),
    };
  };
  const sandbox = () =>
    seedSandboxInstance(db.inspect, {
      data: {
        userId: id,
        sandboxHostId: host.id,
        originHostId: host.id,
        templateId: revision.id,
        originPoolId: null,
        state: "READY",
      },
    });
  /** A COPY build awaiting its context, accepted by `by` (session or key). */
  const build = async (
    content: Uint8Array,
    by: { keyId: string } | null = null,
    createdAt?: Date,
    /** A pool build's frozen capacity wait (direct targets never wait). */
    waitForCapacityMs?: number,
  ) =>
    db.inspect.sandboxTemplateBuild.create({
      data: {
        userId: id,
        templateId: revision.templateId,
        tag: "latest",
        principalKind: by ? "sdkKey" : "session",
        authorizingKeyId: by?.keyId ?? null,
        principalKey: by ? `k:${by.keyId}` : "s",
        idempotencyKey: `build-${randomUUID()}`,
        requestBodyHash: "hash",
        recipe: { v: 1 },
        recipeDigest: "a".repeat(64),
        // Distinct per build: active builds dedupe on the digest.
        buildDigest: hash(Buffer.from(randomUUID())),
        sourceFormat: "RECIPE",
        baseRevisionId: revision.id,
        baseFingerprint: revision.incusFingerprint,
        ...(waitForCapacityMs === undefined
          ? { requestedHostId: host.id, targetKey: host.id }
          : { poolId: `pool-${id}`, targetKey: `pool-${id}`, waitForCapacityMs }),
        cpuCount: 1,
        memoryMiB: 1024,
        diskGiB: 32,
        timeoutMinutes: 10,
        reservedMinutes: 10,
        chargeMonth: new Date("2026-11-01T00:00:00Z"),
        state: "AWAITING_CONTEXT",
        contextSha256: hash(content),
        contextBytes: BigInt(content.byteLength),
        ...(createdAt ? { createdAt } : {}),
      },
    });
  return { id, session, key, sandbox, build };
}
const keyIdOf = (p: Principal) => (p as { keyId: string }).keyId;

async function upload(
  contexts: InstanceType<typeof BuildContextStore>,
  who: Principal,
  buildId: string,
  content: Buffer,
) {
  await contexts.open(who, buildId);
  for (let offset = 0; offset < content.byteLength; offset += CHUNK)
    await contexts.write(who, buildId, offset, content.subarray(offset, offset + CHUNK));
  return contexts.seal(who, buildId);
}
/** A sealed context whose build sandbox is READY: what the orchestrator imports. */
async function sealedReady(stores: Stores, content = Buffer.from(randomUUID().repeat(CHUNK / 18))) {
  const o = await owner();
  const build = await o.build(content);
  await upload(stores.contexts, o.session, build.id, content);
  const sandbox = await o.sandbox();
  await db.inspect.sandboxTemplateBuild.update({
    where: { id: build.id },
    data: { state: "RUNNING", buildSandboxId: sandbox.id },
  });
  const context = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
    where: { buildId: build.id },
  });
  return { o, build, sandbox, content, context };
}

afterEach(async () => {
  clock.offset = 0;
  wake.mockReset();
  for (const store of open.splice(0)) await store.close();
  await db.inspect.sandboxTransfer.updateMany({
    where: { reservationHeld: true },
    data: { state: "EXPIRED", reservationHeld: false },
  });
  await db.inspect.sandboxBuildContext.updateMany({
    where: { state: { in: ["OPEN", "SEALED"] } },
    data: { state: "ABORTED" },
  });
  await db.inspect.sandboxBuildContext.updateMany({
    where: { reservationHeld: true },
    data: { reservationHeld: false },
  });
  for (const dir of dirs.splice(0)) await fs.rm(dir, { recursive: true, force: true });
});
afterAll(() => db.close());

describe("routes: only the accepting principal of the caller's own build (§3.7, pg 8b)", () => {
  it("answers NOT_FOUND to another owner, a session on a keyed build, another key, and a key on a session build", async () => {
    const root = await spool();
    const contexts = await startContexts(root);
    const a = await owner(),
      b = await owner();
    const k1 = await a.key(),
      k2 = await a.key(),
      bKey = await b.key();
    const content = Buffer.from("context bytes");
    const sessionBuild = await a.build(content);
    const keyedBuild = await a.build(content, { keyId: keyIdOf(k1) });
    const principals: Record<string, Principal> = {
      aSession: a.session,
      k1,
      k2,
      bSession: b.session,
      bKey,
    };
    const app = new Hono<SandboxApiEnv>();
    app.onError((error, c) => sdkErrorResponse(c, error));
    app.use("*", async (c, next) => {
      c.set("requestId", randomUUID());
      await next();
    });
    registerBuildContextRoutes(
      app,
      () => contexts,
      async (c) => {
        const who = principals[c.req.header("x-test-principal") ?? ""];
        if (!who) throw new Error("unknown test principal");
        return who;
      },
    );
    const call = (who: string, method: string, path: string, body?: Uint8Array) =>
      app.request(path, {
        method,
        headers: {
          "x-test-principal": who,
          ...(body
            ? {
                "content-type": "application/octet-stream",
                "content-length": String(body.byteLength),
              }
            : {}),
        },
        ...(body ? { body } : {}),
      });
    const routes = (id: string) =>
      [
        ["POST", `/template-builds/${id}/context`],
        ["PUT", `/template-builds/${id}/context/chunks/0`, content],
        ["POST", `/template-builds/${id}/context/seal`],
      ] as const;
    // Before any open (no context row yet), and after the owner opened it.
    for (const phase of ["before", "after"]) {
      if (phase === "after") {
        expect(
          (await call("aSession", "POST", `/template-builds/${sessionBuild.id}/context`)).status,
        ).toBe(200);
        expect((await call("k1", "POST", `/template-builds/${keyedBuild.id}/context`)).status).toBe(
          200,
        );
      }
      const denied: [string, string][] = [
        ["bSession", sessionBuild.id],
        ["bKey", sessionBuild.id],
        ["k1", sessionBuild.id],
        ["k2", sessionBuild.id],
        ["bSession", keyedBuild.id],
        ["aSession", keyedBuild.id],
        ["k2", keyedBuild.id],
        ["aSession", "nonexistent-build"],
      ];
      for (const [who, id] of denied)
        for (const [method, path, body] of routes(id)) {
          const response = await call(who, method, path, body);
          expect([who, id, method, path, response.status]).toEqual([who, id, method, path, 404]);
          expect(await response.json()).toMatchObject({ error: { code: "NOT_FOUND" } });
        }
    }
    // Nothing was written by the refused calls.
    expect(
      await db.inspect.sandboxBuildContextChunk.count({ where: { Context: { userId: a.id } } }),
    ).toBe(0);
    // The accepting principals can upload and seal.
    for (const [who, id] of [
      ["aSession", sessionBuild.id],
      ["k1", keyedBuild.id],
    ] as const) {
      const put = await call(who, "PUT", `/template-builds/${id}/context/chunks/0`, content);
      expect(put.status).toBe(200);
      const sealed = await call(who, "POST", `/template-builds/${id}/context/seal`);
      expect(await sealed.json()).toMatchObject({
        state: "SEALED",
        receivedBytes: content.byteLength,
      });
    }
    expect(wake).toHaveBeenCalledWith(sessionBuild.id);
  });
});

describe("budgets: per-account share inside the global cap (§3.7, r3 N21, pg 25)", () => {
  it("accounts A and B at their share, C still opens; A's next is account-busy, C's next global-busy", async () => {
    const contexts = await startContexts(await spool(), {
      perAccount: CHUNK * 2,
      global: CHUNK * 5,
    });
    const [a, b, c] = [await owner(), await owner(), await owner()];
    const unit = Buffer.alloc(CHUNK, 7);
    for (const o of [a, b]) {
      await contexts.open(o.session, (await o.build(unit)).id);
      await contexts.open(o.session, (await o.build(unit)).id);
    }
    await contexts.open(c.session, (await c.build(unit)).id);
    await expect(contexts.open(a.session, (await a.build(unit)).id)).rejects.toMatchObject({
      status: 429,
      data: { code: "template.build_context_busy", scope: "account" },
    });
    await expect(contexts.open(c.session, (await c.build(unit)).id)).rejects.toMatchObject({
      status: 429,
      data: { code: "template.build_context_busy", scope: "global" },
    });
    // A re-open of an admitted build is idempotent (no second reservation).
    const again = await a.build(Buffer.alloc(1));
    await expect(contexts.open(a.session, again.id)).rejects.toMatchObject({ status: 429 });
    // An ended context releases its reservation.
    const first = await db.inspect.sandboxBuildContext.findFirstOrThrow({
      where: { userId: a.id },
    });
    await contexts.abort(a.session, first.buildId);
    await expect(contexts.open(a.session, again.id)).resolves.toMatchObject({ state: "OPEN" });
    // Staged contexts never hold a transfer slot or disk (r2 N8, pg 19).
    expect(
      await db.inspect.sandboxTransfer.count({ where: { userId: { in: [a.id, b.id, c.id] } } }),
    ).toBe(0);
  });

  it("an ended context stays charged until its staged file is durably deleted", async () => {
    const contexts = await startContexts(await spool(), {
      perAccount: CHUNK * 2,
      global: CHUNK * 2,
    });
    const a = await owner();
    const unit = Buffer.alloc(CHUNK, 7);
    const first = await a.build(unit);
    await upload(contexts, a.session, first.id, unit);
    const row = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
      where: { buildId: first.id },
    });
    // The deletion fails: the staged name is pinned by a read-only root.
    await fs.chmod(contexts.root, 0o500);
    try {
      await expect(contexts.abort(a.session, first.id)).rejects.toBeDefined();
    } finally {
      await fs.chmod(contexts.root, 0o700);
    }
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({ state: "ABORTED", reservationHeld: true });
    await fs.stat(join(contexts.root, contexts.fileName(row.id)));
    // Its bytes are still on disk, so they still count.
    const next = await a.build(Buffer.alloc(CHUNK * 2, 1));
    await expect(contexts.open(a.session, next.id)).rejects.toMatchObject({
      status: 429,
      data: { code: "template.build_context_busy" },
    });
    // The sweep deletes the file, then releases the reservation.
    await contexts.sweep();
    await expect(fs.stat(join(contexts.root, contexts.fileName(row.id)))).rejects.toThrow();
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: row.id } }),
    ).toMatchObject({ reservationHeld: false });
    await expect(contexts.open(a.session, next.id)).resolves.toMatchObject({ state: "OPEN" });
  });
});

describe("lifecycle (§3.7, pg 16/18/25)", () => {
  it("OPEN is bounded by idle progress, not by a fixed window from acceptance", async () => {
    const contexts = await startContexts(await spool());
    const o = await owner();
    const content = Buffer.from(randomUUID().repeat((CHUNK * 3) / 36));
    const slow = await o.build(content);
    await contexts.open(o.session, slow.id);
    // One chunk every 14 min: 42 min after acceptance, still OPEN and sealable.
    for (let offset = 0, step = 1; offset < content.byteLength; offset += CHUNK, step++) {
      clock.offset = step * 14 * 60_000;
      await contexts.sweep();
      await contexts.write(o.session, slow.id, offset, content.subarray(offset, offset + CHUNK));
    }
    clock.offset += 14 * 60_000;
    await contexts.sweep();
    await expect(contexts.seal(o.session, slow.id)).resolves.toMatchObject({ state: "SEALED" });
    // The upload phase still has an absolute ceiling: 6 h after it opened.
    const ceiling = await o.build(content);
    clock.offset = 0;
    await contexts.open(o.session, ceiling.id);
    const opened = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
      where: { buildId: ceiling.id },
    });
    expect(opened.expiresAt.getTime() - opened.createdAt.getTime()).toBeGreaterThanOrEqual(
      6 * HOUR - 1000,
    );
    expect(opened.expiresAt.getTime() - opened.createdAt.getTime()).toBeLessThanOrEqual(
      6 * HOUR + 1000,
    );
  });

  it("mismatched seal, OPEN idle timeout, SEALED survives idle and expires at the 6 h ceiling", async () => {
    const contexts = await startContexts(await spool());
    const o = await owner();
    const content = Buffer.from("the real context");
    // Wrong bytes: the seal hash differs from the accepted contextSha256.
    const wrong = await o.build(content);
    await contexts.open(o.session, wrong.id);
    await contexts.write(o.session, wrong.id, 0, Buffer.from("the fake context"));
    await expect(contexts.seal(o.session, wrong.id)).rejects.toMatchObject({ status: 400 });
    const mismatch = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
      where: { buildId: wrong.id },
    });
    expect(mismatch).toMatchObject({ state: "ABORTED", errorCode: "build_context_mismatch" });
    await expect(fs.stat(join(contexts.root, contexts.fileName(mismatch.id)))).rejects.toThrow();
    // OPEN idle → build_context_timeout.
    const idle = await o.build(content);
    await contexts.open(o.session, idle.id);
    // SEALED with an unlimited wait (stored as the longest finite wait):
    // expires at seal + 15 min + the 6 h ceiling.
    const sealed = await o.build(content, null, undefined, 2_073_600_000);
    const sealedAt = Date.now();
    await upload(contexts, o.session, sealed.id, content);
    // A direct build never waits for capacity: seal + 15 min only.
    const direct = await o.build(content);
    await upload(contexts, o.session, direct.id, content);
    clock.offset = 2 * HOUR; // far past the 15 min idle timeout
    await contexts.sweep();
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { buildId: idle.id } }),
    ).toMatchObject({
      state: "EXPIRED",
      errorCode: "build_context_timeout",
    });
    expect(
      (await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { buildId: sealed.id } }))
        .state,
    ).toBe("SEALED");
    const row = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
      where: { buildId: sealed.id },
    });
    const sealedSpan = row.expiresAt.getTime() - sealedAt;
    expect(sealedSpan).toBeGreaterThanOrEqual(6 * HOUR + 15 * 60_000);
    expect(sealedSpan).toBeLessThan(6 * HOUR + 15 * 60_000 + 60_000);
    // The direct build's sealed context expired at the first sweep past 15 min.
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { buildId: direct.id } }),
    ).toMatchObject({ state: "EXPIRED", errorCode: "build_context_expired" });
    clock.offset = 6 * HOUR + 15 * 60_000 + 1000;
    await contexts.sweep();
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { buildId: sealed.id } }),
    ).toMatchObject({
      state: "EXPIRED",
      errorCode: "build_context_expired",
    });
    await expect(fs.stat(join(contexts.root, contexts.fileName(row.id)))).rejects.toThrow();
    expect(wake).toHaveBeenCalledWith(idle.id);
    expect(wake).toHaveBeenCalledWith(sealed.id);
  });

  it("abort while unadopted ends the context, unlinks it and touches no transfer (pg 20)", async () => {
    const contexts = await startContexts(await spool());
    const o = await owner();
    const content = Buffer.from("abort me");
    const build = await o.build(content);
    await upload(contexts, o.session, build.id, content);
    const row = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
      where: { buildId: build.id },
    });
    await contexts.abort(o.session, build.id);
    await contexts.abort(o.session, build.id);
    expect(
      (await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: row.id } })).state,
    ).toBe("ABORTED");
    await expect(fs.stat(join(contexts.root, contexts.fileName(row.id)))).rejects.toThrow();
    expect(await db.inspect.sandboxTransfer.count({ where: { userId: o.id } })).toBe(0);
  });
});

describe("import (TransferStore.importSealed, §3.7, r3 N17, pg 16)", () => {
  it("adopts into exactly one SEALED transfer under replay; the commit issues PUT_FILE", async () => {
    const root = await spool();
    const contexts = await startContexts(root);
    const transfers = await startTransfers(root);
    const content = Buffer.alloc(CHUNK + 5, 3);
    const s = await sealedReady({ contexts, transfers }, content);
    const first = await contexts.importContext(transfers, s.o.session, s.build.id);
    expect(await contexts.importContext(transfers, s.o.session, s.build.id)).toEqual(first);
    const rows = await db.inspect.sandboxTransfer.findMany({ where: { userId: s.o.id } });
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      id: first.transferId,
      state: "SEALED",
      sha256: hash(content),
      receivedBytes: BigInt(content.byteLength),
      guestPath: `/var/tmp/wssp-build/${s.build.id}/context.tar`,
      idempotencyKey: `tb:${s.build.id}:import:0:0`,
    });
    expect(
      await db.inspect.sandboxTransferChunk.count({ where: { transferId: first.transferId } }),
    ).toBe(2);
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: s.context.id } }),
    ).toMatchObject({
      state: "ADOPTED",
      transferId: first.transferId,
    });
    // One name again: the staged name is gone, the spool file has nlink 1.
    await expect(fs.stat(join(contexts.root, contexts.fileName(s.context.id)))).rejects.toThrow();
    const adopted = await fs.stat(join(root, `${first.transferId}.spool`));
    expect(adopted.nlink).toBe(1);
    expect(await fs.readFile(join(root, `${first.transferId}.spool`))).toEqual(content);
    const key = `tb:${s.build.id}:context:0:0`;
    const committed = await contexts.commitContext(
      transfers,
      s.o.session,
      s.build.id,
      first.transferId,
      key,
    );
    expect(
      await contexts.commitContext(transfers, s.o.session, s.build.id, first.transferId, key),
    ).toEqual(committed);
    expect(
      await db.inspect.sandboxOperation.findUniqueOrThrow({ where: { id: committed.operationId } }),
    ).toMatchObject({
      kind: "PUT_FILE",
      idempotencyKey: key,
    });
    // An adopted context ignores abort (the transfer owns the bytes now).
    await contexts.abort(s.o.session, s.build.id);
    expect(
      (await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: s.context.id } }))
        .state,
    ).toBe("ADOPTED");
    // Restart after import: transfer recovery keeps the SEALED transfer.
    await stop(contexts, transfers);
    await startContexts(root);
    await startTransfers(root);
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: first.transferId } }),
    ).toMatchObject({
      state: "SEALED",
      reservationHeld: true,
    });
  });

  it("crash after tx1 (ALLOCATING, file linked): restart retires it, the staged file survives, attempt 1 imports", async () => {
    const root = await spool();
    const contexts = await startContexts(root);
    const transfers = await startTransfers(root);
    const s = await sealedReady({ contexts, transfers });
    const staged = join(contexts.root, contexts.fileName(s.context.id));
    // The durable state tx1 + link leave behind when the process dies.
    const guestPath = `/var/tmp/wssp-build/${s.build.id}/context.tar`;
    const crashed = randomUUID();
    await db.inspect.sandboxTransfer.create({
      data: {
        id: crashed,
        userId: s.o.id,
        sandboxId: s.sandbox.id,
        acceptedHostId: s.sandbox.sandboxHostId!,
        generation: s.sandbox.generation,
        direction: "UPLOAD",
        guestPath,
        idempotencyKey: `tb:${s.build.id}:import:0:0`,
        requestBodyHash: hashLegacyEnvFreeBody({
          kind: "import",
          sandboxId: s.sandbox.id,
          generation: s.sandbox.generation,
          guestPath,
          sha256: hash(s.content),
          totalBytes: s.content.byteLength,
        }),
        totalBytes: BigInt(s.content.byteLength),
        idleExpiresAt: new Date(Date.now() + HOUR),
        expiresAt: new Date(Date.now() + HOUR),
      },
    });
    await fs.link(staged, join(root, `${crashed}.spool`));
    await stop(contexts, transfers);
    // Context recovery (first) accepts the second name of a SEALED file.
    const contexts2 = await startContexts(root);
    expect(
      (await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: s.context.id } }))
        .state,
    ).toBe("SEALED");
    const transfers2 = await startTransfers(root);
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: crashed } }),
    ).toMatchObject({
      state: "EXPIRED",
      reservationHeld: false,
    });
    expect((await fs.stat(staged)).nlink).toBe(1);
    const adopted = await contexts2.importContext(transfers2, s.o.session, s.build.id);
    expect(adopted.transferId).not.toBe(crashed);
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: adopted.transferId } }),
    ).toMatchObject({
      state: "SEALED",
      idempotencyKey: `tb:${s.build.id}:import:1:0`,
    });
    expect(
      (await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: s.context.id } }))
        .importAttempt,
    ).toBe(1);
  });

  it("crash after tx2 before unlink: context recovery (before transfer start) removes the staged name; the transfer survives", async () => {
    const root = await spool();
    let contexts = await startContexts(root);
    let transfers = await startTransfers(root);
    const s = await sealedReady({ contexts, transfers });
    const staged = join(contexts.root, contexts.fileName(s.context.id));
    const { transferId } = await contexts.importContext(transfers, s.o.session, s.build.id);
    await stop(contexts, transfers);
    // Re-create the second name step 4 would have removed.
    await fs.link(join(root, `${transferId}.spool`), staged);
    contexts = await startContexts(root);
    await expect(fs.stat(staged)).rejects.toThrow();
    transfers = await startTransfers(root);
    expect(
      await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: transferId } }),
    ).toMatchObject({
      state: "SEALED",
      reservationHeld: true,
    });
    expect((await fs.stat(join(root, `${transferId}.spool`))).nlink).toBe(1);
    const op = await contexts.commitContext(
      transfers,
      s.o.session,
      s.build.id,
      transferId,
      `tb:${s.build.id}:context:0:0`,
    );
    expect(op.operationId).toBeTruthy();
  });

  it("the order matters: transfer recovery alone would retire an adopted spool that still has two names", async () => {
    const root = await spool();
    const contexts = await startContexts(root);
    let transfers = await startTransfers(root);
    const s = await sealedReady({ contexts, transfers });
    const { transferId } = await contexts.importContext(transfers, s.o.session, s.build.id);
    await stop(contexts, transfers);
    await fs.link(
      join(root, `${transferId}.spool`),
      join(contexts.root, contexts.fileName(s.context.id)),
    );
    transfers = await startTransfers(root);
    expect(
      (await db.inspect.sandboxTransfer.findUniqueOrThrow({ where: { id: transferId } })).state,
    ).toBe("FAILED");
  });

  it("boots with staged files present (sibling root) and refuses an import over the transfer disk limit as retryable", async () => {
    const root = await spool();
    expect(buildContextRoot(root)).toBe(`${root}.build-context`);
    const contexts = await startContexts(root);
    const transfers = await startTransfers(root);
    const s = await sealedReady({ contexts, transfers }, Buffer.alloc(CHUNK * 3, 1));
    // Another open context file stays staged across a restart.
    const other = await s.o.build(Buffer.from("x"));
    await contexts.open(s.o.session, other.id);
    await contexts.write(s.o.session, other.id, 0, Buffer.from("x"));
    await stop(contexts, transfers);
    const contexts2 = await startContexts(root);
    const tight = await startTransfers(root, { ...transferLimits, diskBytes: CHUNK * 2 });
    const refused = await contexts2
      .importContext(tight, s.o.session, s.build.id)
      .catch((error: unknown) => error);
    expect(refused).toBeInstanceOf(BuildContextPortError);
    expect(refused).toMatchObject({ code: "busy", retryable: true });
    expect(
      (await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: s.context.id } }))
        .state,
    ).toBe("SEALED");
    expect(await db.inspect.sandboxTransfer.count({ where: { userId: s.o.id } })).toBe(0);
  });

  it("a staged name replaced by a symlink is refused terminally and ends the context", async () => {
    const root = await spool();
    const contexts = await startContexts(root);
    const transfers = await startTransfers(root);
    const s = await sealedReady({ contexts, transfers });
    const staged = join(contexts.root, contexts.fileName(s.context.id));
    const elsewhere = join(root, "..", "elsewhere");
    await fs.rename(staged, elsewhere);
    await fs.symlink(elsewhere, staged);
    const refused = await contexts
      .importContext(transfers, s.o.session, s.build.id)
      .catch((error: unknown) => error);
    expect(refused).toMatchObject({ code: "invalid", retryable: false });
    expect(
      await db.inspect.sandboxBuildContext.findUniqueOrThrow({ where: { id: s.context.id } }),
    ).toMatchObject({
      state: "ABORTED",
      errorCode: "build_context_failed",
    });
    expect(
      await db.inspect.sandboxTransfer.findFirstOrThrow({ where: { userId: s.o.id } }),
    ).toMatchObject({ state: "FAILED", reservationHeld: false });
  });
});
