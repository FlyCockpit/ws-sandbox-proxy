vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "template-builds-http-fixture",
    RATE_LIMIT_RPC_POINTS: 10000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30000,
    RATE_LIMIT_SDK_KEY_POINTS: 10000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30000,
    SANDBOX_MAX_TIMEOUT_MS: 86400000,
    TRANSFER_GLOBAL_ACTIVE: 16,
    TRANSFER_OWNER_ACTIVE: 4,
    TEMPLATE_BUILD_MAX_CONCURRENT_PER_ACCOUNT: 20,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.36" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});
vi.mock("@wssp/api/sandbox/image-store/config", async (original) => ({
  ...(await original<typeof import("@wssp/api/sandbox/image-store/config")>()),
  imageDistributionMode: () => "peer",
}));

import { createHash, randomUUID } from "node:crypto";
import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { TRANSFER_CHUNK_BYTES as CHUNK } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, describe, expect, it, vi } from "vitest";
import {
  buildOwnerFixture,
  currentOperation,
  fakeDaemon,
} from "../../../../packages/api/src/template-builds/testing/build-fixtures";
import { type BuildLogEntry, createWsspClient, Template } from "../../../../packages/sdk/src/index";

/**
 * Template builds over `/v1` (B7): the lane C SDK e2e (a keyed COPY build
 * through the real router, context upload, fake daemon, streamed logs), key
 * visibility (pg 26), cross-owner ids (pg 8b, route half), scope gating and
 * the accepting-principal rule of the context routes.
 */
const db = await pgTestDatabase();
const { createSandboxApi } = await import("./middleware.js");
const { TransferStore } = await import("../sandbox-transfers/store.js");
const { BuildContextStore } = await import("../template-builds/context-store.js");
const { bindBuildContextStores } = await import("../template-builds/runtime.js");
const { advanceTemplateBuild } = await import("@wssp/api/template-builds/orchestrator");
const { acceptTemplateBuild } = await import("@wssp/api/template-builds/service");
const { finalizeCapture } = await import("@wssp/api/sandbox/image-store/captures");
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");

const daemon = fakeDaemon(db);
const dirs: string[] = [];
const stores: { close(): Promise<void> }[] = [];
afterAll(async () => {
  for (const store of stores) await store.close();
  for (const dir of dirs) await fs.rm(dir, { recursive: true, force: true });
  await db.close();
});

const base = await fs.mkdtemp(join(tmpdir(), "wssp-b7-builds-"));
dirs.push(base);
const contexts = new BuildContextStore(join(base, "spool"), {
  maxBytes: CHUNK * 4,
  stagedBytesPerAccount: CHUNK * 8,
  stagedBytes: CHUNK * 32,
  idleMs: 900_000,
  globalActive: 16,
});
await contexts.start();
const transfers = new TransferStore(join(base, "spool"), {
  maxBytes: CHUNK * 4,
  diskBytes: CHUNK * 8,
  ownerActive: 4,
  globalActive: 16,
  idleMs: 900_000,
  absoluteMs: 3_600_000,
});
await transfers.start();
stores.push(contexts, transfers);
bindBuildContextStores(contexts, transfers);

const app = new Hono().route("/v1", createSandboxApi());
type Page = { items: { id: string }[]; nextCursor: string | null };
/** A response body as test data of the expected shape. */
async function body<T = Record<string, unknown>>(response: Response): Promise<T> {
  return (await response.json()) as T;
}
type Fixture = Awaited<ReturnType<typeof buildOwnerFixture>>;

async function mintKey(
  f: Fixture,
  mode: "ALL_OWNED" | "ALLOWLIST",
  scopes: string[] = ["templates:build", "templates:write"],
) {
  return createSdkKey(f.session, {
    name: `${mode}-${randomUUID().slice(0, 6)}`,
    resourceMode: mode,
    hostIds: mode === "ALLOWLIST" ? [f.host.id] : [],
    templateRevisionIds: mode === "ALLOWLIST" ? [f.base.id] : [],
    poolIds: [],
    scopes: scopes as never,
  });
}

function call(
  secret: string,
  method: string,
  path: string,
  body?: unknown,
  headers: Record<string, string> = {},
) {
  const binary = body instanceof Uint8Array;
  return app.request(path, {
    method,
    headers: {
      authorization: `Bearer ${secret}`,
      ...(body === undefined
        ? {}
        : { "content-type": binary ? "application/octet-stream" : "application/json" }),
      ...headers,
    },
    ...(body === undefined ? {} : { body: binary ? (body as Uint8Array) : JSON.stringify(body) }),
  });
}
const RUN_RECIPE = {
  version: 1,
  from: { template: "base" },
  steps: [{ type: "run", script: "true" }],
};
async function createOverHttp(
  secret: string,
  f: Fixture,
  extra: Record<string, unknown> = {},
  recipe: unknown = RUN_RECIPE,
) {
  const response = await call(
    secret,
    "POST",
    "/v1/template-builds",
    {
      template: { slug: `target-${randomUUID().slice(0, 8)}` },
      recipe,
      sandboxHostId: f.host.id,
      noCache: true,
      ...extra,
    },
    { "idempotency-key": randomUUID() },
  );
  expect(response.status, JSON.stringify(await response.clone().json())).toBe(201);
  return (await response.json()) as {
    build: { id: string; acceptedBy: string };
    contextUpload: { totalBytes: number } | null;
  };
}

/**
 * Drives a build the way the server tick and the relay would: advance the
 * orchestrator, and complete each issued operation like the host.
 */
async function drive(f: Fixture, stop: () => boolean) {
  for (let i = 0; i < 400 && !stop(); i++) {
    const build = await db.inspect.sandboxTemplateBuild.findFirst({
      where: { userId: f.id },
      orderBy: { createdAt: "desc" },
    });
    if (build && ["SUCCEEDED", "FAILED", "CANCELLED"].includes(build.state)) return build;
    if (build) {
      await advanceTemplateBuild({ id: build.id, userId: f.id });
      const now = await db.inspect.sandboxTemplateBuild.findUniqueOrThrow({
        where: { id: build.id },
      });
      const vm = await db.inspect.sandbox.findUnique({ where: { buildId: build.id } });
      const op = await currentOperation(db, build.id);
      const open =
        op && !["SUCCEEDED", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"].includes(op.state);
      if (op && open && vm) {
        if (op.kind === "CREATE_SANDBOX") await daemon.ready(build.id);
        else if (op.kind === "RUN_COMMAND")
          await daemon.command(op.id, 0, `output of ${op.idempotencyKey}\n`);
        else if (op.kind === "PUT_FILE") await daemon.succeed(op.id);
        else if (op.kind === "STOP_SANDBOX") await daemon.stopped(op.id, vm.id);
      }
      if (now.state === "CAPTURING" && now.captureOperationId) {
        const capture = await db.inspect.sandboxTemplateCapture.findUniqueOrThrow({
          where: { operationId: now.captureOperationId },
        });
        if (capture.state !== "FINALIZED") {
          const host = await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } });
          await daemon.captured(capture.operationId, host.id, host.connectionEpoch).catch(() => {});
          await finalizeCapture(capture.operationId);
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return null;
}

describe("lane C e2e over /v1: an SDK keyed COPY build with streamed logs", () => {
  it("packs, accepts, uploads, seals, disposes, then follows the build to SUCCEEDED", async () => {
    const f = await buildOwnerFixture(db);
    const key = await mintKey(f, "ALLOWLIST");
    const contextDir = join(base, "ctx");
    await fs.mkdir(join(contextDir, "app"), { recursive: true });
    await fs.writeFile(join(contextDir, "app", "main.py"), "print('hi')\n");
    const packDir = await fs.mkdtemp(join(base, "pack-"));
    const sdk = createWsspClient({
      baseUrl: "https://api.example.test",
      apiKey: key.secret,
      fetch: async (url, init) => app.request(url, init),
    });
    const template = Template()
      .fromTemplate("base")
      .setWorkdir("/home/user/app")
      .copy("app/", "./", { owner: "user" })
      .runCmd("echo built");
    const logs: BuildLogEntry[] = [];
    let finished = false;
    const building = sdk.templates
      .build(template, {
        name: "app",
        hostId: f.host.id,
        contextDir,
        context: { tempDir: packDir },
        timeoutMinutes: 10,
        onBuildLogs: (entry) => logs.push(entry),
      })
      .finally(() => {
        finished = true;
      });
    await drive(f, () => finished);
    const build = await building;
    expect(build).toMatchObject({ state: "SUCCEEDED", acceptedBy: "sdkKey", tag: "latest" });
    expect(build.revisionId).not.toBeNull();
    // The packed tar was removed after the upload.
    expect(await fs.readdir(packDir)).toEqual([]);
    // The context went through the /v1 routes and was adopted by the VM.
    const context = await db.inspect.sandboxBuildContext.findUniqueOrThrow({
      where: { buildId: build.id },
    });
    expect(context.state).toBe("ADOPTED");
    expect(context.keyId).toBe(key.key.id);
    // A keyed build runs end to end under the real accepting key.
    const vm = await db.inspect.sandbox.findUniqueOrThrow({ where: { buildId: build.id } });
    const ops = await db.inspect.sandboxOperation.findMany({ where: { sandboxId: vm.id } });
    expect(ops.length).toBeGreaterThan(3);
    for (const op of ops) expect(op.authorizingKeyId, op.kind).toBe(key.key.id);
    // Logs: phase lines interleaved with step output.
    const phases = logs.flatMap((entry) => (entry.type === "phase" ? [entry.message] : []));
    expect(phases.some((line) => line.startsWith("Step "))).toBe(true);
    expect(phases.at(-1)).toBe("SUCCEEDED");
    const text = logs.flatMap((entry) => (entry.type === "output" ? [entry.text] : [])).join("");
    expect(text).toContain(`output of tb:${build.id}:run:`);
    // The step logs of a finished build stay readable through the build.
    const page = await sdk.templates.buildLogs(build.id, { step: 0 });
    expect(page.step.operationId).not.toBeNull();
    expect(page.output?.operationId).toBe(page.step.operationId);
  });
});

describe("visibility, ownership and scope over /v1", () => {
  it("an ALLOWLIST key sees and cancels only its own builds; ALL_OWNED sees all (pg 26)", async () => {
    const f = await buildOwnerFixture(db);
    const mine = await mintKey(f, "ALLOWLIST");
    const other = await mintKey(f, "ALLOWLIST");
    const all = await mintKey(f, "ALL_OWNED");
    const own = await createOverHttp(mine.secret, f);
    const others = await createOverHttp(other.secret, f);
    const session = await acceptTemplateBuild(f.session, {
      idempotencyKey: randomUUID(),
      template: { slug: "target" },
      recipe: RUN_RECIPE,
      sandboxHostId: f.host.id,
      noCache: true,
    });
    expect(own.build.acceptedBy).toBe("sdkKey");
    for (const id of [others.build.id, session.build.id]) {
      for (const [method, path] of [
        ["GET", `/v1/template-builds/${id}`],
        ["GET", `/v1/template-builds/${id}/logs?step=0`],
        ["POST", `/v1/template-builds/${id}/cancel`],
      ] as const) {
        const response = await call(mine.secret, method, path, method === "POST" ? {} : undefined);
        expect(response.status, `${method} ${path}`).toBe(404);
        expect(await response.json()).toMatchObject({ error: { code: "NOT_FOUND" } });
      }
    }
    const ownRead = await call(mine.secret, "GET", `/v1/template-builds/${own.build.id}`);
    expect(ownRead.status).toBe(200);
    const listed = await body<Page>(await call(mine.secret, "GET", "/v1/template-builds"));
    expect(listed.items.map((b: { id: string }) => b.id)).toEqual([own.build.id]);
    const everything = await body<Page>(
      await call(all.secret, "GET", "/v1/template-builds?limit=2"),
    );
    expect(everything.items).toHaveLength(2);
    expect(everything.nextCursor).not.toBeNull();
    const rest = await body<Page>(
      await call(all.secret, "GET", `/v1/template-builds?limit=2&cursor=${everything.nextCursor}`),
    );
    expect([...everything.items, ...rest.items].map((b: { id: string }) => b.id).sort()).toEqual(
      [own.build.id, others.build.id, session.build.id].sort(),
    );
    // ALL_OWNED acts on another principal's build; cancel is idempotent.
    for (let i = 0; i < 2; i++) {
      const cancelled = await call(
        all.secret,
        "POST",
        `/v1/template-builds/${others.build.id}/cancel`,
        {},
      );
      expect(cancelled.status).toBe(200);
      expect((await body(cancelled)).state).toBe("CANCELLING");
    }
    // A system rebuild is invisible to an ALLOWLIST key, visible to ALL_OWNED.
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: session.build.id },
      data: {
        principalKind: "system",
        principalKey: "sys",
        triggeredByRevisionId: f.base.id,
      },
    });
    expect((await call(mine.secret, "GET", `/v1/template-builds/${session.build.id}`)).status).toBe(
      404,
    );
    expect((await call(all.secret, "GET", `/v1/template-builds/${session.build.id}`)).status).toBe(
      200,
    );
  });

  it("another owner's session-free keys get NOT_FOUND on every build route (pg 8b, routes)", async () => {
    const a = await buildOwnerFixture(db);
    const b = await buildOwnerFixture(db);
    const aKey = await mintKey(a, "ALLOWLIST");
    const bKey = await mintKey(b, "ALL_OWNED");
    const content = Buffer.from("context bytes");
    const sha = createHash("sha256").update(content).digest("hex");
    const copy = await createOverHttp(
      aKey.secret,
      a,
      { contextSha256: sha, contextBytes: content.byteLength },
      {
        version: 1,
        from: { template: "base" },
        steps: [{ type: "copy", src: ["app/"], dest: "/home/user/" }],
      },
    );
    expect(copy.contextUpload).toMatchObject({ totalBytes: content.byteLength, state: "OPEN" });
    const id = copy.build.id;
    const routes: [string, string, unknown][] = [
      ["GET", `/v1/template-builds/${id}`, undefined],
      ["GET", `/v1/template-builds/${id}/logs?step=0`, undefined],
      ["POST", `/v1/template-builds/${id}/cancel`, {}],
      ["POST", `/v1/template-builds/${id}/context`, {}],
      ["PUT", `/v1/template-builds/${id}/context/chunks/0`, new Uint8Array(content)],
      ["POST", `/v1/template-builds/${id}/context/seal`, {}],
    ];
    for (const [method, path, body] of routes) {
      const response = await call(bKey.secret, method, path, body);
      expect(response.status, `${method} ${path}`).toBe(404);
    }
    // Same owner, but not the accepting principal: the context routes refuse
    // too (§3.7, stricter than §5), while the build itself is visible.
    const aAll = await mintKey(a, "ALL_OWNED");
    expect((await call(aAll.secret, "GET", `/v1/template-builds/${id}`)).status).toBe(200);
    for (const [method, path, body] of routes.slice(3)) {
      const response = await call(aAll.secret, method, path, body);
      expect(response.status, `${method} ${path}`).toBe(404);
    }
    // The accepting key uploads and seals; the build then queues.
    const open = await call(aKey.secret, "POST", `/v1/template-builds/${id}/context`, {});
    expect(open.status).toBe(200);
    expect(
      (
        await call(
          aKey.secret,
          "PUT",
          `/v1/template-builds/${id}/context/chunks/0`,
          new Uint8Array(content),
        )
      ).status,
    ).toBe(200);
    const sealed = await call(aKey.secret, "POST", `/v1/template-builds/${id}/context/seal`);
    expect(sealed.status).toBe(200);
    expect((await body(sealed)).state).toBe("SEALED");
  });

  it("a template with no revision stays visible to the key whose build created it (E1-A-02)", async () => {
    const f = await buildOwnerFixture(db);
    const scopes = ["templates:build", "templates:write", "templates:read"];
    const creator = await mintKey(f, "ALLOWLIST", scopes);
    const stranger = await mintKey(f, "ALLOWLIST", scopes);
    const all = await mintKey(f, "ALL_OWNED", scopes);
    const slug = `first-fails-${randomUUID().slice(0, 6)}`;
    const build = (secret: string) =>
      call(
        secret,
        "POST",
        "/v1/template-builds",
        { template: { slug }, recipe: RUN_RECIPE, sandboxHostId: f.host.id, noCache: true },
        { "idempotency-key": randomUUID() },
      );
    const first = await build(creator.secret);
    expect(first.status).toBe(201);
    const firstBuild = (await body<{ build: { id: string } }>(first)).build;
    // The first build failed: the template exists but has no revision.
    await db.inspect.sandboxTemplateBuild.update({
      where: { id: firstBuild.id },
      data: { state: "FAILED", completedAt: new Date(), errorCode: "build_step_failed" },
    });
    const template = await db.inspect.sandboxTemplate.findFirstOrThrow({
      where: { userId: f.id, slug },
      select: { id: true, _count: { select: { Revisions: true } } },
    });
    expect(template._count.Revisions).toBe(0);
    // The creating key builds again by slug and by id, and lists and reads it.
    expect((await build(creator.secret)).status).toBe(201);
    const listed = await body<Page>(await call(creator.secret, "GET", "/v1/templates?limit=50"));
    expect(listed.items.map((row) => row.id)).toContain(template.id);
    expect(
      (await call(creator.secret, "GET", `/v1/templates/${template.id}/revisions`)).status,
    ).toBe(200);
    // ALL_OWNED sees every owned template; another ALLOWLIST key does not.
    const allListed = await body<Page>(await call(all.secret, "GET", "/v1/templates?limit=50"));
    expect(allListed.items.map((row) => row.id)).toContain(template.id);
    const strangerBuild = await build(stranger.secret);
    expect(strangerBuild.status).toBe(404);
    expect(await strangerBuild.json()).toMatchObject({
      error: { code: "sandbox.template_not_found" },
    });
    const strangerList = await body<Page>(
      await call(stranger.secret, "GET", "/v1/templates?limit=50"),
    );
    expect(strangerList.items.map((row) => row.id)).not.toContain(template.id);
    expect(
      (await call(stranger.secret, "GET", `/v1/templates/${template.id}/revisions`)).status,
    ).toBe(404);
  });

  it("scope gating: templates:build for every route, templates:write to create by slug", async () => {
    const f = await buildOwnerFixture(db);
    const noBuild = await mintKey(f, "ALL_OWNED", ["templates:read"]);
    const built = await createOverHttp((await mintKey(f, "ALL_OWNED")).secret, f);
    for (const [method, path, body] of [
      ["GET", "/v1/template-builds", undefined],
      ["GET", `/v1/template-builds/${built.build.id}`, undefined],
      ["GET", `/v1/template-builds/${built.build.id}/logs?step=0`, undefined],
      ["POST", `/v1/template-builds/${built.build.id}/cancel`, {}],
      ["POST", `/v1/template-builds/${built.build.id}/context`, {}],
      [
        "POST",
        "/v1/template-builds",
        { template: { slug: "x" }, recipe: RUN_RECIPE, sandboxHostId: f.host.id },
      ],
    ] as const) {
      const response = await call(noBuild.secret, method, path, body, {
        "idempotency-key": randomUUID(),
      });
      expect(response.status, `${method} ${path}`).toBe(403);
    }
    // Build without write: a new slug is not found; an existing template (one
    // with a revision the key can see) builds.
    const buildOnly = await mintKey(f, "ALL_OWNED", ["templates:build"]);
    const missing = await call(
      buildOnly.secret,
      "POST",
      "/v1/template-builds",
      { template: { slug: "brand-new" }, recipe: RUN_RECIPE, sandboxHostId: f.host.id },
      { "idempotency-key": randomUUID() },
    );
    expect(missing.status).toBe(404);
    expect(await missing.json()).toMatchObject({ error: { code: "sandbox.template_not_found" } });
    const existing = await db.inspect.sandboxTemplate.findFirstOrThrow({
      where: { userId: f.id, slug: "base" },
    });
    const ok = await call(
      buildOnly.secret,
      "POST",
      "/v1/template-builds",
      {
        template: { id: existing.id },
        recipe: RUN_RECIPE,
        sandboxHostId: f.host.id,
        noCache: true,
      },
      { "idempotency-key": randomUUID() },
    );
    expect(ok.status, JSON.stringify(await ok.clone().json())).toBe(201);
    // A typed refusal carries its documented fields.
    const invalid = await call(
      buildOnly.secret,
      "POST",
      "/v1/template-builds",
      {
        template: { id: existing.id },
        dockerfile: "FROM base\nFOO bar\n",
        sandboxHostId: f.host.id,
      },
      { "idempotency-key": randomUUID() },
    );
    expect(invalid.status).toBe(400);
    expect((await body(invalid)).error).toMatchObject({
      code: "template.build_recipe_invalid",
      recipeCode: expect.any(String),
      line: 2,
    });
  });
});
