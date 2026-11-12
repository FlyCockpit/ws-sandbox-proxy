import {
  seedAcceptedOperation,
  seedLaunchHost,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import type { CommandOutputPageDto } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  seedSandboxInstance,
  seedTemplateRevision,
} from "../../../../packages/api/src/sandbox/testing/resource-fixtures";

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "c26-output-pg-test-secret",
    RATE_LIMIT_RPC_POINTS: 10_000,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 30_000,
    RATE_LIMIT_SDK_KEY_POINTS: 10_000,
    RATE_LIMIT_SDK_OWNER_POINTS: 30_000,
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.11" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

const db = await pgTestDatabase();
const { createSdkKey } = await import("../../../../packages/api/src/sandbox/services/sdk-keys");
const { getCommandOutput } = await import("@wssp/api/sandbox/services/sandboxes");
const { createSandboxApi } = await import("./middleware.js");

afterAll(() => db.close());

const app = new Hono().route("/v1", createSandboxApi());
const FP = `sha256:${"e".repeat(64)}`;
const session = (ownerId: string) => ({ kind: "session" as const, ownerId });
const get = (path: string, secret: string) =>
  app.request(path, { headers: { authorization: `Bearer ${secret}` } });
type Body = CommandOutputPageDto & { error: { code: string }; outcome: string };
const json = async (response: Response | Promise<Response>) =>
  (await (await response).json()) as Body;

type Seeded = { owner: string; hosts: string[]; templates: string[]; commands: string[] };

async function seedOwner(label: string): Promise<Seeded> {
  const owner = `user-${label}-${randomUUID()}`;
  await db.inspect.user.create({ data: { id: owner, name: label, email: `${owner}@x.test` } });
  const seeded: Seeded = { owner, hosts: [], templates: [], commands: [] };
  for (const slug of ["h1", "h2"]) {
    const host = await seedLaunchHost(db.inspect, {
      data: { userId: owner, slug, label: slug, status: "CONNECTED", connectionEpoch: 1 },
    });
    const template = await seedTemplateRevision(db.inspect, {
      data: {
        userId: owner,
        sandboxHostId: host.id,
        slug: `t-${slug}`,
        label: "T",
        imageRef: "images:ubuntu/24.04/cloud",
        incusFingerprint: FP,
      },
    });
    const sandbox = await seedSandboxInstance(db.inspect, {
      data: {
        userId: owner,
        sandboxHostId: host.id,
        originHostId: host.id,
        templateId: template.id,
        originPoolId: null,
        state: "READY",
      },
    });
    const operation = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: owner,
        sandboxId: sandbox.id,
        kind: "RUN_COMMAND",
        state: "SUCCEEDED",
        generation: 1,
        dispatchAttempt: 1,
        idempotencyKey: `k-${sandbox.id}`,
        requestBodyHash: "h",
        result: { exitCode: 0, outputBytes: 5 },
        completedAt: new Date(),
      },
    });
    await db.inspect.sandboxCommandOutput.create({
      data: {
        id: operation.id,
        attempt: 1,
        nextSequence: 2,
        receivedEnd: 5n,
        totalBytes: 5n,
        headBytes: 5,
        headSegments: 1,
      },
    });
    await db.inspect.sandboxCommandOutputSegment.create({
      data: {
        outputId: operation.id,
        tail: false,
        startOffset: 0n,
        endOffset: 5n,
        bytes: Buffer.from("hi!\n\x07"),
        // Byte 4 (0x07) came from stderr.
        stderrMask: Buffer.from([0b1_0000]),
      },
    });
    seeded.hosts.push(host.id);
    seeded.templates.push(template.id);
    seeded.commands.push(operation.id);
  }
  return seeded;
}

async function mint(
  seeded: Seeded,
  scopes: string[],
  mode: "ALL_OWNED" | "ALLOWLIST" = "ALL_OWNED",
): Promise<string> {
  const minted = await createSdkKey(session(seeded.owner), {
    name: `k-${randomUUID()}`,
    scopes: scopes as never,
    resourceMode: mode,
    hostIds: mode === "ALLOWLIST" ? [seeded.hosts[0]!] : [],
    templateRevisionIds: mode === "ALLOWLIST" ? [seeded.templates[0]!] : [],
  });
  if (mode === "ALLOWLIST")
    await db.inspect.sandboxOperation.updateMany({
      where: {
        userId: seeded.owner,
        kind: "CREATE_SANDBOX",
        authorizingKeyId: null,
        Sandbox: { originHostId: seeded.hosts[0]!, templateRevisionId: seeded.templates[0]! },
      },
      data: { authorizingKeyId: minted.key.id },
    });
  return minted.secret;
}

/**
 * A key the mint path refuses since C46 (a scope that grants nothing given the
 * others), inserted directly so the runtime authorization that must still deny
 * it stays covered.
 */
async function insertUnmintableSdkKey(ownerId: string, scopes: string[]): Promise<string> {
  const { credentialLookupPrefix, generateProductCredentialSecret, hmacDigestForProductPurpose } =
    await import("@wssp/db/credential-security");
  const credential = generateProductCredentialSecret("sdkKey");
  await db.inspect.sdkKey.create({
    data: {
      userId: ownerId,
      name: `unmintable-${randomUUID()}`,
      resourceMode: "ALL_OWNED",
      scopes,
      lookupPrefix: credentialLookupPrefix(credential),
      secretDigest: hmacDigestForProductPurpose({ purpose: "sdkKey", value: credential.raw }),
    },
  });
  return credential.raw;
}

let a: Seeded;
let b: Seeded;
beforeAll(async () => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  a = await seedOwner("a");
  b = await seedOwner("b");
});

describe("GET /v1/operations/{id}/output", () => {
  it("returns base64 chunks with stream identity to operations:read + commands:read", async () => {
    const key = await mint(a, ["operations:read", "commands:read"]);
    const response = await get(`/v1/operations/${a.commands[0]}/output`, key);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const page = await response.json();
    expect(page).toMatchObject({
      operationId: a.commands[0],
      state: "SUCCEEDED",
      exitCode: 0,
      complete: true,
      truncated: false,
      chunks: [
        { stream: "stdout", offset: 0, data: Buffer.from("hi!\n").toString("base64") },
        { stream: "stderr", offset: 4, data: Buffer.from([7]).toString("base64") },
      ],
      nextCursor: "1_5",
      hasMore: false,
    });
    const limited = await json(get(`/v1/operations/${a.commands[0]}/output?maxBytes=2`, key));
    expect(limited).toMatchObject({ chunks: [{ data: "aGk=" }], nextCursor: "1_2", hasMore: true });
    const next = await json(
      get(`/v1/operations/${a.commands[0]}/output?cursor=${limited.nextCursor}`, key),
    );
    expect(next.offset).toBe(2);
  });

  it("status-only, cross-owner and out-of-allowlist keys never read bytes", async () => {
    const statusOnly = await mint(a, ["operations:read"]);
    expect((await get(`/v1/operations/${a.commands[0]}/output`, statusOnly)).status).toBe(403);
    const commandsOnly = await insertUnmintableSdkKey(a.owner, ["commands:read"]);
    expect((await get(`/v1/operations/${a.commands[0]}/output`, commandsOnly)).status).toBe(403);
    const foreign = await mint(b, ["operations:read", "commands:read"]);
    const miss = await get(`/v1/operations/${a.commands[0]}/output`, foreign);
    expect(miss.status).toBe(404);
    expect((await json(miss)).error.code).toBe("sandbox.operation_not_found");
    const allowlisted = await mint(a, ["operations:read", "commands:read"], "ALLOWLIST");
    expect((await get(`/v1/operations/${a.commands[0]}/output`, allowlisted)).status).toBe(200);
    const outside = await get(`/v1/operations/${a.commands[1]}/output`, allowlisted);
    expect(outside.status).toBe(403);
    expect(JSON.stringify(await outside.json())).not.toContain("aGkh");
  });

  it("rejects malformed cursors and budgets, and non-command operations conflict", async () => {
    const key = await mint(a, ["operations:read", "commands:read"]);
    for (const query of ["cursor=1_99", "cursor=bad*", "maxBytes=0", "maxBytes=65537", "x=1"])
      expect((await get(`/v1/operations/${a.commands[0]}/output?${query}`, key)).status).toBe(400);
    const sandbox = await db.inspect.sandbox.findFirstOrThrow({ where: { userId: a.owner } });
    const create = await seedAcceptedOperation(db.inspect, {
      data: {
        userId: a.owner,
        sandboxId: sandbox.id,
        kind: "CREATE_SANDBOX",
        state: "SUCCEEDED",
        generation: 1,
        idempotencyKey: `create-${randomUUID()}`,
        requestBodyHash: "h",
      },
    });
    // A cursor from another attempt restarts at 0 instead of failing or skipping.
    const reset = await json(get(`/v1/operations/${a.commands[0]}/output?cursor=9_99`, key));
    expect(reset).toMatchObject({ reset: true, offset: 0, attempt: 1 });
    const conflict = await get(`/v1/operations/${create.id}/output`, key);
    expect(conflict.status).toBe(409);
  });

  it("expired output is a typed 410 while the operation status stays readable", async () => {
    const key = await mint(a, ["operations:read", "commands:read"]);
    await db.inspect.sandboxOperation.update({
      where: { id: a.commands[1] },
      data: { completedAt: new Date(Date.now() - 24 * 3_600_000 - 1) },
    });
    const expired = await get(`/v1/operations/${a.commands[1]}/output`, key);
    expect(expired.status).toBe(410);
    expect((await json(expired)).error.code).toBe("OUTPUT_EXPIRED");
    const status = await get(`/v1/operations/${a.commands[1]}`, key);
    expect(status.status).toBe(200);
    expect(await status.json()).toMatchObject({ state: "SUCCEEDED", outcome: "succeeded" });
  });

  it("the browser session service returns the same page shape to the owner only", async () => {
    const page = await getCommandOutput(session(a.owner), { operationId: a.commands[0]! });
    expect(page.chunks.map((chunk) => chunk.stream)).toEqual(["stdout", "stderr"]);
    await expect(
      getCommandOutput(session(b.owner), { operationId: a.commands[0]! }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });
});
