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
import { SANDBOX_STATES } from "@wssp/sandbox-contracts";
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
    BETTER_AUTH_SECRET: "c23-reads-pg-test-secret",
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
  getConnInfo: () => ({ remote: { address: "198.51.100.10" } }),
}));
// Redis IO only: the real limiter library runs in memory.
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  return { ...actual, RateLimiterRedis: actual.RateLimiterMemory };
});

const db = await pgTestDatabase();
const { createSdkKey, revokeSdkKey } = await import(
  "../../../../packages/api/src/sandbox/services/sdk-keys"
);
const { generateSdkKeySecret, digestSdkKeySecret } = await import("@wssp/api/lib/sdk-key-access");
const { credentialLookupPrefix } = await import("@wssp/db/credential-security");
const { createSandboxApi } = await import("./middleware.js");

afterAll(() => db.close());

const ALL_SCOPES = ["hosts:read", "templates:read", "sandboxes:read", "operations:read"] as const;
const FP = `sha256:${"d".repeat(64)}`;
const app = new Hono().route("/v1", createSandboxApi());
const session = (ownerId: string) => ({ kind: "session" as const, ownerId });

type Owner = {
  id: string;
  hosts: string[];
  templates: string[];
  logicalTemplates: string[];
  sandboxes: string[];
  operations: string[];
};

async function seedOwner(label: string, sandboxesPerHost: number, base: number): Promise<Owner> {
  const id = `user-${label}-${randomUUID()}`;
  await db.inspect.user.create({ data: { id, name: label, email: `${id}@example.test` } });
  const owner: Owner = {
    id,
    hosts: [],
    templates: [],
    logicalTemplates: [],
    sandboxes: [],
    operations: [],
  };
  for (const slug of ["h1", "h2"]) {
    const host = await seedLaunchHost(db.inspect, {
      data: { userId: id, slug, label: slug, status: "CONNECTED", connectionEpoch: 1 },
    });
    const template = await seedTemplateRevision(db.inspect, {
      data: {
        userId: id,
        sandboxHostId: host.id,
        slug: `t-${slug}`,
        label: "T",
        imageRef: "images:ubuntu/24.04/cloud",
        incusFingerprint: FP,
      },
    });
    owner.hosts.push(host.id);
    owner.templates.push(template.id);
    owner.logicalTemplates.push(template.templateId);
    for (let i = 0; i < sandboxesPerHost; i++) {
      // Interleave both owners on one timeline, with timestamp ties across owners.
      const createdAt = new Date(Date.UTC(2026, 8, 26, 0, 0, base + i * 2));
      const sandbox = await seedSandboxInstance(db.inspect, {
        data: {
          userId: id,
          sandboxHostId: host.id,
          originHostId: host.id,
          templateId: template.id,
          originPoolId: null,
          state: i === 0 ? "DELETED" : "READY",
          createdAt,
        },
      });
      owner.sandboxes.push(sandbox.id);
      const operation = await seedAcceptedOperation(db.inspect, {
        data: {
          userId: id,
          sandboxId: sandbox.id,
          kind: "RUN_COMMAND",
          state: "UNKNOWN_OUTCOME",
          generation: 1,
          idempotencyKey: `k-${sandbox.id}`,
          requestBodyHash: "h",
          result: { stdout: "private-output" },
          errorDetail: "private-detail",
          errorCode: "unknown_outcome",
        },
      });
      owner.operations.push(operation.id);
    }
  }
  return owner;
}

async function mint(owner: Owner, mode: "ALL_OWNED" | "ALLOWLIST") {
  const minted = await createSdkKey(session(owner.id), {
    name: `${mode}-key`,
    scopes: [...ALL_SCOPES],
    resourceMode: mode,
    hostIds: mode === "ALLOWLIST" ? [owner.hosts[0]!] : [],
    templateRevisionIds: mode === "ALLOWLIST" ? [owner.templates[0]!] : [],
  });
  if (mode === "ALLOWLIST")
    await db.inspect.sandboxOperation.updateMany({
      where: {
        userId: owner.id,
        kind: "CREATE_SANDBOX",
        authorizingKeyId: null,
        Sandbox: { originHostId: owner.hosts[0]!, templateRevisionId: owner.templates[0]! },
      },
      data: { authorizingKeyId: minted.key.id },
    });
  return minted;
}

type Json = {
  items: { id: string }[];
  nextCursor: string | null;
  state: string;
  outcome: string;
  hostId: string | null;
  errorCode: string | null;
  error: { code: string; requestId: string };
  features: string[];
};
async function json(response: Response): Promise<Json> {
  return (await response.json()) as Json;
}

function get(path: string, secret: string) {
  return app.request(path, { headers: { authorization: `Bearer ${secret}` } });
}

async function walk(resource: string, secret: string, limit = 1): Promise<string[]> {
  const ids: string[] = [];
  let cursor: string | null = null;
  for (let pages = 0; pages < 50; pages++) {
    const response: Response = await get(
      `/v1/${resource}?limit=${limit}${resource === "sandboxes" ? `&states=${SANDBOX_STATES.join(",")}` : ""}${cursor ? `&cursor=${cursor}` : ""}`,
      secret,
    );
    expect(response.status).toBe(200);
    const body = await json(response);
    expect(body.items.length).toBeLessThanOrEqual(limit);
    ids.push(...body.items.map((item) => item.id));
    cursor = body.nextCursor;
    if (!cursor) return ids;
  }
  throw new Error("pagination did not terminate");
}

beforeAll(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
});

let a: Owner;
let b: Owner;
let aAll: string;
let aAllow: string;
let bAll: string;
beforeAll(async () => {
  a = await seedOwner("a", 2, 0);
  b = await seedOwner("b", 3, 0);
  aAll = (await mint(a, "ALL_OWNED")).secret;
  aAllow = (await mint(a, "ALLOWLIST")).secret;
  bAll = (await mint(b, "ALL_OWNED")).secret;
});

describe("owner-scoped pagination against PostgreSQL", () => {
  it("walks each owner's sandboxes exactly once and never another owner's", async () => {
    for (const limit of [1, 2, 100]) {
      const seenA = await walk("sandboxes", aAll, limit);
      expect(seenA.sort()).toEqual([...a.sandboxes].sort());
      const seenB = await walk("sandboxes", bAll, limit);
      expect(seenB.sort()).toEqual([...b.sandboxes].sort());
    }
    expect((await walk("hosts", aAll)).sort()).toEqual([...a.hosts].sort());
    expect((await walk("templates", bAll)).sort()).toEqual([...b.logicalTemplates].sort());
  });

  it("refuses a sandbox cursor minted for another owner", async () => {
    const first = await json(await get("/v1/sandboxes?limit=1", aAll));
    expect(first.nextCursor).toEqual(expect.any(String));
    expect((await get(`/v1/sandboxes?limit=100&cursor=${first.nextCursor}`, bAll)).status).toBe(
      400,
    );
  });

  it("an allowlist key sees only its host and template, even through cursors", async () => {
    const [allowedHost] = a.hosts;
    const seen = await walk("sandboxes", aAllow);
    const detail = await Promise.all(
      seen.map(async (id) => (await json(await get(`/v1/sandboxes/${id}`, aAllow))).hostId),
    );
    expect(seen.length).toBe(2);
    for (const host of detail) expect(host).toBe(allowedHost);
    expect(await walk("hosts", aAllow)).toEqual([allowedHost]);
    expect(await walk("templates", aAllow)).toEqual([a.logicalTemplates[0]]);
    const other = a.sandboxes.find((id) => !seen.includes(id))!;
    expect((await get(`/v1/sandboxes/${other}`, aAllow)).status).toBe(403);
  });

  it("an allowlist key with empty lists grants nothing", async () => {
    const credential = generateSdkKeySecret();
    await db.inspect.sdkKey.create({
      data: {
        userId: a.id,
        name: "empty",
        resourceMode: "ALLOWLIST",
        scopes: [...ALL_SCOPES],
        lookupPrefix: credentialLookupPrefix(credential),
        secretDigest: digestSdkKeySecret(credential.raw),
      },
    });
    for (const resource of ["hosts", "templates", "sandboxes"]) {
      expect(await walk(resource, credential.raw)).toEqual([]);
    }
    expect((await get(`/v1/sandboxes/${a.sandboxes[0]}`, credential.raw)).status).toBe(403);
  });

  it("foreign sandboxes and operations are indistinguishable from missing ones", async () => {
    for (const [path, code] of [
      [`/v1/sandboxes/${b.sandboxes[0]}`, "sandbox.not_found"],
      ["/v1/sandboxes/no-such-sandbox", "sandbox.not_found"],
      [`/v1/operations/${b.operations[0]}`, "sandbox.operation_not_found"],
      ["/v1/operations/no-such-operation", "sandbox.operation_not_found"],
    ] as const) {
      const response = await get(path, aAll);
      expect(response.status).toBe(404);
      expect((await json(response)).error.code).toBe(code);
    }
  });

  it("returns output-free operation metadata and keeps DELETED readable", async () => {
    const response = await get(`/v1/operations/${a.operations[0]}`, aAll);
    const text = await response.text();
    expect(response.status).toBe(200);
    expect(JSON.parse(text)).toMatchObject({ state: "UNKNOWN_OUTCOME", outcome: "unknown" });
    for (const secret of ["private-output", "private-detail", `k-${a.sandboxes[0]}`]) {
      expect(text).not.toContain(secret);
    }
    const deleted = await json(await get(`/v1/sandboxes/${a.sandboxes[0]}`, aAll));
    expect(deleted.state).toBe("DELETED");
  });

  it("a revoked key cannot continue a walk it started", async () => {
    const { secret, key } = await mint(a, "ALL_OWNED");
    const first = await json(await get("/v1/sandboxes?limit=1", secret));
    expect(first.nextCursor).toEqual(expect.any(String));
    await revokeSdkKey(session(a.id), { id: key.id });
    const next = await get(`/v1/sandboxes?limit=1&cursor=${first.nextCursor}`, secret);
    expect(next.status).toBe(401);
  });
});
