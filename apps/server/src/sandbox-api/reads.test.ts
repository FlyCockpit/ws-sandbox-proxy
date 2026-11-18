vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { IncomingMessage, ServerResponse } from "node:http";
import { Socket } from "node:net";
import { getRequestListener } from "@hono/node-server";
import { digestSdkKeySecret, generateSdkKeySecret } from "@wssp/api/lib/sdk-key-access";
import { invalidateForceTwoFactorSettingsCache } from "@wssp/api/lib/two-factor-policy";
import { AccountDeletionConflictError } from "@wssp/db/account-deletion";
import { credentialLookupPrefix } from "@wssp/db/credential-security";
import {
  SDK_ROUTE_IDS as ALL_ROUTE_IDS,
  SDK_ROUTES as ALL_ROUTES,
  buildSdkOpenApiDocument,
  enabledSdkFeatures,
  FS_PROCESS_LIMITS,
  guestApiCapabilities,
  JSON_ROUTE_IDS as SDK_ROUTE_IDS,
  JSON_ROUTES as SDK_ROUTES,
  sdkErrorEnvelopeSchema,
  VM_SIZE_PUBLIC_LIMITS,
} from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ZodError } from "zod";

const zeroPolicy = vi.hoisted(() => ({ enabled: false }));
vi.mock("../../../../packages/sandbox-contracts/src/command-timeout-policy", () => ({
  get commandTimeoutZeroEnabled() {
    return zeroPolicy.enabled;
  },
}));

const state = vi.hoisted(() => ({
  budgetFailure: undefined as unknown,
  /** Keys every /v1 budget consumed, in order (one entry per charge). */
  consumed: [] as string[],
  env: {
    NODE_ENV: "production",
    BETTER_AUTH_SECRET: "c23-test-only-secret",
    RATE_LIMIT_RPC_POINTS: 100,
    RATE_LIMIT_RPC_WINDOW_SECONDS: 60,
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
    TRUST_PROXY_HOPS: undefined as number | undefined,
    SANDBOX_MAX_TIMEOUT_MS: 86400000,
    TRANSFER_MAX_BYTES: 1_073_741_824,
  },
}));
vi.mock("@wssp/env/server", () => ({ env: state.env, ADMIN_EMAILS: new Set() }));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "198.51.100.9" } }),
}));
vi.mock("rate-limiter-flexible", async (original) => {
  const actual = await original<typeof import("rate-limiter-flexible")>();
  // Only Redis IO is replaced; the real library accounts points and windows.
  return {
    ...actual,
    RateLimiterRedis: class extends actual.RateLimiterMemory {
      override consume(key: string, points?: number) {
        state.consumed.push(key);
        if (state.budgetFailure) return Promise.reject(state.budgetFailure);
        return super.consume(key, points);
      }
    },
  };
});

const { default: prisma } = await import("@wssp/db");
const db = prisma as import("@wssp/api/test/mock-prisma").MockPrisma;
const { RateLimiterRes } = await import("rate-limiter-flexible");
const { createSandboxApi } = await import("./middleware.js");
const { honoPath, registerSdkReadRoutes } = await import("./reads.js");

const ALL_SCOPES = [
  "pools:read",
  "hosts:read",
  "templates:read",
  "templates:write",
  "sandboxes:read",
  "sandboxes:create",
  "sandboxes:manage",
  "sandboxes:destroy",
  "commands:read",
  "commands:execute",
  "files:read",
  "files:write",
  "operations:read",
  "operations:cancel",
];
const credential = generateSdkKeySecret();
const bearer = { authorization: `Bearer ${credential.raw}` };
const T = new Date("2026-09-26T12:00:00.000Z");

function keyRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "key-a",
    kind: "API",
    ownSandboxesOnly: false,
    userId: "owner-a",
    resourceMode: "ALL_OWNED",
    poolMode: "ALL_USABLE",
    scopes: ALL_SCOPES,
    lookupPrefix: credentialLookupPrefix(credential),
    secretDigest: digestSdkKeySecret(credential.raw),
    revokedAt: null,
    expiresAt: null,
    HostAllowlist: [],
    RevisionAllowlist: [],
    User: {
      banned: false,
      banExpires: null,
      deletionRequestedAt: null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
    ...overrides,
  };
}

const hostRow = {
  rootCount: 0,
  daemonVcpuBudget: 64,
  StoragePools: [],
  memoryReservedMiB: 1024,
  vcpuReserved: 0,
  daemonMemoryBudgetMiB: 4096,
  daemonMaxCpuCount: 4,

  admissionEpoch: 3,
  admissionReportedAt: T,
  inventoryAcknowledgedEpoch: 3,
  daemonSchedulable: true,
  id: "host1",
  slug: "lab",
  label: "Lab",
  status: "CONNECTED",
  lastConnectedAt: T,
  lastHeartbeatAt: null,
  connectionCount: 7,
  connectionEpoch: 3,

  liveCount: 1,
  draining: false,
  deletionRequestedAt: null,
  inventoryDigest: "internal-digest",
  egressEnforcement: false,
  daemonFeatures: { egressPolicy: false },
  daemonOpenEgressForOthers: false,
  daemonGuestSudoForOthers: true,
  daemonEgressGuardOk: false,
  daemonEgressGuardReason: "guard_not_installed",
  daemonEgressGuardEpoch: 3,
  daemonEgressGuardLeaseUntil: null,
  userId: "owner-a",
  createdAt: T,
  updatedAt: T,
};
const templateRow = {
  imagePlacement: "INHERIT",
  captureKeep: 3,
  pruneAfterDays: null,
  defaultDiskGiB: 32,
  minDiskGiB: 32,
  cpuCount: 2,
  memoryMiB: 2048,
  id: "tpl1",
  userId: "owner-a",
  sandboxHostId: "host1",
  retiredAt: null,
  archivedAt: null,
  templateId: "tpl1",
  revision: 1,
  manifestDigest: "a".repeat(64),
  slug: "base",
  label: "Base",
  imageRef: "images:ubuntu/24.04/cloud",
  incusFingerprint: `sha256:${"a".repeat(64)}`,
  architecture: "x86_64",
  guestUid: 1000,
  guestGid: 1000,
  guestHome: "/home/user",
  guestShell: "/bin/bash",
  guestVersion: null,
  sourceKind: "MANUAL",
  parentRevisionId: null,
  captureTag: null,
  capturedWithGuestRoot: false,
  builtWithWsspRecipe: false,
  retiredReason: null,
  createdAt: T,
  updatedAt: T,
  // Owner-projection joins (C46); the /v1 DTO must not copy them.
  SandboxHost: { id: "host1", slug: "lab", label: "Lab", status: "CONNECTED", draining: false },
  _count: { Sandboxes: 3 },
};
const sandboxRow = (state: string) => ({
  storagePoolId: null,
  storagePoolName: null,
  storageMarker: null,
  diskGiB: 32,
  cpuCount: 2,
  memoryMiB: 2048,
  id: "sbx1",
  name: "quiet-otter",
  userId: "owner-a",
  state,
  generation: 2,
  templateId: "tpl1",
  templateRevisionId: "tpl1",
  originPoolId: null,
  sandboxHostId: "host1",
  originHostId: "host1",
  incusName: "wssp-sbx-sbx1",
  leaseRevision: 3,
  leaseExpiresAt: T,
  leaseExpireAction: "STOP",
  leaseExpiresAtRequested: T,
  leaseExpireActionRequested: "DESTROY",
  leaseExpiresAtEffective: null,
  leaseExpireActionEffective: null,
  lastErrorCode: "guest_unavailable",
  lastErrorDetail: "stderr: secret-token-in-guest-output",
  liveResourcesHeld: true,
  egressPolicy: null,
  egressPolicyHash: null,
  egressRequest: null,
  egressModeReason: null,
  egressDeniedGrants: [],
  guestSudo: false,
  guestSudoRequested: false,
  guestSudoReason: null,
  guestRoot: false,
  // Disk offload facts (packages/api disk-view.ts): never offloaded.
  purpose: "WORKLOAD",
  diskOffloadId: null,
  cachedOffloadSeq: null,
  offloadPin: "ANY",
  offloadMode: "ON_STOP",
  offloadAfterMs: null,
  lastStoppedAt: null,
  credentialFilesEver: false,
  DiskOffloads: [],
  SandboxTemplateRevision: { Template: { imagePlacement: "INHERIT" } },
  User: { ImagePolicy: null },
  metadata: { purpose: "ci" },
  createdAt: T,
  updatedAt: T,
});
/** One row answers both the authorization-context read and the service read. */
const operationRow = (state: string, errorCode: string | null) => ({
  id: "op1",
  userId: "owner-a",
  sandboxId: "sbx1",
  kind: "RUN_COMMAND",
  state,
  generation: 2,
  idempotencyKey: "caller-key-1",
  requestBodyHash: "hash",
  result: { stdout: "secret-output" },
  errorCode,
  errorDetail: "stderr: secret-output",
  dispatchedAt: T,
  completedAt: null,
  createdAt: T,
  updatedAt: T,
  Sandbox: { id: "sbx1", originHostId: "host1", templateRevisionId: "tpl1", originPoolId: null },
});

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

let app: Hono;
function get(path: string, headers: Record<string, string> = bearer) {
  return app.request(path, { headers });
}
async function expectError(response: Response, status: number, code: string) {
  expect(response.status).toBe(status);
  expect(response.headers.get("cache-control")).toBe("no-store");
  const body = await json(response);
  expect(sdkErrorEnvelopeSchema.parse(body).error.code).toBe(code);
  expect(body.error.requestId).toBe(response.headers.get("x-request-id"));
}

beforeEach(() => {
  zeroPolicy.enabled = false;
  vi.clearAllMocks();
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
  vi.spyOn(console, "warn").mockImplementation(() => {});
  state.budgetFailure = undefined;
  state.consumed.length = 0;
  invalidateForceTwoFactorSettingsCache();
  db.sdkKey.findUnique.mockResolvedValue(keyRow() as never);
  db.sdkKey.update.mockResolvedValue({ id: "key-a" } as never);
  // One row serves the page query and the fenced batch read (discover/re-read/check).
  const poolRow = {
    id: "pool1",
    userId: "owner-a",
    User: { id: "owner-a", name: "Owner A" },
    ownHostsOnly: false,
    preferOwnHosts: true,
    capacityWaitMaxMs: null,
    capacityQueuePerKeyMax: null,
    capacityQueuePerOwnerMax: null,
    disconnectGraceSeconds: 259200,
    slug: "pool",
    label: "Pool",
    createdAt: T,
    updatedAt: T,
    deletedAt: null,
  };
  db.sandboxPool.findMany.mockResolvedValue([poolRow] as never);
  db.sandboxPool.findFirst.mockResolvedValue(poolRow as never);
  db.sandboxPoolMember.findMany.mockResolvedValue([]);
  db.sandboxPoolMember.count.mockResolvedValue(0);
  db.sandboxHost.findMany.mockResolvedValue([hostRow] as never);
  db.sandboxHost.findFirst.mockResolvedValue({ id: "host1" } as never);
  db.sandboxTemplate.findMany.mockResolvedValue([templateRow] as never);
  db.sandboxTemplate.findFirst.mockResolvedValue(templateRow as never);
  db.sandboxTemplateRevision.findFirst.mockResolvedValue(templateRow as never);
  db.sandboxTemplateRevision.findMany.mockResolvedValue([templateRow] as never);
  db.sandboxTemplateAvailability.findMany.mockResolvedValue([]);
  db.sandboxImageArtifact.findMany.mockResolvedValue([]);
  db.sandbox.findMany.mockResolvedValue([sandboxRow("READY")] as never);
  db.sandbox.findFirst.mockResolvedValue(sandboxRow("READY") as never);
  db.sandboxOperation.findFirst.mockResolvedValue(operationRow("RUNNING", null) as never);
  db.$transaction.mockImplementation((async (fn: (tx: typeof db) => Promise<unknown>) =>
    fn(db)) as never);
  app = new Hono().route("/v1", createSandboxApi());
});
afterEach(() => vi.restoreAllMocks());

const concretePath = (path: string) =>
  path
    .replaceAll("{hostId}", "host1")
    .replaceAll("{commandId}", "abcdefghijklmnopqrstuv")
    .replace(
      "{id}",
      path.includes("operations")
        ? "op1"
        : path.includes("pools")
          ? "pool1"
          : path.includes("templates")
            ? "tpl1"
            : "sbx1",
    )
    .replace("{pid}", "42")
    .replace("{accountId}", "acct1")
    .replace("{instanceId}", "inst1") +
  (path.endsWith("/availability")
    ? "?revisionId=tpl1"
    : path.endsWith("/{pid}")
      ? "?generation=1&processId=proc&attempt=1"
      : path.endsWith("/logs")
        ? "?step=0"
        : "");

describe("route and schema coverage", () => {
  it("returns the catalogued metadata code for duplicate keys on native create before allocation", async () => {
    const response = await app.request("/v1/sandboxes", {
      method: "POST",
      headers: {
        ...bearer,
        "content-type": "application/json",
        "idempotency-key": "duplicate-metadata",
      },
      body: '{"sandboxHostId":"host1","templateId":"tpl1","metadata":{"team":"private-first","t\\u0065am":"private-second"}}',
    });
    await expectError(response.clone(), 400, "sandbox.metadata_invalid");
    expect(await response.text()).not.toContain("private-");
    expect(db.sandbox.create).not.toHaveBeenCalled();
    expect(db.sandboxOperation.create).not.toHaveBeenCalled();
  });

  it("serves every registry route with a body that satisfies its documented schema", async () => {
    expect(SDK_ROUTE_IDS.filter((id) => SDK_ROUTES[id].method === "get").sort()).toEqual(
      [
        "listWebhookEndpoints",
        "getWebhookEndpoint",
        "listWebhookDeliveries",
        "getWebhookDelivery",
        "getOperationResult",
        "getSandboxCapabilities",
        "connectProcess",
        "getPool",
        "getPoolCapacity",
        "listPools",
        "listPoolMembers",
        "getCapabilities",
        "getOperation",
        "getCommandOutput",
        "getSandbox",
        "listHosts",
        "getHost",
        "getHostCommand",
        "getQueuedHostCommand",
        "listSandboxes",
        "listTemplates",
        "listTemplateRevisions",
        "listTemplateAvailability",
        "listTemplateBuilds",
        "getTemplateBuild",
        "getTemplateBuildLogs",
        "listCredentialDefinitions",
        "getCredentialDefinition",
        "listCredentials",
        "getCredential",
        "listCredentialEvents",
        "listCredentialAccounts",
        "listCredentialInstances",
        "listCredentialLeases",
        "getSandboxTunnel",
        "getKey",
      ].sort(),
    );
    for (const id of SDK_ROUTE_IDS) {
      const route = SDK_ROUTES[id];
      if (route.method !== "get") continue;
      if (["getHost", "getHostCommand", "getQueuedHostCommand"].includes(id)) continue; // Host adapters: host-access.test.ts and host-access.pg.test.ts.
      if (["getOperationResult", "getSandboxCapabilities", "connectProcess"].includes(id)) continue; // Real services covered in fs-process.pg.test.ts.
      if (id === "getSandboxTunnel") continue; // Preview tunnels: the off-refusal test below and the live e2e.
      if (id === "getKey") continue; // Real service: key.pg.test.ts.
      if (SDK_ROUTES[id].feature === "webhooks.write") continue; // Real services: webhooks.pg.test.ts.
      if (SDK_ROUTES[id].feature === "credentials.read") continue; // Real services: credentials.pg.test.ts.
      if (id === "getPoolCapacity") continue; // Real service covered in capacity-view.pg.test.ts.
      if (SDK_ROUTES[id].feature === "templates.build") continue; // Real services: template-builds.pg.test.ts.
      const response = await get(concretePath(route.path));
      expect(response.status, id).toBe(200);
      expect(response.headers.get("cache-control")).toBe("no-store");
      const body = await json(response);
      expect(route.response.schema.safeParse(body).success, id).toBe(true);
    }
  });

  it("serves populated availability without dashboard-only host fields", async () => {
    db.sandboxTemplateAvailability.findMany.mockResolvedValue([
      {
        id: "availability1",
        revisionId: "tpl1",
        hostId: "host1",
        status: "AVAILABLE",
        verifiedConnectionEpoch: 3,
        observedAt: T,
        createdAt: T,
        Host: { id: "host1", slug: "lab", label: "Private dashboard host label" },
      },
    ] as never);
    const response = await get("/v1/templates/tpl1/availability?revisionId=tpl1");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      items: [
        {
          id: "availability1",
          revisionId: "tpl1",
          hostId: "host1",
          status: "AVAILABLE",
          verifiedConnectionEpoch: 3,
          observedAt: T.toISOString(),
        },
      ],
      nextCursor: null,
    });
  });

  it("maps each OpenAPI operation onto a mounted handler and nothing else", async () => {
    const doc = buildSdkOpenApiDocument() as { paths: Record<string, Record<string, unknown>> };
    const mounted = new Hono<never>();
    registerSdkReadRoutes(mounted as never);
    const { registerUploadRoutes } = await import("../sandbox-transfers/upload-routes.js");
    registerUploadRoutes(mounted as never, async () => ({ kind: "session", ownerId: "unused" }));
    const { registerDownloadRoutes } = await import("../sandbox-transfers/download-routes.js");
    registerDownloadRoutes(mounted as never, async () => ({ kind: "session", ownerId: "unused" }));
    const { registerBuildContextRoutes } = await import("../template-builds/context-routes.js");
    registerBuildContextRoutes(
      mounted as never,
      () => {
        throw new Error("unused");
      },
      async () => ({ kind: "session", ownerId: "unused" }),
    );
    const mountedPaths = new Set(mounted.routes.map((r) => `${r.method} ${r.path}`));
    for (const [path, methods] of Object.entries(doc.paths)) {
      if (path === "/v1/openapi.json") continue;
      for (const method of Object.keys(methods)) {
        expect(mountedPaths.has(`${method.toUpperCase()} ${honoPath(path)}`), path).toBe(true);
      }
    }
    const handlerPaths = mounted.routes.filter((r) => r.method !== "ALL").map((r) => r.path);
    expect(handlerPaths.sort()).toEqual(
      ALL_ROUTE_IDS.map((id) => honoPath(ALL_ROUTES[id].path)).sort(),
    );
  });

  it("refuses to send a response that violates the route contract", async () => {
    const { sdkReadHandlers } = await import("./reads.js");
    const handlers = sdkReadHandlers(SDK_ROUTE_IDS);
    // The production app must not use injected handlers; build an isolated one.
    const isolated = new Hono<{ Variables: { requestId: string; principal: never } }>();
    isolated.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("principal", {} as never);
      await next();
    });
    const { sdkErrorResponse } = await import("./errors.js");
    isolated.onError((error, c) => sdkErrorResponse(c, error));
    registerSdkReadRoutes(isolated as never, ["getOperation"], {
      ...handlers,
      getOperation: async () => ({ ...operationRow("RUNNING", null) }) as never,
    });
    const response = await isolated.request("/operations/op1");
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).not.toContain("secret");
    expect(text).toContain("INTERNAL_SERVER_ERROR");
  });

  it("pool capacity: an unresolvable template keeps template_not_found; other misses stay pool_not_found", async () => {
    const { sdkReadHandlers } = await import("./reads.js");
    const { ORPCError } = await import("@orpc/server");
    const miss = (code: string) => new ORPCError("NOT_FOUND", { message: "x", data: { code } });
    const isolated = new Hono<{ Variables: { requestId: string; principal: never } }>();
    isolated.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("principal", {} as never);
      await next();
    });
    const { sdkErrorResponse } = await import("./errors.js");
    isolated.onError((error, c) => sdkErrorResponse(c, error));
    let failure: Error = miss("sandbox.template_not_found");
    registerSdkReadRoutes(isolated as never, ["getPoolCapacity"], {
      ...sdkReadHandlers(SDK_ROUTE_IDS),
      getPoolCapacity: async () => {
        throw failure;
      },
    });
    const code = async () => {
      const response = await isolated.request("/pools/pool1/capacity?template=nope:latest");
      expect(response.status).toBe(404);
      return ((await response.json()) as { error: { code: string } }).error.code;
    };
    expect(await code()).toBe("sandbox.template_not_found");
    failure = miss("sandbox.pool_not_found");
    expect(await code()).toBe("sandbox.pool_not_found");
    // Any other miss still collapses to the route's stable code.
    failure = miss("sandbox.host_not_found");
    expect(await code()).toBe("sandbox.pool_not_found");
    const doc = buildSdkOpenApiDocument() as {
      paths: Record<string, { get: { responses: Record<string, { description: string }> } }>;
    };
    expect(doc.paths["/v1/pools/{id}/capacity"]!.get.responses["404"]!.description).toBe(
      "Error codes: sandbox.pool_not_found, sandbox.template_not_found.",
    );
  });

  it("projects mutation receipts without spreading additional service fields", async () => {
    const { sdkReadHandlers } = await import("./reads.js");
    const isolated = new Hono<{ Variables: { requestId: string; principal: never } }>();
    isolated.use("*", async (c, next) => {
      c.set("requestId", "rid");
      c.set("principal", {} as never);
      await next();
    });
    const { sdkErrorResponse } = await import("./errors.js");
    isolated.onError((error, c) => sdkErrorResponse(c, error));
    registerSdkReadRoutes(isolated as never, ["stopSandbox"], {
      ...sdkReadHandlers(SDK_ROUTE_IDS),
      stopSandbox: async () =>
        ({ operationId: "op1", state: "QUEUED", dashboardOnly: "private" }) as never,
    });
    const response = await isolated.request("/sandboxes/sbx1/stop", {
      method: "POST",
      headers: { "content-type": "application/json", "idempotency-key": "project-receipt" },
      body: "{}",
    });
    expect(response.status).toBe(202);
    expect(await response.json()).toEqual({
      operationId: "op1",
      state: "QUEUED",
      location: "/v1/operations/op1",
    });
  });

  it("publishes the static spec anonymously, IP-budgeted, without authenticating", async () => {
    const response = await get("/v1/openapi.json", {});
    expect(response.status).toBe(200);
    expect(await json(response)).toEqual(buildSdkOpenApiDocument());
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
    state.budgetFailure = new RateLimiterRes(0, 30_000);
    await expectError(await get("/v1/openapi.json", {}), 429, "TOO_MANY_REQUESTS");
  });

  it("requires a bearer key for every runtime read", async () => {
    for (const id of SDK_ROUTE_IDS) {
      await expectError(await get(concretePath(SDK_ROUTES[id].path), {}), 401, "UNAUTHORIZED");
    }
    expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
    expect(db.sandbox.findFirst).not.toHaveBeenCalled();
  });
});

describe("disclosure", () => {
  it("reports server-side read parse failures as constant internal errors on list and detail", async () => {
    const failure = new ZodError([
      { code: "custom", path: ["metadata"], message: "private-stored-value" },
    ]);
    db.sandbox.findMany.mockRejectedValueOnce(failure);
    db.sandbox.findFirst.mockRejectedValueOnce(failure);
    for (const path of ["/v1/sandboxes", "/v1/sandboxes/sbx1"]) {
      const response = await get(path);
      await expectError(response.clone(), 500, "INTERNAL_SERVER_ERROR");
      expect(await response.json()).toMatchObject({
        error: { message: "An internal error occurred." },
      });
    }
    expect(console.error).not.toHaveBeenCalledWith(expect.stringContaining("private-stored-value"));
  });

  it("returns operation status metadata only, never output, results or idempotency keys", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(
      operationRow("FAILED", "stderr: leaked detail") as never,
    );
    const response = await get("/v1/operations/op1");
    const body = await json(response);
    expect(response.status).toBe(200);
    expect(Object.keys(body).sort()).toEqual(
      [
        "completedAt",
        "createdAt",
        "dispatchedAt",
        "errorCode",
        "failure",
        "generation",
        "id",
        "kind",
        "leaseIntent",
        "outcome",
        "sandboxId",
        "state",
        "updatedAt",
      ].sort(),
    );
    expect(body.errorCode).toBe("internal");
    const text = JSON.stringify(body);
    for (const secret of ["secret", "caller-key-1", "leaked", "hash"]) {
      expect(text).not.toContain(secret);
    }
  });

  it("omits internal host, sandbox and template columns", async () => {
    const texts = [
      await (await get("/v1/hosts")).text(),
      await (await get("/v1/sandboxes/sbx1")).text(),
      await (await get("/v1/sandboxes")).text(),
      await (await get("/v1/templates")).text(),
    ].join("\n");
    for (const internal of [
      "connectionEpoch",
      "connectionCount",
      "internal-digest",
      "userId",
      "owner-a",
      "incusName",
      "lastErrorDetail",
      "secret-token",
      "liveResourcesHeld",
      "originHostId",
      // The browser owner projection's joins never reach /v1 (C46).
      "sandboxCount",
      "_count",
      "SandboxHost",
    ]) {
      expect(texts).not.toContain(internal);
    }
  });

  it.each(["startCommand", "getOperation", "writeStdin", "sendProcessStdin"] as const)(
    "with zero enabled, missing command route %s suppresses the global capability",
    async (missing) => {
      zeroPolicy.enabled = true;
      const { sdkReadHandlers } = await import("./reads.js");
      const principal: import("@wssp/api/lib/sdk-key-access").ServicePrincipal = {
        kind: "sdkKey",
        credentialKind: "API",
        ownSandboxesOnly: false,
        ownerId: "owner-a",
        keyId: "key-a",
        expiresAt: null,
        resourceMode: "ALL_OWNED",
        scopes: new Set(["commands:execute"]),
        allowedHostIds: "allOwned",
        allowedRevisionIds: "allOwned",
        allowedPoolIds: "allUsable",
      };
      const input = { params: {}, query: {} };
      const complete = await sdkReadHandlers(ALL_ROUTE_IDS).getCapabilities(principal, input);
      expect(complete.limits.commandTimeoutZero).toBe(true);
      const partial = await sdkReadHandlers(
        ALL_ROUTE_IDS.filter((id) => id !== missing),
      ).getCapabilities(principal, input);
      expect(partial.features).not.toContain("commands.execute");
      expect(partial.limits.commandTimeoutZero).toBe(false);
    },
  );

  it("refuses a create with tunnel ports with tunnel_off while no tunnel server is configured", async () => {
    db.tunnelServerConfig.findUnique.mockResolvedValue(null);
    // A create that declares tunnel ports is refused before any write.
    const create = await app.request("/v1/sandboxes", {
      method: "POST",
      headers: { ...bearer, "content-type": "application/json", "idempotency-key": "tunnel-off" },
      body: JSON.stringify({
        sandboxHostId: "host1",
        template: "revision/tpl1",
        network: { tunnelPorts: [3000] },
      }),
    });
    await expectError(create.clone(), 400, "UNSUPPORTED_CAPABILITY");
    expect(sdkErrorEnvelopeSchema.parse(await json(create)).error).toMatchObject({
      reason: "tunnel_off",
    });
    expect(db.sandbox.create).not.toHaveBeenCalled();
  });

  it("reports the calling key's grant and only registered features", async () => {
    db.sdkKey.findUnique.mockResolvedValue(
      keyRow({
        scopes: ["sandboxes:read"],
        resourceMode: "ALLOWLIST",
        poolMode: "SELECTED",
      }) as never,
    );
    const body = await json(await get("/v1/capabilities"));
    expect(body).toEqual({
      apiVersion: "v1",
      // DATA_ENCRYPTION_KEY is unset here, so webhooks and CLI logins are not advertised.
      // No tunnel server is configured, so preview tunnels are not advertised.
      features: enabledSdkFeatures().filter(
        (feature) =>
          feature !== "webhooks.write" &&
          !feature.startsWith("credentials.") &&
          feature !== "sandboxes.tunnel",
      ),
      guestApi: guestApiCapabilities(true),
      limits: {
        ...FS_PROCESS_LIMITS,
        ...VM_SIZE_PUBLIC_LIMITS,
        sandboxTimeoutMinMs: 1,
        sandboxTimeoutDefaultMs: 300000,
        sandboxTimeoutMaxMs: 86400000,
        sandboxTimeoutZero: false,
        pageSizeDefault: 20,
        pageSizeMax: 100,
        jsonBodyMaxBytes: 1_048_576,
        transferMaxBytes: 1_073_741_824,
        // Deployment defaults (no admin override for this owner).
        imageStore: { mode: "peer", maxStoredGiB: 50, downloadsPerHour: 120 },
        // Builds on (image distribution peer), defaults, 24 h lease leaves room.
        templateBuilds: {
          enabled: true,
          reason: null,
          maxMinutes: 60,
          maxConcurrent: 2,
          minutesPerMonth: 1000,
          contextMaxBytes: 1_073_741_824,
          contextWaitMaxMs: 21_600_000,
          openEgress: true,
        },
        capacityWaitMaxMs: 3_600_000,
        capacityQueuePerKey: 16,
        capacityQueuePerOwner: 64,
      },
      ports: { ingress: false, proxy: false, tunnel: false },
      network: { egressModes: ["open", "allowlist"], defaultEgressMode: "open" },
      key: {
        scopes: ["sandboxes:read"],
        resourceMode: "allowlist",
        poolMode: "selected",
        ownSandboxesOnly: false,
      },
    });
    const { sdkReadHandlers } = await import("./reads.js");
    const partial = await sdkReadHandlers([
      "getCapabilities",
      "listSandboxes",
      "getSandbox",
    ]).getCapabilities({ kind: "session", ownerId: "owner-a" } as never, { params: {}, query: {} });
    expect(partial.features).toEqual(["sandboxes.read"]);
  });
});

describe("outcome, gone and unavailable stay distinct", () => {
  it("reports UNKNOWN_OUTCOME as its own outcome, not failure or absence", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(
      operationRow("UNKNOWN_OUTCOME", "unknown_outcome") as never,
    );
    const body = await json(await get("/v1/operations/op1"));
    expect(body).toMatchObject({ state: "UNKNOWN_OUTCOME", outcome: "unknown" });
    expect(body.errorCode).toBe("unknown_outcome");
    db.sandboxOperation.findFirst.mockResolvedValue(operationRow("FAILED", "timeout") as never);
    expect(await json(await get("/v1/operations/op1"))).toMatchObject({ outcome: "failed" });
  });

  it("returns a recorded DELETED sandbox as gone state and HOST_LOST as unavailable, not 404", async () => {
    for (const recorded of ["DELETED", "HOST_LOST", "UNREACHABLE"]) {
      db.sandbox.findFirst.mockResolvedValue(sandboxRow(recorded) as never);
      const response = await get("/v1/sandboxes/sbx1");
      expect(response.status).toBe(200);
      expect((await json(response)).state).toBe(recorded);
    }
    db.sandbox.findFirst.mockResolvedValue(null);
    await expectError(await get("/v1/sandboxes/sbx1"), 404, "sandbox.not_found");
  });
});

describe("status mappings", () => {
  it("401 for missing, malformed and host credentials", async () => {
    await expectError(await get("/v1/hosts", {}), 401, "UNAUTHORIZED");
    await expectError(
      await get("/v1/hosts", { authorization: "Bearer nope" }),
      401,
      "UNAUTHORIZED",
    );
    db.sdkKey.findUnique.mockResolvedValue(keyRow({ revokedAt: T }) as never);
    await expectError(await get("/v1/hosts"), 401, "UNAUTHORIZED");
  });

  it("403 when the key lacks the route scope, before any resource read", async () => {
    db.sdkKey.findUnique.mockResolvedValue(keyRow({ scopes: ["operations:cancel"] }) as never);
    for (const id of SDK_ROUTE_IDS) {
      // Scope-free self routes: any active key may read them.
      if (id === "getCapabilities" || id === "getKey" || SDK_ROUTES[id].method !== "get") continue;
      await expectError(await get(concretePath(SDK_ROUTES[id].path)), 403, "FORBIDDEN");
    }
    expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
    expect(db.sandbox.findMany).not.toHaveBeenCalled();
    expect(db.sandboxTemplate.findMany).not.toHaveBeenCalled();
    expect(db.sandbox.findFirst).not.toHaveBeenCalled();
    expect(db.sandboxOperation.findFirst).not.toHaveBeenCalled();
    expect((await get("/v1/capabilities")).status).toBe(200);
  });

  it("404 with the route's stable code for missing or foreign resources", async () => {
    db.sandbox.findFirst.mockResolvedValue(null);
    await expectError(await get("/v1/sandboxes/other-owner"), 404, "sandbox.not_found");
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    await expectError(await get("/v1/operations/other-owner"), 404, "sandbox.operation_not_found");
  });

  it("400 for invalid IDs, undeclared, repeated or malformed query parameters", async () => {
    for (const path of [
      "/v1/sandboxes/has.dot",
      `/v1/sandboxes/${"a".repeat(65)}`,
      "/v1/hosts?limit=0",
      "/v1/hosts?limit=101",
      "/v1/hosts?limit=1e1",
      "/v1/hosts?limit=5&limit=6",
      "/v1/hosts?offset=5",
      "/v1/hosts?cursor=not*base64",
      "/v1/hosts?cursor=Zm9v",
      "/v1/sandboxes/sbx1?expand=result",
      "/v1/capabilities?x=1",
    ]) {
      await expectError(await get(path), 400, "BAD_REQUEST");
    }
    expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
  });

  it("405 for other methods on documented paths", async () => {
    for (const path of ["/v1/hosts", "/v1/operations/op1"]) {
      await expectError(
        await app.request(path, { method: "DELETE", headers: bearer }),
        405,
        "METHOD_NOT_SUPPORTED",
      );
    }
  });

  it("409 when the service reports a concurrent account deletion", async () => {
    db.sandboxHost.findMany.mockRejectedValue(new AccountDeletionConflictError(["hosts"]));
    await expectError(await get("/v1/hosts"), 409, "CONFLICT");
  });

  it("429 and 503 from the fail-closed budgets", async () => {
    state.budgetFailure = new RateLimiterRes(0, 12_000);
    const limited = await get("/v1/hosts");
    await expectError(limited, 429, "TOO_MANY_REQUESTS");
    state.budgetFailure = new Error("redis down: secret-host:6379");
    const unavailable = await get("/v1/hosts");
    expect(unavailable.headers.get("retry-after")).toBe("5");
    await expectError(unavailable, 503, "SERVICE_UNAVAILABLE");
  });

  it("GET routes never buffer a request body, so no read can reach 413", async () => {
    const incoming = new IncomingMessage(new Socket());
    incoming.url = "/v1/hosts";
    incoming.method = "GET";
    incoming.headers = {
      host: "localhost",
      ...bearer,
      "content-type": "application/json",
      "content-length": String(2 * 1024 * 1024),
    };
    incoming.rawHeaders = ["Host", "localhost", "Authorization", bearer.authorization];
    incoming.httpVersionMajor = 1;
    incoming.httpVersion = "1.1";
    const response = new ServerResponse(incoming);
    const chunks: string[] = [];
    vi.spyOn(response, "write").mockImplementation((chunk) => {
      chunks.push(String(chunk));
      return true;
    });
    vi.spyOn(response, "end").mockImplementation((chunk) => {
      if (chunk) chunks.push(String(chunk));
      return response;
    });
    incoming.push("x".repeat(2 * 1024 * 1024));
    incoming.push(null);
    await getRequestListener(app.fetch)(incoming, response);
    expect(response.statusCode).toBe(200);
    expect(JSON.parse(chunks.join(""))).toMatchObject({ items: [{ id: "host1" }] });
    incoming.destroy();
  });
});

it.each([
  [{ metadata: { invalid: 3 }, egress: { domains: 7 }, cpuCount: 0 }, "sandbox.metadata_invalid"],
  [{ egress: { domains: 7 }, memoryMiB: 513 }, "sandbox.egress_policy_invalid"],
  [
    { cpuCount: "private-size-sentinel", envs: { PRIVATE: "private-size-sentinel" } },
    "sandbox.vm_size_invalid",
  ],
  [{ memoryMiB: 513 }, "sandbox.vm_size_invalid"],
] as const)("B5 native safe validation precedence %j", async (fields, code) => {
  const response = await app.request("/v1/sandboxes", {
    method: "POST",
    headers: { ...bearer, "content-type": "application/json", "idempotency-key": "size-invalid" },
    body: JSON.stringify({ template: "base", sandboxHostId: "host1", ...fields }),
  });
  await expectError(response.clone(), 400, code);
  expect(response.headers.has("Location")).toBe(false);
  expect(await response.text()).not.toContain("private-size-sentinel");
  expect(db.sandbox.create).not.toHaveBeenCalled();
  expect(db.sandboxOperation.create).not.toHaveBeenCalled();
  expect(db.sandboxActionReceipt.create).not.toHaveBeenCalled();
});

describe("sandbox name validation is route-scoped (R8/M1)", () => {
  it.each(["Bad_Name", "wssp-reserved", "123e4567-e89b-12d3-a456-426614174000", "x".repeat(64)])(
    "create refuses %j with sandbox.name_invalid before allocation",
    async (name) => {
      const response = await app.request("/v1/sandboxes", {
        method: "POST",
        headers: { ...bearer, "content-type": "application/json", "idempotency-key": "bad-name" },
        body: JSON.stringify({ template: "base", sandboxHostId: "host1", name }),
      });
      await expectError(response, 400, "sandbox.name_invalid");
      expect(db.sandbox.create).not.toHaveBeenCalled();
    },
  );

  it("rename refuses an invalid name with sandbox.name_invalid before any write", async () => {
    const response = await app.request("/v1/sandboxes/sbx1", {
      method: "PUT",
      headers: { ...bearer, "content-type": "application/json" },
      body: JSON.stringify({ name: "Bad_Name" }),
    });
    await expectError(response, 400, "sandbox.name_invalid");
    expect(db.sandbox.update).not.toHaveBeenCalled();
  });

  it("a credential account's `name` keeps its own error code", async () => {
    const response = await app.request("/v1/credentials/cred1/accounts", {
      method: "POST",
      headers: { ...bearer, "content-type": "application/json" },
      body: JSON.stringify({ name: "" }),
    });
    await expectError(response, 400, "BAD_REQUEST");
  });
});

const waiters = await import("@wssp/api/sandbox/operation-waiters");
describe("operation long-poll (waitMs)", () => {
  afterEach(() => {
    expect(waiters.operationWaiterCounts()).toEqual({ held: 0, watches: 0 });
  });
  /** Let the held request reach its wait (real timers, in-process app). */
  const settle = () => new Promise((resolve) => setTimeout(resolve, 30));

  it("parses waitMs strictly: 0–25000 decimal, once, on the three operation reads only", async () => {
    expect((await get("/v1/operations/op1?waitMs=0")).status).toBe(200);
    for (const bad of ["25001", "-1", "1.5", "01", "abc", ""]) {
      await expectError(await get(`/v1/operations/op1?waitMs=${bad}`), 400, "BAD_REQUEST");
    }
    await expectError(await get("/v1/operations/op1?waitMs=10&waitMs=10"), 400, "BAD_REQUEST");
    await expectError(await get("/v1/operations/op1/output?waitMs=25001"), 400, "BAD_REQUEST");
    await expectError(await get("/v1/operations/op1/result?waitMs=x"), 400, "BAD_REQUEST");
    // Every other read still rejects it as an undeclared parameter.
    await expectError(await get("/v1/sandboxes/sbx1?waitMs=10"), 400, "BAD_REQUEST");
  });

  it("holds a pending read, answers on the commit wake, and charges one request", async () => {
    const plain = await get("/v1/operations/op1");
    expect(plain.status).toBe(200);
    const perRequest = state.consumed.length;
    state.consumed.length = 0;
    const started = Date.now();
    const pending = get("/v1/operations/op1?waitMs=20000");
    await settle();
    expect(waiters.operationWaiterCounts()).toEqual({ held: 1, watches: 1 });
    db.sandboxOperation.findFirst.mockResolvedValue(operationRow("SUCCEEDED", null) as never);
    waiters.notifyOperationsChanged(waiters.operationChange(["op1"]));
    const response = await pending;
    expect(response.status).toBe(200);
    expect((await json(response)).outcome).toBe("succeeded");
    expect(Date.now() - started).toBeLessThan(5_000);
    // The held wait and its re-read are free: same budget charges as one plain read.
    expect(state.consumed.length).toBe(perRequest);
  });

  it("answers as-is when waitMs elapses", async () => {
    const started = Date.now();
    const response = await get("/v1/operations/op1?waitMs=200");
    expect(response.status).toBe(200);
    expect((await json(response)).outcome).toBe("pending");
    expect(Date.now() - started).toBeGreaterThanOrEqual(190);
  });

  it("a client disconnect frees the waiter slot", async () => {
    const controller = new AbortController();
    const pending = Promise.resolve(
      app.request("/v1/operations/op1?waitMs=20000", {
        headers: bearer,
        signal: controller.signal,
      }),
    ).catch(() => null);
    await settle();
    expect(waiters.operationWaiterCounts().held).toBe(1);
    controller.abort();
    await pending;
    expect(waiters.operationWaiterCounts()).toEqual({ held: 0, watches: 0 });
  });

  it("a key revoked mid-wait gets the normal auth refusal on the re-read", async () => {
    const pending = get("/v1/operations/op1?waitMs=20000");
    await settle();
    db.sdkKey.findUnique.mockResolvedValue(keyRow({ revokedAt: T }) as never);
    db.sandboxOperation.findFirst.mockResolvedValue(operationRow("SUCCEEDED", null) as never);
    waiters.notifyOperationsChanged(waiters.operationChange(["op1"]));
    const response = await pending;
    expect([401, 403]).toContain(response.status);
    const body = await json(response);
    expect(JSON.stringify(body)).not.toContain("succeeded");
  });

  it("nothing is registered while a foreign id's authorizing read is in flight", async () => {
    let resolveRow!: (row: null) => void;
    db.sandboxOperation.findFirst.mockImplementation(
      (() =>
        new Promise((resolve) => {
          resolveRow = resolve;
        })) as never,
    );
    const pending = get("/v1/operations/other-owner?waitMs=20000");
    await settle();
    expect(waiters.operationWaiterCounts()).toEqual({ held: 0, watches: 0 });
    resolveRow(null);
    await expectError(await pending, 404, "sandbox.operation_not_found");
  });

  it("a foreign or missing operation is a plain 404 and leaves no waiter", async () => {
    db.sandboxOperation.findFirst.mockResolvedValue(null);
    await expectError(
      await get("/v1/operations/other-owner?waitMs=20000"),
      404,
      "sandbox.operation_not_found",
    );
  });

  it("output pages: hold before start, brief hold on progress, answer when finished", async () => {
    const { outputPageReady } = await import("./reads.js");
    const empty = {
      chunks: [],
      gaps: [],
      hasMore: false,
      complete: false,
      reset: false,
      state: "RUNNING" as const,
    };
    expect(outputPageReady(empty)).toBe(false);
    // Not started yet: an empty page holds through every pre-start state.
    for (const state of ["QUEUED", "DISPATCHED", "ACCEPTED", "CANCEL_REQUESTED"] as const)
      expect(outputPageReady({ ...empty, state })).toBe(false);
    // New bytes of a running command: held briefly for the completion.
    expect(outputPageReady({ ...empty, chunks: [{}] })).toBe("progress");
    expect(outputPageReady({ ...empty, gaps: [{}] })).toBe("progress");
    expect(outputPageReady({ ...empty, reset: true })).toBe("progress");
    // Finished, or more pages waiting: answered now.
    expect(outputPageReady({ ...empty, hasMore: true })).toBe(true);
    expect(outputPageReady({ ...empty, complete: true })).toBe(true);
    expect(outputPageReady({ ...empty, chunks: [{}], complete: true })).toBe(true);
    expect(outputPageReady({ ...empty, state: "UNKNOWN_OUTCOME" })).toBe(true);
    expect(outputPageReady({ ...empty, state: "SUCCEEDED" })).toBe(true);
  });
});
