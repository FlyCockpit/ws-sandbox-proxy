import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  SERVICE_ACTION_REQUIREMENTS,
  SERVICE_SCOPES,
  type ServiceAction,
} from "@wssp/api/lib/service-scopes";
import { credentialLookupPrefix } from "@wssp/db/credential-security";
import { SDK_ROUTE_IDS, SDK_ROUTES } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, expect, it, vi } from "vitest";
import { z } from "zod";

vi.mock("@wssp/db", async () => ({
  default: await (await import("@wssp/api/test/mock-prisma")).createMockPrisma(),
}));
vi.mock("@wssp/env/server", () => ({
  env: {
    BETTER_AUTH_SECRET: "http-matrix-fixture",
    RATE_LIMIT_SDK_IP_POINTS: 300,
    RATE_LIMIT_SDK_KEY_POINTS: 100,
    RATE_LIMIT_SDK_OWNER_POINTS: 300,
    SANDBOX_MAX_TIMEOUT_MS: 86400000,
    TRANSFER_MAX_BYTES: 1073741824,
    TRANSFER_DISK_BYTES: 1073741824,
    TRANSFER_OWNER_ACTIVE: 10,
    TRANSFER_GLOBAL_ACTIVE: 100,
    TRANSFER_IDLE_SECONDS: 60,
    TRANSFER_ABSOLUTE_SECONDS: 600,
  },
  ADMIN_EMAILS: new Set(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {}, imageStoreMaintenanceQueue: {} }));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/api/lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));
vi.mock("@hono/node-server/conninfo", () => ({
  getConnInfo: () => ({ remote: { address: "127.0.0.1" } }),
}));
const { default: prisma } = await import("@wssp/db");
const db = prisma as import("@wssp/api/test/mock-prisma").MockPrisma;
const { createSandboxApi } = await import("./middleware");
const auth = await import("@wssp/api/lib/sdk-key-access");

// Independent adapter-to-service oracle, including binary transfer routes.
const actions = {
  getHost: "hosts.get",
  listHosts: "hosts.list",
  startHostCommand: "hostCommands.run",
  getHostCommand: "hostCommands.get",
  writeHostCommandStdin: "hostCommands.writeStdin",
  cancelHostCommand: "hostCommands.cancel",
  queueHostCommand: "hostCommands.queue",
  getQueuedHostCommand: "hostCommands.queue",
  readHostFile: "hostFiles.read",
  listHostFiles: "hostFiles.list",
  writeHostFile: "hostFiles.write",
  editHostFile: "hostFiles.edit",
  getCapabilities: "capabilities.get",
  getKey: "key.get",
  revokeKey: "key.revokeSelf",
  listPools: "pools.list",
  getPool: "pools.get",
  getPoolCapacity: "pools.capacity",
  listPoolMembers: "pools.members",
  listTemplates: "templates.list",
  listTemplateRevisions: "templates.revisions",
  listTemplateAvailability: "templates.availability",
  listSandboxes: "sandboxes.list",
  getSandbox: "sandboxes.get",
  getSandboxCapabilities: "sandboxes.capabilities",
  createSandbox: "sandboxes.create",
  updateSandbox: "sandboxes.update",
  getSandboxTunnel: "sandboxes.tunnelGet",
  exposeSandboxTunnel: "sandboxes.tunnelExpose",
  closeSandboxTunnel: "sandboxes.tunnelClose",
  createSandboxTunnelLink: "sandboxes.tunnelLink",
  revokeSandboxTunnelLink: "sandboxes.tunnelLinkRevoke",
  updateSandboxTunnelPorts: "sandboxes.tunnelPorts",
  destroySandbox: "sandboxes.kill",
  stopSandbox: "sandboxes.stop",
  reconnectSandbox: "sandboxes.reconnect",
  renewSandboxLease: "sandboxes.setTimeout",
  captureSandbox: "sandboxes.capture",
  probeSandbox: "sandboxes.probe",
  getOperation: "operations.get",
  getOperationResult: "operations.get",
  getCommandOutput: "operations.getCommandOutput",
  cancelOperation: "operations.cancel",
  startCommand: "commands.run",
  writeStdin: "commands.writeStdin",
  sendProcessStdin: "commands.writeStdin",
  listProcesses: "processes.list",
  connectProcess: "processes.connect",
  signalProcess: "processes.signal",
  killProcess: "processes.signal",
  statPath: "files.stat",
  listDir: "files.listDir",
  mkdir: "files.mkdir",
  movePath: "files.move",
  removePath: "files.remove",
  requestDownload: "files.read",
  registerTemplate: "templates.create",
  appendTemplateRevision: "templates.append",
  associateTemplateAvailability: "templates.associate",
  listWebhookEndpoints: "webhooks.list",
  createWebhookEndpoint: "webhooks.create",
  getWebhookEndpoint: "webhooks.get",
  updateWebhookEndpoint: "webhooks.update",
  deleteWebhookEndpoint: "webhooks.delete",
  rotateWebhookSecret: "webhooks.rotateSecret",
  testWebhookEndpoint: "webhooks.test",
  listWebhookDeliveries: "webhooks.listDeliveries",
  getWebhookDelivery: "webhooks.getDelivery",
  redeliverWebhook: "webhooks.redeliver",
  createTemplateBuild: "templates.build",
  listTemplateBuilds: "templates.build",
  getTemplateBuild: "templates.build",
  cancelTemplateBuild: "templates.build",
  getTemplateBuildLogs: "templates.build",
  createCommunityTemplate: ["templates.create", "templates.build"],
  listCredentialDefinitions: "credentialDefinitions.list",
  createCredentialDefinition: "credentialDefinitions.create",
  getCredentialDefinition: "credentialDefinitions.get",
  archiveCredentialDefinition: "credentialDefinitions.archive",
  listCredentials: "credentials.list",
  createCredential: "credentials.create",
  getCredential: "credentials.get",
  updateCredential: "credentials.update",
  deleteCredential: "credentials.delete",
  listCredentialEvents: "credentials.events",
  listCredentialAccounts: "credentialAccounts.list",
  createCredentialAccount: "credentialAccounts.create",
  updateCredentialAccount: "credentialAccounts.update",
  deleteCredentialAccount: "credentialAccounts.delete",
  listCredentialInstances: "credentialInstances.list",
  createCredentialInstance: "credentialInstances.create",
  updateCredentialInstance: "credentialInstances.update",
  deleteCredentialInstance: "credentialInstances.delete",
  writeCredentialValue: "credentialInstances.writeValue",
  listCredentialLeases: "credentialInstances.listLeases",
  forceReleaseCredentialLease: "credentialInstances.forceRelease",
  attachSandboxCredential: "sandboxCredentials.attach",
  freeSandboxCredential: "sandboxCredentials.free",
  createUpload: "files.write",
  getUpload: "files.write",
  putUploadChunk: "files.write",
  commitUpload: "files.write",
  abortUpload: "files.write",
  downloadFile: "operations.downloadFile",
  openBuildContext: "templates.build",
  putBuildContextChunk: "templates.build",
  sealBuildContext: "templates.build",
} satisfies Record<keyof typeof SDK_ROUTES, ServiceAction | ServiceAction[]>;

const spool = await mkdtemp(join(tmpdir(), "rp5-fuwssp-matrix-"));
const { env } = await import("@wssp/env/server");
Object.assign(env, { TRANSFER_SPOOL_DIR: spool });
const { startTransferStore } = await import("../sandbox-transfers/runtime");
let store: Awaited<ReturnType<typeof startTransferStore>>;
beforeAll(async () => {
  db.sandboxTransfer.findMany.mockResolvedValue([]);
  store = await startTransferStore();
});
afterAll(async () => {
  await store?.close();
  await rm(spool, { recursive: true, force: true });
});
const credential = auth.generateSdkKeySecret();
let scopes: string[] = [];
beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, "log").mockImplementation(() => {});
  db.appSetting.findMany.mockResolvedValue([]);
  db.sandboxOperation.findFirst.mockResolvedValue({
    id: "operation",
    kind: "RUN_COMMAND",
    sandboxId: "sandbox",
    authorizingKeyId: "key",
    Sandbox: {
      id: "sandbox",
      sandboxHostId: "host",
      hostOwnerId: "owner",
      originHostId: "host",
      templateRevisionId: "revision",
      originPoolId: null,
      usagePoolId: null,
      purpose: "WORKLOAD",
    },
  } as never);
  db.sandboxHost.findFirst.mockResolvedValue({ id: "host" } as never);
  db.sandboxTransfer.findFirst.mockResolvedValue({
    id: "00000000-0000-4000-8000-000000000001",
    userId: "owner",
    keyId: "key",
    direction: "UPLOAD",
    sandboxId: "sandbox",
  } as never);
  db.sdkKey.findUnique.mockImplementation((async () => ({
    id: "key",
    userId: "owner",
    kind: "API",
    ownSandboxesOnly: false,
    scopes,
    lookupPrefix: credentialLookupPrefix(credential),
    secretDigest: auth.digestSdkKeySecret(credential.raw),
    resourceMode: "ALL_OWNED",
    poolMode: "ALL_USABLE",
    revokedAt: null,
    expiresAt: null,
    HostAllowlist: [],
    RevisionAllowlist: [],
    PoolAllowlist: [],
    User: {
      banned: false,
      banExpires: null,
      deletionRequestedAt: null,
      twoFactorEnabled: true,
      role: "user",
      createdAt: new Date(0),
    },
  })) as never);
});

it("maps every route to the scope union of its native service actions", () => {
  expect(Object.keys(actions).sort()).toEqual([...SDK_ROUTE_IDS].sort());
  for (const id of SDK_ROUTE_IDS) {
    const value = actions[id];
    const mapped = typeof value === "string" ? [value] : value;
    expect(
      [...new Set(mapped.flatMap((action) => SERVICE_ACTION_REQUIREMENTS[action].scopes))].sort(),
      id,
    ).toEqual([...SDK_ROUTES[id].scopes].sort());
  }
});

// Generate mundane required fields from each contract; pin refined payloads below.
function sample(schema: Record<string, unknown>): unknown {
  if ("default" in schema) return schema.default;
  if ("const" in schema) return schema.const;
  if (Array.isArray(schema.enum)) return schema.enum[0];
  if (Array.isArray(schema.anyOf)) return sample(schema.anyOf[0]);
  if (Array.isArray(schema.oneOf)) return sample(schema.oneOf[0]);
  if (schema.type === "object")
    return Object.fromEntries(
      ((schema.required as string[]) ?? []).map((key) => [
        key,
        sample((schema.properties as Record<string, Record<string, unknown>>)[key]!),
      ]),
    );
  if (schema.type === "array")
    return Array.from({ length: Number(schema.minItems ?? 0) }, () =>
      sample(schema.items as Record<string, unknown>),
    );
  if (schema.type === "number" || schema.type === "integer") return schema.minimum ?? 1;
  if (schema.type === "boolean") return false;
  if (schema.type === "null") return null;
  if (schema.format === "uri" || schema.format === "url") return "https://example.test/webhook";
  if (schema.format === "date-time") return "2026-12-01T00:00:00.000Z";
  return "x".repeat(Math.max(1, Number(schema.minLength ?? 1)));
}
const bodies: Record<string, unknown> = {
  createTemplateBuild: {
    template: { slug: "test" },
    dockerfile: "FROM ubuntu",
    sandboxHostId: "host",
  },
  createCommunityTemplate: { source: "ubuntu-26.04", sandboxHostId: "host" },
  updateCredential: { name: "updated" },
  updateCredentialAccount: { name: "updated" },
  updateCredentialInstance: { name: "updated" },
  writeCredentialValue: { env: { TEST_VALUE: "fixture" } },
  registerTemplate: {
    hostId: "host",
    slug: "test",
    label: "Test",
    imageRef: "images:ubuntu/24.04/cloud",
  },
  appendTemplateRevision: { hostId: "host", imageRef: "images:ubuntu/24.04/cloud" },
  associateTemplateAvailability: { hostId: "host", revisionId: "revision" },
  commitUpload: { sha256: "a".repeat(64) },
  createUpload: { sandboxId: "sandbox", guestPath: "/tmp/test", totalBytes: 0 },
  createSandbox: { sandboxHostId: "host", template: "revision/revision" },
  updateSandbox: { name: "quiet-otter", offload: { mode: "on_pressure" } },
  exposeSandboxTunnel: { ports: [3000] },
  createSandboxTunnelLink: { port: 3000 },
  updateSandboxTunnelPorts: { add: [3000] },
  startCommand: { script: "true" },
  startHostCommand: { script: "true" },
  writeHostCommandStdin: { data: "aGk=", eof: true },
  readHostFile: { path: "/tmp/test" },
  listHostFiles: { path: "/tmp" },
  writeHostFile: { path: "/tmp/test", content: "hi", createOnly: true },
  editHostFile: { path: "/tmp/test", edits: [{ oldText: "hi", newText: "hello" }] },
  queueHostCommand: { command: "true", reason: "review" },
  requestDownload: { path: "/tmp/test" },
  statPath: { path: "/tmp/test" },
  listDir: { path: "/tmp" },
  mkdir: { path: "/tmp/test" },
  removePath: { path: "/tmp/test" },
  movePath: { path: "/tmp/test", destPath: "/tmp/other" },
  writeStdin: { contentBase64: "aGk=", eof: true },
  sendProcessStdin: {
    generation: 1,
    processId: "process",
    attempt: 1,
    contentBase64: "aGk=",
    eof: true,
  },
  signalProcess: { generation: 1, processId: "process", attempt: 1, signal: "SIGTERM" },
  killProcess: { generation: 1, processId: "process", attempt: 1 },
};
for (const id of SDK_ROUTE_IDS) {
  const route = SDK_ROUTES[id];
  for (const missing of route.scopes)
    it(`${id} refuses without ${missing} through Hono`, async () => {
      scopes = SERVICE_SCOPES.filter((scope) => scope !== missing);
      const app = new Hono().route("/v1", createSandboxApi());
      const url = new URL(
        route.path
          .replace(/\{pid\}/g, "42")
          .replace(/\{commandId\}/g, "abcdefghijklmnopqrstuv")
          .replace(/\{linkId\}/g, "al_resource")
          .replace(/\{[^}]+\}/g, "resource"),
        "http://localhost",
      );
      if (["getUpload", "putUploadChunk", "commitUpload", "abortUpload"].includes(id))
        url.pathname = url.pathname.replace("resource", "00000000-0000-4000-8000-000000000001");
      const query = z.toJSONSchema(route.query, { io: "input", unrepresentable: "any" });
      const queryValue = sample(query) as Record<string, unknown>;
      for (const [key, value] of Object.entries(queryValue))
        url.searchParams.set(key, String(value));
      if (id === "listTemplateAvailability") url.searchParams.set("revisionId", "revision");
      if (id === "getTemplateBuildLogs") url.searchParams.set("step", "0");
      if (id === "connectProcess")
        for (const [key, value] of Object.entries({
          generation: "1",
          processId: "process",
          attempt: "1",
        }))
          url.searchParams.set(key, value);
      let body: string | undefined;
      if ("body" in route && route.body) {
        const value =
          bodies[id] ?? sample(z.toJSONSchema(route.body, { io: "input", unrepresentable: "any" }));
        const parsed = route.body.safeParse(value);
        expect(parsed.success, `${id}: ${JSON.stringify(parsed.error?.issues)}`).toBe(true);
        body = JSON.stringify(value);
      }
      const response = await app.request(url.pathname + url.search, {
        method: route.method.toUpperCase(),
        headers: {
          authorization: `Bearer ${credential.raw}`,
          "content-type": "application/json",
          "idempotency-key": "matrix-retry",
        },
        body,
      });
      expect(response.status, `${id}: ${await response.clone().text()}`).toBe(403);
      expect(((await response.json()) as { error: { code: string } }).error.code).toBe("FORBIDDEN");
    });
}
