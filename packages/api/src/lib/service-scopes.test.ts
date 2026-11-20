vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import type { SandboxOperationKind } from "@wssp/db";
import { describe, expect, it, vi } from "vitest";
import type { Principal } from "../sandbox/contracts";
import type { ServicePrincipal } from "./sdk-key-access";
import type { ServiceAction, ServiceScope } from "./service-scopes";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: { BETTER_AUTH_SECRET: "scope-matrix-test" },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const { sandboxPoolsRouter } = await import("../routers/sandbox-pools");
const pools = await import("../sandbox/services/pools");
const sharing = await import("../sandbox/services/sharing");
const capacityView = await import("../sandbox/capacity-view");
const { sandboxHostsRouter } = await import("../routers/sandbox-hosts");
const { sandboxTemplatesRouter } = await import("../routers/sandbox-templates");
const { sandboxesRouter } = await import("../routers/sandboxes");
const hosts = await import("../sandbox/services/hosts");
const templates = await import("../sandbox/services/templates");
const sandboxes = await import("../sandbox/services/sandboxes");
const { SANDBOX_PROCEDURE_INVENTORY } = await import("../sandbox/services");
const { webhooksRouter } = await import("../routers/webhooks");
const webhookServices = await import("../webhooks/service");
const { loginsRouter } = await import("../routers/logins");
const loginServices = {
  ...(await import("../credentials/service")),
  ...(await import("../credentials/live")),
  ...(await import("../credentials/login-sessions")),
};
const { authorizeServiceAction } = await import("./sdk-key-access");
const production = await import("./service-scopes");
const { default: db } = await import("@wssp/db");

// Independent literal oracle: do not derive any expected value from production.
const expected = {
  "operations.getFileResult": { scopes: ["operations:read", "files:read"], requiresSandbox: true },
  "operations.getFileMutationResult": {
    scopes: ["operations:read", "files:write"],
    requiresSandbox: true,
  },
  "operations.getRenameResult": {
    scopes: ["operations:read", "files:read", "files:write"],
    requiresSandbox: true,
  },
  "operations.getCommandResult": {
    scopes: ["operations:read", "commands:read"],
    requiresSandbox: true,
  },
  "operations.getSignalResult": {
    scopes: ["operations:read", "commands:execute", "operations:cancel"],
    requiresSandbox: true,
  },
  "capabilities.get": { scopes: [] },
  // The calling key itself (GET/DELETE /v1/key); never an MCP tool.
  "key.get": { scopes: [] },
  "key.revokeSelf": { scopes: [] },
  "hosts.list": { scopes: ["hosts:read"] },
  "hosts.get": { scopes: ["hosts:read"], requiresHost: true },
  "hostCommands.run": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostCommands.get": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostCommands.writeStdin": {
    scopes: ["hosts:execute"],
    requiresHost: true,
    requiresOwnedHost: true,
  },
  "hostCommands.cancel": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostCommands.queue": { scopes: ["hosts:execute"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.read": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.list": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.write": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },
  "hostFiles.edit": { scopes: ["hosts:files"], requiresHost: true, requiresOwnedHost: true },

  "hosts.storagePools": { scopes: ["hosts:read"], requiresHost: true },
  "pools.list": { scopes: ["pools:read"] },
  "pools.get": { scopes: ["pools:read"], requiresPool: true },
  "pools.members": { scopes: ["pools:read", "hosts:read"], requiresPool: true },
  "pools.capacity": { scopes: ["pools:read"], requiresPool: true },
  "templates.list": { scopes: ["templates:read"] },
  "templates.create": { scopes: ["templates:write"], requiresHost: true },
  "templates.retire": { scopes: ["templates:write"], requiresTemplate: true },
  "templates.build": { scopes: ["templates:build"] },
  "templates.revisions": { scopes: ["templates:read"] },
  "templates.availability": { scopes: ["templates:read", "hosts:read"], requiresTemplate: true },
  "templates.append": { scopes: ["templates:write"], requiresHost: true },
  "templates.associate": {
    scopes: ["templates:write"],
    requiresHost: true,
    requiresTemplate: true,
  },
  "sandboxes.list": { scopes: ["sandboxes:read"] },
  "sandboxes.get": { scopes: ["sandboxes:read"], requiresSandbox: true },
  "sandboxes.probe": { scopes: ["sandboxes:read"], requiresSandbox: true },
  "sandboxes.createIntent": { scopes: ["sandboxes:create"] },
  "sandboxes.replayCreate": {
    scopes: ["sandboxes:create"],
    requiresSandbox: true,
    requiresPoolWhenPooled: true,
  },
  "sandboxes.create": {
    scopes: ["sandboxes:create"],
    requiresHost: true,
    requiresTemplate: true,
    requiresPoolWhenPooled: true,
  },
  "sandboxes.kill": { scopes: ["sandboxes:destroy"], requiresSandbox: true },
  "sandboxes.stop": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.capture": { scopes: ["sandboxes:manage", "templates:write"], requiresSandbox: true },
  "sandboxes.reconnect": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.setTimeout": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.update": { scopes: ["sandboxes:manage"], requiresSandbox: true },
  "sandboxes.tunnelGet": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelExpose": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelClose": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelLink": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelLinkRevoke": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.tunnelPorts": { scopes: ["sandboxes:tunnel"], requiresSandbox: true },
  "sandboxes.connect": { scopes: ["sandboxes:connect"], requiresSandbox: true },
  "operations.getReceipt": { scopes: ["operations:read"], requiresHost: true },
  "operations.get": { scopes: ["operations:read"], requiresSandbox: true },
  "operations.getCommandOutput": {
    scopes: ["operations:read", "commands:read"],
    requiresSandbox: true,
  },
  "operations.downloadFile": { scopes: ["operations:read", "files:read"], requiresSandbox: true },
  "operations.cancel": {
    scopes: ["operations:cancel"],
    requiresSandbox: true,
    cancelMutationScope: true,
  },
  "commands.run": { scopes: ["commands:execute"], requiresSandbox: true },
  "commands.writeStdin": { scopes: ["commands:execute"], requiresSandbox: true },
  "files.read": { scopes: ["files:read"], requiresSandbox: true },
  "files.write": { scopes: ["files:write"], requiresSandbox: true },
  "files.listDir": { scopes: ["files:read"], requiresSandbox: true },
  "files.stat": { scopes: ["files:read"], requiresSandbox: true },
  "files.mkdir": { scopes: ["files:write"], requiresSandbox: true },
  "files.remove": { scopes: ["files:write"], requiresSandbox: true },
  "files.move": { scopes: ["files:write"], requiresSandbox: true },
  "processes.connect": { scopes: ["commands:read"], requiresSandbox: true },
  "sandboxes.capabilities": { scopes: ["sandboxes:read"], requiresSandbox: true },
  "processes.list": { scopes: ["commands:read"], requiresSandbox: true },
  "processes.signal": { scopes: ["commands:execute", "operations:cancel"], requiresSandbox: true },
  "webhooks.list": { scopes: ["webhooks:write"] },
  "webhooks.get": { scopes: ["webhooks:write"] },
  "webhooks.create": { scopes: ["webhooks:write"] },
  "webhooks.update": { scopes: ["webhooks:write"] },
  "webhooks.delete": { scopes: ["webhooks:write"] },
  "webhooks.rotateSecret": { scopes: ["webhooks:write"] },
  "webhooks.test": { scopes: ["webhooks:write"] },
  "webhooks.listDeliveries": { scopes: ["webhooks:write"] },
  "webhooks.getDelivery": { scopes: ["webhooks:write"] },
  "webhooks.redeliver": { scopes: ["webhooks:write"] },
  "credentialDefinitions.list": { scopes: ["credentials:read"] },
  "credentialDefinitions.get": { scopes: ["credentials:read"] },
  "credentialDefinitions.create": { scopes: ["credentials:write"] },
  "credentialDefinitions.archive": { scopes: ["credentials:write"] },
  "credentials.list": { scopes: ["credentials:read"] },
  "credentials.get": { scopes: ["credentials:read"] },
  "credentials.create": { scopes: ["credentials:write"] },
  "credentials.update": { scopes: ["credentials:write"] },
  "credentials.delete": { scopes: ["credentials:write"] },
  "credentials.events": { scopes: ["credentials:read"] },
  "credentialAccounts.list": { scopes: ["credentials:read"] },
  "credentialAccounts.create": { scopes: ["credentials:write"] },
  "credentialAccounts.update": { scopes: ["credentials:write"] },
  "credentialAccounts.delete": { scopes: ["credentials:write"] },
  "credentialInstances.list": { scopes: ["credentials:read"] },
  "credentialInstances.create": { scopes: ["credentials:write"] },
  "credentialInstances.update": { scopes: ["credentials:write"] },
  "credentialInstances.delete": { scopes: ["credentials:write"] },
  "credentialInstances.writeValue": { scopes: ["credentials:write"] },
  "sandboxCredentials.attach": {
    scopes: ["sandboxes:manage", "credentials:use"],
    requiresSandbox: true,
  },
  "sandboxCredentials.free": {
    scopes: ["sandboxes:manage", "credentials:use"],
    requiresSandbox: true,
  },
  "credentialInstances.listLeases": { scopes: ["credentials:read"] },
  "credentialInstances.forceRelease": { scopes: ["credentials:write"] },
} as const;
const allScopes: ServiceScope[] = [
  "pools:read",
  "hosts:read",
  "hosts:execute",
  "hosts:files",
  "templates:read",
  "templates:write",
  "templates:build",
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
  "webhooks:write",
  "credentials:read",
  "credentials:write",
  "credentials:use",
  "sandboxes:tunnel",
  "sandboxes:connect",
];
const kindScopes: Record<SandboxOperationKind, [ServiceScope, ServiceScope]> = {
  CREATE_SANDBOX: ["sandboxes:create", "sandboxes:read"],
  KILL_SANDBOX: ["sandboxes:destroy", "sandboxes:read"],
  STOP_SANDBOX: ["sandboxes:manage", "sandboxes:read"],
  RECONNECT_SANDBOX: ["sandboxes:manage", "sandboxes:read"],
  RENEW_SANDBOX_LEASE: ["sandboxes:manage", "sandboxes:read"],
  RUN_COMMAND: ["commands:execute", "commands:read"],
  SIGNAL_PROCESS: ["commands:execute", "commands:read"],
  GET_FILE: ["files:read", "files:read"],
  PUT_FILE: ["files:write", "files:read"],
  LIST_DIR: ["files:read", "files:read"],
  STAT_PATH: ["files:read", "files:read"],
  MKDIR: ["files:write", "files:read"],
  REMOVE_PATH: ["files:write", "files:read"],
  MOVE_PATH: ["files:write", "files:read"],
  LIST_PROCESSES: ["commands:read", "sandboxes:read"],
};
// Real router keys form the inventory, independent of SERVICE_ACTIONS. Each
// supported procedure maps to exactly one action; exclusions are explicit.
const surface = [
  {
    router: sandboxPoolsRouter,
    services: {
      listShared: sharing.listSharedPools,
      listUsable: sharing.listUsablePools,
      getUsable: sharing.getUsablePool,
      listUsableMembers: sharing.listUsablePoolMembers,
      listContributions: sharing.listPoolContributions,
      listShares: sharing.listPoolShares,
      grantShare: sharing.grantPoolShare,
      updateShare: sharing.updatePoolShare,
      revokeShare: sharing.revokePoolShare,
      leave: sharing.leavePool,
      resendInvite: sharing.resendPoolInvite,
      revokeInvite: sharing.revokePoolInvite,
      acceptInvite: sharing.acceptPoolInvite,
      contributeHost: sharing.contributePoolHost,
      withdrawHost: sharing.withdrawPoolHost,

      listInvites: sharing.listPoolInvites,
      list: pools.listPools,
      get: pools.getPool,
      create: pools.createPool,
      update: pools.updatePool,
      delete: pools.deletePool,
      listMembers: pools.listPoolMembers,
      addMember: pools.addPoolMember,
      updateMember: pools.updatePoolMember,
      removeMember: pools.removePoolMember,
      previewLeaseLowering: pools.previewLeaseLowering,
      capacity: capacityView.getPoolCapacity,
      queue: pools.listPoolQueue,
    },
    actions: {
      listShared: null,
      listUsable: "pools.list",
      getUsable: "pools.get",
      listUsableMembers: "pools.members",
      listContributions: null,
      listShares: null,
      grantShare: null,
      updateShare: null,
      revokeShare: null,
      leave: null,
      resendInvite: null,
      revokeInvite: null,
      acceptInvite: null,
      contributeHost: null,
      withdrawHost: null,

      listInvites: null,
      list: "pools.list",
      get: "pools.get",
      listMembers: "pools.members",
      create: null,
      update: null,
      delete: null,
      addMember: null,
      updateMember: null,
      removeMember: null,
      previewLeaseLowering: null,
      capacity: "pools.capacity",
      queue: null,
    },
  },

  {
    router: sandboxHostsRouter,
    services: hosts,
    actions: {
      listHosts: "hosts.list",
      getHost: "hosts.get",
      listHostGuests: null,
      listHostStoragePools: "hosts.storagePools",
      createHost: null,
      updateHost: null,
      setHostDraining: null,
      deleteHost: null,
      forgetHost: null,
      listHostTokens: null,
      createHostToken: null,
      revokeHostToken: null,
      listDeviceCredentials: null,
      revokeDeviceCredential: null,
      imageCache: null,
      lowerAgentHostCommands: null,
      lowerHostTerminal: null,
      liftAgentHostCommandsVeto: null,
      liftHostTerminalVeto: null,
    },
  },
  {
    router: sandboxTemplatesRouter,
    services: templates,
    actions: {
      listTemplates: "templates.list",
      getTemplate: null,
      getTemplateRevision: null,
      listRevisionChoices: null,
      listRevisions: "templates.revisions",
      listAvailability: "templates.availability",
      appendRevision: "templates.append",
      associateAvailability: "templates.associate",
      setTag: null,
      retireRevision: null,
      createTemplate: "templates.create",
      retireTemplate: "templates.retire",
      getImageSettings: null,
      updateImageSettings: null,
      publishRevision: null,
      pruneNow: null,
    },
  },
  {
    router: sandboxesRouter,
    services: sandboxes,
    actions: {
      // Session-only dashboard projections (sandbox-views.ts); the SDK reads the
      // same data through listSandboxes/getSandbox (/v1, below).
      list: null,
      getSandbox: null,
      // Dashboard limits share the SDK discovery capability service.
      getLimits: "capabilities.get",
      getOperationResult: null,
      getSandboxCapabilities: "sandboxes.capabilities",
      connectProcess: "processes.connect",
      killProcess: null,
      sendProcessStdin: null,
      // Session-only operation projections (operation-views.ts); /v1 has no list.
      listOperations: null,
      getOperationView: null,
      probeSandbox: "sandboxes.probe",
      createSandbox: "sandboxes.create",
      killSandbox: "sandboxes.kill",
      stopSandbox: "sandboxes.stop",
      reconnectSandbox: "sandboxes.reconnect",
      setSandboxTimeout: "sandboxes.setTimeout",
      updateSandbox: "sandboxes.update",
      // Offload §8.7 (U10): an owner session action, never on /v1.
      retryCleanup: null,
      // Dashboard-only restore pin (disk-offload/pin.ts).
      setOffloadPin: null,
      getOperation: "operations.get",
      getCommandOutput: "operations.getCommandOutput",
      cancelOperation: "operations.cancel",
      runCommand: "commands.run",
      writeStdin: "commands.writeStdin",
      readFile: "files.read",
      listDir: "files.listDir",
      statPath: "files.stat",
      mkdir: "files.mkdir",
      removePath: "files.remove",
      movePath: "files.move",
      listProcesses: "processes.list",
      signalProcess: "processes.signal",
      createSnapshot: null,
      restoreSnapshot: null,
      forkSandbox: null,
      // Same service as POST /v1/sandboxes/{id}/capture (image-store/captures.ts).
      captureSandbox: "sandboxes.capture",
    },
  },
  {
    // Router keys name the services directly (like the pools group); `status`
    // is a configuration probe, not a service.
    router: webhooksRouter,
    services: {
      list: webhookServices.listWebhookEndpoints,
      get: webhookServices.getWebhookEndpoint,
      create: webhookServices.createWebhookEndpoint,
      update: webhookServices.updateWebhookEndpoint,
      delete: webhookServices.deleteWebhookEndpoint,
      rotateSecret: webhookServices.rotateWebhookSecret,
      test: webhookServices.testWebhookEndpoint,
      listDeliveries: webhookServices.listWebhookDeliveries,
      getDelivery: webhookServices.getWebhookDelivery,
      redeliver: webhookServices.redeliverWebhook,
    },
    actions: {
      status: null,
      list: "webhooks.list",
      get: "webhooks.get",
      create: "webhooks.create",
      update: "webhooks.update",
      delete: "webhooks.delete",
      rotateSecret: "webhooks.rotateSecret",
      test: "webhooks.test",
      listDeliveries: "webhooks.listDeliveries",
      getDelivery: "webhooks.getDelivery",
      redeliver: "webhooks.redeliver",
    },
  },
  {
    // CLI logins: router keys name the services directly.
    router: loginsRouter,
    services: Object.fromEntries(
      Object.entries(loginServices).filter(
        ([name, value]) => typeof value === "function" && name !== "status",
      ),
    ) as Record<string, (actor: Principal, input: never) => Promise<unknown>>,
    actions: {
      status: null,
      listDefinitions: "credentialDefinitions.list",
      getDefinition: "credentialDefinitions.get",
      createDefinition: "credentialDefinitions.create",
      archiveDefinition: "credentialDefinitions.archive",
      listLogins: "credentials.list",
      getLogin: "credentials.get",
      createLogin: "credentials.create",
      updateLogin: "credentials.update",
      updateLoginPolicy: null,
      repinLogin: null,
      deleteLogin: "credentials.delete",
      listEvents: "credentials.events",
      listAccounts: "credentialAccounts.list",
      createAccount: "credentialAccounts.create",
      updateAccount: "credentialAccounts.update",
      deleteAccount: "credentialAccounts.delete",
      listInstances: "credentialInstances.list",
      createInstance: "credentialInstances.create",
      updateInstance: "credentialInstances.update",
      deleteInstance: "credentialInstances.delete",
      writeValue: "credentialInstances.writeValue",
      attachSandboxCredential: "sandboxCredentials.attach",
      freeSandboxCredential: "sandboxCredentials.free",
      listInstanceLeases: "credentialInstances.listLeases",
      listRejectedCaptures: null,
      forceRelease: "credentialInstances.forceRelease",
      discardRejectedCaptures: null,
      // The login sandbox flow is session-only (§11): no /v1 twin.
      startLogin: null,
      getLoginSession: null,
      listLoginSessions: null,
      finishLogin: null,
      verifyLogin: null,
      cancelLogin: null,
      listSandboxCredentials: null,
    },
  },
] as const;
/** Router keys served only by a session-only view module (no /v1 twin service). */
const aliases: Record<string, string> = {
  listRevisions: "listTemplateRevisions",
  listAvailability: "listTemplateAvailability",
  appendRevision: "appendTemplateRevision",
  associateAvailability: "associateTemplateAvailability",
  setTag: "setTemplateTag",
  retireRevision: "retireTemplateRevision",
  updateSandbox: "updateSandbox",
  retryCleanup: "retryRestoreCleanup",
};
const SESSION_VIEW_ONLY: ReadonlySet<string> = new Set([
  "listOperations",
  "getOperationView",
  "getLimits",
  "getOperationResult",
  "getSandboxCapabilities",
  "connectProcess",
  "killProcess",
  "sendProcessStdin",
  // Image-store modules (image-store/settings.ts, image-store/captures.ts).
  "imageCache",
  "getImageSettings",
  "updateImageSettings",
  "publishRevision",
  "pruneNow",
  "captureSandbox",
  // Restore pin (disk-offload/pin.ts): dashboard only, no /v1 twin.
  "setOffloadPin",
  "status",
]);
function principal(withScopes: readonly ServiceScope[] = allScopes): ServicePrincipal {
  db.sdkKey.findUnique.mockResolvedValue({
    id: "key-1",
    userId: "user-a",
    resourceMode: "ALL_OWNED",
    poolMode: "ALL_USABLE",
    scopes: [...withScopes],
    revokedAt: null,
    expiresAt: null,
    HostAllowlist: [],
    RevisionAllowlist: [],
    User: {
      banned: false,
      banExpires: null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
  } as never);
  db.sandboxPool.findFirst.mockResolvedValue({ id: "pool-1" } as never);
  db.sandboxHost.findFirst.mockResolvedValue({ id: "host-1" } as never);
  db.sandboxTemplateRevision.findFirst.mockResolvedValue({ id: "tpl-1" } as never);
  return {
    kind: "sdkKey",
    credentialKind: "API",
    ownSandboxesOnly: false,
    expiresAt: null,
    ownerId: "user-a",
    keyId: "key-1",
    resourceMode: "ALL_OWNED",
    scopes: new Set(withScopes),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
}
const context = {
  poolId: "pool-1",
  sandboxHostId: "host-1",
  templateRevisionId: "tpl-1",
  originPoolId: null,
  operationKind: "RUN_COMMAND" as const,
};

describe("independent SDK scope and service inventory", () => {
  it("accounts for all 145 real router procedures and every service export", () => {
    const actions: string[] = [];
    let count = 0;
    for (const group of surface) {
      const routerKeys = Object.keys(group.router).sort();
      expect(routerKeys).toEqual(Object.keys(group.actions).sort());
      count += routerKeys.length;
      actions.push(
        ...Object.values(group.actions).filter(
          (action): action is NonNullable<typeof action> => action !== null,
        ),
      );
      // Session-only dashboard views live in their own modules (sandbox-views.ts,
      // operation-views.ts); every other router key is a same-named service.
      const serviceNames = routerKeys
        .filter((key) => !SESSION_VIEW_ONLY.has(key))
        .map((key) =>
          group.router === sandboxPoolsRouter ||
          group.router === webhooksRouter ||
          group.router === loginsRouter
            ? key
            : key === "list"
              ? "listSandboxes"
              : (aliases[key] ?? key),
        );
      expect(Object.keys(group.services).sort()).toEqual(serviceNames.sort());
    }
    expect(count).toBe(145);
    // Owner dashboard reads and qualified usable reads share the same budgets
    // and SDK actions. Only these three explicit aliases may repeat.
    expect(actions.filter((action, index) => actions.indexOf(action) !== index).sort()).toEqual([
      "pools.get",
      "pools.list",
      "pools.members",
    ]);
    // Non-router entries: SDK discovery/receipts, the /v1 sandbox reads (the
    // browser reads the session-only views), and the binary transfer HTTP
    // adapters (C29 uploads use files.write, C30 downloads operations.downloadFile).
    expect(
      [
        ...new Set(actions),
        "hostCommands.run",
        "hostCommands.get",
        "hostCommands.writeStdin",
        "hostCommands.cancel",
        "hostCommands.queue",
        "hostFiles.read",
        "hostFiles.list",
        "hostFiles.write",
        "hostFiles.edit",
        "sandboxes.list",
        "sandboxes.get",
        "sandboxes.createIntent",
        "sandboxes.replayCreate",
        "operations.getReceipt",
        "files.write",
        "operations.downloadFile",
        // Every template-build entry (both planes and the context routes)
        // shares one action; template-builds/views.test.ts covers its gate.
        "templates.build",
        // Staged typed result readers; intentionally not mounted before 6C.
        "operations.getFileResult",
        "operations.getFileMutationResult",
        "operations.getRenameResult",
        "operations.getCommandResult",
        "operations.getSignalResult",
        // Preview tunnels: /v1 only (no dashboard router; the port update
        // also has the MCP tool `sandbox_tunnel_ports`).
        "sandboxes.tunnelGet",
        "sandboxes.tunnelExpose",
        "sandboxes.tunnelClose",
        "sandboxes.tunnelLink",
        "sandboxes.tunnelLinkRevoke",
        "sandboxes.tunnelPorts",
        // CLI shells: the /v1 connect WebSocket only (kind API, never MCP).
        "sandboxes.connect",
        // The calling key itself: /v1 only (GET/DELETE /v1/key), never MCP.
        "key.get",
        "key.revokeSelf",
      ].sort(),
    ).toEqual(Object.keys(expected).sort());
    expect(production.SERVICE_ACTIONS.slice().sort()).toEqual(Object.keys(expected).sort());
    expect(production.SERVICE_ACTION_REQUIREMENTS).toEqual(expected);
    expect(production.SERVICE_SCOPES.slice().sort()).toEqual(allScopes.slice().sort());
  });

  for (const [name, requirement] of Object.entries(expected)) {
    const action = name as ServiceAction;
    it(`${action} succeeds with all scopes and fails with every required scope omitted`, async () => {
      await expect(authorizeServiceAction(principal(), action, context)).resolves.toEqual(
        expect.any(Object),
      );
      for (const missing of requirement.scopes) {
        await expect(
          authorizeServiceAction(
            principal(allScopes.filter((scope) => scope !== missing)),
            action,
            context,
          ),
        ).rejects.toMatchObject({ code: "FORBIDDEN" });
      }
    });
  }

  for (const group of surface) {
    for (const [procedure, action] of Object.entries(group.actions)) {
      if (!action) continue;
      it(`${procedure} enforces its action in the actual service before database IO`, async () => {
        const services: Record<string, (actor: Principal, input: never) => Promise<unknown>> =
          group.services;
        const service =
          group.router === sandboxesRouter &&
          (procedure === "getSandboxCapabilities" ||
            procedure === "connectProcess" ||
            procedure === "captureSandbox")
            ? SANDBOX_PROCEDURE_INVENTORY[procedure]
            : services[
                group.router === sandboxPoolsRouter ||
                group.router === webhooksRouter ||
                group.router === loginsRouter
                  ? procedure
                  : procedure === "list"
                    ? "listSandboxes"
                    : (aliases[procedure] ?? procedure)
              ];
        for (const missing of expected[action].scopes) {
          vi.clearAllMocks();
          // Command shape validation is pure and precedes IO; use a valid
          // command to independently exercise the service authorization gate.
          const input =
            procedure === "runCommand"
              ? { id: "sbx-1", idempotencyKey: "scope-test", argv: ["true"] }
              : {};
          await expect(
            service(principal(allScopes.filter((scope) => scope !== missing)), input as never),
          ).rejects.toMatchObject({ code: "FORBIDDEN" });
          expect(db.sandbox.findFirst).not.toHaveBeenCalled();
          expect(db.sandboxOperation.findFirst).not.toHaveBeenCalled();
          expect(db.sandboxHost.findMany).not.toHaveBeenCalled();
          expect(db.sandboxTemplate.findMany).not.toHaveBeenCalled();
          expect(db.$transaction).not.toHaveBeenCalled();
          expect(db.webhookEndpoint.findMany).not.toHaveBeenCalled();
          expect(db.webhookEndpoint.findFirst).not.toHaveBeenCalled();
          expect(db.webhookDelivery.findFirst).not.toHaveBeenCalled();
          expect(db.credential.findFirst).not.toHaveBeenCalled();
          expect(db.credential.findMany).not.toHaveBeenCalled();
        }
      });
    }
  }

  for (const [name, action] of [
    ["listSandboxes", "sandboxes.list"],
    ["getSandbox", "sandboxes.get"],
  ] as const) {
    it(`/v1 read ${name} enforces ${action} in the actual service before database IO`, async () => {
      const service = sandboxes[name] as (actor: Principal, input: never) => Promise<unknown>;
      for (const missing of expected[action].scopes) {
        vi.clearAllMocks();
        await expect(
          service(principal(allScopes.filter((scope) => scope !== missing)), {} as never),
        ).rejects.toMatchObject({ code: "FORBIDDEN" });
        expect(db.sandbox.findFirst).not.toHaveBeenCalled();
        expect(db.sandbox.findMany).not.toHaveBeenCalled();
      }
    });
  }

  it.each(Object.entries(kindScopes))(
    "%s requires its own cancellation scope",
    async (kind, [mutation]) => {
      const operationKind = kind as SandboxOperationKind;
      expect(production.mutationScopeForOperationKind(operationKind)).toBe(mutation);
      await expect(
        authorizeServiceAction(
          principal(allScopes.filter((s) => s !== mutation)),
          "operations.cancel",
          { ...context, operationKind },
        ),
      ).rejects.toMatchObject({ code: "FORBIDDEN" });
    },
  );
});

it.each([
  ["STAT_PATH", "operations.getFileResult"],
  ["LIST_DIR", "operations.getFileResult"],
  ["MKDIR", "operations.getFileMutationResult"],
  ["REMOVE_PATH", "operations.getFileMutationResult"],
  ["MOVE_PATH", "operations.getRenameResult"],
  ["RUN_COMMAND", "operations.getCommandResult"],
  ["LIST_PROCESSES", "operations.getCommandResult"],
  ["SIGNAL_PROCESS", "operations.getSignalResult"],
  ["GET_FILE", null],
  ["PUT_FILE", null],
  ["CREATE_SANDBOX", null],
] as const)("derives the result class from stored kind %s", (kind, action) => {
  expect(production.resultActionForOperationKind(kind)).toBe(action);
});

it("closed guest-work budget membership leaves lifecycle/read/transfer chunks on existing families", () => {
  const ordinary = [
    "commands.run",
    "files.read",
    "files.write",
    "files.listDir",
    "files.stat",
    "files.mkdir",
    "files.remove",
    "files.move",
    "processes.list",
  ];
  for (const action of production.SERVICE_ACTIONS) {
    const family = production.fsProcessBudgetFamily(action, "RUN_COMMAND");
    expect(family, action).toBe(
      ordinary.includes(action)
        ? "ordinary"
        : action === "commands.writeStdin"
          ? "stdin"
          : ["processes.signal", "operations.cancel"].includes(action)
            ? "termination"
            : null,
    );
  }
  for (const kind of [
    "LIST_PROCESSES",
    "STAT_PATH",
    "LIST_DIR",
    "SIGNAL_PROCESS",
    "PUT_FILE",
  ] as const)
    expect(production.fsProcessBudgetFamily("operations.cancel", kind)).toBe("ordinary");
});
