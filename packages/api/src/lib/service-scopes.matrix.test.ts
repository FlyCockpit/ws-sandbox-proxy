import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ServicePrincipal } from "./sdk-key-access";
import { SERVICE_ACTION_REQUIREMENTS, SERVICE_ACTIONS, SERVICE_SCOPES } from "./service-scopes";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({ env: { BETTER_AUTH_SECRET: "scope-matrix-fixture" } }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const { default: db } = await import("@wssp/db");
const { authorizeServiceIntent } = await import("./sdk-key-access");

// OAuth's request ceiling lets the empty set reach the scope gate while its
// backing row remains a valid, nonempty credential. No resource checks are mocked.
function principal(scopes: readonly string[]): ServicePrincipal {
  return {
    kind: "sdkKey",
    credentialKind: "OAUTH_GRANT",
    keyId: "key",
    ownerId: "owner",
    expiresAt: null,
    resourceMode: "ALL_OWNED",
    ownSandboxesOnly: true,
    scopes: new Set(SERVICE_SCOPES.filter((scope) => scopes.includes(scope))),
    allowedHostIds: "allOwned",
    allowedRevisionIds: "allOwned",
    allowedPoolIds: "allUsable",
  };
}
beforeEach(() => {
  vi.clearAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
  db.sdkKey.findUnique.mockResolvedValue({
    id: "key",
    userId: "owner",
    kind: "OAUTH_GRANT",
    scopes: [...SERVICE_SCOPES],
    ownSandboxesOnly: true,
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
  });
});

describe.each(SERVICE_ACTIONS)("%s scope gate", (action) => {
  const required = SERVICE_ACTION_REQUIREMENTS[action].scopes;
  it("admits exactly the declared set", async () => {
    await expect(authorizeServiceIntent(principal(required), action)).resolves.toEqual({});
  });
  it.each(SERVICE_SCOPES)("removing %s refuses iff required", async (scope) => {
    const call = authorizeServiceIntent(principal(required.filter((s) => s !== scope)), action);
    if (required.includes(scope)) await expect(call).rejects.toMatchObject({ code: "FORBIDDEN" });
    else await expect(call).resolves.toEqual({});
  });
});

// Independent policy oracle: changing the production table alone must fail.
it("pins lifecycle split and physical host ownership requirements", () => {
  const expected = {
    "sandboxes.createIntent": ["sandboxes:create"],
    "sandboxes.replayCreate": ["sandboxes:create"],
    "sandboxes.create": ["sandboxes:create"],
    "sandboxes.stop": ["sandboxes:manage"],
    "sandboxes.reconnect": ["sandboxes:manage"],
    "sandboxes.setTimeout": ["sandboxes:manage"],
    "sandboxes.rename": ["sandboxes:manage"],
    "sandboxes.capture": ["sandboxes:manage", "templates:write"],
    "sandboxCredentials.attach": ["sandboxes:manage", "credentials:use"],
    "sandboxCredentials.free": ["sandboxes:manage", "credentials:use"],
    "sandboxes.kill": ["sandboxes:destroy"],
    "hosts.get": ["hosts:read"],
    "hostCommands.run": ["hosts:execute"],
    "hostCommands.get": ["hosts:execute"],
    "hostCommands.writeStdin": ["hosts:execute"],
    "hostCommands.cancel": ["hosts:execute"],
    "hostCommands.queue": ["hosts:execute"],
    "hostFiles.read": ["hosts:files"],
    "hostFiles.list": ["hosts:files"],
    "hostFiles.write": ["hosts:files"],
    "hostFiles.edit": ["hosts:files"],
  } as const;
  for (const [action, scopes] of Object.entries(expected)) {
    const requirement = SERVICE_ACTION_REQUIREMENTS[action as keyof typeof expected];
    expect(requirement.scopes, action).toEqual(scopes);
    if (action.startsWith("hostCommands.") || action.startsWith("hostFiles.")) {
      expect(requirement, action).toMatchObject({ requiresHost: true, requiresOwnedHost: true });
    }
  }
});
