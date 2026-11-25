import { digestContextSnapshot } from "../digest-context";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: vi.fn(async () => {}),
  consumeSandboxWriteBudget: vi.fn(async () => {}),
}));

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ServicePrincipal } from "../../lib/sdk-key-access";
import type { Principal } from "../contracts";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "service-boundary-test",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));
const { default: db } = await import("@wssp/db");
const services = await import("./sandboxes");
const hosts = await import("./hosts");
const templates = await import("./templates");
const keys = await import("./sdk-keys");
const views = await import("./sandbox-views");
const operationViews = await import("./operation-views");
const { hashOperationRequestBody, hashRequestBody, requestDigestMetadata } = await import(
  "../idempotency"
);
const { withAuthorityChange } = await import("@wssp/db/authority");
const { initialLeaseFields } = await import("../lease");
const { SERVICE_SCOPES } = await import("../../lib/service-scopes");
const { authenticateSdkKeySecret, digestSdkKeySecret } = await import("../../lib/sdk-key-access");
const { generateProductCredentialSecret, credentialLookupPrefix } = await import(
  "@wssp/db/credential-security"
);
const now = new Date("2026-09-24T00:00:00Z");
function principal(overrides: Partial<ServicePrincipal> = {}): ServicePrincipal {
  const principal = {
    kind: "sdkKey",
    credentialKind: "API",
    ownSandboxesOnly: false,
    expiresAt: null,
    keyId: "key-1",
    ownerId: "user-a",
    resourceMode: "ALLOWLIST",
    scopes: new Set(SERVICE_SCOPES),
    allowedHostIds: new Set(["host-1"]),
    allowedRevisionIds: new Set(["tpl-1"]),
    allowedPoolIds: new Set<string>(),
    ...overrides,
  } satisfies ServicePrincipal;
  db.sdkKey.findUnique.mockResolvedValue({
    id: principal.keyId,
    userId: principal.ownerId,
    resourceMode: principal.resourceMode,
    scopes: [...principal.scopes],
    revokedAt: null,
    expiresAt: null,
    HostAllowlist:
      principal.allowedHostIds === "allOwned"
        ? []
        : [...principal.allowedHostIds].map((sandboxHostId) => ({
            sandboxHostId,
            SandboxHost: { userId: principal.ownerId },
          })),
    RevisionAllowlist:
      principal.allowedRevisionIds === "allOwned"
        ? []
        : [...principal.allowedRevisionIds].map((templateRevisionId) => ({ templateRevisionId })),
    User: {
      banned: false,
      banExpires: null,
      deletionRequestedAt: null,
      twoFactorEnabled: true,
      createdAt: new Date("2020-01-01"),
      role: "user",
    },
  } as never);
  db.sandboxHost.findFirst.mockResolvedValue({ id: "host-1" } as never);
  db.sandboxTemplateRevision.findFirst.mockResolvedValue({ id: "tpl-1" } as never);
  return principal;
}
const sandbox = {
  purpose: "WORKLOAD",
  id: "sbx-1",
  userId: "user-a",
  state: "DELETED",
  generation: 1,
  sandboxHostId: null,
  originHostId: "host-1",
  CurrentPlacement: { originHostId: "host-1", hostOwnerId: "user-a", originPoolId: null },
  hostOwnerId: "user-a",
  templateId: "tpl-1",
  templateRevisionId: "tpl-1",
  originPoolId: null,
  SandboxTemplateRevision: { defaultCwd: null },
  Operations: [{ kind: "CREATE_SANDBOX", authorizingKeyId: "key-1", userId: "user-a" }],
  ...initialLeaseFields({ now: now.getTime() }),
  leaseRevision: 1,
  metadata: {},
  createdAt: now,
  updatedAt: now,
};
const output = {
  stdout: "private stdout",
  stderr: "private stderr",
  nested: { content: "private bytes" },
};
let operation: Record<string, unknown>;
// A query-sensitive mock: projections and owner predicates determine disclosure.
function project(
  row: Record<string, unknown>,
  select: Record<string, unknown> | undefined,
): Record<string, unknown> {
  // A null relation (a retired template's host) projects to null.
  if (!select || row == null) return row;
  return Object.fromEntries(
    Object.entries(select)
      .filter(([, value]) => value)
      .map(([key, value]) => [
        key,
        typeof value === "object" && value !== null
          ? project(
              row[key] as Record<string, unknown>,
              (value as { select: Record<string, unknown> }).select,
            )
          : row[key],
      ]),
  );
}
function matches(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([key, wanted]) => {
    if (key === "AND")
      return (wanted as Record<string, unknown>[]).every((part) => matches(row, part));
    if (key === "OR")
      return (wanted as Record<string, unknown>[]).some((part) => matches(row, part));
    const value = row[key];
    if (wanted && typeof wanted === "object" && !(wanted instanceof Date)) {
      const filter = wanted as Record<string, unknown>;
      if ("some" in filter)
        return (
          Array.isArray(value) &&
          value.some((child) => matches(child, filter.some as Record<string, unknown>))
        );
      if ("in" in filter) return (filter.in as unknown[]).includes(value);
      if ("lt" in filter) return (value as string | number) < (filter.lt as string | number);
      if (Object.keys(filter).length === 0) return true;
      return (
        typeof value === "object" &&
        value !== null &&
        matches(value as Record<string, unknown>, filter)
      );
    }
    return value instanceof Date && wanted instanceof Date
      ? value.getTime() === wanted.getTime()
      : value === wanted;
  });
}
type Query = { where: Record<string, unknown>; select?: Record<string, unknown>; take?: number };
function setupOperation() {
  operation = {
    ...requestDigestMetadata(),
    digestContext: digestContextSnapshot({
      domain: "wssp-request-v2",
      hostId: "host-1",
      hostOwnerId: "user-a",
    }),
    authorizingKeyId: "key-1",
    id: "op-1",
    userId: "user-a",
    sandboxId: "sbx-1",
    kind: "RUN_COMMAND",
    state: "SUCCEEDED",
    generation: 1,
    idempotencyKey: "retry",
    errorCode: null,
    dispatchedAt: null,
    completedAt: null,
    createdAt: now,
    updatedAt: now,
    result: output,
    errorDetail: "private failure output",
    Sandbox: sandbox,
  };
  db.sandbox.findFirst.mockImplementation(async ({ where, select }: Query) =>
    matches(sandbox, where) ? project(sandbox, select) : null,
  );
  db.sandboxOperation.findUnique.mockImplementation(async ({ select }: Query) =>
    project(operation, select),
  );
  db.sandboxOperation.findFirst.mockImplementation(async ({ where, select }: Query) =>
    where.kind === "CREATE_SANDBOX"
      ? project({ ...operation, kind: "CREATE_SANDBOX", authorizingKeyId: "key-1" }, select)
      : matches(operation, where)
        ? project(operation, select)
        : null,
  );
  db.$transaction.mockImplementation(async (fn: (tx: typeof db) => Promise<unknown>) => fn(db));
  db.sandbox.updateMany.mockResolvedValue({ count: 1 });
}
beforeEach(() => {
  vi.resetAllMocks();
  db.appSetting.findMany.mockResolvedValue([]);
  db.user.findUnique.mockResolvedValue({ deletionRequestedAt: null } as never);
  setupOperation();
});

describe("retained sandbox authorization and output boundary", () => {
  it.each(["ALL_OWNED", "ALLOWLIST"] as const)(
    "%s retains status, operations and command output after destruction",
    async (resourceMode) => {
      const actor = principal(
        resourceMode === "ALL_OWNED"
          ? { resourceMode, allowedHostIds: "allOwned", allowedRevisionIds: "allOwned" }
          : {},
      );
      expect(await services.getSandbox(actor, { id: "sbx-1" })).toMatchObject({
        state: "DELETED",
        sandboxHostId: null,
      });
      expect(await services.getOperation(actor, { operationId: "op-1" })).toMatchObject({
        state: "SUCCEEDED",
      });
      // Durable output pages (C26): retained reads keep working after destruction.
      expect(await services.getCommandOutput(actor, { operationId: "op-1" })).toMatchObject({
        operationId: "op-1",
        state: "SUCCEEDED",
        chunks: [],
        complete: true,
      });
    },
  );
  it.each(["host", "template"])(
    "retains the creating key's history after its %s grant disappears",
    async (dimension) => {
      const actor = principal(
        dimension === "host"
          ? { allowedHostIds: new Set(["host-other"]) }
          : { allowedRevisionIds: new Set(["tpl-other"]) },
      );
      for (const read of [
        () => services.getSandbox(actor, { id: "sbx-1" }),
        () => services.getOperation(actor, { operationId: "op-1" }),
        () => services.getCommandOutput(actor, { operationId: "op-1" }),
      ]) {
        await expect(read()).resolves.toBeDefined();
      }
      for (const [args] of db.sandboxOperation.findFirst.mock.calls)
        if (args.where.kind === "CREATE_SANDBOX")
          expect(args.select).toEqual({ authorizingKeyId: true });
    },
  );
  it("hides cross-owner sandbox and operation identities before grant evaluation", async () => {
    const other = principal({ ownerId: "user-b" });
    await expect(services.getSandbox(other, { id: "sbx-1" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    await expect(services.getOperation(other, { operationId: "op-1" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
    expect(db.sandboxOperation.findFirst).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { id: "op-1", userId: "user-b", Sandbox: { userId: "user-b" } },
      }),
    );
  });
  it.each(["RUN_COMMAND", "GET_FILE", "LIST_DIR", "LIST_PROCESSES"])(
    "operations:read never returns %s output or free-form error detail",
    async (kind) => {
      operation.kind = kind;
      const actor = principal({ scopes: new Set(["operations:read"]) });
      const metadata = await services.getOperation(actor, { operationId: "op-1" });
      expect(metadata).toMatchObject({ id: "op-1", kind, state: "SUCCEEDED" });
      expect(metadata).not.toHaveProperty("result");
      expect(metadata).not.toHaveProperty("errorDetail");
      for (const [args] of db.sandboxOperation.findFirst.mock.calls) {
        expect(args.select).not.toHaveProperty("result");
        expect(args.select).not.toHaveProperty("errorDetail");
        for (const privateField of [
          "processId",
          "processPid",
          "processStartedAt",
          "processBootId",
          "processStartTicks",
          "processDescription",
          "scalarResult",
          "TypedResult",
          "resultVersion",
          "resultExpiresAt",
        ])
          expect(args.select).not.toHaveProperty(privateField);
      }
    },
  );
  it("sessions return status metadata only through one operation read", async () => {
    const session = { kind: "session" as const, ownerId: "user-a" };
    const dto = await services.getOperation(session, { operationId: "op-1" });
    expect(dto).toMatchObject({
      failure: null,
      id: "op-1",
      sandboxId: "sbx-1",
      kind: "RUN_COMMAND",
      state: "SUCCEEDED",
      generation: 1,
      errorCode: null,
      dispatchedAt: null,
      completedAt: null,
      createdAt: now,
      updatedAt: now,
    });
    expect(db.sandboxOperation.findFirst).toHaveBeenCalledTimes(1);
  });
  it("session getOperation fails if metadata and output came from different reads", async () => {
    let reads = 0;
    db.sandboxOperation.findFirst.mockImplementation(async ({ select }: Query) => {
      reads += 1;
      const row =
        reads === 1
          ? {
              ...operation,
              state: "RUNNING",
              result: null,
              errorDetail: null,
            }
          : {
              ...operation,
              state: "SUCCEEDED",
              result: output,
              errorDetail: "private failure output",
            };
      return project(row, select);
    });
    const session = { kind: "session" as const, ownerId: "user-a" };
    const dto = await services.getOperation(session, { operationId: "op-1" });
    expect(reads).toBe(1);
    expect(dto.state).toBe("RUNNING");
    expect(dto).not.toHaveProperty("result");
    expect(dto).not.toHaveProperty("errorDetail");
  });
});

describe("list grant filters before pagination", () => {
  for (const [label, delegate, service, rows] of [
    [
      "hosts",
      db.sandboxHost,
      hosts.listHosts,
      [
        { id: "host-other", userId: "user-a" },
        { id: "host-1", userId: "user-a" },
        { id: "host-2", userId: "user-a" },
        { id: "host-1", userId: "user-b" },
      ],
    ],
    [
      "templates",
      db.sandboxTemplate,
      templates.listTemplates,
      [
        { id: "tpl-other", userId: "user-a" },
        { id: "tpl-1", userId: "user-a" },
        { id: "tpl-2", userId: "user-a" },
        { id: "tpl-1", userId: "user-b" },
      ].map((row) => ({
        ...row,
        Revisions: [{ id: row.id, userId: row.userId }],
        archivedAt: null,
      })),
    ],
    [
      "sandboxes",
      db.sandbox,
      services.listSandboxes,
      [
        {
          ...sandbox,
          id: "blocked-host",
          originHostId: "other",
          Operations: [{ kind: "CREATE_SANDBOX", authorizingKeyId: "other", userId: "user-a" }],
        },
        {
          ...sandbox,
          id: "blocked-template",
          templateRevisionId: "other",
          Operations: [{ kind: "CREATE_SANDBOX", authorizingKeyId: "other", userId: "user-a" }],
        },
        { ...sandbox, id: "sbx-2" },
        sandbox,
        { ...sandbox, id: "foreign", userId: "user-b" },
      ],
    ],
  ] as const) {
    it(`${label} fills pages only with owned grants, including terminal history`, async () => {
      const data = rows.map((row) => ({ ...row, createdAt: now }));
      delegate.findMany.mockImplementation(async ({ where, take, select }: Query) =>
        data
          .filter((row) => matches(row, where))
          .sort((a, b) => b.id.localeCompare(a.id))
          .slice(0, take)
          .map((row) => project(row, select)),
      );
      const actor = principal({
        allowedHostIds: new Set(["host-1", "host-2"]),
        allowedRevisionIds: new Set(["tpl-1", "tpl-2"]),
        allowedPoolIds: new Set<string>(),
      });
      const history = label === "sandboxes" ? { status: "all" as const } : {};
      const first = await service(actor, { limit: 1, ...history });
      expect(first.items).toHaveLength(1);
      expect(first.nextCursor).toBeTruthy();
      const second = await service(actor, { limit: 1, cursor: first.nextCursor!, ...history });
      expect(second.items).toHaveLength(1);
      expect(second.nextCursor).toBeNull();
      expect(new Set([...first.items, ...second.items].map((row) => row.id))).toEqual(
        new Set(
          label === "hosts"
            ? ["host-1", "host-2"]
            : label === "templates"
              ? ["tpl-1", "tpl-2"]
              : ["sbx-1", "sbx-2"],
        ),
      );
      expect(delegate.findMany).toHaveBeenCalledWith(expect.objectContaining({ take: 2 }));
      const empty = await service(
        principal({ allowedHostIds: new Set(), allowedRevisionIds: new Set() }),
        { limit: 10 },
      );
      expect(empty).toEqual({ items: [], nextCursor: null });
    });
  }
});

const base = { id: "sbx-1", idempotencyKey: "retry" };
const renewal = {
  ...base,
  timeoutMs: 10_000,
};
const command = { ...base, argv: ["true"], timeoutMs: 30_000 };
const replayCases: {
  name: string;
  kind: string;
  body: unknown;
  run: (actor: Principal) => Promise<unknown>;
}[] = [
  {
    name: "create",
    kind: "CREATE_SANDBOX",
    body: {
      template: "revision/" + "tpl-1",
      sandboxHostId: "host-1",
      idempotencyKey: "retry",
      timeoutMs: 300000,
      lifecycle: { onTimeout: "kill", autoResume: false },
    },
    run: (p) =>
      services.createSandbox(p, {
        template: "revision/" + "tpl-1",
        sandboxHostId: "host-1",
        idempotencyKey: "retry",
      }),
  },
  {
    name: "kill",
    kind: "KILL_SANDBOX",
    body: { sandboxId: base.id },
    run: (p) => services.killSandbox(p, base),
  },
  {
    name: "command",
    kind: "RUN_COMMAND",
    body: command,
    run: (p) => services.runCommand(p, command),
  },
  {
    name: "readFile",
    kind: "GET_FILE",
    body: { ...base, path: "/a" },
    run: (p) => services.readFile(p, { ...base, path: "/a" }),
  },
  {
    name: "stop",
    kind: "STOP_SANDBOX",
    body: { sandboxId: base.id, action: "stop" },
    run: (p) => services.stopSandbox(p, base),
  },
  {
    name: "reconnect",
    kind: "RECONNECT_SANDBOX",
    body: {
      sandboxId: base.id,
      action: "reconnect",
      mode: "default",
    },
    run: (p) => services.reconnectSandbox(p, base),
  },
  {
    name: "listDir",
    kind: "LIST_DIR",
    body: { ...base, path: "/" },
    run: (p) => services.listDir(p, { ...base, path: "/" }),
  },
  {
    name: "statPath",
    kind: "STAT_PATH",
    body: { ...base, path: "/a" },
    run: (p) => services.statPath(p, { ...base, path: "/a" }),
  },
  {
    name: "mkdir",
    kind: "MKDIR",
    body: { ...base, path: "/a" },
    run: (p) => services.mkdir(p, { ...base, path: "/a" }),
  },
  {
    name: "removePath",
    kind: "REMOVE_PATH",
    body: { ...base, path: "/a" },
    run: (p) => services.removePath(p, { ...base, path: "/a" }),
  },
  {
    name: "movePath",
    kind: "MOVE_PATH",
    body: { ...base, path: "/a", destPath: "/b" },
    run: (p) => services.movePath(p, { ...base, path: "/a", destPath: "/b" }),
  },
  {
    name: "processes",
    kind: "LIST_PROCESSES",
    body: base,
    run: (p) => services.listProcesses(p, base),
  },
  {
    name: "renewal normal",
    kind: "RENEW_SANDBOX_LEASE",
    body: {
      sandboxId: base.id,
      timeoutMs: renewal.timeoutMs,
    },
    run: (p) => services.setSandboxTimeout(p, renewal),
  },
  {
    name: "renewal conflict",
    kind: "RENEW_SANDBOX_LEASE",
    body: {
      sandboxId: base.id,
      timeoutMs: renewal.timeoutMs,
    },
    run: (p) => {
      if (p.scopes.has("sandboxes:create"))
        db.$transaction.mockRejectedValueOnce({ code: "P2002" });
      return services.setSandboxTimeout(p, renewal);
    },
  },
];
describe("all replay entries authorize current principals", () => {
  it.each(replayCases)(
    "$name replays retained receipt only with current scopes and the creating key",
    async ({ kind, body, run }) => {
      operation.kind = kind;
      operation.requestBodyHash = hashOperationRequestBody(body, kind, {
        ownerId: "user-a",
        hostOwnerId: "user-a",
        hostId: "host-1",
        authorizingKeyId: "key-1",
      });
      Object.assign(operation, requestDigestMetadata(kind));
      await expect(run(principal())).resolves.toBeDefined();
      for (const makeActor of [
        () => principal({ scopes: new Set(["hosts:read"]) }),
        () => principal({ keyId: "other-key" }),
      ]) {
        const actor = makeActor();
        db.sandboxOperation.findFirst.mockClear();
        await expect(run(actor)).rejects.toMatchObject({
          code: actor.keyId === "other-key" ? "CONFLICT" : "FORBIDDEN",
        });
        if (actor.scopes.has("hosts:read") && actor.scopes.size === 1)
          expect(db.sandboxOperation.findFirst).not.toHaveBeenCalled();
        else expect(db.sandboxOperation.create).not.toHaveBeenCalled();
      }
      expect(db.sandboxOperation.create).not.toHaveBeenCalled();
      expect(db.outboxEvent.create).not.toHaveBeenCalled();
    },
  );
  it("renewal conflict reauthorizes after rollback before fetching the winner", async () => {
    const actor = principal();
    db.$transaction.mockImplementationOnce(async () => {
      db.sdkKey.findUnique.mockResolvedValue(null);
      throw { code: "P2002" };
    });
    await expect(services.setSandboxTimeout(actor, renewal)).rejects.toMatchObject({
      code: "FORBIDDEN",
    });
    expect(db.sandboxOperation.findFirst).not.toHaveBeenCalled();
    expect(db.sandbox.findFirst).toHaveBeenCalledTimes(1); // only owner preflight; inactive key denies before replay context
  });
  it("real authentication rejects revoked/expired keys before replay and honors changed persisted grants", async () => {
    operation.kind = "RUN_COMMAND";
    operation.requestBodyHash = hashRequestBody(command, {
      ownerId: "user-a",
      hostOwnerId: "user-a",
      hostId: "host-1",
      authorizingKeyId: "key-1",
    });
    const secret = generateProductCredentialSecret("sdkKey");
    const row = {
      id: "key-1",
      userId: "user-a",
      resourceMode: "ALLOWLIST",
      scopes: ["commands:execute"],
      lookupPrefix: credentialLookupPrefix(secret),
      kind: "API",
      ownSandboxesOnly: false,
      secretDigest: digestSdkKeySecret(secret.raw),
      revokedAt: null,
      expiresAt: null,
      HostAllowlist: [{ sandboxHostId: "host-1", SandboxHost: { userId: "user-a" } }],
      RevisionAllowlist: [{ templateRevisionId: "tpl-1" }],
      User: {
        banned: false,
        banExpires: null,
        twoFactorEnabled: true,
        createdAt: now,
        role: "user",
      },
    };
    for (const change of [{ revokedAt: now }, { expiresAt: now }]) {
      db.sdkKey.findUnique.mockResolvedValue({ ...row, ...change });
      expect(await authenticateSdkKeySecret(secret.raw, now)).toBeNull();
      expect(db.sandboxOperation.findFirst).not.toHaveBeenCalled();
    }
    db.sdkKey.findUnique.mockResolvedValue({ ...row, HostAllowlist: [] });
    const denied = await authenticateSdkKeySecret(secret.raw, now);
    expect(denied).not.toBeNull();
    await expect(services.runCommand(denied!, command)).resolves.toMatchObject({
      operationId: "op-1",
    });
    expect(db.sandboxOperation.create).not.toHaveBeenCalled();
    db.sdkKey.findUnique.mockResolvedValue(row);
    db.sandboxHost.findFirst.mockResolvedValue({ id: "host-1" });
    db.sandboxTemplateRevision.findFirst.mockResolvedValue({ id: "tpl-1" });
    const allowed = await authenticateSdkKeySecret(secret.raw, now);
    expect(allowed).not.toBeNull();
    expect(await services.runCommand(allowed!, command)).toEqual({
      operationId: "op-1",
      state: "SUCCEEDED",
    });
  });
});

it("all session-only management siblings reject SDK principals before IO", async () => {
  const management: ((actor: Principal, input: never) => Promise<unknown>)[] = [
    hosts.createHost,
    hosts.updateHost,
    hosts.deleteHost,
    hosts.listHostTokens,
    hosts.createHostToken,
    hosts.revokeHostToken,
    hosts.listDeviceCredentials,
    hosts.revokeDeviceCredential,
    templates.getTemplateRevision,
    templates.listRevisionChoices,
    templates.setTemplateTag,
    templates.retireTemplate,
    templates.retireTemplateRevision,
    views.listSandboxViews,
    views.getSandboxView,
    operationViews.listOperationViews,
    operationViews.getOperationView,
    keys.createSdkKey,
    keys.listSdkKeys,
    keys.revokeSdkKey,
  ];
  for (const service of management)
    await expect(service(principal(), {} as never)).rejects.toMatchObject({ code: "FORBIDDEN" });
  expect(db.$transaction).not.toHaveBeenCalled();
  expect(db.sdkKey.findMany).not.toHaveBeenCalled();
  expect(db.sandboxHost.findFirst).not.toHaveBeenCalled();
  expect(db.sandboxTemplateRevision.findFirst).not.toHaveBeenCalled();
});

it("does not disclose a list collected before a grant was removed", async () => {
  const actor = principal();
  const row = await db.sdkKey.findUnique({ where: { id: actor.keyId } });
  db.sandbox.findMany.mockImplementation(async () => {
    db.sdkKey.findUnique.mockResolvedValue({ ...row, HostAllowlist: [] });
    return [sandbox];
  });
  await expect(services.listSandboxes(actor, { limit: 10 })).rejects.toMatchObject({
    code: "FORBIDDEN",
  });
});

describe("C21-READEXIT every service exit passes the post-entry authority ticket", () => {
  const revoke = () =>
    withAuthorityChange({ ownerId: "user-a", credentialId: "key-1" }, async () => undefined);
  const STALE = { code: "FORBIDDEN", message: "Authority changed during request." };

  it("getSandbox: a NOT_FOUND after a mid-request revoke becomes FORBIDDEN", async () => {
    const actor = principal();
    db.sandbox.findFirst
      .mockImplementationOnce(
        async () => ({ ...sandbox, templateRevisionId: "tpl-1", originPoolId: null }) as never,
      )
      .mockImplementationOnce(async () => {
        await revoke();
        return null as never;
      });
    await expect(services.getSandbox(actor, { id: "sbx-1" })).rejects.toMatchObject(STALE);
    // Control: the same miss without a revoke is the ordinary NOT_FOUND.
    db.sandbox.findFirst
      .mockImplementationOnce(
        async () => ({ ...sandbox, templateRevisionId: "tpl-1", originPoolId: null }) as never,
      )
      .mockImplementationOnce(async () => null as never);
    await expect(services.getSandbox(principal(), { id: "sbx-1" })).rejects.toMatchObject({
      code: "NOT_FOUND",
    });
  });

  it("probeSandbox: an early 'unreachable' return after a mid-request revoke becomes FORBIDDEN", async () => {
    const actor = principal();
    db.sandbox.findFirst
      .mockImplementationOnce(
        async () => ({ ...sandbox, templateRevisionId: "tpl-1", originPoolId: null }) as never,
      )
      .mockImplementationOnce(async () => ({ ...sandbox, hostOwnerId: actor.ownerId }) as never)
      .mockImplementationOnce(async () => {
        await revoke();
        return { ...sandbox, sandboxHostId: null } as never;
      });
    await expect(services.probeSandbox(actor, { id: "sbx-1" })).rejects.toMatchObject(STALE);
    db.sandbox.findFirst
      .mockImplementationOnce(
        async () => ({ ...sandbox, templateRevisionId: "tpl-1", originPoolId: null }) as never,
      )
      .mockImplementationOnce(async () => ({ ...sandbox, hostOwnerId: actor.ownerId }) as never)
      .mockImplementationOnce(async () => ({ ...sandbox, sandboxHostId: null }) as never);
    await expect(services.probeSandbox(principal(), { id: "sbx-1" })).resolves.toEqual({
      state: "unreachable",
    });
  });

  it("replay: a hash-mismatch CONFLICT after a mid-request revoke becomes FORBIDDEN", async () => {
    operation.kind = "RUN_COMMAND";
    operation.requestBodyHash = hashRequestBody({ ...command, argv: ["different"] });
    const replayLookup = db.sandboxOperation.findFirst.getMockImplementation()!;
    db.sandboxOperation.findFirst.mockImplementationOnce(async (args) => {
      await revoke();
      return replayLookup(args as never);
    });
    await expect(services.runCommand(principal(), command)).rejects.toMatchObject(STALE);
    // Control: without the revoke the mismatch is the idempotency CONFLICT.
    await expect(services.runCommand(principal(), command)).rejects.toMatchObject({
      code: "CONFLICT",
    });
  });

  it("setSandboxTimeout: the P2002 replay after a mid-request revoke becomes FORBIDDEN", async () => {
    operation.kind = "RENEW_SANDBOX_LEASE";
    operation.requestBodyHash = hashRequestBody(
      {
        sandboxId: renewal.id,
        timeoutMs: renewal.timeoutMs,
      },
      { ownerId: "user-a", hostOwnerId: "user-a", hostId: "host-1", authorizingKeyId: "key-1" },
    );
    const replayLookup = db.sandboxOperation.findFirst.getMockImplementation()!;
    db.$transaction.mockRejectedValueOnce({ code: "P2002" });
    db.sandboxOperation.findFirst.mockImplementationOnce(async (args) => {
      await revoke();
      return replayLookup(args as never);
    });
    await expect(services.setSandboxTimeout(principal(), renewal)).rejects.toMatchObject(STALE);
    db.$transaction.mockRejectedValueOnce({ code: "P2002" });
    await expect(services.setSandboxTimeout(principal(), renewal)).resolves.toBeDefined();
  });
});

it("rejects invalid command envs before authorization/resource IO", async () => {
  for (const fields of [
    { env: [["A", "private-value"]] },
    { envs: [["A", "private-value"]] },
    { envs: { A: "界".repeat(1366) } },
    { envs: Object.fromEntries(Array.from({ length: 65 }, (_, i) => [`K${i}`, "x"])) },
  ]) {
    vi.clearAllMocks();
    await expect(
      services.runCommand(principal(), {
        id: "sbx-1",
        idempotencyKey: "env-test",
        argv: ["true"],
        ...fields,
      } as never),
    ).rejects.toMatchObject({ code: "BAD_REQUEST" });
    expect(db.sdkKey.findUnique).not.toHaveBeenCalled();
    expect(db.sandbox.findFirst).not.toHaveBeenCalled();
    expect(db.$transaction).not.toHaveBeenCalled();
  }
});

it("lease rearm refuses a zero-row write before creating an accepted intent or outbox event", async () => {
  const owner = { kind: "session" as const, ownerId: "user-a" };
  const ready = {
    ...sandbox,
    state: "READY",
    sandboxHostId: "host-1",
    hostOwnerId: "user-a",
    storagePoolId: null,
    storagePoolName: null,
    storageMarker: null,
    SandboxHost: { id: "host-1", userId: "user-a", connectionEpoch: 1 },
    CurrentPlacement: {
      id: "placement",
      userId: "user-a",
      sandboxId: sandbox.id,
      generation: 1,
      originHostId: "host-1",
      hostOwnerId: "user-a",
      storagePoolId: null,
      storagePoolName: null,
      storageMarker: null,
    },
  };
  db.sandbox.findFirst.mockImplementation(async ({ where, select }: Query) =>
    matches(ready, where) ? project(ready, select) : null,
  );
  db.sandboxHost.findFirst.mockResolvedValue({
    id: "host-1",
    userId: owner.ownerId,
    connectionEpoch: 1,
  } as never);
  db.$queryRaw.mockResolvedValue([{ id: "locked" }]);
  // Admission CAS succeeds. The subsequent lease rearm misses its fence.
  db.sandbox.updateMany.mockResolvedValueOnce({ count: 1 }).mockResolvedValueOnce({ count: 0 });
  await expect(
    services.reconnectSandbox(
      owner,
      {
        id: sandbox.id,
        mode: "warm",
        idempotencyKey: "rearm-miss",
      },
      () => now,
    ),
  ).rejects.toMatchObject({
    code: "CONFLICT",
    data: { code: "sandbox.state_conflict" },
  });
  expect(db.sandbox.updateMany).toHaveBeenCalledTimes(2);
  expect(db.sandbox.updateMany.mock.calls[1]![0].data).toHaveProperty("leaseRevision", 2);
  expect(db.sandboxOperation.create).not.toHaveBeenCalled();
  expect(db.outboxEvent.create).not.toHaveBeenCalled();
});

describe("updateSandbox", () => {
  const owner = { kind: "session" as const, ownerId: "user-a" };
  const live = { ...sandbox, state: "READY", name: "quiet-otter" };
  beforeEach(() => {
    db.$queryRaw.mockResolvedValue([{ id: live.id, purpose: "WORKLOAD", buildId: null }] as never);
    db.sandbox.findMany.mockResolvedValue([]);
    db.sandbox.update.mockImplementation((async ({ data, select }: Query & { data: object }) =>
      project({ ...live, ...data }, select)) as never);
  });

  it("charges the ordinary budget exactly once and returns the renamed sandbox", async () => {
    const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
    const renamed = await services.updateSandbox(owner, { id: live.id, name: "brisk-heron" });
    expect(renamed.name).toBe("brisk-heron");
    expect(consumeSandboxWriteBudget).toHaveBeenCalledTimes(1);
    expect(consumeSandboxWriteBudget).toHaveBeenCalledWith("user-a", "ordinary");
    expect(db.sandbox.update).toHaveBeenCalledWith(
      expect.objectContaining({ data: { name: "brisk-heron" } }),
    );
  });

  it("refuses an invalid name with sandbox.name_invalid before any write", async () => {
    await expect(
      services.updateSandbox(owner, { id: live.id, name: "Bad_Name" }),
    ).rejects.toMatchObject({ data: { code: "sandbox.name_invalid" } });
    expect(db.sandbox.update).not.toHaveBeenCalled();
  });

  it("maps a name-index P2002 backstop to sandbox.name_taken", async () => {
    db.sandbox.update.mockRejectedValue(
      Object.assign(new Error("unique"), {
        code: "P2002",
        meta: { target: "sandbox_instance_owner_live_name" },
      }),
    );
    await expect(
      services.updateSandbox(owner, { id: live.id, name: "brisk-heron" }),
    ).rejects.toMatchObject({ data: { code: "sandbox.name_taken" } });
  });

  it("a build principal is refused by the shared gate and charges nothing", async () => {
    const { consumeSandboxWriteBudget } = await import("@wssp/api/sandbox/budgets");
    const build = { kind: "build", ownerId: "user-a", buildId: "b1", keyId: null } as never;
    await expect(
      services.updateSandbox(build, { id: live.id, name: "brisk-heron" }),
    ).rejects.toThrow();
    expect(consumeSandboxWriteBudget).not.toHaveBeenCalled();
    expect(db.sandbox.update).not.toHaveBeenCalled();
  });
});
