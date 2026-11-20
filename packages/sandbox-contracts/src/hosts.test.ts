import { expect, it } from "vitest";
import { capabilitiesSchema, hostAgentAccessSchema, SDK_SCOPES } from "./dto";
import { HOST_FILE_ERROR_REASONS, SDK_ERRORS, sdkErrorEnvelopeSchema } from "./errors";
import {
  hostCommandBodySchema,
  hostCommandQuerySchema,
  hostCommandStatusSchema,
  hostFileEditBodySchema,
  hostFileReadBodySchema,
  hostFileWriteBodySchema,
  hostStdinDataSchema,
  queueHostCommandBodySchema,
} from "./hosts";
import { buildSdkOpenApiDocument } from "./openapi";
import {
  enabledSdkFeatures,
  HOST_ROUTES,
  SDK_FEATURE_ROUTES,
  SDK_ROUTES,
  sdkRouteErrorStatuses,
} from "./routes";

it("keeps the service scope order and splits lifecycle mutation authority", () => {
  expect(SDK_SCOPES).toEqual([
    "hosts:read",
    "hosts:execute",
    "hosts:files",
    "pools:read",
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
  ]);
  expect(SDK_ROUTES.createSandbox.scopes).toEqual(["sandboxes:create"]);
  expect(SDK_ROUTES.destroySandbox.scopes).toEqual(["sandboxes:destroy"]);
  for (const id of [
    "updateSandbox",
    "stopSandbox",
    "reconnectSandbox",
    "renewSandboxLease",
  ] as const)
    expect(SDK_ROUTES[id].scopes).toEqual(["sandboxes:manage"]);
  expect(SDK_ROUTES.captureSandbox.scopes).toEqual(["sandboxes:manage", "templates:write"]);
  expect(SDK_ROUTES.attachSandboxCredential.scopes).toEqual([
    "sandboxes:manage",
    "credentials:use",
  ]);
  expect(SDK_ROUTES.freeSandboxCredential.scopes).toEqual(["sandboxes:manage", "credentials:use"]);
  for (const feature of [
    "hosts.execute",
    "hosts.files",
    "sandboxes.create",
    "sandboxes.manage",
    "sandboxes.destroy",
  ] as const)
    for (const missing of SDK_FEATURE_ROUTES[feature])
      expect(
        enabledSdkFeatures(
          Object.keys(SDK_ROUTES).filter((id) => id !== missing) as (keyof typeof SDK_ROUTES)[],
        ),
      ).not.toContain(feature);
});

it("reports ownSandboxesOnly explicitly and hides all policy fields on foreign hosts", () => {
  const key = capabilitiesSchema.shape.key;
  expect(
    key.safeParse({
      scopes: [],
      resourceMode: "allOwned",
      poolMode: "allUsable",
      ownSandboxesOnly: true,
    }).success,
  ).toBe(true);
  expect(
    key.safeParse({ scopes: [], resourceMode: "allOwned", poolMode: "allUsable" }).success,
  ).toBe(false);
  expect(hostAgentAccessSchema.parse({ owned: false })).toEqual({ owned: false });
  expect(hostAgentAccessSchema.safeParse({ owned: false, hostCommands: false }).success).toBe(
    false,
  );
  expect(
    hostAgentAccessSchema.safeParse({
      owned: true,
      hostCommands: true,
      hostFiles: true,
      hostCommandMaxMs: 600_000,
    }).success,
  ).toBe(true);
});

it("bounds host commands by UTF-8 bytes and refuses ambiguous or unknown input", () => {
  for (const input of [
    { argv: ["echo", "é".repeat(2048)] },
    { script: "é".repeat(8192), timeoutMs: 86_400_000, waitMs: 60_000 },
  ])
    expect(hostCommandBodySchema.safeParse(input).success).toBe(true);
  for (const input of [
    {},
    { argv: [] },
    { argv: [""] },
    { argv: ["echo"], script: "echo" },
    { script: "x\0" },
    { argv: ["echo", "x\0"] },
    { script: "x", cwd: "\0" },
    { argv: ["echo", "é".repeat(2049)] },
    { argv: Array(257).fill("x") },
    { argv: Array(5).fill("x".repeat(4096)) },
    { script: "é".repeat(8193) },
    { script: "x", timeoutMs: 0 },
    { script: "x", timeoutMs: 86_400_001 },
    { script: "x", waitMs: 60_001 },
    { script: "x", env: {} },
    { argv: ["id"], actor: "person" },
    { argv: ["id"], actor: "agent" },
  ])
    expect(hostCommandBodySchema.safeParse(input).success, JSON.stringify(input).slice(0, 80)).toBe(
      false,
    );
  expect(
    hostCommandQuerySchema.parse({
      waitMs: "60000",
      maxBytes: "65536",
      stdoutOffset: "9007199254740991",
    }),
  ).toMatchObject({ waitMs: 60_000, maxBytes: 65_536 });
  for (const query of [
    { waitMs: "60001" },
    { maxBytes: "65537" },
    { stdoutOffset: "9007199254740992" },
    { stderrOffset: "-1" },
    { waitMs: "1e3" },
    { unknown: "x" },
  ])
    expect(hostCommandQuerySchema.safeParse(query).success).toBe(false);
});

it("validates canonical base64 and decoded stdin/output chunk limits", () => {
  expect(hostStdinDataSchema.safeParse(Buffer.alloc(65_536).toString("base64")).success).toBe(true);
  for (const value of [
    Buffer.alloc(65_537).toString("base64"),
    "Zg",
    "Zg===",
    "Zh==",
    "Zm9=",
    "Zg==\n",
    "----",
  ])
    expect(hostStdinDataSchema.safeParse(value).success).toBe(false);
  const status = {
    commandId: "a".repeat(22),
    state: "running",
    stdout: { offset: 0, data: "", dropped: false },
    stderr: { offset: 0, data: "", dropped: false },
    stdoutBytes: 0,
    stderrBytes: 0,
  };
  expect(hostCommandStatusSchema.safeParse({ ...status, signal: 15 }).success).toBe(true);
  expect(
    hostCommandStatusSchema.safeParse({ ...status, requestId: "private-correlation" }).success,
  ).toBe(false);
  expect(hostCommandStatusSchema.safeParse({ ...status, commandId: "short" }).success).toBe(false);
});

it("bounds text file input, edit counts and queue expiry", () => {
  expect(
    hostFileWriteBodySchema.safeParse({ path: "/work/a", content: "é".repeat(131_072) }).success,
  ).toBe(true);
  expect(
    hostFileWriteBodySchema.safeParse({ path: "/work/a", content: "é".repeat(131_073) }).success,
  ).toBe(false);
  expect(
    hostFileWriteBodySchema.safeParse({ path: "/work/a", content: "⟦redacted⟧" }).success,
  ).toBe(false);
  expect(hostFileReadBodySchema.safeParse({ path: "/work/a", maxBytes: 262_145 }).success).toBe(
    false,
  );
  const edit = { oldText: "old", newText: "new" };
  expect(
    hostFileEditBodySchema.safeParse({ path: "/work/a", edits: Array(20).fill(edit) }).success,
  ).toBe(true);
  for (const edits of [
    [],
    Array(21).fill(edit),
    [{ oldText: "⟦redacted", newText: "x" }],
    [{ oldText: "", newText: "x" }],
  ])
    expect(hostFileEditBodySchema.safeParse({ path: "/work/a", edits }).success).toBe(false);
  for (const expiresInHours of [1, 168])
    expect(
      queueHostCommandBodySchema.safeParse({ command: "id", reason: "check", expiresInHours })
        .success,
    ).toBe(true);
  for (const expiresInHours of [0, 169, 1.5])
    expect(
      queueHostCommandBodySchema.safeParse({ command: "id", reason: "check", expiresInHours })
        .success,
    ).toBe(false);
});

it("documents host response statuses, scopes, idempotency and strict file refusals", () => {
  const doc = buildSdkOpenApiDocument() as {
    paths: Record<
      string,
      Record<string, { responses: Record<string, unknown>; parameters: { name: string }[] }>
    >;
  };
  for (const route of Object.values(HOST_ROUTES)) {
    const op = doc.paths[route.path]?.[route.method];
    expect(op).toBeDefined();
    if (route.method === "post")
      expect(op?.parameters.some((p) => p.name === "Idempotency-Key")).toBe(true);
  }
  expect(doc.paths[HOST_ROUTES.startHostCommand.path]?.post?.responses).toHaveProperty("202");
  expect(sdkRouteErrorStatuses(HOST_ROUTES.readHostFile)).toContain(422);
  const base = { message: "static", requestId: "11111111-1111-4111-8111-111111111111" };
  for (const reason of HOST_FILE_ERROR_REASONS) {
    expect(
      sdkErrorEnvelopeSchema.safeParse({
        error: { ...base, code: "host.file_error", data: { reason } },
      }).success,
    ).toBe(true);
  }
  expect(SDK_ERRORS["host.file_error"][0]).toBe(422);
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: { ...base, code: "host.file_error", data: { reason: "arbitrary", path: "/secret" } },
    }).success,
  ).toBe(false);
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: { ...base, code: "host.agent_access_off", retryable: true },
    }).success,
  ).toBe(false);
  expect(
    sdkErrorEnvelopeSchema.safeParse({
      error: { ...base, code: "host.node_offline", retryable: true },
    }).success,
  ).toBe(false);
});
