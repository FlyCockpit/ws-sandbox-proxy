import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, afterEach, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({ secret: "0123456789abcdef".repeat(4) }));
vi.mock("@wssp/env/server", () => ({
  env: {
    get SANDBOX_REQUEST_HMAC_SECRET() {
      return state.secret;
    },
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));
vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));
vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));

import { loadExecutionConfig } from "./execution-config";
import { bindHostImageVerifier } from "./host-image-verifier";
import { loadRevisionDefaults, writeRevisionDefaults } from "./revision-config";
import { createSandbox } from "./services/sandboxes";
import { createTemplate } from "./services/templates";
import { seedLaunchHost, seedTemplateRevision } from "./testing/resource-fixtures";

const db = await pgTestDatabase();
afterAll(() => db.close());
afterEach(() => {
  state.secret = "0123456789abcdef".repeat(4);
  bindHostImageVerifier(null);
});
async function fixture(defaults: Record<string, string> = { APP: "synthetic-template-private" }) {
  const userId = randomUUID();
  await db.inspect.user.create({
    data: { id: userId, name: "Owner", email: `${userId}@example.test` },
  });
  const owner = { kind: "session" as const, ownerId: userId };
  const host = await seedLaunchHost(db.inspect, {
    data: { userId, slug: "host", label: "Host", status: "CONNECTED", egressEnforcement: true },
  });
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  await db.inspect.sandboxRevisionConfig.deleteMany({ where: { revisionId: revision.id } });
  await writeRevisionDefaults(db.inspect, userId, revision.id, defaults);
  const input = {
    template: `revision/${revision.id}`,
    sandboxHostId: host.id,
    idempotencyKey: randomUUID(),
    envs: { APP: "synthetic-sandbox-private" },
  };
  return { owner, host, revision, input, userId };
}
it("3E template default reread validates the same keyed checksum and never exposes env in public rows", async () => {
  const f = await fixture();
  expect(await loadRevisionDefaults(db.inspect, f.revision.id, f.userId)).toEqual([
    ["APP", "synthetic-template-private"],
  ]);
  const sandbox = await createSandbox(f.owner, f.input);
  expect((await loadExecutionConfig(db.inspect, sandbox.id, f.userId))?.env).toEqual([
    ["APP", "synthetic-sandbox-private"],
  ]);
  // A fresh database connection is a restart boundary; no module cache is authority.
  expect(
    await db.run("reread", () =>
      db.prisma.$transaction((tx) => loadRevisionDefaults(tx, f.revision.id, f.userId)),
    ),
  ).toEqual([["APP", "synthetic-template-private"]]);
  expect(
    JSON.stringify([
      sandbox,
      await db.inspect.sandboxTemplateRevision.findUniqueOrThrow({ where: { id: f.revision.id } }),
    ]),
  ).not.toContain("synthetic-");
});
it.each(["same replay", "changed replay", "revision defaults", "sandbox snapshot"])(
  "3E changed HMAC ID refuses %s before digest comparison",
  async (variant) => {
    const f = await fixture();
    const sandbox = await createSandbox(f.owner, f.input);
    state.secret = "abcdef0123456789".repeat(4);
    const result =
      variant === "revision defaults"
        ? loadRevisionDefaults(db.inspect, f.revision.id, f.userId)
        : variant === "sandbox snapshot"
          ? loadExecutionConfig(db.inspect, sandbox.id, f.userId)
          : createSandbox(
              f.owner,
              variant === "same replay"
                ? f.input
                : { ...f.input, envs: { APP: "changed-private" } },
            );
    await expect(result).rejects.toMatchObject({
      code: "CONFLICT",
      data: { code: "digest_key_changed" },
    });
    expect(await db.inspect.sandbox.count({ where: { userId: f.userId } })).toBe(1);
  },
);
it.each(["checksum", "stored-env", "union"])(
  "3E %s corruption/refusal rolls back every tentative create row with constant errors",
  async (fault) => {
    const defaults =
      fault === "union"
        ? Object.fromEntries(Array.from({ length: 64 }, (_, n) => [`T${n}`, "value"]))
        : { APP: "synthetic-template-private" };
    const f = await fixture(defaults);
    if (fault === "checksum")
      await db.inspect.sandboxRevisionConfig.update({
        where: { revisionId: f.revision.id },
        data: { defaultEnvs: { APP: "synthetic-tampered-private" } },
      });
    if (fault === "stored-env")
      await db.inspect.sandboxRevisionConfig.update({
        where: { revisionId: f.revision.id },
        data: { defaultEnvs: { HOME: "synthetic-invalid-private" } },
      });
    const error = await createSandbox(f.owner, f.input).catch((error: unknown) => error);
    expect(error).toMatchObject({
      code: fault === "checksum" ? "INTERNAL_SERVER_ERROR" : "BAD_REQUEST",
    });
    expect(JSON.stringify(error)).not.toContain("synthetic-");
    expect(String(error)).not.toContain("synthetic-");
    expect(await db.inspect.sandbox.count({ where: { userId: f.userId } })).toBe(0);
    expect(
      (await db.inspect.sandboxHost.findUniqueOrThrow({ where: { id: f.host.id } })).liveCount,
    ).toBe(0);
  },
);
it("3E invalid supplied template defaults are refused before verification or persistence", async () => {
  const f = await fixture();
  const verify = vi.fn();
  bindHostImageVerifier(verify);
  const error = await createTemplate(f.owner, {
    hostId: f.host.id,
    slug: "new",
    label: "New",
    imageRef: "local:base",
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/user",
    guestShell: "/bin/bash",
    envs: { TERM: "synthetic-invalid-private" },
  }).catch((error: unknown) => error);
  expect(error).toMatchObject({ code: "BAD_REQUEST" });
  expect(String(error)).not.toContain("synthetic-");
  expect(verify).not.toHaveBeenCalled();
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.userId } })).toBe(1);
});

it("3E revision private producer failure rolls back registration and strips invocation and nested causes at its service boundary", async () => {
  const f = await fixture();
  bindHostImageVerifier(async () => ({
    incusFingerprint: f.revision.incusFingerprint,
    architecture: "x86_64",
  }));
  const gate = db.pauseAt("revision-service", { after: "sandboxRevisionConfig.create" });
  const creating = db
    .run("revision-service", () =>
      createTemplate(f.owner, {
        hostId: f.host.id,
        slug: "new-private",
        label: "New",
        imageRef: "local:base",
        architecture: "x86_64",
        guestUid: 1000,
        guestGid: 1000,
        guestHome: "/home/user",
        guestShell: "/bin/bash",
        envs: { APP: "synthetic-revision-producer-private" },
      }),
    )
    .catch((error: unknown) => error);
  await gate.waitReached();
  gate.fail(
    new Error("Invalid invocation synthetic-revision-producer-private", {
      cause: new Error(Buffer.from("synthetic-revision-producer-private").toString("base64")),
    }),
  );
  const error = await creating;
  expect(error).toMatchObject({ code: "INTERNAL_SERVER_ERROR" });
  expect(String(error)).not.toContain("synthetic-revision-producer-private");
  expect(JSON.stringify(error)).not.toContain("synthetic-revision-producer-private");
  expect(JSON.stringify(error)).not.toContain(
    Buffer.from("synthetic-revision-producer-private").toString("base64"),
  );
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: f.userId } })).toBe(1);
  expect(await db.inspect.sandboxTemplateRevision.count({ where: { userId: f.userId } })).toBe(1);
  expect(await db.inspect.sandboxRevisionConfig.count({ where: { userId: f.userId } })).toBe(1);
});
