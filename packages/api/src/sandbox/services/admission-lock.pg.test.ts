import { seedLaunchHost } from "../testing/resource-fixtures";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

import { randomUUID } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { afterAll, describe, expect, it, vi } from "vitest";
import { seedSandboxInstance, seedTemplateRevision } from "../testing/resource-fixtures";

vi.mock("@wssp/db", async () => {
  const { pgTestDatabase: database } = await import("@wssp/db/testing/pg");
  return { default: (await database()).prisma };
});
vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
    BETTER_AUTH_SECRET: "admission-lock-pg-test-secret",
  },
  ADMIN_EMAILS: new Set<string>(),
}));
vi.mock("@wssp/env/shared", () => ({ env: {} }));

const db = await pgTestDatabase();
const { AccountDeletionConflictError, requestAccountDeletion } = await import(
  "@wssp/db/account-deletion"
);
const { bindHostImageVerifier } = await import("../host-image-verifier");
const {
  createHostInput,
  createHostTokenInput,
  createSandboxInput,
  createTemplateInput,
  killSandboxInput,
  stopSandboxInput,
} = await import("../contracts");
const { createHost, createHostToken, deleteHost } = await import("./hosts");
const { createTemplate, retireTemplateRevision: retireTemplate } = await import("./templates");
const { createSdkKey, createSdkKeyInput } = await import("./sdk-keys");
const { createSandbox, killSandbox, stopSandbox } = await import("./sandboxes");
const { authenticateSdkKeySecret } = await import("../../lib/sdk-key-access");
type Principal = import("../contracts").Principal;
const { mintHostDeviceCredentialFromApprovedDeviceCode } = await import(
  "../../lib/host-device-credential-access"
);

afterAll(() => db.close());

const FP = `sha256:${"a".repeat(64)}`;
bindHostImageVerifier(async () => ({ incusFingerprint: FP, architecture: "x86_64" }));

/** The shared owner lock every admission transaction takes first (C21-13). */
const OWNER_SHARE_LOCK = /^sql:SELECT id FROM "user" WHERE id = \? FOR SHARE$/;
/** The exclusive owner lock account finalization takes first. */
const OWNER_UPDATE_LOCK = /^sql:SELECT id FROM "user" WHERE id = \? FOR UPDATE$/;

type Seeded = {
  ownerId: string;
  hostId?: string;
  templateId?: string;
  sandboxId?: string;
  /** Plane credentials a site prepares before any lock is held (C57). */
  sdkPrincipal?: Principal;
  deviceCode?: string;
};
type SeedKind = "none" | "host" | "host+template" | "host+template+sandbox";

async function seedOwner(resources: SeedKind): Promise<Seeded> {
  const ownerId = `user-${randomUUID()}`;
  await db.inspect.user.create({
    // Verified, 2FA-enrolled: the SDK and device-enrollment planes require a
    // satisfied owner credential policy; the session sites ignore both fields.
    data: {
      id: ownerId,
      name: "Owner",
      email: `${ownerId}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
    },
  });
  if (resources === "none") return { ownerId };
  const host = await seedLaunchHost(db.inspect, {
    data: {
      userId: ownerId,
      slug: "lab",
      label: "Lab",
      status: "CONNECTED",
      connectionEpoch: 1,
      egressEnforcement: true,
    },
  });
  if (resources === "host") return { ownerId, hostId: host.id };
  const template = await seedTemplateRevision(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      imageRef: "images:ubuntu/24.04/cloud",
      incusFingerprint: FP,
    },
  });
  if (resources === "host+template") return { ownerId, hostId: host.id, templateId: template.id };
  const sandbox = await seedSandboxInstance(db.inspect, {
    data: {
      userId: ownerId,
      sandboxHostId: host.id,
      originHostId: host.id,
      templateId: template.id,
      originPoolId: null,
      state: "READY",
    },
  });
  return { ownerId, hostId: host.id, templateId: template.id, sandboxId: sandbox.id };
}

const operationCount = (kind: "STOP_SANDBOX" | "KILL_SANDBOX") => (ownerId: string) =>
  db.inspect.sandboxOperation.count({ where: { userId: ownerId, kind } });

type Site = {
  name: string;
  /** Owner resources the admission needs; any seeded host blocks account deletion. */
  seed: SeedKind;
  /** Blocker kind the committed admission adds, or null when the row is not a blocker. */
  blocker: "hosts" | "sandboxes" | null;
  run: (seeded: Seeded) => Promise<unknown>;
  admitted: (ownerId: string) => Promise<number>;
  /**
   * Fixture rows the site needs, written BEFORE either actor holds a lock: a
   * row referencing the owner takes a KEY SHARE that would itself wait on the
   * finalizer's FOR UPDATE and hide the admission's own wait.
   */
  prepare?: (seeded: Seeded) => Promise<void>;
  /** The domain CONFLICT a losing admission reports on an empty account. */
  conflict?: string;
  /**
   * SDK-plane principals also carry an owner authority ticket, which every
   * finalization attempt holds open (`withAuthorityChange`), refused or not.
   */
  sdkAuthority?: true;
};

const session = (ownerId: string) => ({ kind: "session" as const, ownerId });

const sites: Site[] = [
  {
    name: "session-principal sandbox create",
    seed: "host+template",
    blocker: "sandboxes",
    run: ({ ownerId, hostId, templateId }) =>
      createSandbox(
        session(ownerId),
        createSandboxInput.parse({
          template: "revision/" + templateId,
          sandboxHostId: hostId,
          idempotencyKey: `create-${randomUUID()}`,
        }),
      ),
    admitted: (ownerId) => db.inspect.sandbox.count({ where: { userId: ownerId } }),
  },
  {
    name: "SDK key create",
    seed: "none",
    // Credentials are not deletion blockers: they cascade with the user (C21-3).
    blocker: null,
    run: ({ ownerId }) =>
      createSdkKey(
        session(ownerId),
        createSdkKeyInput.parse({
          name: "ci",
          scopes: ["sandboxes:read"],
          resourceMode: "ALL_OWNED",
        }),
      ),
    admitted: (ownerId) => db.inspect.sdkKey.count({ where: { userId: ownerId } }),
  },
  {
    name: "host token create",
    seed: "host",
    // Tokens cascade with the user; the refusal names the token's host.
    blocker: "hosts",
    run: ({ ownerId, hostId }) =>
      createHostToken(session(ownerId), createHostTokenInput.parse({ hostId, name: "daemon" })),
    admitted: (ownerId) => db.inspect.hostToken.count({ where: { userId: ownerId } }),
  },
  {
    name: "sandbox stop",
    seed: "host+template+sandbox",
    blocker: "sandboxes",
    run: ({ ownerId, sandboxId }) =>
      stopSandbox(
        session(ownerId),
        stopSandboxInput.parse({ id: sandboxId, idempotencyKey: `stop-${randomUUID()}` }),
      ),
    admitted: operationCount("STOP_SANDBOX"),
  },
  {
    name: "sandbox kill",
    seed: "host+template+sandbox",
    blocker: "sandboxes",
    run: ({ ownerId, sandboxId }) =>
      killSandbox(
        session(ownerId),
        killSandboxInput.parse({ id: sandboxId, idempotencyKey: `kill-${randomUUID()}` }),
      ),
    admitted: operationCount("KILL_SANDBOX"),
  },
  {
    // C57 (C21-13 carry-in): the SDK plane's admission path, `/v1` create.
    name: "SDK-principal sandbox create",
    seed: "host+template",
    blocker: "sandboxes",
    sdkAuthority: true,
    prepare: async (seeded) => {
      const minted = await createSdkKey(
        session(seeded.ownerId),
        createSdkKeyInput.parse({
          name: "sdk",
          scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy", "sandboxes:read"],
          resourceMode: "ALL_OWNED",
        }),
      );
      // Authenticated exactly as `/v1` does, before finalization starts: the
      // race under test is the service boundary, not bearer authentication.
      const principal = await authenticateSdkKeySecret(minted.secret);
      if (!principal) throw new Error("fixture SDK key did not authenticate");
      seeded.sdkPrincipal = principal;
    },
    run: (seeded) =>
      createSandbox(
        seeded.sdkPrincipal!,
        createSandboxInput.parse({
          template: "revision/" + seeded.templateId,
          sandboxHostId: seeded.hostId,
          idempotencyKey: `sdk-create-${randomUUID()}`,
        }),
      ),
    admitted: (ownerId) => db.inspect.sandbox.count({ where: { userId: ownerId } }),
  },
  {
    // C57 (C21-13 carry-in): the host plane's create path, an approved device
    // enrollment minting its host and credential.
    name: "device-enrollment host create",
    seed: "none",
    blocker: "hosts",
    conflict: "The account changed during enrollment.",
    prepare: async (seeded) => {
      seeded.deviceCode = `device-${randomUUID()}`;
      await db.inspect.deviceCode.create({
        data: {
          deviceCode: seeded.deviceCode,
          userCode: `user-${randomUUID()}`,
          userId: seeded.ownerId,
          expiresAt: new Date(Date.now() + 600_000),
          status: "approved",
          scope: "host-slug:edge",
          enrollmentIntent: "create",
        },
      });
    },
    run: ({ deviceCode }) =>
      mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode: deviceCode!, hostSlug: "edge" }),
    admitted: (ownerId) => db.inspect.sandboxHost.count({ where: { userId: ownerId } }),
  },
  {
    name: "host create",
    seed: "none",
    blocker: "hosts",
    run: ({ ownerId }) =>
      createHost(session(ownerId), createHostInput.parse({ slug: "edge", label: "Edge" })),
    admitted: (ownerId) => db.inspect.sandboxHost.count({ where: { userId: ownerId } }),
  },
  {
    name: "template create",
    seed: "host",
    // Templates are receipts, never blockers (DECISIONS "Account-deletion
    // blockers"): the refusal names the template's host, which is live state.
    blocker: "hosts",
    run: ({ ownerId, hostId }) =>
      createTemplate(
        session(ownerId),
        createTemplateInput.parse({
          hostId,
          slug: "base",
          label: "Base",
          imageRef: "images:ubuntu/24.04/cloud",
        }),
      ),
    admitted: (ownerId) => db.inspect.sandboxTemplate.count({ where: { userId: ownerId } }),
  },
];

const settle = (promise: Promise<unknown>) =>
  promise.then(
    (value) => ({ ok: true as const, value }),
    (error: unknown) => ({ ok: false as const, error }),
  );

describe("C21-ACCTDEL-RACE (real PostgreSQL): account finalization vs concurrent admission", () => {
  it.each(sites)(
    "$name commits first: finalization waits on the owner lock, then refuses or finalizes after it",
    async (site) => {
      const seeded = await seedOwner(site.seed);
      await site.prepare?.(seeded);
      const before = await site.admitted(seeded.ownerId);
      const parked = db.pauseAt("admission", { after: OWNER_SHARE_LOCK });
      const admission = settle(db.run("admission", () => site.run(seeded)));
      await parked.waitReached();

      const deletion = settle(db.run("deletion", () => requestAccountDeletion(seeded.ownerId)));
      // Finalization cannot even take the owner lock while admission holds it.
      await db.waitUntilBlocked("deletion", { by: "admission" });
      parked.release();

      const admitted = await admission;
      if (site.sdkAuthority) {
        // The finalizer's authority hold opened while the admission was parked:
        // its in-transaction ticket re-check refuses, so the transaction ROLLS
        // BACK and the FORBIDDEN is definite (nothing committed, checked below).
        expect(admitted.ok).toBe(false);
        expect((admitted as { error: unknown }).error).toMatchObject({
          code: "FORBIDDEN",
          message: expect.stringMatching(/^Authority changed during/),
        });
        const finalized = await deletion;
        expect(finalized.ok).toBe(false);
        expect((finalized as { error: { kinds: string[] } }).error.kinds).toEqual(["hosts"]);
        expect(await site.admitted(seeded.ownerId)).toBe(before);
        return;
      }
      expect(admitted, String((admitted as { error?: unknown }).error)).toMatchObject({ ok: true });
      const finalized = await deletion;
      if (site.blocker === null) {
        // Not a blocker: finalization proceeds and the new row goes with the user.
        expect(finalized).toEqual({ ok: true, value: true });
        expect(await db.inspect.user.count({ where: { id: seeded.ownerId } })).toBe(0);
        expect(await site.admitted(seeded.ownerId)).toBe(0);
        return;
      }
      expect(finalized.ok).toBe(false);
      const refusal = (finalized as { error: unknown }).error;
      expect(refusal).toBeInstanceOf(AccountDeletionConflictError);
      expect((refusal as InstanceType<typeof AccountDeletionConflictError>).kinds).toContain(
        site.blocker,
      );
      expect((refusal as Error).message).toContain(site.blocker);
      expect((refusal as { kinds: string[] }).kinds).not.toContain("templates");
      expect(await site.admitted(seeded.ownerId)).toBe(before + 1);
      expect(await db.inspect.user.count({ where: { id: seeded.ownerId } })).toBe(1);
    },
  );

  it.each(sites)(
    "$name while finalization holds the owner FOR UPDATE: admission is observed BLOCKED, then loses with CONFLICT or proceeds after a refusal",
    async (site) => {
      const seeded = await seedOwner(site.seed);
      await site.prepare?.(seeded);
      const before = await site.admitted(seeded.ownerId);
      const parked = db.pauseAt("deletion", { after: OWNER_UPDATE_LOCK });
      const deletion = settle(db.run("deletion", () => requestAccountDeletion(seeded.ownerId)));
      await parked.waitReached();

      const admission = settle(db.run("admission", () => site.run(seeded)));
      if (site.sdkAuthority) {
        // The open authority hold refuses the SDK principal at entry, before
        // it opens a transaction: nothing is inserted and nothing waits.
        const refused = await admission;
        expect(refused.ok).toBe(false);
        // The key revalidation reads the owner's authority as held: inactive.
        expect((refused as { error: unknown }).error).toMatchObject({
          code: "FORBIDDEN",
          message: "Credential is inactive.",
        });
        expect(await site.admitted(seeded.ownerId)).toBe(before);
        parked.release();
        const finalized = await deletion;
        expect(finalized.ok).toBe(false);
        expect((finalized as { error: { kinds: string[] } }).error.kinds).toContain("hosts");
        expect(await site.admitted(seeded.ownerId)).toBe(before);
        return;
      }
      // Lock-before-insert, observed in PostgreSQL itself: the admission backend
      // waits on a lock held by the finalizer's backend. Nothing was inserted.
      const blocked = await db.waitUntilBlocked("admission", { by: "deletion" });
      expect(blocked.waitEventType).toBe("Lock");
      // Blocked on the owner lock itself, before any insert was attempted.
      expect(blocked.query).toMatch(/SELECT id FROM "user" WHERE id = \$1 FOR SHARE/);
      expect(await site.admitted(seeded.ownerId)).toBe(before);
      parked.release();

      const finalized = await deletion;
      const admitted = await admission;
      if (site.seed === "none") {
        // Empty account: finalization wins; admission loses with a domain CONFLICT.
        expect(finalized).toEqual({ ok: true, value: true });
        expect(admitted.ok).toBe(false);
        expect((admitted as { error: unknown }).error).toMatchObject({
          code: "CONFLICT",
          message: site.conflict ?? "Account deletion is in progress.",
        });
        expect(await site.admitted(seeded.ownerId)).toBe(0);
        expect(await db.inspect.user.count({ where: { id: seeded.ownerId } })).toBe(0);
        return;
      }
      // The admission's prerequisite host is a live blocker (templates never are), so the
      // finalizer refuses and releases the lock; the admission then commits.
      expect(finalized.ok).toBe(false);
      expect((finalized as { error: unknown }).error).toBeInstanceOf(AccountDeletionConflictError);
      expect((finalized as { error: { kinds: string[] } }).error.kinds).toContain("hosts");
      expect((finalized as { error: { kinds: string[] } }).error.kinds).not.toContain("templates");
      expect(admitted).toMatchObject({ ok: true });
      expect(await site.admitted(seeded.ownerId)).toBe(before + 1);
    },
  );
});

describe("SDK key mint vs concurrent template retirement (real PostgreSQL)", () => {
  const allowlistMint = (seeded: Seeded) =>
    createSdkKey(
      session(seeded.ownerId),
      createSdkKeyInput.parse({
        name: "pinned",
        scopes: ["sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
        resourceMode: "ALLOWLIST",
        hostIds: [seeded.hostId],
        templateRevisionIds: [seeded.templateId],
      }),
    );
  const retire = (seeded: Seeded) =>
    retireTemplate(session(seeded.ownerId), { id: seeded.templateId! });

  it("a retirement that commits first makes the mint refuse the archived template", async () => {
    const seeded = await seedOwner("host+template");
    // The mint has taken the owner lock but not yet validated its allowlist.
    const parked = db.pauseAt("mint", { after: OWNER_SHARE_LOCK });
    const mint = settle(db.run("mint", () => allowlistMint(seeded)));
    await parked.waitReached();
    await expect(db.run("retire", () => retire(seeded))).resolves.toEqual({ ok: true });
    parked.release();
    const minted = await mint;
    expect(minted.ok).toBe(false);
    expect((minted as { error: unknown }).error).toMatchObject({ code: "BAD_REQUEST" });
    expect(await db.inspect.sdkKey.count({ where: { userId: seeded.ownerId } })).toBe(0);
  });

  it("3E a retirement racing a validated mint waits on placement before parents", async () => {
    const seeded = await seedOwner("host+template");
    const parked = db.pauseAt("mint", { before: "sdkKey.create" });
    const mint = settle(db.run("mint", () => allowlistMint(seeded)));
    await parked.waitReached();
    const retirement = settle(db.run("retire", () => retire(seeded)));
    const blocked = await db.waitUntilBlocked("retire", { by: "mint" });
    try {
      expect(blocked.query).toMatch(/pg_advisory_xact_lock/);
    } finally {
      parked.release();
    }
    expect(await mint).toMatchObject({ ok: true });
    expect(await retirement).toEqual({ ok: true, value: { ok: true } });
  });
});

describe("3A host grant mint versus host finalization (real PostgreSQL)", () => {
  it("an allowlisted host deletion waits for the mint through grant insertion", async () => {
    const seeded = await seedOwner("host+template");
    // A second allowlisted host with no template is locked with the full H set.
    const spare = await seedLaunchHost(db.inspect, {
      data: { userId: seeded.ownerId, slug: "spare", label: "Spare" },
    });
    // Finalization must wait at H, before any credential/grant suffix.
    const parked = db.pauseAt("mint", { before: "sdkKey.create" });
    const mint = settle(
      db.run("mint", () =>
        createSdkKey(
          session(seeded.ownerId),
          createSdkKeyInput.parse({
            name: "pinned",
            scopes: ["sandboxes:read"],
            resourceMode: "ALLOWLIST",
            hostIds: [seeded.hostId, spare.id],
            templateRevisionIds: [seeded.templateId],
          }),
        ),
      ),
    );
    await parked.waitReached();
    const deleting = db.run("delete", () => deleteHost(session(seeded.ownerId), { id: spare.id }));
    try {
      expect((await db.waitUntilBlocked("delete", { by: "mint", timeoutMs: 2000 })).query).toMatch(
        /FROM sandbox_host.*FOR UPDATE/,
      );
    } finally {
      parked.release();
    }
    expect(await mint).toMatchObject({ ok: true });
    expect(await deleting).toEqual({ ok: true, pending: false });
    expect(await db.inspect.sdkKey.count({ where: { userId: seeded.ownerId } })).toBe(1);
    expect(await db.inspect.sdkKeyHostAllowlist.count({ where: { sandboxHostId: spare.id } })).toBe(
      0,
    );
    expect(
      await db.inspect.sdkKeyHostAllowlist.count({ where: { sandboxHostId: seeded.hostId } }),
    ).toBe(1);
  });
});

it("3A key mint locks the bounded H set in ID order before templates/grants", async () => {
  const f = await seedOwner("host+template");
  const second = await seedLaunchHost(db.inspect, {
    data: { userId: f.ownerId, slug: "second", label: "Second" },
  });
  const ids = [f.hostId!, second.id].sort();
  const held = db.pauseAt("large-host", { before: "$transaction.commit" });
  const holder = db.run("large-host", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${ids[1]} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const mint = db.run("mint", () =>
    createSdkKey(
      session(f.ownerId),
      createSdkKeyInput.parse({
        name: "sorted",
        scopes: ["sandboxes:read"],
        resourceMode: "ALLOWLIST",
        hostIds: [...ids].reverse(),
        templateRevisionIds: [f.templateId],
      }),
    ),
  );
  try {
    expect(
      (await db.waitUntilBlocked("mint", { by: "large-host", timeoutMs: 2000 })).query,
    ).toMatch(/FROM sandbox_host.*ORDER BY id FOR UPDATE/);
    // The smaller H is held already even though the caller listed it last.
    await expect(
      db.inspect.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM sandbox_host WHERE id = ${ids[0]} FOR UPDATE NOWAIT`;
      }),
    ).rejects.toMatchObject({
      code: "P2010",
      meta: { driverAdapterError: { cause: { code: "55P03" } } },
    });
  } finally {
    held.release();
  }
  await holder;
  await mint;
});

it("3A device replacement prelocks sorted paged credential history before revocation", async () => {
  const f = await seedOwner("host");
  const deviceCode = `device-${randomUUID()}`;
  await db.inspect.deviceCode.create({
    data: {
      deviceCode,
      userCode: `user-${randomUUID()}`,
      userId: f.ownerId,
      expiresAt: new Date(Date.now() + 600_000),
      status: "approved",
      scope: "host-slug:lab",
      enrollmentIntent: "replace",
      replaceHostId: f.hostId,
    },
  });
  const ids = Array.from(
    { length: 205 },
    (_, index) => `${f.ownerId}-${String(index).padStart(3, "0")}`,
  );
  await db.inspect.hostDeviceCredential.createMany({
    data: ids.map((id) => ({
      id,
      userId: f.ownerId,
      sandboxHostId: f.hostId!,
      lookupPrefix: randomUUID(),
      secretDigest: randomUUID(),
    })),
  });
  const held = db.pauseAt("credential", { before: "$transaction.commit" });
  const holder = db.run("credential", () =>
    db.prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM host_device_credential WHERE id = ${ids.at(-1)!} FOR UPDATE`;
    }),
  );
  await held.waitReached();
  const replacing = db.run("replacement", () =>
    mintHostDeviceCredentialFromApprovedDeviceCode({ deviceCode, hostSlug: "lab" }),
  );
  try {
    const blocked = await db.waitUntilBlocked("replacement", { by: "credential" });
    expect(blocked.query).toMatch(
      /SELECT id FROM host_device_credential.*ORDER BY id LIMIT 100 FOR UPDATE/,
    );
    // A later page waits on the high ID; the first page is already held.
    await expect(
      db.inspect.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM host_device_credential WHERE id = ${ids[0]!} FOR UPDATE NOWAIT`;
      }),
    ).rejects.toMatchObject({ meta: { driverAdapterError: { cause: { code: "55P03" } } } });
  } finally {
    held.release();
  }
  await holder;
  const minted = await replacing;
  expect(minted.hostId).toBe(f.hostId);
  expect(
    await db.inspect.hostDeviceCredential.count({
      where: { sandboxHostId: f.hostId, revokedAt: { not: null } },
    }),
  ).toBe(205);
  expect(
    await db.inspect.hostDeviceCredential.findMany({
      where: { sandboxHostId: f.hostId, revokedAt: null },
      select: { id: true },
      take: 2,
    }),
  ).toEqual([{ id: minted.credentialId }]);
});
