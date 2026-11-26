import { randomBytes } from "node:crypto";
import { pgTestDatabase } from "@wssp/db/testing/pg";
import { credentialSpecV11Schema } from "@wssp/sandbox-contracts";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", async () => ({
  default: (await (await import("@wssp/db/testing/pg")).pgTestDatabase()).prisma,
}));
vi.mock("@wssp/env/server", () => ({ env: {}, ADMIN_EMAILS: new Set<string>() }));
vi.mock("@wssp/env/shared", () => ({ env: { NODE_ENV: "test" } }));
// Budgets are Redis-backed; their behaviour has its own tests.
vi.mock("../lib/procedure-budget", () => ({ createProcedureBudget: () => async () => {} }));

/**
 * Template capture scrub spec against real
 * PostgreSQL: the capture scrubs EVERY login path the sandbox ever held —
 * residue a stop reported scrubbed (cleared) and paths whose residue rows
 * went with a deleted login included — never only what is still uncleared.
 */
const db = await pgTestDatabase();
const { seedOwner, seedSandbox } = await import("../webhooks/testing/fixtures");
const service = await import("./service");
const { buildCaptureScrubSpec, encodeCredentialSpec, recordCredentialPathHistory } = await import(
  "./specs"
);
afterAll(() => db.close());

const savedKey = process.env.DATA_ENCRYPTION_KEY;
beforeAll(() => {
  process.env.DATA_ENCRYPTION_KEY = randomBytes(32).toString("hex");
  process.env.CREDENTIALS_ENABLED = "true";
});
afterAll(() => {
  if (savedKey === undefined) delete process.env.DATA_ENCRYPTION_KEY;
  else process.env.DATA_ENCRYPTION_KEY = savedKey;
});

const DOCUMENT = {
  schemaVersion: 1,
  id: "fakecli",
  displayName: "Fake CLI",
  login: { command: "fakecli login", method: "device-code" },
  credentials: { files: { required: [".fakecli/token"], optional: [], exclude: [] } },
};

async function world() {
  const owner = await seedOwner(db.inspect);
  const actor = { kind: "session", ownerId: owner } as const;
  const definition = await service.createDefinition(actor, { document: DOCUMENT });
  const login = await service.createLogin(actor, { name: "fakecli", definitionId: definition.id });
  const account = await service.createAccount(actor, { credentialId: login.id, name: "a" });
  const instance = await service.createInstance(actor, {
    credentialId: login.id,
    accountId: account.id,
  });
  const sandbox = await seedSandbox(db.inspect, owner, "STOPPED");
  return { owner, login, account, instance, sandbox };
}

type World = Awaited<ReturnType<typeof world>>;

/** A settled lease with one binding and its residue row (cleared or not). */
async function residue(w: World, paths: (string | number)[], cleared: boolean) {
  const lease = await db.inspect.credentialLease.create({
    data: {
      userId: w.owner,
      credentialId: w.login.id,
      accountId: w.account.id,
      instanceId: w.instance.id,
      sandboxId: w.sandbox.id,
      operationId: "op",
      kind: "WORKLOAD",
      exclusive: true,
      state: "RELEASED",
      releasedAt: new Date(),
    },
    select: { id: true },
  });
  const binding = await db.inspect.credentialBinding.create({
    data: {
      leaseId: lease.id,
      instanceId: w.instance.id,
      sandboxId: w.sandbox.id,
      hostId: "host",
      grantGeneration: 1,
      purpose: "INSTALL",
    },
    select: { id: true },
  });
  await db.inspect.credentialResidue.create({
    data: {
      sandboxId: w.sandbox.id,
      userId: w.owner,
      credentialId: w.login.id,
      instanceId: w.instance.id,
      leaseId: lease.id,
      bindingId: binding.id,
      grantGeneration: 1,
      paths,
      recoverable: false,
      ...(cleared ? { clearedAt: new Date(), clearReason: "scrubbed" } : {}),
    },
  });
  return lease.id;
}

const spec = (sandboxId: string) =>
  db.prisma.$transaction((tx) => buildCaptureScrubSpec(tx, sandboxId));
const specPaths = (s: Awaited<ReturnType<typeof spec>>) => s?.residue.flatMap((r) => r.paths);

describe("template capture scrub spec (pg)", () => {
  it("E1-B-01: residue a stop reported scrubbed (cleared) is still scrubbed by the capture", async () => {
    const w = await world();
    // The repro: the stop's scrub reported verifiedAbsent, so the only
    // residue row is cleared, and the capture spec is still built.
    await residue(w, [".fakecli/token"], true);
    const built = await spec(w.sandbox.id);
    expect(built).not.toBeNull();
    expect(built?.leases).toEqual([]);
    expect(specPaths(built)).toEqual([".fakecli/token"]);
    expect(credentialSpecV11Schema.safeParse(built).success).toBe(true);
    if (built) encodeCredentialSpec(built);
  });

  it("unions cleared and uncleared residue with the path history, deduplicated", async () => {
    const w = await world();
    await residue(w, [".fakecli/token", ".config/a"], true);
    await residue(w, [".fakecli/token"], false);
    await db.prisma.$transaction((tx) =>
      recordCredentialPathHistory(tx, w.sandbox.id, [".netrc", ".config/a"]),
    );
    expect(specPaths(await spec(w.sandbox.id))).toEqual([".config/a", ".fakecli/token", ".netrc"]);
  });

  it("paths survive the cascade that removes residue with a deleted login", async () => {
    const w = await world();
    const leaseId = await residue(w, [".fakecli/token"], true);
    await db.prisma.$transaction((tx) =>
      recordCredentialPathHistory(tx, w.sandbox.id, [".fakecli/token"]),
    );
    // deleteSettledLeases: the lease, its binding and its residue go.
    await db.inspect.credentialLease.delete({ where: { id: leaseId } });
    expect(await db.inspect.credentialResidue.count({ where: { sandboxId: w.sandbox.id } })).toBe(
      0,
    );
    expect(specPaths(await spec(w.sandbox.id))).toEqual([".fakecli/token"]);
  });

  it("history appends are atomic, distinct and sorted; empty adds nothing", async () => {
    const w = await world();
    await Promise.all(
      [[".b"], [".a", ".b"], [".c"], []].map((paths) =>
        db.prisma.$transaction((tx) => recordCredentialPathHistory(tx, w.sandbox.id, paths)),
      ),
    );
    expect(
      await db.inspect.sandbox.findUniqueOrThrow({
        where: { id: w.sandbox.id },
        select: { credentialPathHistory: true },
      }),
    ).toEqual({ credentialPathHistory: [".a", ".b", ".c"] });
  });

  it("no login ever installed: no spec", async () => {
    const w = await world();
    expect(await spec(w.sandbox.id)).toBeNull();
  });

  it("more paths than one entry holds are chunked into valid entries; past the cap, refused", async () => {
    const w = await world();
    const many = Array.from({ length: 130 }, (_, i) => `.p/${String(i).padStart(3, "0")}`);
    await db.prisma.$transaction((tx) => recordCredentialPathHistory(tx, w.sandbox.id, many));
    const built = await spec(w.sandbox.id);
    expect(built?.residue.map((r) => r.paths.length)).toEqual([64, 64, 2]);
    expect(specPaths(built)).toEqual(many);
    expect(credentialSpecV11Schema.safeParse(built).success).toBe(true);
    const over = Array.from({ length: 16 * 64 + 1 - 130 }, (_, i) => `.q/${i}`);
    await db.prisma.$transaction((tx) => recordCredentialPathHistory(tx, w.sandbox.id, over));
    await expect(spec(w.sandbox.id)).rejects.toMatchObject({
      data: { code: "credential.spec_too_large" },
    });
  });

  it("a malformed stored residue path refuses the capture instead of being dropped", async () => {
    const w = await world();
    await residue(w, [".fakecli/token", 7], true);
    await expect(spec(w.sandbox.id)).rejects.toThrow(/malformed/);
  });
});
