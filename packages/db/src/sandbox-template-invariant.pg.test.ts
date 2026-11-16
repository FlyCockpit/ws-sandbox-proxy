import { randomUUID } from "node:crypto";
import { afterAll, expect, it } from "vitest";
import { pgTestDatabase } from "./testing/pg";

const db = await pgTestDatabase();
afterAll(() => db.close());
async function owner() {
  const id = randomUUID();
  await db.inspect.user.create({ data: { id, name: "Owner", email: `${id}@example.test` } });
  return id;
}
it("logical templates have no host invariant; revisions and tags enforce the composite owner/template FKs", async () => {
  const a = await owner();
  const b = await owner();
  const logical = await db.inspect.sandboxTemplate.create({
    data: { userId: a, slug: "base", label: "Base" },
  });
  const data = {
    userId: a,
    templateId: logical.id,
    revision: 1,
    incusFingerprint: `sha256:${"c".repeat(64)}`,
    architecture: "x86_64",
    manifestDigest: "c".repeat(64),
  };
  await expect(
    db.inspect.sandboxTemplateRevision.create({ data: { ...data, userId: b } }),
  ).rejects.toMatchObject({ code: "P2003" });
  const revision = await db.inspect.sandboxTemplateRevision.create({ data });
  const other = await db.inspect.sandboxTemplate.create({
    data: { userId: a, slug: "other", label: "Other" },
  });
  await expect(
    db.inspect.sandboxTemplateTag.create({
      data: { userId: a, templateId: other.id, revisionId: revision.id, tag: "latest" },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandboxTemplateTag.create({
      data: { userId: b, templateId: logical.id, revisionId: revision.id, tag: "latest" },
    }),
  ).rejects.toMatchObject({ code: "P2003" });
  await db.inspect.sandboxTemplateTag.create({
    data: { userId: a, templateId: logical.id, revisionId: revision.id, tag: "latest" },
  });
  await db.inspect.sandboxTemplateRevision.update({
    where: { id: revision.id },
    data: { retiredAt: new Date() },
  });
  expect(await db.inspect.sandboxTemplate.count({ where: { userId: a } })).toBe(2);
});
it("revision checks are nonsecret and all private env-bearing tables have no CHECK", async () => {
  const rows = await db.inspect.$queryRaw<
    { table: string; name: string }[]
  >`SELECT c.conrelid::regclass::text AS table, c.conname AS name FROM pg_constraint c WHERE c.contype = 'c' AND c.conrelid IN ('sandbox_template_revision'::regclass, 'sandbox_revision_config'::regclass, 'sandbox_execution_config'::regclass, 'sandbox_dispatch_outbox'::regclass)`;
  expect(rows).toHaveLength(7);
  expect(rows).toEqual(
    expect.arrayContaining([
      {
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_number_ck[0-9a-f]{8}$/),
      },
      {
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_root_disk_ck[0-9a-f]{8}$/),
      },
      {
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_vm_size_ck[0-9a-f]{8}$/),
      },
      {
        // Nonsecret: build provenance shape and recipe length bounds only; the
        // revision row carries no env (that lives in sandbox_revision_config).
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_template_build_ck[0-9a-f]{8}$/),
      },
      {
        // Nonsecret: an enumerated retirement reason only.
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_retired_reason_ck[0-9a-f]{8}$/),
      },
      {
        // Nonsecret: provenance flags of the wssp community recipe (guest-sudo-plan DG-12).
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_wssp_recipe_ck[0-9a-f]{8}$/),
      },
      {
        // Nonsecret: the shape of an UPSTREAM community pin (no parent, build, tag).
        table: "sandbox_template_revision",
        name: expect.stringMatching(/^sandbox_revision_upstream_ck[0-9a-f]{8}$/),
      },
    ]),
  );
  expect(await db.inspect.$queryRaw`SELECT to_regclass('sandbox_template')::text AS old`).toEqual([
    { old: null },
  ]);
});

it("storage composite owner/host FKs restrict retained roots and allow detached history", async () => {
  const a = await owner();
  const b = await owner();
  const host = await db.inspect.sandboxHost.create({
    data: { userId: a, slug: "storage", label: "Storage" },
  });
  const otherHost = await db.inspect.sandboxHost.create({
    data: { userId: a, slug: "other", label: "Other" },
  });
  const poolData = {
    userId: a,
    sandboxHostId: host.id,
    name: "default",
    marker: "storage_1",
    capacityGiB: 32,
    capacitySource: "explicit",
    health: "healthy",
    connectionEpoch: 1,
    observationSequence: 0,
    reportedAt: new Date(),
  };
  await expect(
    db.inspect.sandboxHostStoragePool.create({ data: { ...poolData, userId: b } }),
  ).rejects.toMatchObject({ code: "P2003" });
  const pool = await db.inspect.sandboxHostStoragePool.create({ data: poolData });
  await expect(db.inspect.sandboxHostStoragePool.create({ data: poolData })).rejects.toMatchObject({
    code: "P2002",
  });
  const template = await db.inspect.sandboxTemplate.create({
    data: { userId: a, slug: "storage", label: "Storage" },
  });
  const revision = await db.inspect.sandboxTemplateRevision.create({
    data: {
      userId: a,
      templateId: template.id,
      revision: 1,
      incusFingerprint: `sha256:${"d".repeat(64)}`,
      architecture: "x86_64",
      manifestDigest: "d".repeat(64),
    },
  });
  expect(revision).toMatchObject({ defaultDiskGiB: 32, minDiskGiB: 32 });
  const data = {
    hostOwnerId: a,
    userId: a,
    sandboxHostId: host.id,
    originHostId: host.id,
    templateId: template.id,
    templateRevisionId: revision.id,
    originalSelector: "storage@1",
    diskGiB: 32,
    rootChargeGiB: 33,
    storagePoolId: pool.id,
    storageMarker: pool.marker,
    storagePoolName: pool.name,
    diskReservationHeld: true,
  };
  await expect(
    db.inspect.sandbox.create({ data: { ...data, sandboxHostId: otherHost.id } }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandbox.create({ data: { ...data, storageMarker: "other_marker" } }),
  ).rejects.toMatchObject({ code: "P2003" });
  await expect(
    db.inspect.sandbox.create({ data: { ...data, storagePoolName: "other_pool" } }),
  ).rejects.toMatchObject({ code: "P2003" });
  const sandbox = await db.inspect.sandbox.create({ data });
  await expect(
    db.inspect.sandboxHostStoragePool.delete({ where: { id: pool.id } }),
  ).rejects.toMatchObject({ code: "P2003" });
  // Scalar history survives FK detachment; this is schema qualification, not release proof.
  await db.inspect.sandbox.update({
    where: { id: sandbox.id },
    data: {
      state: "DELETED",
      diskReservationHeld: false,
      storagePoolId: null,
      sandboxHostId: null,
    },
  });
  await db.inspect.sandboxHostStoragePool.delete({ where: { id: pool.id } });
  expect(
    await db.inspect.sandbox.findUnique({
      where: { id: sandbox.id },
      select: { storageMarker: true, storagePoolName: true, diskGiB: true },
    }),
  ).toEqual({ storageMarker: "storage_1", storagePoolName: "default", diskGiB: 32 });
});

it("storage CHECKs permit zero implicit cap and overcommit, reject malformed derivation and bounded counters", async () => {
  const userId = await owner();
  const host = await db.inspect.sandboxHost.create({
    data: { userId, slug: "checks", label: "Checks" },
  });
  const base = {
    userId,
    sandboxHostId: host.id,
    name: "default",
    marker: "checks_1",
    capacityGiB: 0,
    totalBasedCapacityGiB: 80,
    capacitySource: "implicit",
    derivationTotalBytes: 1000n,
    derivationFreeBytes: 0n,
    derivationCommittedBytes: 33n,
    derivationActualBytes: 0n,
    derivationHeadroomBytes: 50n,
    implicitCeilingGiB: 0,
    health: "healthy",
    connectionEpoch: 1,
    observationSequence: 0,
    reportedAt: new Date(),
    diskReservedGiB: 33,
  };
  const pool = await db.inspect.sandboxHostStoragePool.create({ data: base });
  expect(pool.capacityGiB).toBe(0);
  for (const data of [
    { capacityGiB: -1 },
    { capacitySource: "explicit" },
    { derivationActualBytes: 34n },
    { derivationFreeBytes: 1001n },
    { implicitCeilingGiB: null },
    { connectionEpoch: 0 },
    { health: "offline" },
    { diskReservedGiB: -1 },
    { totalBytes: 10n, usedBytes: 11n, freeBytes: 0n },
  ]) {
    await expect(
      db.inspect.sandboxHostStoragePool.update({ where: { id: pool.id }, data }),
    ).rejects.toBeDefined();
  }
  await db.inspect.sandboxHost.update({
    where: { id: host.id },
    data: { daemonVcpuBudget: 1, vcpuReserved: 8000, rootCount: 250 },
  });
  for (const data of [
    { daemonVcpuBudget: 0 },
    { daemonVcpuBudget: 8193 },
    { vcpuReserved: 8001 },
    { vcpuReserved: -1 },
    { rootCount: 251 },
    { rootCount: -1 },
  ]) {
    await expect(
      db.inspect.sandboxHost.update({ where: { id: host.id }, data }),
    ).rejects.toBeDefined();
  }
});
