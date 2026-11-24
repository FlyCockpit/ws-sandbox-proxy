import { randomUUID } from "node:crypto";
import { readdirSync } from "node:fs";
import { resolve } from "node:path";

import { afterAll, describe, expect, inject, it } from "vitest";

import { createClone, dropFileDatabases, newCloneName, pgTestDatabase } from "./pg";

const db = await pgTestDatabase();
afterAll(() => db.close());

async function seedUser() {
  const id = `user-${randomUUID()}`;
  await db.inspect.user.create({ data: { id, name: "U", email: `${id}@example.test` } });
  return id;
}

describe("pg test harness", () => {
  it("clones this file's database from the template the production migration runner wrote", async () => {
    const [current] = await db.inspect.$queryRawUnsafe<{ name: string }[]>(
      "SELECT current_database() AS name",
    );
    expect(current?.name).toBe(db.name);
    const migrations = await db.inspect.$queryRawUnsafe<{ count: bigint }[]>(
      "SELECT count(*) AS count FROM _prisma_migrations WHERE finished_at IS NOT NULL AND rolled_back_at IS NULL",
    );
    // Every committed migration folder (0_init and the additive ones after it).
    const committed = readdirSync(resolve(import.meta.dirname, "../../prisma/migrations"), {
      withFileTypes: true,
    }).filter((entry) => entry.isDirectory()).length;
    expect(Number(migrations[0]?.count)).toBe(committed);
  });

  it("forces A-then-B and observes B blocked on A's real row lock", async () => {
    const id = await seedUser();
    const order: string[] = [];
    const lock = (actor: string) =>
      db.run(actor, () =>
        db.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${id} FOR UPDATE`;
          order.push(actor);
        }),
      );
    const parked = db.pauseAt("A", { after: /FOR UPDATE$/ });
    const a = lock("A");
    await parked.waitReached();
    const b = lock("B");
    const blocked = await db.waitUntilBlocked("B", { by: "A" });
    expect(blocked.waitEventType).toBe("Lock");
    expect(blocked.blockers).toContain(db.backendPid("A"));
    // A is parked holding the lock; B cannot have passed its FOR UPDATE.
    expect(order).toEqual([]);
    parked.release();
    await Promise.all([a, b]);
    expect(order).toEqual(["A", "B"]);
  });

  it("waitUntilBlocked fails loudly when the actor is not waiting on a lock", async () => {
    const id = await seedUser();
    const parked = db.pauseAt("idle", { after: /FOR UPDATE$/ });
    const idle = db.run("idle", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${id} FOR UPDATE`;
      }),
    );
    await parked.waitReached();
    await expect(db.waitUntilBlocked("idle", { timeoutMs: 200 })).rejects.toThrow(
      /never observed blocked/,
    );
    parked.release();
    await idle;
  });

  it("waitUntilBlocked with `by` naming an actor that has no transaction keeps polling and fails naming the missing holder", async () => {
    const id = await seedUser();
    const lock = (actor: string) =>
      db.run(actor, () =>
        db.prisma.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT id FROM "user" WHERE id = ${id} FOR UPDATE`;
        }),
      );
    const parked = db.pauseAt("A", { after: /FOR UPDATE$/ });
    const a = lock("A");
    await parked.waitReached();
    const b = lock("B");
    // B really is blocked (by A); a typo'd holder must not turn that into a pass.
    await db.waitUntilBlocked("B", { by: "A" });
    await expect(db.waitUntilBlocked("B", { by: "no-such-actor", timeoutMs: 300 })).rejects.toThrow(
      /never observed blocked on a lock held by "no-such-actor" \(holder "no-such-actor" has no recorded transaction backend\)/,
    );
    parked.release();
    await Promise.all([a, b]);
  });

  it("an injected failure at a paused statement rolls the transaction back", async () => {
    const id = await seedUser();
    const parked = db.pauseAt("writer", { before: "user.update" });
    const write = db.run("writer", () =>
      db.prisma.$transaction(async (tx) => {
        await tx.session.create({
          data: { userId: id, token: `t-${id}`, expiresAt: new Date(Date.now() + 60_000) },
        });
        await tx.user.update({ where: { id }, data: { name: "changed" } });
      }),
    );
    await parked.waitReached();
    parked.fail(new Error("injected"));
    await expect(write).rejects.toThrow("injected");
    expect(await db.inspect.session.count({ where: { userId: id } })).toBe(0);
  });
});

describe("per-file database drop", () => {
  const adminUrl = inject("wsspPgAdminUrl");
  const template = inject("wsspPgTemplateDb");
  const container = inject("wsspPgContainer");

  async function databases(prefix: string) {
    const rows = await db.inspect.$queryRawUnsafe<{ datname: string }[]>(
      "SELECT datname FROM pg_database WHERE starts_with(datname, $1) ORDER BY datname",
      prefix,
    );
    return rows.map((row) => row.datname);
  }

  it("drops a finished file's clone and its satellites, and nothing else", async () => {
    const clone = newCloneName();
    await createClone(adminUrl, template, clone);
    await db.inspect.$executeRawUnsafe(`CREATE DATABASE ${clone}_upgrade_1`);
    expect(await databases(clone)).toEqual([clone, `${clone}_upgrade_1`]);
    await dropFileDatabases(adminUrl, container, clone);
    expect(await databases(clone)).toEqual([]);
    expect(await databases(db.name)).toEqual([db.name]);
    expect(await databases(template)).toEqual([template]);
  });

  it("refuses a server that is not the harness's container, before dropping anything", async () => {
    const clone = newCloneName();
    await createClone(adminUrl, template, clone);
    const port = container.slice(container.lastIndexOf(":") + 1);
    // Same URL and port, but another (well-formed) container identity: only
    // the live cluster_name check can tell, and it must refuse.
    const impostor = `wssp-test-pg-0000000000000000:${port}`;
    await expect(dropFileDatabases(adminUrl, impostor, clone)).rejects.toThrow(
      /the server is not the test container/,
    );
    expect(await databases(clone)).toEqual([clone]);
    await dropFileDatabases(adminUrl, container, clone);
    expect(await databases(clone)).toEqual([]);
  });

  it("refuses a clone this process did not create, and a satellite it cannot name", async () => {
    await expect(
      // A different last character: never this file's own clone name.
      dropFileDatabases(
        adminUrl,
        container,
        db.name.replace(/.$/, (last) => (last === "0" ? "1" : "0")),
      ),
    ).rejects.toThrow(/did not create that clone/);
    const clone = newCloneName();
    await createClone(adminUrl, template, clone);
    const odd = `${clone}_Odd`;
    await db.inspect.$executeRawUnsafe(`CREATE DATABASE "${odd}"`);
    await expect(dropFileDatabases(adminUrl, container, clone)).rejects.toThrow(
      /unexpected database/,
    );
    expect(await databases(clone)).toEqual([clone, odd]);
    await db.inspect.$executeRawUnsafe(`ALTER DATABASE "${odd}" RENAME TO ${clone}_renamed`);
    await dropFileDatabases(adminUrl, container, clone);
    expect(await databases(clone)).toEqual([]);
  });
});
