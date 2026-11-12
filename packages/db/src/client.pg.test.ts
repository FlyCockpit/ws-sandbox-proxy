import { afterAll, expect, it } from "vitest";
import { createPrismaClient, DATABASE_SESSION_OPTIONS } from "./client";

import { pgTestDatabase } from "./testing/pg";

const db = await pgTestDatabase();
afterAll(() => db.close());

it("every client session runs in UTC even when the database default is not UTC", async () => {
  expect(DATABASE_SESSION_OPTIONS).toBe("-c TimeZone=UTC");
  await db.inspect.$executeRawUnsafe(
    `ALTER DATABASE ${db.name} SET "TimeZone" = 'America/Los_Angeles'`,
  );
  const client = createPrismaClient({ connectionString: db.url, max: 2 });
  try {
    // The database default really is non-UTC...
    const [stored] = await client.$queryRaw<{ config: string[] }[]>`
      SELECT setconfig AS config FROM pg_db_role_setting
      WHERE setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
        AND setrole = 0`;
    expect(stored?.config).toContain("TimeZone=America/Los_Angeles");
    // ...yet a new client session reports UTC.
    const [zone] = await client.$queryRaw<
      { zone: string }[]
    >`SELECT current_setting('TimeZone') AS zone`;
    expect(zone?.zone).toBe("UTC");
    // A bare clock read (as trigger functions do) and a bare timestamptz →
    // timestamp stamp both land on the true UTC instant.
    const before = Date.now();
    const [clock] = await client.$queryRaw<{ now: Date }[]>`SELECT clock_timestamp() AS now`;
    expect(Math.abs(clock!.now.getTime() - before)).toBeLessThan(60_000);
    const [stamp] = await client.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(
        "CREATE TEMP TABLE utc_stamp (at timestamp(3) DEFAULT clock_timestamp()) ON COMMIT DROP",
      );
      await tx.$executeRawUnsafe("INSERT INTO utc_stamp DEFAULT VALUES");
      return tx.$queryRaw<{ at: Date }[]>`SELECT at FROM utc_stamp`;
    });
    expect(Math.abs(stamp!.at.getTime() - before)).toBeLessThan(60_000);
  } finally {
    await client.$disconnect();
    await db.inspect.$executeRawUnsafe(`ALTER DATABASE ${db.name} RESET "TimeZone"`);
  }
});

it("URL options are merged, never allowed to drop the UTC session setting", async () => {
  await db.inspect.$executeRawUnsafe(
    `ALTER DATABASE ${db.name} SET "TimeZone" = 'Pacific/Kiritimati'`,
  );
  const withOptions = (options: string) => {
    const url = new URL(db.url);
    url.searchParams.set("options", options);
    return url.toString();
  };
  const settings = async (connectionString: string) => {
    const client = createPrismaClient({ connectionString, max: 1 });
    try {
      const [row] = await client.$queryRaw<{ zone: string; timeout: string }[]>`
        SELECT current_setting('TimeZone') AS zone,
          current_setting('statement_timeout') AS timeout`;
      return row;
    } finally {
      await client.$disconnect();
    }
  };
  try {
    // (a) An unrelated URL option is kept, and the session is still UTC.
    expect(await settings(withOptions("-c statement_timeout=5000"))).toEqual({
      zone: "UTC",
      timeout: "5s",
    });
    // (b) A conflicting TimeZone in the URL loses to UTC.
    expect(
      (await settings(withOptions("-c TimeZone=America/Los_Angeles -c statement_timeout=7000")))
        ?.zone,
    ).toBe("UTC");
  } finally {
    await db.inspect.$executeRawUnsafe(`ALTER DATABASE ${db.name} RESET "TimeZone"`);
  }
});
