import { describe, expect, it } from "vitest";
import {
  CONNECT_AUDIT_POOL,
  DATABASE_SESSION_OPTIONS,
  poolConfig,
  utcConnectionConfig,
} from "./client";

const options = (connectionString: string) =>
  new URL(utcConnectionConfig(connectionString).connectionString).searchParams.get("options");

describe("utcConnectionConfig (unit; real-DB: client.pg.test.ts)", () => {
  it("adds the UTC setting to a URL without options", () => {
    expect(options("postgresql://u:p@db.example:5432/app?sslmode=require")).toBe(
      DATABASE_SESSION_OPTIONS,
    );
    const out = new URL(
      utcConnectionConfig("postgresql://u:p%40x@db.example:5432/app?sslmode=require")
        .connectionString,
    );
    expect([out.password, out.pathname, out.searchParams.get("sslmode")]).toEqual([
      "p%40x",
      "/app",
      "require",
    ]);
  });
  it("appends UTC last to existing URL options, including a conflicting TimeZone", () => {
    expect(options("postgresql://h/app?options=-c%20statement_timeout%3D5000")).toBe(
      "-c statement_timeout=5000 -c TimeZone=UTC",
    );
    expect(options("postgresql://h/app?options=-c+TimeZone%3DAsia%2FTokyo")).toBe(
      "-c TimeZone=Asia/Tokyo -c TimeZone=UTC",
    );
  });
  it("passes the option alongside a non-URL connection string", () => {
    expect(utcConnectionConfig("host=/var/run/postgresql dbname=app")).toEqual({
      connectionString: "host=/var/run/postgresql dbname=app",
      options: DATABASE_SESSION_OPTIONS,
    });
  });
});

describe("poolConfig (driver settings)", () => {
  const url = "postgresql://u:p@db.example:5432/app";
  const optionsOf = (config: { connectionString: string }) =>
    new URL(config.connectionString).searchParams.get("options");

  it("passes only the URL options and max without driver settings", () => {
    const config = poolConfig({ connectionString: url, max: 7 });
    expect(Object.keys(config).sort()).toEqual(["connectionString", "max"]);
    expect(optionsOf(config)).toBe(DATABASE_SESSION_OPTIONS);
  });

  it("merges the session statement_timeout after the URL's options and before UTC", () => {
    const config = poolConfig({
      connectionString: `${url}?options=-c%20TimeZone%3DAsia%2FTokyo%20-c%20statement_timeout%3D0`,
      max: 2,
      driver: { statementTimeoutMs: 2_000, connectionTimeoutMillis: 1_500 },
    });
    expect(optionsOf(config)).toBe(
      "-c TimeZone=Asia/Tokyo -c statement_timeout=0 -c statement_timeout=2000 -c TimeZone=UTC",
    );
    expect(config).toMatchObject({ max: 2, connectionTimeoutMillis: 1_500 });
    expect(config).not.toHaveProperty("statementTimeoutMs");
    // A non-URL string gets the same merged options alongside it.
    expect(
      poolConfig({
        connectionString: "host=/run/pg dbname=app",
        max: 1,
        driver: { statementTimeoutMs: 250 },
      }),
    ).toEqual({
      connectionString: "host=/run/pg dbname=app",
      options: "-c statement_timeout=250 -c TimeZone=UTC",
      max: 1,
    });
  });

  it("the connect audit pool: two connections, every startup and statement bounded", () => {
    const config = poolConfig({ connectionString: url, ...CONNECT_AUDIT_POOL });
    expect(config).toMatchObject({
      max: 2,
      connectionTimeoutMillis: 2_000,
      query_timeout: 3_000,
      idleTimeoutMillis: 5_000,
    });
    expect(optionsOf(config)).toBe("-c statement_timeout=2000 -c TimeZone=UTC");
  });
});
