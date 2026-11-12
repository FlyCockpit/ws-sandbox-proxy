import { describe, expect, it } from "vitest";
import { DATABASE_SESSION_OPTIONS, utcConnectionConfig } from "./client";

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
