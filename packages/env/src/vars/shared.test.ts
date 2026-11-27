import { describe, expect, it } from "vitest";
import { sharedVars } from "./shared.js";

describe("migration and backup shared declarations", () => {
  it("accepts an absent runtime identity or a UUID, and rejects reused descriptive IDs", () => {
    expect(sharedVars.WSSP_INSTANCE_ID.parse(undefined)).toBeUndefined();
    expect(sharedVars.WSSP_INSTANCE_ID.parse("287cfcd5-c83e-4d8d-bafc-31a9982c185b")).toBe(
      "287cfcd5-c83e-4d8d-bafc-31a9982c185b",
    );
    expect(sharedVars.WSSP_INSTANCE_ID.safeParse("worker-1").success).toBe(false);
  });

  it("defaults automatic backups off and keeps per-user credentials on", () => {
    expect(sharedVars.BACKUP_ENABLED.parse(undefined)).toBe(false);
    expect(sharedVars.BACKUP_ENABLED.parse("true")).toBe(true);
    expect(sharedVars.CREDENTIALS_ENABLED.parse(undefined)).toBe(true);
  });

  it("has no implicit shared backup namespace", () => {
    expect(sharedVars.BACKUP_S3_PREFIX.parse(undefined)).toBe("");
    expect(sharedVars.BACKUP_S3_ACCESS_KEY_ID.parse(undefined)).toBeUndefined();
    expect(sharedVars.BACKUP_S3_SECRET_ACCESS_KEY.parse(undefined)).toBeUndefined();
  });

  it("retires the old schema and restore operator controls", () => {
    expect(
      Object.keys(sharedVars).filter((key) =>
        /^(APPLY_SCHEMA|WAIT_FOR_SCHEMA|SCHEMA_WAIT|DB_APPLIER|RESTORE_)/.test(key),
      ),
    ).toEqual([]);
  });
});

it("reserves room for a password lock, nested revocation and handler work", () => {
  expect(sharedVars.DATABASE_POOL_MAX.parse(undefined)).toBe(10);
  for (const value of [0, 1, 2, -1, 3.5, "many"])
    expect(sharedVars.DATABASE_POOL_MAX.safeParse(value).success).toBe(false);
  expect(sharedVars.DATABASE_POOL_MAX.parse("3")).toBe(3);
});
