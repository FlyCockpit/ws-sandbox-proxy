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
