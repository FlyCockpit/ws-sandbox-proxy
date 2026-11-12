import { describe, expect, it } from "vitest";
import { backupCommonConfigWarnings, backupMonitorConfigWarnings } from "./backup-config.js";

describe("backup monitor configuration", () => {
  it("requires an explicit nonempty namespace for a configured bucket", () => {
    for (const prefix of [undefined, "", "/", "///"]) {
      expect(
        backupCommonConfigWarnings({ BACKUP_S3_BUCKET: "snapshots", BACKUP_S3_PREFIX: prefix }),
      ).toContainEqual(expect.stringContaining("BACKUP_S3_PREFIX is empty"));
    }
    expect(
      backupCommonConfigWarnings({
        BACKUP_S3_BUCKET: "snapshots",
        BACKUP_S3_PREFIX: "/wssp/dev/database/",
      }),
    ).toEqual([]);
  });

  it("lets monitor-only processes omit writer credentials", () => {
    expect(
      backupMonitorConfigWarnings({
        BACKUP_ENABLED: true,
        BACKUP_S3_BUCKET: "snapshots",
        BACKUP_S3_PREFIX: "wssp/prod/database",
        BACKUP_S3_REGION: "us-east-1",
        BACKUP_MONITOR_S3_ACCESS_KEY_ID: "monitor-only",
        BACKUP_MONITOR_S3_SECRET_ACCESS_KEY: "synthetic-monitor-key",
      }),
    ).toEqual([]);
  });

  it("describes the monitor intent independently of writers", () => {
    expect(backupCommonConfigWarnings({ BACKUP_ENABLED: true })).toContainEqual(
      expect.stringContaining("freshness monitoring is enabled"),
    );
    expect(backupCommonConfigWarnings({ BACKUP_ENABLED: false })).toEqual([]);
  });
});
