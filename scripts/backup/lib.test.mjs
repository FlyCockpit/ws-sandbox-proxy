import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

import {
  detectArchiveFormat,
  expectedConfirmation,
  guidedAnswerConfirms,
  guidedQuestion,
  parseRestoreArgs,
  parseS3Source,
  pgEnvFromUrl,
  pickLatest,
  shellQuote,
  sortBackups,
  UsageError,
} from "./lib.mjs";

describe("pgEnvFromUrl", () => {
  it("maps a URL to libpq variables and decodes credentials", () => {
    assert.deepEqual(
      pgEnvFromUrl(
        "postgresql://app%40x:p%24ss%20w@db.internal:6543/my_db?schema=public&sslmode=require",
      ),
      {
        PGHOST: "db.internal",
        PGPORT: "6543",
        PGDATABASE: "my_db",
        PGUSER: "app@x",
        PGPASSWORD: "p$ss w",
        PGSSLMODE: "require",
      },
    );
  });

  it("defaults the port and unwraps IPv6 hosts", () => {
    const env = pgEnvFromUrl("postgres://u@[::1]/wssp");
    assert.equal(env.PGHOST, "::1");
    assert.equal(env.PGPORT, "5432");
    assert.equal(env.PGPASSWORD, undefined);
  });

  it("refuses URLs without a database or with the wrong scheme", () => {
    assert.throws(() => pgEnvFromUrl(undefined), /not set/);
    assert.throws(() => pgEnvFromUrl("postgresql://u:p@h:5432/"), /name exactly one database/);
    assert.throws(() => pgEnvFromUrl("mysql://u:p@h/db"), /postgres/);
    assert.throws(() => pgEnvFromUrl("not a url"), /valid URL/);
  });
});

describe("detectArchiveFormat", () => {
  const custom = Buffer.concat([Buffer.from("PGDMP"), Buffer.alloc(600, 1)]);
  it("recognizes pg_dump custom archives", () => {
    assert.equal(detectArchiveFormat(custom), "custom");
  });
  it("recognizes gzip wrappers (Dokploy .sql.gz holds pg_dump -Fc | gzip)", () => {
    const wrapped = gzipSync(custom);
    assert.equal(detectArchiveFormat(wrapped.subarray(0, 512)), "gzip");
  });
  it("recognizes tar archives", () => {
    const tar = Buffer.alloc(512);
    tar.write("toc.dat", 0, "latin1");
    tar.write("ustar", 257, "latin1");
    assert.equal(detectArchiveFormat(tar), "tar");
  });
  it("identifies plain SQL so it can be refused", () => {
    assert.equal(
      detectArchiveFormat(Buffer.from("--\n-- PostgreSQL database dump\n--\n")),
      "plain-sql",
    );
    assert.equal(detectArchiveFormat(Buffer.from("SET statement_timeout = 0;\n")), "plain-sql");
  });
  it("returns unknown for anything else, including empty input", () => {
    assert.equal(detectArchiveFormat(Buffer.alloc(0)), "unknown");
    assert.equal(detectArchiveFormat(Buffer.from([0x50, 0x4b, 0x03, 0x04])), "unknown");
  });
});

describe("parseS3Source", () => {
  it("splits bucket and key", () => {
    assert.deepEqual(parseS3Source("s3://bkt/database/pre-migrate-1.dump"), {
      bucket: "bkt",
      key: "database/pre-migrate-1.dump",
    });
    assert.equal(parseS3Source("/backups/x.dump"), null);
  });
  it("rejects a bucket without a key", () => {
    assert.throws(() => parseS3Source("s3://bkt"), UsageError);
    assert.throws(() => parseS3Source("s3://bkt/dir/"), UsageError);
  });
});

describe("parseRestoreArgs", () => {
  it("parses a full local invocation and drops a leading CMD word", () => {
    assert.deepEqual(
      parseRestoreArgs(["restore", "/backups/a.dump", "--confirm", "RESTORE:app", "--replace"]),
      {
        source: "/backups/a.dump",
        confirm: "RESTORE:app",
        replace: true,
        allowActiveConnections: false,
        skipSnapshot: false,
        etag: null,
        versionId: null,
        help: false,
        list: false,
        guided: false,
      },
    );
  });

  it("lists without a source, and guided restores ask instead of taking --confirm", () => {
    assert.equal(parseRestoreArgs(["--list"]).list, true);
    assert.throws(() => parseRestoreArgs(["--list", "/backups/a.dump"]), /--list takes no source/);
    const guided = parseRestoreArgs(["latest", "--guided"]);
    assert.equal(guided.source, "latest");
    assert.equal(guided.guided, true);
    assert.throws(
      () => parseRestoreArgs(["latest", "--guided", "--confirm", "RESTORE:app"]),
      /--guided asks/,
    );
    assert.throws(() => parseRestoreArgs(["latest", "--guided", "--replace"]), /--guided asks/);
  });

  it("accepts --flag=value forms and S3 pins", () => {
    const args = parseRestoreArgs([
      "s3://b/k.dump",
      '--etag="abc"',
      "--version-id=v1",
      "--confirm=RESTORE:db",
    ]);
    assert.equal(args.etag, '"abc"');
    assert.equal(args.versionId, "v1");
    assert.equal(args.confirm, "RESTORE:db");
  });

  it("leaves confirm unset for a preview", () => {
    assert.equal(parseRestoreArgs(["/backups/a.dump"]).confirm, null);
  });

  it("rejects malformed invocations", () => {
    assert.throws(() => parseRestoreArgs([]), /Missing <source>/);
    assert.throws(() => parseRestoreArgs(["a", "b"]), /one <source>/);
    assert.throws(() => parseRestoreArgs(["a", "--confirm"]), /needs a value/);
    assert.throws(() => parseRestoreArgs(["a", "--confirm", "--replace"]), /needs a value/);
    assert.throws(() => parseRestoreArgs(["a", "--force"]), /Unknown option/);
    assert.throws(() => parseRestoreArgs(["a", "--replace=yes"]), /does not take a value/);
    assert.throws(() => parseRestoreArgs(["/backups/a", "--etag", "x"]), /only to s3/);
    assert.throws(() => parseRestoreArgs(["/backups/a", "--skip-snapshot"]), /--replace/);
  });

  it("returns help without requiring a source", () => {
    assert.equal(parseRestoreArgs(["--help"]).help, true);
  });

  it("allows a source that starts with a dash after --", () => {
    assert.equal(parseRestoreArgs(["--", "-odd.dump"]).source, "-odd.dump");
  });
});

describe("helpers", () => {
  it("binds the confirmation to the database name", () => {
    assert.equal(expectedConfirmation("wssp"), "RESTORE:wssp");
  });
  it("guided: replacing a database with data needs its name typed; an empty one takes y", () => {
    assert.match(guidedQuestion("wssp", true), /Type the database name \(wssp\)/);
    assert.match(guidedQuestion("wssp", false), /\[y\/N\]/);
    assert.equal(guidedAnswerConfirms("wssp", "wssp", true), true);
    assert.equal(guidedAnswerConfirms("  wssp\n", "wssp", true), true);
    for (const answer of ["y", "yes", "Y", "", "Wssp", "wss", "RESTORE:wssp"])
      assert.equal(guidedAnswerConfirms(answer, "wssp", true), false, answer);
    for (const answer of ["y", "Yes", " y "])
      assert.equal(guidedAnswerConfirms(answer, "wssp", false), true, answer);
    for (const answer of ["", "n", "wssp", "yep"])
      assert.equal(guidedAnswerConfirms(answer, "wssp", false), false, answer);
  });
  it("quotes shell values only when needed", () => {
    assert.equal(shellQuote("/backups/a.dump"), "/backups/a.dump");
    assert.equal(shellQuote('"etag"'), `'"etag"'`);
    assert.equal(shellQuote("it's"), `'it'\\''s'`);
  });
});

describe("backups in the volume", () => {
  const at = (name, mtimeMs) => ({ name, mtimeMs, size: 1 });
  it("lists restorable files newest first, skipping hidden and partial ones", () => {
    const sorted = sortBackups([
      at("pre-migrate-20261101T000000Z.dump", 1),
      at(".daily-20261103T030000Z.dump.partial", 9),
      at("daily-20261103T030000Z.dump", 3),
      at("notes.txt", 8),
      at("dokploy-2026-11-02.sql.gz", 2),
    ]).map((entry) => entry.name);
    assert.deepEqual(sorted, [
      "daily-20261103T030000Z.dump",
      "dokploy-2026-11-02.sql.gz",
      "pre-migrate-20261101T000000Z.dump",
    ]);
  });
  it("latest is the newest backup that is not a pre-restore snapshot", () => {
    assert.equal(
      pickLatest([
        at("daily-20261102T030000Z.dump", 2),
        at("pre-restore-20261103T120000Z.dump", 5),
        at("manual-20261103T110000Z.dump", 4),
      ]),
      "manual-20261103T110000Z.dump",
    );
    assert.equal(pickLatest([at("pre-restore-20261103T120000Z.dump", 5)]), null);
    assert.equal(pickLatest([]), null);
  });
});

describe("host backup wrapper", () => {
  it("uses the database network and forwards heartbeat without monitor credentials", async () => {
    const directory = await mkdtemp(join(tmpdir(), "wssp-host-backup-"));
    try {
      const output = join(directory, "result.json");
      const stub = `#!/bin/bash
case "$1" in
  info) exit 0 ;;
  ps)
    if [[ "$*" == *--format* ]]; then printf 'wssp-test\\n';
    elif [[ "$*" == *service=server* ]]; then printf 'server\\n';
    elif [[ "$*" == *service=postgres* ]]; then printf 'postgres\\n'; fi ;;
  inspect)
    case "$3" in
      *Config.Env*) printf '%s\\n' 'DATABASE_URL=postgresql://localhost/inert' 'BACKUP_S3_BUCKET=bucket' 'BACKUP_S3_ACCESS_KEY_ID=inert-writer' 'BACKUP_HEARTBEAT_URL=https://monitor.example/inert' 'BACKUP_MONITOR_S3_ACCESS_KEY_ID=inert-monitor' 'UNRELATED_SETTING=inert' ;;
      *Image*) printf 'app-image\\n' ;;
      *Mounts*) printf 'project-backups\\n' ;;
      *NetworkSettings*) if [ "$4" = postgres ]; then printf 'project-private\\n'; else printf 'custom-ingress project-private\\n'; fi ;;
      *) exit 2 ;;
    esac ;;
  network) [ "$3" = project-private ] ;;
  image) [ "$2" = inspect ] && [ "$3" = app-image ] ;;
  run)
    printf '%s\\n' "$@" > "$HOST_FIXTURE_RESULT.args"
    while [ "$1" != --env-file ]; do shift; done
    cat "$2" > "$HOST_FIXTURE_RESULT" ;;
  *) exit 2 ;;
esac
`;
      await writeFile(join(directory, "docker"), stub, { mode: 0o755 });
      const result = spawnSync(
        "bash",
        [fileURLToPath(new URL("./host.sh", import.meta.url)), "backup"],
        {
          env: {
            PATH: `${directory}:${dirname(process.execPath)}:/usr/bin:/bin`,
            HOST_FIXTURE_RESULT: output,
          },
          encoding: "utf8",
          timeout: 5000,
        },
      );
      assert.equal(result.status, 0, `${result.stdout}${result.stderr}`);
      const args = (await readFile(`${output}.args`, "utf8")).trim().split("\n");
      assert.equal(args[args.indexOf("--network") + 1], "project-private");
      const names = (await readFile(output, "utf8"))
        .trim()
        .split("\n")
        .map((line) => line.split("=")[0]);
      assert.deepEqual(names, [
        "DATABASE_URL",
        "BACKUP_S3_BUCKET",
        "BACKUP_S3_ACCESS_KEY_ID",
        "BACKUP_HEARTBEAT_URL",
      ]);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
