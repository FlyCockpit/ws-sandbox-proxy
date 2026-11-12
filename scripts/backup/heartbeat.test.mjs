import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { sendBackupHeartbeat } from "../backup-heartbeat.mjs";
import { uploadBackupAndHeartbeat } from "./s3.mjs";

const token = "inert-heartbeat-token";
const env = { BACKUP_HEARTBEAT_URL: `https://monitor.example/${token}` };

test("heartbeat retries transient failures and cancels response bodies", async () => {
  const waits = [];
  const events = [];
  let attempts = 0;
  await sendBackupHeartbeat({
    env,
    fetch: async (url, options) => {
      assert.equal(url.pathname, `/${token}`);
      assert.equal(options.method, "GET");
      assert.equal(options.signal.aborted, false);
      attempts += 1;
      if (attempts === 1) throw new Error(`secret exception ${token}`);
      return {
        ok: attempts === 3,
        status: 503,
        body: { cancel: async () => events.push("cancel") },
      };
    },
    sleep: async (ms) => waits.push(ms),
    warn: (message) => events.push(message),
    log: (message) => events.push(message),
  });
  assert.equal(attempts, 3);
  assert.deepEqual(waits, [1000, 2000]);
  assert.deepEqual(events, ["cancel", "cancel", "Heartbeat sent."]);
});

test("exhausted heartbeat failures warn safely and resolve", async () => {
  const messages = [];
  let attempts = 0;
  await sendBackupHeartbeat({
    env,
    fetch: async () => {
      attempts += 1;
      throw new Error(env.BACKUP_HEARTBEAT_URL);
    },
    sleep: async () => {},
    warn: (message) => messages.push(message),
  });
  assert.equal(attempts, 3);
  assert.match(messages.join("\n"), /unreachable after 3 attempts.*dump itself is safe/);
  assert.doesNotMatch(messages.join("\n"), /inert-heartbeat-token|https:/);
});

test("missing and invalid URLs do not make requests or disclose values", async () => {
  for (const value of [undefined, token, `file:///${token}`]) {
    const messages = [];
    await sendBackupHeartbeat({
      env: { BACKUP_HEARTBEAT_URL: value },
      fetch: async () => assert.fail("invalid heartbeat must not send"),
      warn: (message) => messages.push(message),
    });
    assert.equal(messages.length, 1);
    assert.doesNotMatch(messages[0], /inert-heartbeat-token/);
  }
});

test("upload CLI sends the heartbeat only after success, including upload-only retries", async () => {
  const events = [];
  const options = { file: "/backups/daily-20261112T030000Z.dump" };
  const result = { eTag: "etag", versionId: "version" };
  const dependencies = {
    upload: async (input) => {
      assert.equal(input, options);
      events.push("upload");
      return result;
    },
    heartbeat: async () => {
      events.push("heartbeat");
    },
  };
  assert.equal(await uploadBackupAndHeartbeat(options, dependencies), result);
  assert.equal(await uploadBackupAndHeartbeat(options, dependencies), result);
  assert.deepEqual(events, ["upload", "heartbeat", "upload", "heartbeat"]);
  await assert.rejects(
    uploadBackupAndHeartbeat(options, {
      ...dependencies,
      upload: async () => {
        throw new Error("failed upload");
      },
    }),
    /failed upload/,
  );
  assert.equal(events.length, 4);
  // Both production paths invoke this CLI; local-only writing never invokes it.
  const writer = await readFile(new URL("./pre-migrate.sh", import.meta.url), "utf8");
  const scheduler = await readFile(new URL("./schedule.mjs", import.meta.url), "utf8");
  assert.match(writer, /if \[ "\$use_s3" = 1 \] && ! node "\$HERE\/s3.mjs" upload/);
  assert.match(scheduler, /path.join\(HERE, "s3.mjs"\),\s*"upload"/);
  assert.doesNotMatch(writer, /backup-heartbeat/);
});

test("a heartbeat error cannot fail an already successful upload", async (t) => {
  const messages = [];
  t.mock.method(console, "error", (message) => messages.push(message));
  const result = { eTag: "etag" };
  assert.equal(
    await uploadBackupAndHeartbeat(
      {},
      {
        upload: async () => result,
        heartbeat: async () => {
          throw new Error(token);
        },
      },
    ),
    result,
  );
  assert.match(messages[0], /dump itself is safe/);
  assert.doesNotMatch(messages[0], /inert-heartbeat-token/);
});
