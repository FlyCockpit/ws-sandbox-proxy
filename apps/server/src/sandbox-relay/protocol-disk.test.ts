import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  DISK_CREATE_KEY_MAX_BYTES,
  DISK_OFFLOAD_INVENTORY_PAGE_MAX,
  dispatchHasDiskFields,
  hostHelloV11Schema,
  redactImageFrame,
  serverDiskMessageSchema,
  validNodeUrl,
} from "@wssp/sandbox-contracts";
import { expect, it } from "vitest";
import receiptLimits from "../../../../packages/config/src/sandbox-receipt-limits.json";
import { helloFixture } from "./capacity-fixtures";
import {
  encodeServerControlMessage,
  parseDaemonControlFrame,
  type ServerControlMessage,
} from "./protocol";

// Shared with `crates/sandbox-protocol/tests/disk_frames.rs`.
const fixtures = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../crates/sandbox-protocol/fixtures",
);
const read = (name: string) => JSON.parse(readFileSync(join(fixtures, name), "utf8"));
const fixture = read("control_disk.json") as {
  daemon: Array<Record<string, unknown>>;
  server: ServerControlMessage[];
  rejectedDaemon: Array<Record<string, unknown>>;
  rejectedServer: ServerControlMessage[];
};

it("shares the disk frame fixture with Rust: daemon frames parse, server frames encode, malformed frames are refused", () => {
  for (const message of fixture.daemon)
    expect(parseDaemonControlFrame(JSON.stringify(message)), JSON.stringify(message)).toEqual(
      message,
    );
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.rejectedDaemon)
    expect(
      () => parseDaemonControlFrame(JSON.stringify(message)),
      JSON.stringify(message),
    ).toThrow();
  for (const message of fixture.rejectedServer)
    expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
});

it("an offload inventory page carries at most DISK_OFFLOAD_INVENTORY_PAGE_MAX entries", () => {
  const page = (n: number) =>
    JSON.stringify({
      type: "disk.offload.inventory",
      entries: Array.from({ length: n }, (_, i) => ({
        sandboxId: `sbx-${i}`,
        offloadId: `off-${i}`,
        seq: 1,
      })),
    });
  expect(parseDaemonControlFrame(page(DISK_OFFLOAD_INVENTORY_PAGE_MAX))).toMatchObject({
    type: "disk.offload.inventory",
  });
  expect(() => parseDaemonControlFrame(page(DISK_OFFLOAD_INVENTORY_PAGE_MAX + 1))).toThrow();
});

it("I13: a grant's key is valid when present; continuation grants and resume answers carry none", () => {
  const grant = fixture.server.find((frame) => frame.type === "disk.upload.grant")!;
  expect(serverDiskMessageSchema.safeParse(grant).success).toBe(true);
  const { encryption: _key, ...bare } = grant as Record<string, unknown>;
  expect(serverDiskMessageSchema.safeParse(bare).success).toBe(true);
  expect(serverDiskMessageSchema.safeParse({ ...bare, encryption: null }).success).toBe(false);
  expect(
    serverDiskMessageSchema.safeParse({ ...bare, encryption: { scheme: "aes256gcm-r1", key: "x" } })
      .success,
  ).toBe(false);
  const resumed = fixture.server.find((frame) => frame.type === "disk.upload.resumed")!;
  expect(serverDiskMessageSchema.safeParse(resumed).success).toBe(true);
  expect(
    serverDiskMessageSchema.safeParse({
      ...resumed,
      encryption: (grant as { encryption: unknown }).encryption,
    }).success,
  ).toBe(false);
});

it("redactImageFrame hides a resume answer's presigned URLs", () => {
  const resumed = fixture.server.find((frame) => frame.type === "disk.upload.resumed")!;
  const text = JSON.stringify(
    redactImageFrame(resumed as { type: string } & Record<string, unknown>),
  );
  expect(text).not.toContain("X-Amz-Signature");
  expect(text).toContain("<1 parts>");
});

it("redactImageFrame hides the disk grant's key and presigned URLs", () => {
  const grant = fixture.server.find((frame) => frame.type === "disk.upload.grant")!;
  const text = JSON.stringify(
    redactImageFrame(grant as { type: string } & Record<string, unknown>),
  );
  expect(text).not.toContain("AAAAAAAA");
  expect(text).not.toContain("X-Amz-Signature");
  expect(text).toContain("<redacted>");
});

it("I10: a reconnect without disk fields encodes exactly as before", () => {
  const startup = read("control_startup.json") as { server: ServerControlMessage[] };
  const reconnect = startup.server.find(
    (frame) => frame.type === "operation.dispatch" && frame.kind === "sandbox.reconnect",
  )!;
  expect(dispatchHasDiskFields(reconnect as Parameters<typeof dispatchHasDiskFields>[0])).toBe(
    false,
  );
  const encoded = encodeServerControlMessage(reconnect, "1.0");
  expect(encoded).toBe(JSON.stringify(reconnect));
  for (const key of ["restore", "launchMode", "expectDisk", "diskBaseFingerprint"])
    expect(encoded).not.toContain(`"${key}"`);
  // Never null: an absent field is omitted.
  for (const key of ["restore", "launchMode", "expectDisk", "diskBaseFingerprint"])
    expect(() =>
      encodeServerControlMessage({ ...reconnect, [key]: null } as ServerControlMessage, "1.0"),
    ).toThrow();
});

it("the hello capability is optional, true-only, and requires image.fetch", () => {
  const hello = helloFixture("host-1");
  expect(hello.daemon.capabilities.diskOffload).toBeUndefined();
  const image = {
    fetch: true,
    serve: false,
    publish: false,
    capture: false,
    acceptForeign: false,
    leaseFromReady: false,
    formats: ["unified"],
  };
  const withCaps = (caps: Record<string, unknown>) =>
    hostHelloV11Schema.safeParse({
      ...hello,
      daemon: { ...hello.daemon, capabilities: { ...hello.daemon.capabilities, ...caps } },
    }).success;
  expect(withCaps({ diskOffload: true, image })).toBe(true);
  expect(withCaps({ diskOffload: true })).toBe(false);
  expect(withCaps({ diskOffload: true, image: { ...image, fetch: false } })).toBe(false);
  expect(withCaps({ diskOffload: false, image })).toBe(false);
});

it("disk grant URLs are HTTPS, or HTTP only to a loopback host (Rust valid_url)", () => {
  for (const ok of [
    "https://bucket.example.com/k?X-Amz-Signature=x",
    "http://127.0.0.1:9000/b/k",
    "http://localhost:7070/k",
    "http://[::1]:9000/k",
  ])
    expect(validNodeUrl(ok), ok).toBe(true);
  for (const bad of [
    "http://s3.example.com/k",
    "http://10.0.0.5:9000/k",
    "http://127.0.0.1.example.com/k",
    "http://user@127.0.0.1/k",
    "ftp://127.0.0.1/k",
    "http://localhost.evil.test/k",
    "http://127.0.0.01/k",
  ])
    expect(validNodeUrl(bad), bad).toBe(false);
});

it("a discard's create key is bounded like every idempotency key", () => {
  expect(DISK_CREATE_KEY_MAX_BYTES).toBe(receiptLimits.idempotencyKeyBytes);
});
