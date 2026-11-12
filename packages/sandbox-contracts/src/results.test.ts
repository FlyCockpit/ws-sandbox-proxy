import { describe, expect, it } from "vitest";
import wireCodes from "../../config/src/sandbox-error-codes.json";
import resultErrors from "../../config/src/sandbox-result-errors.json";
import { OPERATION_ERROR_CODES } from "./dto";
import {
  processQualifiersSchema,
  processRefSchema,
  qualifiedProcessSignalSchema,
} from "./processes";
import {
  entryInfoSchema,
  failureSchema,
  modePermissions,
  operationResultSchema,
  RESULT_TYPE_BY_KIND,
  resultContinuationSchema,
  resultListOptionsSchema,
} from "./results";

const entry = {
  name: "x",
  path: "/x",
  type: "file",
  size: 0,
  mode: 0o644,
  permissions: "rw-r--r--",
  uid: 0,
  gid: 0,
  owner: null,
  group: null,
  modifiedTime: null,
  symlinkTarget: null,
};
const envelope = {
  operationId: "o",
  sandboxId: "s",
  generation: 1,
  kind: "STAT_PATH",
  outcome: "succeeded",
  observedAt: "2026-10-27T00:00:00Z",
  expiresAt: "2026-10-27T01:00:00Z",
  result: { type: "file.stat", entry },
};
describe("typed result boundary", () => {
  it("matches the stored kind and refuses private fields", () => {
    expect(operationResultSchema.safeParse(envelope).success).toBe(true);
    for (const kind of Object.keys(RESULT_TYPE_BY_KIND).filter((kind) => kind !== "STAT_PATH"))
      expect(operationResultSchema.safeParse({ ...envelope, kind }).success).toBe(false);
    expect(operationResultSchema.safeParse({ ...envelope, nonce: "private" }).success).toBe(false);
    expect(entryInfoSchema.safeParse({ ...entry, config: "private" }).success).toBe(false);
  });
  it("validates actual encoded bounds, safe numbers and well-formed UTF-8", () => {
    for (const change of [
      { name: "é".repeat(128) },
      { path: "/" + "é".repeat(2048) },
      { name: "\ud800" },
      { size: Number.MAX_SAFE_INTEGER + 1 },
      { size: -1 },
      { uid: 4_294_967_296 },
      { permissions: "rwxrwxrwx" },
    ])
      expect(entryInfoSchema.safeParse({ ...entry, ...change }).success).toBe(false);
    expect(
      entryInfoSchema.safeParse({ ...entry, name: "with space\n", path: "/with space\n" }).success,
    ).toBe(true);
    const large = {
      ...envelope,
      kind: "LIST_DIR",
      result: {
        type: "file.list",
        path: "/",
        depth: 1,
        consistency: "live",
        nextCursor: null,
        items: Array.from({ length: 100 }, () => ({ ...entry, path: "/" + "x".repeat(4000) })),
      },
    };
    expect(operationResultSchema.safeParse(large).success).toBe(false);
  });
  it("models special mode bits and symlinks without traversal", () => {
    expect(modePermissions(0o7754)).toBe("rwsr-sr-T");
    expect(
      entryInfoSchema.safeParse({ ...entry, type: "symlink", symlinkTarget: "../missing" }).success,
    ).toBe(true);
  });
  it("does not turn failure or unknown into successful content", () => {
    for (const outcome of ["failed", "cancelled", "unknown", "pending"])
      expect(operationResultSchema.safeParse({ ...envelope, outcome }).success).toBe(false);
    expect(
      operationResultSchema.safeParse({ ...envelope, outcome: "failed", result: null }).success,
    ).toBe(true);
  });
  it("requires qualified identity with PID at least two", () => {
    const ref = { sandboxId: "s", generation: 1, processId: "p", attempt: 1, pid: 2 };
    expect(processRefSchema.safeParse(ref).success).toBe(true);
    expect(processRefSchema.safeParse({ ...ref, nonce: "private" }).success).toBe(false);
    for (const pid of [0, 1, 2_147_483_648])
      expect(processRefSchema.safeParse({ ...ref, pid }).success).toBe(false);
  });
});

it("canonicalizes metadata paths only after rejecting unsafe input", async () => {
  const { metadataGuestPathSchema, metadataGuestEntryPathSchema, guestFilePathSchema } =
    await import("./guest-path");
  expect(metadataGuestPathSchema.parse("//a/./b///")).toBe("/a/b");
  for (const path of [" /x", "/x ", "/x/../y", "/x\0", "/\ud800"])
    expect(metadataGuestPathSchema.safeParse(path).success).toBe(false);
  expect(metadataGuestEntryPathSchema.safeParse("/./").success).toBe(false);
  expect(guestFilePathSchema.safeParse("/x/./y").success).toBe(false);
});

it("refuses duplicate, unordered and outside-root directory entries", () => {
  const page = {
    ...envelope,
    kind: "LIST_DIR",
    result: {
      type: "file.list",
      path: "/",
      depth: 1,
      items: [entry],
      nextCursor: null,
      consistency: "live",
    },
  };
  expect(operationResultSchema.safeParse(page).success).toBe(true);
  for (const result of [
    { ...page.result, items: [entry, entry] },
    { ...page.result, path: "/elsewhere" },
    { ...page.result, items: [{ ...entry, path: "/a/x" }] },
  ])
    expect(operationResultSchema.safeParse({ ...page, result }).success).toBe(false);
});

it("shares valid and invalid result fixtures with Rust", async () => {
  const fixtures = (await import("../../../crates/sandbox-protocol/fixtures/typed_results.json"))
    .default;
  for (const fixture of fixtures)
    expect(operationResultSchema.safeParse(fixture.value).success, fixture.name).toBe(
      fixture.valid,
    );
});

it("bounds the complete serialized public response in bytes", () => {
  const root = "/" + Array.from({ length: 14 }, () => "p".repeat(250)).join("/");
  const items = Array.from({ length: 100 }, (_, i) => {
    const name = `x${String(i).padStart(3, "0")}`;
    return { ...entry, name, path: `${root}/${name}` };
  });
  const result = {
    ...envelope,
    kind: "LIST_DIR",
    result: {
      type: "file.list",
      path: root,
      depth: 1,
      items,
      nextCursor: null,
      consistency: "live",
    },
  };
  expect(operationResultSchema.safeParse(result).success).toBe(false);
});

it("rejects malformed UTF-16 before replacement during UTF-8 encoding", () => {
  expect(entryInfoSchema.safeParse({ ...entry, name: "\ud800", path: "/\ud800" }).success).toBe(
    false,
  );
});

it("result-error catalog keys and resource tags match the wire catalog (B1-K-2)", () => {
  const family = (code: string) =>
    code.startsWith("fs_") || code.startsWith("process_") || code.startsWith("signal_");
  const keys = Object.keys(resultErrors).sort();
  expect(keys).toEqual(wireCodes.filter(family).sort());
  expect(keys).toEqual(OPERATION_ERROR_CODES.filter(family).sort());
  const resources: readonly string[] = failureSchema.shape.resource.options;
  for (const [code, entry] of Object.entries(resultErrors)) {
    expect(Object.keys(entry).sort(), code).toEqual(["message", "resource"]);
    expect(entry.message.length, code).toBeGreaterThan(0);
    expect(resources, code).toContain(entry.resource);
    expect(entry.resource, code).toBe(code.startsWith("fs_") ? "filesystem" : "process");
  }
});

describe("staged request and continuation codecs (B1-K-5)", () => {
  it("bounds the private continuation generation like every other generation", () => {
    const continuation = {
      lastKey: "x",
      root: "/",
      depth: 1,
      limit: 100,
      generation: 2_147_483_647,
      kind: "LIST_DIR",
    };
    expect(resultContinuationSchema.safeParse(continuation).success).toBe(true);
    for (const generation of [0, 2_147_483_648, 1.5])
      expect(resultContinuationSchema.safeParse({ ...continuation, generation }).success).toBe(
        false,
      );
    expect(resultContinuationSchema.safeParse({ ...continuation, hostPath: "/x" }).success).toBe(
      false,
    );
  });
  it("list options default the limit, bound it and take only an opaque cursor", () => {
    expect(resultListOptionsSchema.parse({})).toEqual({ limit: 100 });
    expect(resultListOptionsSchema.parse({ limit: 1, cursor: "op_1" })).toEqual({
      limit: 1,
      cursor: "op_1",
    });
    for (const options of [{ limit: 0 }, { limit: 101 }, { cursor: "a/b" }, { offset: 1 }])
      expect(resultListOptionsSchema.safeParse(options).success, JSON.stringify(options)).toBe(
        false,
      );
  });
  it("qualified process controls carry identity qualifiers, never a sandbox or naked pid", () => {
    const qualifiers = { generation: 1, processId: "p", attempt: 1 };
    expect(processQualifiersSchema.parse(qualifiers)).toEqual(qualifiers);
    expect(processQualifiersSchema.safeParse({ ...qualifiers, pid: 2 }).success).toBe(false);
    expect(processQualifiersSchema.safeParse({ ...qualifiers, sandboxId: "s" }).success).toBe(
      false,
    );
    expect(qualifiedProcessSignalSchema.parse({ ...qualifiers, signal: "SIGTERM" })).toEqual({
      ...qualifiers,
      signal: "SIGTERM",
    });
    for (const signal of ["SIGSTOP", "TERM", undefined])
      expect(qualifiedProcessSignalSchema.safeParse({ ...qualifiers, signal }).success).toBe(false);
  });
});
