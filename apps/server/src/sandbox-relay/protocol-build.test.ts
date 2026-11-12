import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildContextPath,
  buildIdOfContextPath,
  dispatchImageV11Schema,
  imageCapabilitiesV11Schema,
  UPSTREAM_DISK_MAX_BYTES,
  UPSTREAM_IMAGE_BASE_URL,
  UPSTREAM_META_MAX_BYTES,
  validUpstreamImagePath,
} from "@wssp/sandbox-contracts";
import { expect, it } from "vitest";
import { encodeServerControlMessage, type ServerControlMessage } from "./protocol";

// Shared with `crates/sandbox-protocol/tests/build_fields.rs` (D1: root only in build VMs).
const fixture = JSON.parse(
  readFileSync(
    join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../../crates/sandbox-protocol/fixtures/control_build.json",
    ),
    "utf8",
  ),
) as {
  server: ServerControlMessage[];
  rejectedServer: ServerControlMessage[];
  capabilities: unknown[];
  rejectedCapabilities: unknown[];
  upstreamImage: { valid: unknown[]; rejected: unknown[] };
};

it("shares the build dispatch fixture with Rust: valid frames encode, misplaced fields are refused", () => {
  for (const message of fixture.server)
    expect(JSON.parse(encodeServerControlMessage(message, "1.0"))).toEqual(message);
  for (const message of fixture.rejectedServer)
    expect(() => encodeServerControlMessage(message, "1.0"), JSON.stringify(message)).toThrow();
});

it("refuses every build field outside its one dispatch kind", () => {
  const [, run, copy] = fixture.server as Array<Record<string, unknown>>;
  const base = {
    type: "operation.dispatch" as const,
    sandboxOwnerId: "owner",
    operationId: "op",
    sandboxId: "sbx",
    idempotencyKey: "k",
    generation: 1,
    attempt: 1,
  };
  for (const kind of ["sandbox.stop", "sandbox.kill", "file.put", "file.get", "process.signal"])
    for (const extra of [
      { build: { buildId: "build-1" } },
      { runAs: run?.runAs },
      { buildCopy: copy?.buildCopy },
    ])
      expect(() =>
        encodeServerControlMessage({ ...base, kind, ...extra } as ServerControlMessage, "1.0"),
      ).toThrow();
});

it("advertises build capabilities only on capture-capable daemons", () => {
  for (const caps of fixture.capabilities)
    expect(imageCapabilitiesV11Schema.parse(caps)).toEqual(caps);
  for (const caps of fixture.rejectedCapabilities)
    expect(imageCapabilitiesV11Schema.safeParse(caps).success, JSON.stringify(caps)).toBe(false);
});

it("names one fixed context path per build", () => {
  expect(buildContextPath("build-1")).toBe("/var/tmp/wssp-build/build-1/context.tar");
  expect(buildContextPath("../x")).toBeNull();
  expect(buildIdOfContextPath("/var/tmp/wssp-build/build-1/context.tar")).toBe("build-1");
  for (const bad of [
    "/var/tmp/wssp-build/context.tar",
    "/var/tmp/wssp-build/a/b/context.tar",
    "/var/tmp/wssp-build/../context.tar",
    "/var/tmp/wssp-buildx/a/context.tar",
  ])
    expect(buildIdOfContextPath(bad), bad).toBeNull();
});

it("shares the upstream image bodies with Rust: valid plans parse, malformed ones are refused", () => {
  for (const body of fixture.upstreamImage.valid)
    expect(dispatchImageV11Schema.parse(body)).toEqual(body);
  for (const body of fixture.upstreamImage.rejected)
    expect(dispatchImageV11Schema.safeParse(body).success, JSON.stringify(body)).toBe(false);
  expect(UPSTREAM_IMAGE_BASE_URL).toBe("https://images.linuxcontainers.org/");
  expect(UPSTREAM_META_MAX_BYTES).toBe(2 ** 20);
  expect(UPSTREAM_DISK_MAX_BYTES).toBe(2 ** 32);
  expect(
    validUpstreamImagePath("images/ubuntu/resolute/amd64/cloud/20261105_07:42/disk.qcow2"),
  ).toBe(true);
  for (const bad of ["images/../disk.qcow2", "images//x", "images/x?y", "x/images/a", "images/"])
    expect(validUpstreamImagePath(bad), bad).toBe(false);
});

it("encodes an upstream plan only on a create whose build carries bootstrap", () => {
  const upstream = fixture.server[4] as Record<string, unknown>;
  const { build: _build, ...withoutBuild } = upstream;
  for (const message of [
    withoutBuild,
    { ...upstream, build: { buildId: "build-1" } },
    { ...upstream, kind: "sandbox.reconnect" },
  ])
    expect(() => encodeServerControlMessage(message as ServerControlMessage, "1.0")).toThrow();
});
