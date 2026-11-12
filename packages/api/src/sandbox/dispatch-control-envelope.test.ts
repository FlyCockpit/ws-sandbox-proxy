vi.mock("@wssp/env/server", () => ({
  env: {
    SANDBOX_REQUEST_HMAC_SECRET: "0123456789abcdef".repeat(4),
    BETTER_AUTH_URL: "http://localhost:3000",
  },
}));

import { describe, expect, it, vi } from "vitest";
import { encodeServerControlMessage } from "../../../../apps/server/src/sandbox-relay/protocol";
import receiptLimits from "../../../config/src/sandbox-receipt-limits.json";
import {
  buildCommandRunOperationDispatchMessage,
  commandRunDispatchBuildInputForEnqueueGuard,
  commandRunDispatchBuildInputFromOutboxPayload,
  commandRunDispatchFitsControlLimit,
  encodedCommandRunDispatchControlBytes,
} from "./dispatch-control-envelope";
import { createSandboxOutboxEvent, sandboxOutboxTransaction } from "./outbox";

vi.mock("@wssp/db", async () => {
  const { createMockPrisma } = await import("@wssp/api/test/mock-prisma");
  return { default: await createMockPrisma() };
});

import prisma from "@wssp/db";

const templateIdentity = {
  incusFingerprint: "sha256:" + "a".repeat(64),
  architecture: "x86_64",
  guestUid: 1234,
  guestGid: 2345,
  guestHome: "/home/declared",
  guestShell: "/bin/bash",
};

function fullCommandPayload(script: string, overrides: Record<string, unknown> = {}) {
  return {
    kind: "command.run",
    script,
    sandboxId: "sandbox-1",
    sandboxHostId: "host-1",
    generation: 1,
    dispatchAttempt: 0,
    operationId: "o".repeat(64),
    idempotencyKey: "k".repeat(128),
    incusName: `wssp-sbx-${"x".repeat(53)}`,
    timeoutMs: 120_000,
    ...templateIdentity,
    templateDigest: templateIdentity.incusFingerprint,
    ...overrides,
  };
}

function productionDispatchInput(
  payload: Record<string, unknown>,
  sandboxId: string,
  bodyHash: string,
) {
  return commandRunDispatchBuildInputFromOutboxPayload(payload, sandboxId, {
    sandboxOwnerId: "creator",
    attempt: 1,
    bodyHash,
    stdinSequence: 0,
  });
}

describe("command.run dispatch control envelope (C15-S1)", () => {
  it("enqueue guard frame is never smaller than production dispatch encode", () => {
    const payload = fullCommandPayload("echo hi");
    const bodyHash = "a".repeat(receiptLimits.bodyHashBytes);
    const production = buildCommandRunOperationDispatchMessage(
      productionDispatchInput(payload, "sandbox-1", bodyHash),
    );
    const guard = buildCommandRunOperationDispatchMessage(
      commandRunDispatchBuildInputForEnqueueGuard(payload, "sandbox-1"),
    );
    expect(
      encodedCommandRunDispatchControlBytes(
        commandRunDispatchBuildInputForEnqueueGuard(payload, "sandbox-1"),
      ),
    ).toBeGreaterThanOrEqual(new TextEncoder().encode(JSON.stringify(production)).byteLength);
    expect(() => encodeServerControlMessage(production, "1.0")).not.toThrow();
    expect(JSON.stringify(guard)).toEqual(expect.stringContaining('"recursive":false'));
    expect(JSON.stringify(guard)).toEqual(expect.stringContaining('"stdinSequence":2147483647'));
  });

  it.each([undefined, false, true])(
    "sizes all mutable Int32 fields at max with hasStdin=%s",
    (hasStdin) => {
      const input = commandRunDispatchBuildInputForEnqueueGuard(
        fullCommandPayload("true", { hasStdin }),
        "sandbox-1",
      );
      expect(input).toMatchObject({
        attempt: 2147483647,
        generation: 2147483647,
        stdinSequence: 2147483647,
      });
    },
  );

  it("reserves absent identity widths without changing the wire message", () => {
    const payload = fullCommandPayload("true", {
      incusName: undefined,
      guestUid: undefined,
      guestGid: undefined,
      guestHome: undefined,
      guestShell: undefined,
    });
    const original = JSON.stringify(payload);
    const guard = commandRunDispatchBuildInputForEnqueueGuard(payload, "sandbox-1");
    expect(guard).toMatchObject({
      guestUid: receiptLimits.guestIdMax,
      guestGid: receiptLimits.guestIdMax,
    });
    expect(guard.guestHome!.length).toBe(receiptLimits.guestPathBytes);
    expect(guard.guestShell!.length).toBe(receiptLimits.guestPathBytes);
    expect(guard.incusName!.length).toBe(receiptLimits.identityBytes);
    const wire = JSON.parse(
      JSON.stringify(
        buildCommandRunOperationDispatchMessage(
          productionDispatchInput(payload, "sandbox-1", "a".repeat(64)),
        ),
      ),
    );
    for (const field of ["incusName", "guestUid", "guestGid", "guestHome", "guestShell"]) {
      expect(wire).not.toHaveProperty(field);
    }
    expect(JSON.stringify(payload)).toBe(original);
  });

  it("codex counterexample: guard rejects or production encodes", () => {
    const payload = fullCommandPayload("true", {
      architecture: "x".repeat(500),
      guestHome: `/${"x".repeat(64296)}`,
      operationId: "o".repeat(24),
      idempotencyKey: "k".repeat(128),
      guestUid: 1000,
      guestGid: 1000,
    });
    const bodyHash = "a".repeat(receiptLimits.bodyHashBytes);
    const fits = commandRunDispatchFitsControlLimit(payload, "sandbox-1");
    const production = buildCommandRunOperationDispatchMessage(
      productionDispatchInput(payload, "sandbox-1", bodyHash),
    );
    if (fits) {
      expect(() => encodeServerControlMessage(production, "1.0")).not.toThrow();
    } else {
      expect(() => encodeServerControlMessage(production, "1.0")).toThrow(/64 KiB/);
    }
  });

  it("accepts at stored-template boundary and rejects one more guestHome byte", () => {
    let guestHome = "/home/user";
    let low = 0;
    let high = 80_000;
    let fitsLen = 0;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      guestHome = `/home/${"x".repeat(mid)}`;
      const payload = fullCommandPayload("true", { guestHome });
      if (commandRunDispatchFitsControlLimit(payload, "sandbox-1")) {
        fitsLen = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }
    expect(fitsLen).toBeGreaterThan(0);
    const atLimit = fullCommandPayload("true", { guestHome: `/home/${"x".repeat(fitsLen)}` });
    expect(commandRunDispatchFitsControlLimit(atLimit, "sandbox-1")).toBe(true);
    const bodyHash = "a".repeat(receiptLimits.bodyHashBytes);
    expect(() =>
      encodeServerControlMessage(
        buildCommandRunOperationDispatchMessage(
          productionDispatchInput(atLimit, "sandbox-1", bodyHash),
        ),
        "1.0",
      ),
    ).not.toThrow();
    const over = fullCommandPayload("true", { guestHome: `/home/${"x".repeat(fitsLen + 1)}` });
    expect(commandRunDispatchFitsControlLimit(over, "sandbox-1")).toBe(false);
  });

  it("createSandboxOutboxEvent rejects one byte past the boundary", async () => {
    vi.mocked(prisma.sandbox.findFirst).mockResolvedValue({
      template: "revision/" + "template-1",
      sandboxHostId: "host-1",
    } as never);
    vi.mocked(prisma.sandboxPlacement.findFirst).mockResolvedValue({
      ...templateIdentity,
      artifact: templateIdentity.incusFingerprint,
    } as never);
    vi.mocked(prisma.$transaction).mockImplementation(async (fn) =>
      (fn as (tx: typeof prisma) => Promise<unknown>)(prisma),
    );

    let low = 0;
    let high = 80_000;
    let fits = 0;
    while (low <= high) {
      const mid = Math.floor((low + high) / 2);
      if (commandRunDispatchFitsControlLimit(fullCommandPayload("s".repeat(mid)), "sandbox-1")) {
        fits = mid;
        low = mid + 1;
      } else {
        high = mid - 1;
      }
    }

    await sandboxOutboxTransaction((tx) =>
      createSandboxOutboxEvent(tx, {
        userId: "user-1",
        aggregateId: "sandbox-1",
        eventType: "sandbox.command_requested",
        payload: fullCommandPayload("s".repeat(fits)),
      }),
    );
    await expect(
      sandboxOutboxTransaction((tx) =>
        createSandboxOutboxEvent(tx, {
          userId: "user-1",
          aggregateId: "sandbox-1",
          eventType: "sandbox.command_requested",
          payload: fullCommandPayload("s".repeat(fits + 1)),
        }),
      ),
    ).rejects.toThrow("Encoded command dispatch exceeds 64 KiB");
  });
});

describe("template-build step fields (plan template-builds §3.1)", () => {
  const base = {
    operationId: "op-1",
    idempotencyKey: "tb:b1:run:0:0",
    generation: 1,
    timeoutMs: 1000,
    ...templateIdentity,
  };
  const dispatch = {
    sandboxOwnerId: "owner",
    attempt: 1,
    bodyHash: "f".repeat(64),
    stdinSequence: 0,
  };
  const copy = {
    contextPath: "/var/tmp/wssp-build/b1/context.tar",
    sha256: "c".repeat(64),
    src: ["."],
    dest: "/app/",
    owner: "user" as const,
  };

  it("carries runAs and buildCopy from the durable payload onto the frame", () => {
    const root = buildCommandRunOperationDispatchMessage(
      commandRunDispatchBuildInputFromOutboxPayload(
        { ...base, script: "id -u", runAs: "root" },
        "sbx-1",
        dispatch,
      ),
    );
    expect(root).toMatchObject({ script: "id -u", runAs: "root" });
    expect(root).not.toHaveProperty("buildCopy");
    const copied = buildCommandRunOperationDispatchMessage(
      commandRunDispatchBuildInputFromOutboxPayload(
        { ...base, buildCopy: copy },
        "sbx-1",
        dispatch,
      ),
    );
    expect(copied.buildCopy).toEqual(copy);
    expect(copied).not.toHaveProperty("script");
    expect(copied).not.toHaveProperty("runAs");
    const plain = buildCommandRunOperationDispatchMessage(
      commandRunDispatchBuildInputFromOutboxPayload({ ...base, script: "id" }, "sbx-1", dispatch),
    );
    expect(plain).not.toHaveProperty("runAs");
    expect(plain).not.toHaveProperty("buildCopy");
  });

  it("refuses a malformed stored build field instead of dropping it", () => {
    expect(() =>
      commandRunDispatchBuildInputFromOutboxPayload(
        { ...base, script: "id", runAs: "admin" },
        "sbx-1",
        dispatch,
      ),
    ).toThrow();
    expect(() =>
      commandRunDispatchBuildInputFromOutboxPayload(
        { ...base, buildCopy: { ...copy, contextPath: "/tmp/x" } },
        "sbx-1",
        dispatch,
      ),
    ).toThrow();
  });
});
