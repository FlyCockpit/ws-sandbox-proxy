import { inspect } from "node:util";
import { ORPCError } from "@orpc/server";
import { publicOperationErrorCode, SDK_ERRORS } from "@wssp/sandbox-contracts";
import { describe, expect, it } from "vitest";
import {
  isTransientDatabaseOverload,
  rethrowSensitiveSandboxError,
  safeErrnoCode,
  safeErrorLog,
  safeOperationError,
} from "./sensitive-errors";

const sentinel = "synthetic-env-stdin-sensitive-3a";

describe("cold start disk refusal", () => {
  const cold = { kind: "RECONNECT_SANDBOX", launchMode: "COLD", state: "FAILED" };

  it("maps a failed cold reconnect's sandbox_not_found to fixed public text", () => {
    const error = safeOperationError("sandbox_not_found", sentinel, cold);
    expect(error).toEqual({
      code: "start_disk_missing",
      message:
        "This sandbox can't start: its host has no usable disk for it. Create a new sandbox.",
    });
    expect(publicOperationErrorCode(error.code)).toBe("start_disk_missing");
    // Public operation detail re-renders from the stored code alone.
    expect(safeOperationError(error.code)).toEqual(error);
    expect(inspect(error)).not.toContain(sentinel);
  });

  it("keeps other kinds, launch modes, outcomes and errors unchanged", () => {
    for (const operation of [
      undefined,
      { ...cold, kind: "STOP_SANDBOX" },
      { ...cold, launchMode: "WARM" },
      { ...cold, launchMode: "NEW_ROOT" },
      { ...cold, launchMode: null },
      { ...cold, state: "UNKNOWN_OUTCOME" },
      { ...cold, state: "SUCCEEDED" },
    ])
      expect(safeOperationError("sandbox_not_found", sentinel, operation)).toEqual({
        code: "sandbox_not_found",
        message: "Sandbox not found.",
      });
    expect(safeOperationError("state_conflict", sentinel, cold)).toEqual({
      code: "state_conflict",
      message: "Operation conflicts with current state.",
    });
    expect(safeOperationError("timeout", undefined, cold)).toEqual(safeOperationError("timeout"));
    expect(safeOperationError(sentinel, undefined, cold)).toEqual(safeOperationError(sentinel));
  });
});

describe("sensitive producer errors", () => {
  it("takes the HTTP status from the domain code's catalog row, not the outer code (B1-K-6)", () => {
    const caught = (error: unknown) => {
      try {
        rethrowSensitiveSandboxError(error);
      } catch (safe) {
        return safe;
      }
      throw new Error("expected a rethrow");
    };
    // A domain-coded 410 wrapped in a non-catalog outer code keeps 410.
    const wrapped = caught(new ORPCError("TEAPOT", { data: { code: "OPERATION_RESULT_EXPIRED" } }));
    expect(wrapped).toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      status: SDK_ERRORS.OPERATION_RESULT_EXPIRED[0],
      message: SDK_ERRORS.OPERATION_RESULT_EXPIRED[1],
      data: { code: "OPERATION_RESULT_EXPIRED" },
    });
    // A catalog outer code with a different catalog domain: the domain wins.
    const mismatched = caught(
      new ORPCError("CONFLICT", { status: 409, data: { code: "OPERATION_RESULT_QUOTA" } }),
    );
    expect(mismatched).toMatchObject({ code: "CONFLICT", status: 429 });
    // No domain code: the outer catalog code's own status.
    expect(caught(new ORPCError("NOT_FOUND"))).toMatchObject({
      status: SDK_ERRORS.NOT_FOUND[0],
    });
  });
  it("discards raw Prisma text, stack and nested sources", () => {
    const error = new Error(sentinel, {
      cause: { detail: Buffer.from(sentinel).toString("base64") },
    });
    error.stack = sentinel;
    let safe: unknown;
    try {
      rethrowSensitiveSandboxError(error);
    } catch (caught) {
      safe = caught;
    }
    expect(safe).toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      message: "An internal error occurred.",
    });
    expect(inspect(safe, { depth: 10 })).not.toContain(sentinel);
    expect(inspect(safe, { depth: 10 })).not.toContain(Buffer.from(sentinel).toString("base64"));
    expect(safe).not.toHaveProperty("cause", error);
  });
  it("reconstructs known domain errors rather than trusting an ORPCError message", () => {
    const raw = new ORPCError("CONFLICT", {
      message: sentinel,
      data: { code: "sandbox.idempotency_conflict", value: sentinel },
      cause: new Error(sentinel),
    });
    expect(() => rethrowSensitiveSandboxError(raw)).toThrow(
      "Idempotency key was used for different input.",
    );
    try {
      rethrowSensitiveSandboxError(raw);
    } catch (safe) {
      expect(safe).toMatchObject({
        code: "CONFLICT",
        data: { code: "sandbox.idempotency_conflict" },
      });
      expect(inspect(safe, { depth: 10 })).not.toContain(sentinel);
    }
  });
  it("does not accept inherited catalog names or arbitrary error names/codes", () => {
    expect(safeOperationError("toString")).toEqual({
      code: "internal",
      message: "Operation failed.",
    });
    expect(safeErrorLog(Object.assign(new Error(sentinel), { name: sentinel }))).toEqual({
      code: "unhandled_error",
      errorClass: "Error",
    });
    expect(safeErrorLog(new ORPCError(sentinel, { message: sentinel }))).toEqual({
      code: "unhandled_error",
      errorClass: "ORPCError",
    });
  });
  it("retains error classes and exact Prisma/PG codes without arbitrary values", () => {
    class PrismaClientKnownRequestError extends Error {}
    for (const code of ["P2028", "23505", "P2003"]) {
      const raw = Object.assign(
        new PrismaClientKnownRequestError(sentinel, { cause: new Error(sentinel) }),
        {
          code,
          name: sentinel,
          stack: sentinel,
          detail: sentinel,
          constructor: { name: sentinel },
        },
      );
      expect(safeErrorLog(raw, "operation_failed")).toEqual({
        code,
        errorClass: "PrismaClientKnownRequestError",
      });
      expect(inspect(safeErrorLog(raw), { depth: 10 })).not.toContain(sentinel);
    }
    for (const code of [sentinel, "P2028-secret", "23505-secret", "secret-P2003"]) {
      expect(
        safeErrorLog(Object.assign(new TypeError(sentinel), { code }), "operation_failed"),
      ).toEqual({
        code: "operation_failed",
        errorClass: "TypeError",
      });
    }
    expect(safeErrorLog(new ORPCError("CONFLICT", { message: sentinel }))).toEqual({
      code: "CONFLICT",
      errorClass: "ORPCError",
    });
    expect(
      safeErrorLog(
        new Proxy(
          {},
          {
            getPrototypeOf: () => {
              throw new Error(sentinel);
            },
          },
        ),
      ),
    ).toEqual({ code: "unhandled_error", errorClass: "UnknownError" });
  });

  it("retains only closed capability identifiers through sensitive transactions", () => {
    for (const capability of [
      "snapshot",
      "restore",
      "fork",
      "egress",
      "pause",
      "ingress",
      sentinel,
    ]) {
      try {
        rethrowSensitiveSandboxError(
          new ORPCError("BAD_REQUEST", {
            message: sentinel,
            data: { code: "UNSUPPORTED_CAPABILITY", capability, detail: sentinel },
            cause: new Error(sentinel),
          }),
        );
      } catch (safe) {
        expect(safe).toMatchObject({
          code: "BAD_REQUEST",
          message: "Capability is unsupported.",
          data: {
            code: "UNSUPPORTED_CAPABILITY",
            ...(capability === sentinel ? {} : { capability }),
          },
        });
        expect(inspect(safe, { depth: 10 })).not.toContain(sentinel);
      }
    }
  });

  it("keeps a tunnel refusal's capability and closed reason", () => {
    for (const reason of ["tunnel_no_host", "tunnel_host_unsupported", sentinel])
      try {
        rethrowSensitiveSandboxError(
          new ORPCError("BAD_REQUEST", {
            message: sentinel,
            data: { code: "UNSUPPORTED_CAPABILITY", capability: "tunnel", reason },
          }),
        );
      } catch (safe) {
        expect(safe).toMatchObject({
          data: {
            code: "UNSUPPORTED_CAPABILITY",
            capability: "tunnel",
            ...(reason === sentinel ? {} : { reason }),
          },
        });
        expect(inspect(safe, { depth: 10 })).not.toContain(sentinel);
      }
  });
});

it("passes only errno tokens through safeErrnoCode", () => {
  expect(safeErrnoCode(Object.assign(new Error("/private/x"), { code: "EACCES" }))).toBe("EACCES");
  for (const code of ["EACCES /private", "eacces", "E", "P2002", "Esecret", 42, undefined])
    expect(safeErrnoCode(Object.assign(new Error("x"), { code }))).toBeNull();
  expect(safeErrnoCode("EACCES")).toBeNull();
  expect(
    safeErrnoCode({
      get code() {
        throw new Error("boom");
      },
    }),
  ).toBeNull();
});

describe("transient database overload", () => {
  class PrismaClientKnownRequestError extends Error {}
  const caught = (error: unknown) => {
    try {
      rethrowSensitiveSandboxError(error);
    } catch (thrown) {
      return thrown as ORPCError<string, unknown>;
    }
    throw new Error("did not throw");
  };

  it.each(["P2028", "P2024"])(
    "%s (transaction expired or no connection in time) is a retryable SERVICE_UNAVAILABLE",
    (code) => {
      const raw = Object.assign(new PrismaClientKnownRequestError(sentinel), { code });
      expect(isTransientDatabaseOverload(raw)).toBe(true);
      const thrown = caught(raw);
      expect(thrown.code).toBe("SERVICE_UNAVAILABLE");
      expect(thrown.status).toBe(503);
      expect(thrown.message).toBe(SDK_ERRORS.SERVICE_UNAVAILABLE[1]);
      // The cause is values-free: class and code only, for the request log.
      expect(thrown.cause).toEqual({ errorClass: "PrismaClientKnownRequestError", code });
      expect(inspect(thrown, { depth: 10 })).not.toContain(sentinel);
    },
  );

  it("anything else stays an internal error that still names its class and code", () => {
    const unique = Object.assign(new PrismaClientKnownRequestError(sentinel), { code: "P2002" });
    expect(isTransientDatabaseOverload(unique)).toBe(false);
    expect(caught(unique)).toMatchObject({
      code: "INTERNAL_SERVER_ERROR",
      cause: { errorClass: "PrismaClientKnownRequestError", code: "P2002" },
    });
    // The same code on another class is not a Prisma transaction error.
    const lookalike = Object.assign(new TypeError(sentinel), { code: "P2028" });
    expect(isTransientDatabaseOverload(lookalike)).toBe(false);
    expect(caught(lookalike).code).toBe("INTERNAL_SERVER_ERROR");
  });
});
