import { ORPCError } from "@orpc/server";
import { expect, it, vi } from "vitest";

vi.mock("@wssp/env/server", () => ({ env: { CAPACITY_RETRY_AFTER_SECONDS: 5 } }));

import { mcpError, mcpQuotaResponse } from "./errors";

it("retains retryable capacity reasons and emits delay only for retryable refusals", () => {
  const error = (retryable: boolean) =>
    new ORPCError("CONFLICT", {
      data: { code: "sandbox.host_capacity", reason: "ram", retryable },
    });
  expect(mcpError(error(true), "stable")).toMatchObject({
    isError: true,
    structuredContent: {
      error: {
        code: "sandbox.host_capacity",
        reason: "ram",
        retryable: true,
        retryAfterSeconds: 5,
        idempotencyKey: "stable",
      },
    },
  });
  expect(mcpError(error(false)).structuredContent.error).not.toHaveProperty("retryAfterSeconds");
});
it("preserves a typed nested host file reason and refuses arbitrary internal reasons", () => {
  expect(
    mcpError(
      new ORPCError("BAD_REQUEST", {
        data: { code: "host.file_error", data: { reason: "path_denied" } },
      }),
    ),
  ).toMatchObject({
    structuredContent: { error: { code: "host.file_error", reason: "path_denied" } },
  });
  const response = mcpError(
    new ORPCError("INTERNAL_SERVER_ERROR", {
      message: "private-query",
      data: { reason: "private_internal_identifier" },
    }),
  );
  expect(JSON.stringify(response)).not.toMatch(/private-query|private_internal_identifier/);
});
it("keeps HTTP and structured rate refusal delays consistent and fails infrastructure errors closed", async () => {
  const response = mcpQuotaResponse(
    new ORPCError("TOO_MANY_REQUESTS", { data: { retryAfterSeconds: 7 } }),
  );
  expect(response.status).toBe(429);
  expect(response.headers.get("retry-after")).toBe("7");
  expect(await response.json()).toMatchObject({
    error: { data: { retryable: true, retryAfterSeconds: 7 } },
  });
  expect(mcpQuotaResponse(new Error("private")).status).toBe(503);
});
