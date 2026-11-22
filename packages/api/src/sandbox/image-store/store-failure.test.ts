import { IMAGE_FAILURE_CAUSES } from "@wssp/sandbox-contracts";
import { expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const {
  cancelReasonOf,
  imageFailureDetail,
  SERVER_UPLOAD_DETAILS,
  STORE_DETAIL_PATTERN,
  STORE_RULE_DETAILS,
  transferEndDetail,
} = await import("./store-failure");

/** The exact detail of every cause (a status or refusal where it has one). */
const EXPECTED: Record<(typeof IMAGE_FAILURE_CAUSES)[number], string> = {
  timeout: "upload_timeout",
  stalled: "upload_stalled",
  reset: "upload_reset",
  connect: "upload_connect",
  tls: "upload_tls",
  http_status: "upload_http_503",
  url_expired: "upload_url_expired",
  local_io: "upload_local_io",
  export: "upload_export",
  no_grant: "upload_no_grant",
  refused: "upload_refused.image_quota_exceeded",
  protocol: "upload_protocol",
};

it.each(IMAGE_FAILURE_CAUSES)("maps cause %s to its exact code-shaped detail", (cause) => {
  const detail = imageFailureDetail({
    cause,
    ...(cause === "http_status" || cause === "url_expired" ? { httpStatus: 503 } : {}),
    ...(cause === "refused" ? { refusal: "image_quota_exceeded" } : {}),
  });
  expect(detail).toBe(EXPECTED[cause]);
  expect(detail).toMatch(STORE_DETAIL_PATTERN);
});

it("keeps the status and the server's refusal in the detail", () => {
  expect(imageFailureDetail({ cause: "http_status", httpStatus: 503 })).toBe("upload_http_503");
  expect(imageFailureDetail({ cause: "url_expired", httpStatus: 403 })).toBe("upload_url_expired");
  expect(imageFailureDetail({ cause: "stalled" })).toBe("upload_stalled");
  expect(imageFailureDetail({ cause: "refused", refusal: "image_quota_exceeded" })).toBe(
    "upload_refused.image_quota_exceeded",
  );
  // A 64-byte refusal is cut, never rejected by the CHECK.
  const long = imageFailureDetail({ cause: "refused", refusal: "a".repeat(64) });
  expect(long).toMatch(STORE_DETAIL_PATTERN);
  expect(long).toHaveLength(64);
});

it("maps ended transfers and the finalizer's rules to code-shaped details", () => {
  expect(transferEndDetail("upload_stalled")).toBe("upload_stalled");
  expect(transferEndDetail("expired")).toBe("upload_expired");
  expect(transferEndDetail("operation_ended")).toBe("upload_operation_ended");
  expect(transferEndDetail(null)).toBe("upload_failed");
  expect(transferEndDetail("Not A Code!")).toBe("upload_failed");
  // Server-side ends keep their own name.
  expect(transferEndDetail("store_complete_failed")).toBe("store_complete_failed");
  for (const detail of [...STORE_RULE_DETAILS, ...SERVER_UPLOAD_DETAILS])
    expect(detail).toMatch(STORE_DETAIL_PATTERN);
});

it("turns a detail into a cancel reason the daemon accepts", () => {
  expect(cancelReasonOf("upload_stalled")).toBe("upload_stalled");
  expect(cancelReasonOf("upload_http_503")).toBe("upload_http____");
  for (const detail of [...STORE_RULE_DETAILS, ...SERVER_UPLOAD_DETAILS])
    expect(cancelReasonOf(detail)).toMatch(/^[a-z_.]{1,64}$/);
});
