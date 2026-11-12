import { ORPCError } from "@orpc/server";
import { SDK_ERRORS, type SdkErrorCode } from "@wssp/sandbox-contracts";

/**
 * Stable `credential.*` / `definition.*` domain codes. The one table is the public `/v1` catalog (`SDK_ERRORS`); messages are
 * constant and never name a value.
 */
export type CredentialErrorCode = Extract<
  SdkErrorCode,
  `credential.${string}` | `definition.${string}`
>;

const ORPC_CODE_BY_STATUS: Record<number, string> = {
  400: "BAD_REQUEST",
  404: "NOT_FOUND",
  409: "CONFLICT",
};

export function credentialError(
  code: CredentialErrorCode,
  extra: Record<string, unknown> = {},
): ORPCError<string, unknown> {
  const [status, message] = SDK_ERRORS[code];
  return new ORPCError(ORPC_CODE_BY_STATUS[status] ?? "BAD_REQUEST", {
    message,
    data: { ...extra, code },
  });
}
