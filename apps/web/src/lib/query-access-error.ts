const ACCESS_CODES = new Set([
  "UNAUTHORIZED",
  "FORBIDDEN",
  "NOT_FOUND",
  "sandbox.not_found",
  "sandbox.operation_not_found",
  "sandbox.template_not_found",
  "sandbox.host_not_found",
  "sandbox.pool_not_found",
  "credential.not_found",
  "credential.account_not_found",
  "credential.instance_not_found",
  "credential.lease_not_found",
  "credential.definition_not_found",
  "credential.login_session_not_found",
]);

/** Access failures must hide cached private content, even when a refetch retains data. */
export function isQueryAccessError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const code = "code" in error ? error.code : undefined;
  const status = "status" in error ? error.status : undefined;
  const data = "data" in error ? error.data : undefined;
  const dataCode = data && typeof data === "object" && "code" in data ? data.code : undefined;
  return (
    [code, dataCode].some((value) => typeof value === "string" && ACCESS_CODES.has(value)) ||
    status === 401 ||
    status === 403 ||
    status === 404
  );
}
