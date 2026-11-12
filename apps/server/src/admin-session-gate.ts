import { isAdminSessionAuthorized } from "@wssp/api/lib/sensitive-session-two-factor-gate";
import { auth, type Session } from "@wssp/auth";

type AdminSessionGateResult =
  | { ok: true; session: Session }
  | { ok: false; status: 404; error: string; errorDescription: string };

// Cookie-only OpenAPI reference gate; the parallel Better Auth admin API is disabled.
// The decision itself is the shared `isAdminSessionAuthorized`, the same one the
// oRPC admin procedures and the web `/admin` route guard use.
export async function requireVerifiedAdminSession(
  headers: Headers,
): Promise<AdminSessionGateResult> {
  let session: Session | null = null;
  try {
    // A machine bearer credential never authorizes browser administration.
    const cookieOnly = new Headers(headers);
    cookieOnly.delete("authorization");
    session = (await auth.api.getSession({ headers: cookieOnly })) as Session | null;
  } catch {
    session = null;
  }

  if (!session || !(await isAdminSessionAuthorized(session))) {
    return {
      ok: false,
      status: 404,
      error: "not_found",
      errorDescription: "Not found",
    };
  }

  return { ok: true, session };
}
