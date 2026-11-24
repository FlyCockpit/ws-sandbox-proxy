import { BASE_ERROR_CODES } from "better-auth";
import { APIError, isAPIError } from "better-auth/api";

export const SIGN_UP_EMAIL_PATH = "/sign-up/email";

// The one body `/sign-up/email` ever answers with on success. No client reads
// the success body (the web form reads only `error`, and with
// `requireEmailVerification` there is never a session to hand back).
const NEUTRAL_SIGN_UP_RESPONSE = { token: null, user: null } as const;

// Requests (keyed by their dispatch `ctx.context`, which Better Auth keeps
// across the endpoint, its database hooks and `hooks.after`) in which a user
// row really was created.
const createdInRequest = new WeakSet<object>();

/** `databaseHooks.user.create.after`: this request really created a user. */
export function markUserCreatedInRequest(endpoint: { context?: object } | null | undefined): void {
  if (endpoint?.context) createdInRequest.add(endpoint.context);
}

type SignUpAfterHookContext = {
  context: object & { returned?: unknown };
  json: (body: typeof NEUTRAL_SIGN_UP_RESPONSE) => unknown;
};

/**
 * After-hook for `/sign-up/email` that makes the response independent of
 * whether the address already has an account.
 *
 * With `requireEmailVerification`, Better Auth answers a sign-up for a
 * registered address with a synthetic "pretend it worked" user. That user is
 * built without plugin defaults (the admin plugin's `role` is null instead of
 * "user"), so its body tells a registered address from a free one. Any future
 * plugin field would reopen that, so every success body becomes one fixed
 * shape instead of patching the synthetic user.
 *
 * Better Auth also returns that synthetic 200 *before* `createUser`, so while
 * sign-up is disabled the database hook's rejection (422
 * FAILED_TO_CREATE_USER) only ever reached free addresses. A 200 therefore
 * stands only if this request really created the user (sign-up open, an
 * `ADMIN_EMAILS` bootstrap or a valid pool invitation of a new address) or
 * sign-up is open; every other duplicate gets the same 422 a free address
 * gets. So a registered address reveals neither that it is registered nor
 * whether it is on the admin list. "Really created" is the mark the
 * user.create database hook leaves on the request: no user lookup here.
 * `signupEnabled` runs only for a request that created nothing, and must make
 * exactly the reads the database hook makes for a free address (invitation
 * preflight, then the setting: `signupAdmission`), so a duplicate costs what
 * a free address costs.
 *
 * Error responses are left alone: they are already address-independent.
 */
export async function neutralizeSignUpResponse(
  ctx: SignUpAfterHookContext,
  opts: { signupEnabled: () => Promise<boolean> },
) {
  const created = createdInRequest.delete(ctx.context);
  if (isAPIError(ctx.context.returned)) return;
  if (!created && !(await opts.signupEnabled())) {
    throw APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.FAILED_TO_CREATE_USER);
  }
  return ctx.json(NEUTRAL_SIGN_UP_RESPONSE);
}
