import { ORPCError } from "@orpc/server";
import type { Session } from "@wssp/auth";
import { isUserBanned } from "@wssp/auth/ban";

import {
  isSensitiveSessionTwoFactorPolicySatisfied,
  loadSensitiveSessionGateUser,
} from "./sensitive-session-two-factor-gate";

export type OwnerDeviceGateBody = {
  error: string;
  error_description: string;
};

export type OwnerDeviceGateFailure = {
  ok: false;
  status: 401 | 403;
  body: OwnerDeviceGateBody;
};

export type OwnerDeviceGateSuccess = {
  ok: true;
  session: Session;
};

/** Shared owner-device policy used by the Hono gate and owner-scoped oRPC procedures. */
export async function evaluateOwnerDeviceSession(
  session: Session | null | undefined,
): Promise<OwnerDeviceGateSuccess | OwnerDeviceGateFailure> {
  if (!session?.user) {
    return {
      ok: false,
      status: 401,
      body: { error: "access_denied", error_description: "Authentication required" },
    };
  }

  if (isUserBanned(session.user)) {
    return {
      ok: false,
      status: 403,
      body: { error: "access_denied", error_description: "Account is banned" },
    };
  }

  const gateUser = await loadSensitiveSessionGateUser(session.user.id);
  if (gateUser && isUserBanned(gateUser)) {
    return {
      ok: false,
      status: 403,
      body: { error: "access_denied", error_description: "Account is banned" },
    };
  }
  if (!gateUser?.emailVerified) {
    return {
      ok: false,
      status: 403,
      body: { error: "access_denied", error_description: "Email verification required" },
    };
  }

  if (!(await isSensitiveSessionTwoFactorPolicySatisfied(session.user.id))) {
    return {
      ok: false,
      status: 403,
      body: {
        error: "access_denied",
        error_description: "Two-factor authentication setup is required",
      },
    };
  }

  return { ok: true, session };
}

/** oRPC middleware helper: throws UNAUTHORIZED/FORBIDDEN matching the Hono gate. */
export async function assertOwnerDeviceSession(
  session: Session | null | undefined,
): Promise<Session> {
  const result = await evaluateOwnerDeviceSession(session);
  if (!result.ok) {
    throw new ORPCError(result.status === 401 ? "UNAUTHORIZED" : "FORBIDDEN", {
      message: result.body.error_description,
    });
  }
  return result.session;
}
