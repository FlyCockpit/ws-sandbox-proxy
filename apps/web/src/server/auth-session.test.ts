import { TWO_FACTOR_ENROLLMENT_GRACE_MS } from "@wssp/auth/two-factor-policy";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { twoFactorEnrollmentState } from "@/utils/two-factor-policy";

import {
  hasSessionTokenCookie,
  resolveProtectedRouteSessionFromAuth,
  resolveRouteSessionFromAuth,
  toRouteSession,
} from "./auth-session";

const getSessionMock = vi.fn();

const fullSession = {
  user: {
    id: "user-1",
    name: "Test User",
    email: "test@example.com",
    emailVerified: true,
    role: "admin",
    twoFactorEnabled: true,
    locale: "en-US",
    banned: false,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-02"),
  },
  session: {
    id: "session-1",
    token: "secret-session-token",
    userId: "user-1",
    expiresAt: new Date("2026-02-01"),
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-02"),
  },
};

describe("auth route session server helpers", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns a route-safe session shape without the session token", () => {
    expect(toRouteSession(fullSession)).toEqual({
      user: {
        id: "user-1",
        name: "Test User",
        email: "test@example.com",
        emailVerified: true,
        role: "admin",
        twoFactorEnabled: true,
        createdAt: new Date("2026-01-01").getTime(),
      },
    });
  });

  // `createdAt` crosses the createServerFn boundary, so it travels as epoch
  // milliseconds rather than a Date. The forced-2FA enrollment grace window is
  // measured from it; an unreadable value must become null, not NaN, so the
  // grace fails closed.
  it("normalizes an unreadable createdAt to null", () => {
    expect(
      toRouteSession({ ...fullSession, user: { ...fullSession.user, createdAt: "nope" } })?.user
        .createdAt,
    ).toBeNull();
    expect(
      toRouteSession({ ...fullSession, user: { ...fullSession.user, createdAt: undefined } })?.user
        .createdAt,
    ).toBeNull();
  });

  it("returns null for a confirmed anonymous request", () => {
    expect(toRouteSession(null)).toBeNull();
  });

  it("uses request headers when resolving the route session", async () => {
    const headers = new Headers({ cookie: "session=abc" });
    getSessionMock.mockResolvedValue(fullSession);

    await expect(resolveRouteSessionFromAuth(headers, getSessionMock)).resolves.toEqual({
      status: "resolved",
      session: {
        user: {
          id: "user-1",
          name: "Test User",
          email: "test@example.com",
          emailVerified: true,
          role: "admin",
          twoFactorEnabled: true,
          createdAt: new Date("2026-01-01").getTime(),
        },
      },
    });
    expect(getSessionMock).toHaveBeenCalledOnce();
    const call = getSessionMock.mock.calls[0]?.[0] as { headers: Headers } | undefined;
    expect(call?.headers.get("cookie")).toBe("session=abc");
  });

  it("resolves a confirmed anonymous request to a resolved null session", async () => {
    getSessionMock.mockResolvedValue(null);

    await expect(resolveRouteSessionFromAuth(new Headers(), getSessionMock)).resolves.toEqual({
      status: "resolved",
      session: null,
    });
  });

  it("does not convert auth transport failures into anonymous sessions", async () => {
    getSessionMock.mockRejectedValue(new Error("auth service unavailable"));

    await expect(resolveRouteSessionFromAuth(new Headers(), getSessionMock)).resolves.toEqual({
      status: "error",
    });
  });

  describe("protected (_auth) route session", () => {
    const notPending = vi.fn(async (_userId: string) => false);
    const unenrolledPastGrace = {
      ...fullSession,
      user: {
        ...fullSession.user,
        role: "user",
        twoFactorEnabled: false,
        createdAt: new Date(Date.now() - 2 * TWO_FACTOR_ENROLLMENT_GRACE_MS),
      },
    };

    it("returns the session and ONLY the client-readable force-2FA settings", async () => {
      getSessionMock.mockResolvedValue(fullSession);
      const loadSettings = vi.fn(async () => ({
        force2faPublicUsers: "true",
        force2faInternalUsers: "false",
        // Whatever else a loader hands over — admin-only settings included —
        // must never cross to the browser.
        signupEnabled: "false",
        someAdminOnlySecretSetting: "s3cr3t",
      }));

      const resolution = await resolveProtectedRouteSessionFromAuth(
        new Headers({ cookie: "better-auth.session_token=abc" }),
        getSessionMock,
        loadSettings,
        notPending,
      );

      expect(resolution).toEqual({
        status: "resolved",
        session: toRouteSession(fullSession),
        forcedTwoFactorSettings: { force2faPublicUsers: "true", force2faInternalUsers: "false" },
        passwordChangeRequired: false,
      });
      expect(loadSettings).toHaveBeenCalledOnce();
      expect(notPending).toHaveBeenCalledWith(fullSession.user.id);
    });

    it("keeps absent rows absent, exactly like settings.getAll", async () => {
      getSessionMock.mockResolvedValue(fullSession);
      await expect(
        resolveProtectedRouteSessionFromAuth(
          new Headers(),
          getSessionMock,
          async () => ({
            force2faPublicUsers: "true",
            force2faInternalUsers: undefined,
          }),
          notPending,
        ),
      ).resolves.toMatchObject({ forcedTwoFactorSettings: { force2faPublicUsers: "true" } });
    });

    // authenticatedProcedure semantics: no session, no settings — the read
    // never even runs for an anonymous request.
    it("never loads settings for an anonymous request", async () => {
      getSessionMock.mockResolvedValue(null);
      const loadSettings = vi.fn(async () => ({ force2faPublicUsers: "true" }));

      await expect(
        resolveProtectedRouteSessionFromAuth(
          new Headers(),
          getSessionMock,
          loadSettings,
          notPending,
        ),
      ).resolves.toEqual({ status: "resolved", session: null });
      expect(loadSettings).not.toHaveBeenCalled();
    });

    it("is an error, not a settings-less session, when the settings read fails", async () => {
      getSessionMock.mockResolvedValue(fullSession);
      await expect(
        resolveProtectedRouteSessionFromAuth(
          new Headers(),
          getSessionMock,
          async () => {
            throw new Error("db down");
          },
          notPending,
        ),
      ).resolves.toEqual({ status: "error" });
    });

    it("carries a pending admin-set password from the user row, and fails closed when that read fails", async () => {
      getSessionMock.mockResolvedValue(fullSession);
      await expect(
        resolveProtectedRouteSessionFromAuth(
          new Headers(),
          getSessionMock,
          async () => ({}),
          async () => true,
        ),
      ).resolves.toMatchObject({ status: "resolved", passwordChangeRequired: true });
      await expect(
        resolveProtectedRouteSessionFromAuth(
          new Headers(),
          getSessionMock,
          async () => ({}),
          async () => {
            throw new Error("db down");
          },
        ),
      ).resolves.toEqual({ status: "error" });
    });

    it("is an error when the session lookup fails, without reading settings", async () => {
      getSessionMock.mockRejectedValue(new Error("auth down"));
      const loadSettings = vi.fn(async () => ({}));
      await expect(
        resolveProtectedRouteSessionFromAuth(
          new Headers(),
          getSessionMock,
          loadSettings,
          notPending,
        ),
      ).resolves.toEqual({ status: "error" });
      expect(loadSettings).not.toHaveBeenCalled();
    });

    it("carries what the layout needs to keep an unenrolled user past grace blocked", async () => {
      getSessionMock.mockResolvedValue(unenrolledPastGrace);
      const resolution = await resolveProtectedRouteSessionFromAuth(
        new Headers(),
        getSessionMock,
        async () => ({ force2faPublicUsers: "true" }),
        notPending,
      );
      if (resolution.status !== "resolved" || !resolution.session) {
        throw new Error("expected a resolved session");
      }
      expect(
        twoFactorEnrollmentState(resolution.forcedTwoFactorSettings, resolution.session.user),
      ).toEqual({ status: "blocked" });
    });

    it("keeps an unenrolled admin past grace blocked when no setting row exists (default on)", async () => {
      getSessionMock.mockResolvedValue({
        ...unenrolledPastGrace,
        user: { ...unenrolledPastGrace.user, role: "admin" },
      });
      const resolution = await resolveProtectedRouteSessionFromAuth(
        new Headers(),
        getSessionMock,
        async () => ({}),
        notPending,
      );
      if (resolution.status !== "resolved" || !resolution.session) {
        throw new Error("expected a resolved session");
      }
      expect(resolution.forcedTwoFactorSettings).toEqual({});
      expect(
        twoFactorEnrollmentState(resolution.forcedTwoFactorSettings, resolution.session.user),
      ).toEqual({ status: "blocked" });
    });
  });

  it("recognises a non-empty Better Auth session cookie by exact name", () => {
    expect(hasSessionTokenCookie("better-auth.session_token=a")).toBe(true);
    expect(hasSessionTokenCookie("x=1; __Secure-better-auth.session_token=a")).toBe(true);
    // Empty value (a cleared cookie), look-alike names and other cookies: no.
    expect(hasSessionTokenCookie("better-auth.session_token=")).toBe(false);
    expect(hasSessionTokenCookie("better-auth.session_data=a")).toBe(false);
    expect(hasSessionTokenCookie("x-better-auth.session_token=a")).toBe(false);
    expect(hasSessionTokenCookie("x=1")).toBe(false);
    expect(hasSessionTokenCookie(null)).toBe(false);
  });
});
