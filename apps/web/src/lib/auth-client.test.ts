import { describe, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  listeners: [] as (() => void)[],
  announce: vi.fn(),
  listen: vi.fn(),
}));

vi.mock("better-auth/react", () => ({
  createAuthClient: () => ({
    $store: {
      atoms: {
        $sessionSignal: {
          listen: (listener: () => void) => {
            fixture.listeners.push(listener);
            return () => {};
          },
        },
      },
    },
  }),
}));
vi.mock("better-auth/client/plugins", () => ({
  adminClient: () => ({}),
  inferAdditionalFields: () => ({}),
  twoFactorClient: () => ({}),
}));
vi.mock("@better-auth/oauth-provider/client", () => ({ oauthProviderClient: () => ({}) }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.test" } }));
vi.mock("@/i18n", () => ({ default: { language: "en-US" } }));
vi.mock("@/lib/document-identity", () => ({
  announceSessionChange: fixture.announce,
  listenForIdentityPeers: fixture.listen,
}));

await import("./auth-client");

describe("authClient", () => {
  it("announces every session change made in this tab to the other tabs", () => {
    // Better Auth flips its session signal after a sign-in, sign-up, 2FA
    // verification, sign-out, …: each is announced (lib/document-identity.ts)
    // before the flow navigates, whatever page it lands on.
    expect(fixture.listeners).toHaveLength(1);
    expect(fixture.announce).not.toHaveBeenCalled();
    fixture.listeners[0]?.();
    expect(fixture.announce).toHaveBeenCalledTimes(1);
  });

  it("listens to the other tabs from the moment a session can be read here", () => {
    // Before any watcher mounts (a public page reading the session for the
    // language menu): an announcement must still mark the identity unverified.
    expect(fixture.listen).toHaveBeenCalledTimes(1);
  });
});
