// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { TWO_FACTOR_ENROLLMENT_GRACE_MS } from "@wssp/auth/two-factor-policy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth-client", () => ({
  authClient: { twoFactor: { enable: vi.fn(), verifyTotp: vi.fn() } },
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

import type {
  ForcedTwoFactorSettings,
  TwoFactorPolicySessionUser,
} from "@/utils/two-factor-policy";

import { ForcedTwoFactorGate } from "./forced-two-factor-gate";

const now = Date.now();
const user = (
  overrides: Partial<{ role: string; twoFactorEnabled: boolean; createdAt: number }>,
) => ({
  role: "user",
  twoFactorEnabled: false,
  createdAt: now - 2 * TWO_FACTOR_ENROLLMENT_GRACE_MS,
  ...overrides,
});

let queryClient: QueryClient;
const fetchSpy = vi.fn();

beforeEach(() => {
  queryClient = new QueryClient();
  fetchSpy.mockReset();
  vi.stubGlobal("fetch", fetchSpy);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderGate(
  sessionUser: TwoFactorPolicySessionUser,
  forcedTwoFactorSettings: ForcedTwoFactorSettings,
) {
  return render(
    <QueryClientProvider client={queryClient}>
      <ForcedTwoFactorGate user={sessionUser} forcedTwoFactorSettings={forcedTwoFactorSettings}>
        <p>protected page</p>
      </ForcedTwoFactorGate>
    </QueryClientProvider>,
  );
}

describe("forced-2FA gate (_auth layout)", () => {
  // The waterfall regression: the layout used to render a skeleton until its
  // own `settings.getAll` request resolved, so the page (and its queries)
  // mounted a round trip late. The gate now decides from route data on the
  // first render and starts no request of its own.
  it("renders the page on the first render with no settings request pending", () => {
    renderGate(user({ twoFactorEnabled: true }), {});

    expect(screen.getByText("protected page")).toBeTruthy();
    expect(queryClient.getQueryCache().getAll()).toHaveLength(0);
    expect(queryClient.isFetching()).toBe(0);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("renders the page for a required user still inside the enrollment grace", () => {
    renderGate(user({ createdAt: now - 60_000 }), { force2faPublicUsers: "true" });
    expect(screen.getByText("protected page")).toBeTruthy();
  });

  it("renders the enrollment takeover, never the page, for a required user past grace", () => {
    renderGate(user({}), { force2faPublicUsers: "true" });

    expect(screen.getByText("twoFactor.requiredTitle")).toBeTruthy();
    expect(screen.queryByText("protected page")).toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("blocks an unenrolled admin past grace when no setting row exists (default on)", () => {
    renderGate(user({ role: "admin" }), {});

    expect(screen.getByText("twoFactor.requiredTitle")).toBeTruthy();
    expect(screen.queryByText("protected page")).toBeNull();
  });

  it("fails closed for an undated session (no grace)", () => {
    renderGate({ role: "admin", twoFactorEnabled: false, createdAt: null }, {});
    expect(screen.queryByText("protected page")).toBeNull();
  });

  it("lets the page through when the policy is off for the user's role", () => {
    renderGate(user({}), { force2faPublicUsers: "false" });
    expect(screen.getByText("protected page")).toBeTruthy();
  });
});
