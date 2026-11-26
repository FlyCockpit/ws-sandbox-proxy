// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { TWO_FACTOR_ENROLLMENT_GRACE_MS } from "@wssp/auth/two-factor-policy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({ enable: vi.fn(), verifyTotp: vi.fn() }));
vi.mock("@/lib/auth-client", () => ({
  authClient: { twoFactor: { enable: auth.enable, verifyTotp: auth.verifyTotp } },
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: () => "friendly",
  isRateLimit: (error: { status?: number } | null) => error?.status === 429,
}));
vi.mock("@/components/two-factor-setup-details", () => ({ TwoFactorSetupDetails: () => null }));

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
  auth.enable.mockReset();
  auth.verifyTotp.mockReset();
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
    // The takeover replaces the page, so its title is the page's one h1.
    const headings = document.querySelectorAll("h1");
    expect([...headings].map((h) => h.textContent)).toEqual(["twoFactor.requiredTitle"]);
    expect(document.querySelector('[role="heading"]')).toBeNull();
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

describe("enrollment takeover errors sit under their field", () => {
  async function toPasswordStep() {
    renderGate(user({}), { force2faPublicUsers: "true" });
    fireEvent.click(screen.getByRole("button", { name: "twoFactor.setUp" }));
    return screen.getByLabelText("fields.password") as HTMLInputElement;
  }

  it("says the password was wrong, on the field, and focuses it", async () => {
    auth.enable.mockResolvedValue({ error: { code: "INVALID_PASSWORD", status: 400 } });
    const password = await toPasswordStep();
    fireEvent.change(password, { target: { value: "not-it" } });
    fireEvent.click(screen.getByRole("button", { name: "twoFactor.continue" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("auth:errors.wrongPassword");
    expect(password.getAttribute("aria-invalid")).toBe("true");
    expect(password.getAttribute("aria-describedby")).toBe(alert.id);
    expect(document.activeElement).toBe(password);

    // Editing clears it.
    fireEvent.change(password, { target: { value: "not-it-2" } });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(password.getAttribute("aria-invalid")).toBeNull();
  });

  it("keeps the setup fallback for other failures", async () => {
    auth.enable.mockResolvedValue({ error: { code: "SOMETHING", status: 500 } });
    const password = await toPasswordStep();
    fireEvent.change(password, { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "twoFactor.continue" }));
    expect((await screen.findByRole("alert")).textContent).toBe(
      "auth:twoFactor.couldNotStartSetup",
    );
  });

  it("puts a refused authenticator code under the code field", async () => {
    auth.enable.mockResolvedValue({
      data: { method: "totp", totpURI: "otpauth://totp/x?secret=ABC", backupCodes: [] },
    });
    auth.verifyTotp.mockResolvedValue({ error: { code: "INVALID_CODE", status: 401 } });
    const password = await toPasswordStep();
    fireEvent.change(password, { target: { value: "pw" } });
    fireEvent.click(screen.getByRole("button", { name: "twoFactor.continue" }));
    const code = (await screen.findByLabelText("fields.verificationCode")) as HTMLInputElement;
    fireEvent.change(code, { target: { value: "123456" } });
    fireEvent.click(screen.getByRole("button", { name: "twoFactor.verifyAndEnable" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("auth:errors.invalidTotp");
    expect(code.getAttribute("aria-invalid")).toBe("true");
    expect(document.activeElement).toBe(code);
  });
});
