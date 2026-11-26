// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The security settings page's 2FA enrollment (routes/$lang/_app/_auth/
 * settings/security.tsx): every step past the Enable button has a Cancel
 * that returns to it with nothing kept, and is held while a request runs.
 */
const fx = vi.hoisted(() => ({ enable: vi.fn(), verifyTotp: vi.fn(), disable: vi.fn() }));

vi.mock("@tanstack/react-router", async (importOriginal) => ({
  lazyRouteComponent: (await importOriginal<typeof import("@tanstack/react-router")>())
    .lazyRouteComponent,
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ lang: "en-US" }),
    useRouteContext: () => ({ session: { user: { twoFactorEnabled: false } } }),
  }),
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: { canChangePassword: false }, isPending: false, isError: false }),
}));
vi.mock("@/lib/auth-client", () => ({
  authClient: {
    twoFactor: { enable: fx.enable, verifyTotp: fx.verifyTotp, disable: fx.disable },
  },
}));
vi.mock("@/utils/orpc", () => ({
  orpc: { auth: { passwordCapabilities: { queryOptions: () => ({}) } } },
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: () => "friendly",
  isRateLimit: (error: { status?: number } | null) => error?.status === 429,
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@/components/settings/account-settings-layout", () => ({
  AccountSettingsLayout: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}));
vi.mock("@/components/settings/change-password-card", () => ({ ChangePasswordCard: () => null }));
vi.mock("@/components/two-factor-setup-details", () => ({ TwoFactorSetupDetails: () => null }));

type Page = (() => ReactNode) & { preload?: () => Promise<void> };
const mod = (await import("@/routes/$lang/_app/_auth/settings/security")) as unknown as {
  Route: { options: { component: Page } };
};
await mod.Route.options.component.preload?.();
const SecurityPage = mod.Route.options.component;

beforeEach(() => {
  fx.enable.mockReset().mockResolvedValue({
    data: { method: "totp", totpURI: "otpauth://totp/x?secret=ABC", backupCodes: ["a"] },
  });
  fx.verifyTotp.mockReset();
});
afterEach(() => cleanup());

const button = (name: string) => screen.getByRole("button", { name });
const enable = () => button("settings:security.enable2FA");

async function toSetupStep() {
  render(<SecurityPage />);
  fireEvent.click(enable());
  fireEvent.change(screen.getByLabelText("auth:fields.password"), { target: { value: "pw" } });
  fireEvent.click(button("auth:twoFactor.continue"));
  return screen.findByRole("button", { name: "settings:security.savedBackupCodes" });
}

describe("security settings 2FA Cancel", () => {
  it("cancels the password step and forgets the password", () => {
    render(<SecurityPage />);
    fireEvent.click(enable());
    fireEvent.change(screen.getByLabelText("auth:fields.password"), { target: { value: "typed" } });
    fireEvent.click(button("common:actions.cancel"));
    fireEvent.click(enable());
    expect((screen.getByLabelText("auth:fields.password") as HTMLInputElement).value).toBe("");
  });

  it("cancels the QR step back to the Enable button", async () => {
    await toSetupStep();
    fireEvent.click(button("common:actions.cancel"));
    expect(enable()).toBeTruthy();
    expect(screen.queryByRole("button", { name: "settings:security.savedBackupCodes" })).toBeNull();
  });

  it("cancels the verify step, and enabling again asks for the password again", async () => {
    fireEvent.click(await toSetupStep());
    const code = screen.getByLabelText("auth:fields.verificationCode") as HTMLInputElement;
    fireEvent.change(code, { target: { value: "123" } });
    fireEvent.click(button("common:actions.cancel"));

    expect(screen.queryByLabelText("auth:fields.verificationCode")).toBeNull();
    fireEvent.click(enable());
    expect((screen.getByLabelText("auth:fields.password") as HTMLInputElement).value).toBe("");
    expect(fx.verifyTotp).not.toHaveBeenCalled();
  });

  it("holds Cancel while the code is being checked", async () => {
    fx.verifyTotp.mockReturnValue(new Promise(() => {}));
    fireEvent.click(await toSetupStep());
    fireEvent.change(screen.getByLabelText("auth:fields.verificationCode"), {
      target: { value: "123456" },
    });
    fireEvent.click(button("settings:security.verifyAndEnable"));
    expect(
      (await screen.findByRole("button", { name: "common:actions.cancel" })).hasAttribute(
        "disabled",
      ),
    ).toBe(true);
  });
});
