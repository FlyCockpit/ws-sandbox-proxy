// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({
  verifyTotp: vi.fn(),
  verifyOtp: vi.fn(),
  verifyBackupCode: vi.fn(),
  sendOtp: vi.fn(),
  transport: vi.fn(),
  toast: { success: vi.fn(), error: vi.fn() },
}));
vi.mock("@/lib/auth-client", () => ({
  authClient: {
    twoFactor: {
      verifyTotp: auth.verifyTotp,
      verifyOtp: auth.verifyOtp,
      verifyBackupCode: auth.verifyBackupCode,
      sendOtp: auth.sendOtp,
    },
  },
}));
vi.mock("@/utils/orpc", () => ({
  orpc: { auth: { verifyEmailTransport: { call: auth.transport } } },
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: auth.toast }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: () => "Too many attempts. Wait a minute.",
  isRateLimit: (error: { status?: number } | null) => error?.status === 429,
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

import { codeIsComplete, normalizeBackupCode, TwoFactorChallenge } from "./two-factor-challenge";

const onVerified = vi.fn();
const onBack = vi.fn();

beforeEach(() => {
  for (const fn of [auth.verifyTotp, auth.verifyOtp, auth.verifyBackupCode, auth.sendOtp])
    fn.mockReset();
  auth.transport.mockReset().mockResolvedValue({ ok: true });
  onVerified.mockReset();
  onBack.mockReset();
});
afterEach(() => cleanup());

function mount(emailEnabled = true) {
  return render(
    <TwoFactorChallenge emailEnabled={emailEnabled} onVerified={onVerified} onBack={onBack} />,
  );
}
const button = (name: string) => screen.getByRole("button", { name });
const field = () => screen.getByRole("textbox") as HTMLInputElement;

describe("backup codes", () => {
  it("normalizes what people paste or type to the stored xxxxx-xxxxx form", () => {
    expect(normalizeBackupCode("AbCde-12345")).toBe("AbCde-12345");
    expect(normalizeBackupCode(" AbCde 12345 ")).toBe("AbCde-12345");
    expect(normalizeBackupCode("AbCde12345")).toBe("AbCde-12345");
    expect(normalizeBackupCode("abc")).toBe("abc");
    expect(codeIsComplete("backup", "AbCde12345")).toBe(true);
    expect(codeIsComplete("backup", "AbCde-")).toBe(false);
    expect(codeIsComplete("totp", "123456")).toBe(true);
    expect(codeIsComplete("totp", "12345a")).toBe(false);
  });

  it("switches to a text field that takes the whole code, verifies it once, and signs in", async () => {
    auth.verifyBackupCode.mockResolvedValue({ data: { token: "t" }, error: null });
    mount();
    expect(field().maxLength).toBe(6);
    expect(field().inputMode).toBe("numeric");

    fireEvent.click(button("auth:twoFactor.useBackupCode"));
    const backup = field();
    expect(backup.id).toBe("backup-code");
    expect(backup.inputMode).toBe("text");
    expect(backup.getAttribute("autocomplete")).toBe("off");
    expect(backup.maxLength).toBeGreaterThanOrEqual(11);
    expect(document.activeElement).toBe(backup);
    // "Each code works once" is the field's description.
    const hint = screen.getByText("auth:twoFactor.backupCodeHint");
    expect(backup.getAttribute("aria-describedby")).toContain(hint.id);
    expect(screen.queryByRole("button", { name: "auth:twoFactor.useBackupCode" })).toBeNull();

    fireEvent.change(backup, { target: { value: "AbCde-12345" } });
    expect(backup.value).toBe("AbCde-12345");
    fireEvent.click(button("auth:twoFactor.verify"));
    await waitFor(() => expect(onVerified).toHaveBeenCalledOnce());
    expect(auth.verifyBackupCode).toHaveBeenCalledWith({ code: "AbCde-12345" });
    expect(auth.verifyTotp).not.toHaveBeenCalled();
  });

  it("puts a refused backup code under the field, focused, and keeps the mode", async () => {
    auth.verifyBackupCode.mockResolvedValue({
      error: { code: "INVALID_BACKUP_CODE", status: 401 },
    });
    mount();
    fireEvent.click(button("auth:twoFactor.useBackupCode"));
    fireEvent.change(field(), { target: { value: "AbCde12345" } });
    fireEvent.click(button("auth:twoFactor.verify"));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("auth:errors.invalidBackupCode");
    expect(field().getAttribute("aria-invalid")).toBe("true");
    expect(field().getAttribute("aria-describedby")).toContain(alert.id);
    expect(document.activeElement).toBe(field());
    expect(auth.verifyBackupCode).toHaveBeenCalledWith({ code: "AbCde-12345" });
    expect(onVerified).not.toHaveBeenCalled();
  });

  it("goes back to the authenticator code from backup mode", () => {
    mount();
    fireEvent.click(button("auth:twoFactor.useBackupCode"));
    fireEvent.click(button("auth:twoFactor.useAuthenticator"));
    expect(field().id).toBe("totp-code");
    expect(field().value).toBe("");
    expect(screen.queryByRole("button", { name: "auth:twoFactor.useAuthenticator" })).toBeNull();
  });
});

describe("authenticator and email codes", () => {
  it("puts a wrong authenticator code under the field and clears it on edit", async () => {
    auth.verifyTotp.mockResolvedValue({ error: { code: "INVALID_CODE", status: 401 } });
    mount();
    fireEvent.change(field(), { target: { value: "123456" } });
    fireEvent.click(button("auth:twoFactor.verify"));
    expect((await screen.findByRole("alert")).textContent).toBe("auth:errors.invalidTotp");
    expect(document.activeElement).toBe(field());
    fireEvent.change(field(), { target: { value: "12345" } });
    expect(screen.queryByRole("alert")).toBeNull();
    expect(field().getAttribute("aria-invalid")).toBeNull();
  });

  it("shows a rate limit in the same place", async () => {
    auth.verifyTotp.mockResolvedValue({ error: { status: 429 } });
    mount();
    fireEvent.change(field(), { target: { value: "123456" } });
    fireEvent.click(button("auth:twoFactor.verify"));
    expect((await screen.findByRole("alert")).textContent).toBe(
      "Too many attempts. Wait a minute.",
    );
  });

  it("after emailing a code, verifies it by email and can go back to the authenticator", async () => {
    auth.sendOtp.mockResolvedValue({ data: { status: true }, error: null });
    auth.verifyOtp.mockResolvedValue({ error: { code: "INVALID_CODE", status: 401 } });
    auth.verifyTotp.mockResolvedValue({ data: { token: "t" }, error: null });
    const view = mount();
    fireEvent.click(button("auth:twoFactor.emailMeCode"));
    await waitFor(() =>
      expect(
        view.container.querySelector("[data-challenge-mode]")?.getAttribute("data-challenge-mode"),
      ).toBe("email"),
    );
    expect(button("auth:twoFactor.resendEmailCode")).toBeTruthy();
    fireEvent.change(field(), { target: { value: "654321" } });
    fireEvent.click(button("auth:twoFactor.verify"));
    expect((await screen.findByRole("alert")).textContent).toBe("auth:errors.invalidEmailCode");
    expect(auth.verifyOtp).toHaveBeenCalledWith({ code: "654321" });

    fireEvent.click(button("auth:twoFactor.useAuthenticator"));
    expect(screen.queryByRole("alert")).toBeNull();
    fireEvent.change(field(), { target: { value: "111111" } });
    fireEvent.click(button("auth:twoFactor.verify"));
    await waitFor(() => expect(onVerified).toHaveBeenCalledOnce());
    expect(auth.verifyTotp).toHaveBeenCalledWith({ code: "111111" });
  });

  it("offers no email option without a mail transport, and Back returns to sign-in", () => {
    mount(false);
    expect(screen.queryByRole("button", { name: "auth:twoFactor.emailMeCode" })).toBeNull();
    expect(button("auth:twoFactor.useBackupCode")).toBeTruthy();
    fireEvent.click(button("auth:twoFactor.back"));
    expect(onBack).toHaveBeenCalledOnce();
  });

  it("keeps every action a 44px target", () => {
    mount();
    for (const b of screen.getAllByRole("button")) expect(b.className).toContain("min-h-[44px]");
  });
});
