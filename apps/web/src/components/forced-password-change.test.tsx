// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const changePassword = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth-client", () => ({ authClient: { changePassword } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (_error: unknown, fallback: string) => fallback,
  isRateLimit: () => false,
}));

import { toast } from "@wssp/ui/components/sileo";
import { ForcedPasswordChange } from "./forced-password-change";

const reload = vi.fn();
beforeEach(() => {
  changePassword.mockReset();
  reload.mockReset();
  vi.stubGlobal("location", { ...window.location, reload });
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("forced password change takeover", () => {
  it("explains why, and replaces the temporary password before reloading into the app", async () => {
    changePassword.mockResolvedValue({ data: { token: "t" }, error: null });
    render(<ForcedPasswordChange />);
    expect(screen.getByText("passwordChange.requiredTitle")).toBeTruthy();
    expect(screen.getByText("passwordChange.requiredDescription")).toBeTruthy();
    fill("settings:security.currentPasswordLabel", "temporary-password");
    fill("settings:security.newPasswordLabel", "a-new-long-password");
    fill("settings:security.confirmPasswordLabel", "a-new-long-password");
    fireEvent.click(screen.getByRole("button", { name: "settings:security.changePassword" }));
    await waitFor(() => expect(reload).toHaveBeenCalledOnce());
    expect(changePassword).toHaveBeenCalledWith({
      currentPassword: "temporary-password",
      newPassword: "a-new-long-password",
      revokeOtherSessions: true,
    });
  });

  it("stays on the takeover when the change is refused", async () => {
    changePassword.mockResolvedValue({ data: null, error: { code: "INVALID_PASSWORD" } });
    render(<ForcedPasswordChange />);
    fill("settings:security.currentPasswordLabel", "wrong");
    fill("settings:security.newPasswordLabel", "a-new-long-password");
    fill("settings:security.confirmPasswordLabel", "a-new-long-password");
    fireEvent.click(screen.getByRole("button", { name: "settings:security.changePassword" }));
    await waitFor(() => expect(changePassword).toHaveBeenCalledOnce());
    expect(reload).not.toHaveBeenCalled();
  });

  it("says why when the temporary password is chosen again", async () => {
    changePassword.mockResolvedValue({ data: null, error: { code: "PASSWORD_REUSED" } });
    render(<ForcedPasswordChange />);
    fill("settings:security.currentPasswordLabel", "temporary-password");
    fill("settings:security.newPasswordLabel", "temporary-password");
    fill("settings:security.confirmPasswordLabel", "temporary-password");
    fireEvent.click(screen.getByRole("button", { name: "settings:security.changePassword" }));
    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("settings:security.passwordReused"),
    );
    expect(reload).not.toHaveBeenCalled();
  });
});
