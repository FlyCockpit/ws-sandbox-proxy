// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import enSettings from "@wssp/locales/src/en-US/settings.json";
import enValidation from "@wssp/locales/src/en-US/validation.json";
import esSettings from "@wssp/locales/src/es-MX/settings.json";
import { createInstance } from "i18next";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { installZodErrorMap } from "@/i18n/zod";

// The real en-US bundles and the app's locale-aware Zod map, so the test reads
// the copy a person sees.
const i18n = vi.hoisted(() => ({ instance: null as ReturnType<typeof createInstance> | null }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options: Record<string, unknown> = {}) =>
      i18n.instance?.t(key, options) ?? key,
  }),
}));
const changePassword = vi.hoisted(() => vi.fn());
vi.mock("@/lib/auth-client", () => ({ authClient: { changePassword } }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (_error: unknown, fallback: string) => fallback,
  isRateLimit: () => false,
}));

import { ChangePasswordCard } from "./change-password-card";

beforeAll(async () => {
  const instance = createInstance();
  await instance.init({
    lng: "en-US",
    fallbackLng: "en-US",
    ns: ["settings", "validation"],
    resources: { "en-US": { settings: enSettings, validation: enValidation } },
    interpolation: { escapeValue: false },
  });
  installZodErrorMap(instance);
  i18n.instance = instance;
});
afterEach(() => cleanup());

const submit = () => fireEvent.click(screen.getByRole("button", { name: "Change password" }));

describe("change password validation", () => {
  it("says what each empty field needs instead of a generic length message", async () => {
    render(<ChangePasswordCard />);
    submit();
    await waitFor(() => expect(screen.getAllByRole("alert")).toHaveLength(3));
    const errorFor = (label: string) =>
      document.getElementById(
        screen.getByLabelText(label).getAttribute("aria-describedby")?.split(" ").at(-1) ?? "",
      )?.textContent;
    await waitFor(() =>
      expect(document.activeElement).toBe(screen.getByLabelText("Current password")),
    );
    expect(errorFor("Current password")).toBe("Enter your current password.");
    expect(errorFor("New password")).toBe("Use at least 12 characters.");
    expect(errorFor("Confirm new password")).toBe("Enter the new password again.");
    expect(document.body.textContent).not.toContain("Must be at least");
    expect(changePassword).not.toHaveBeenCalled();
  });

  it("names the upper bound for an over-long new password", async () => {
    render(<ChangePasswordCard />);
    const long = "x".repeat(129);
    fireEvent.change(screen.getByLabelText("Current password"), { target: { value: "old" } });
    fireEvent.change(screen.getByLabelText("New password"), { target: { value: long } });
    fireEvent.change(screen.getByLabelText("Confirm new password"), { target: { value: long } });
    submit();
    expect((await screen.findByRole("alert")).textContent).toBe("Use at most 128 characters.");
  });
});

it("discloses credential revocation and replacement before submission in both locales", () => {
  render(<ChangePasswordCard />);
  expect(screen.getByText(/API.*MCP/).textContent).toMatch(/replacement credentials/);
  expect(enSettings.security.passwordSessionRevocation).toMatch(/CLI/);
  expect(esSettings.security.passwordSessionRevocation).toMatch(/CLI.*API.*MCP/);
  expect(esSettings.security.passwordSessionRevocation).toMatch(/credenciales nuevas/);
  expect(changePassword).not.toHaveBeenCalled();
});
