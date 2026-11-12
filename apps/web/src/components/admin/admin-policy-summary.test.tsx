// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const settings = vi.hoisted(() => ({
  value: { signupEnabled: true, force2faInternalUsers: false, force2faPublicUsers: false },
}));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    settings: {
      adminGet: {
        queryOptions: () => ({ queryKey: ["adminGet"], queryFn: async () => settings.value }),
      },
    },
  },
}));

import { AdminPolicySummary } from "./admin-policy-summary";

afterEach(cleanup);

async function mount() {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["admin"],
    defaultNS: "admin",
    resources: { "en-US": { admin: enAdmin } },
    interpolation: { escapeValue: false },
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <I18nextProvider i18n={i18n}>
        <AdminPolicySummary lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

it.each([
  [
    { signupEnabled: true, force2faInternalUsers: false, force2faPublicUsers: false },
    "Sign-up is open. 2FA for admins: not required. 2FA for everyone else: not required.",
  ],
  [
    { signupEnabled: false, force2faInternalUsers: true, force2faPublicUsers: true },
    "Sign-up is closed. 2FA for admins: required. 2FA for everyone else: required.",
  ],
])("summarizes the deployment policy read-only (%j)", async (value, text) => {
  settings.value = value;
  await mount();
  const line = await screen.findByText(
    (_, node) => node?.hasAttribute("data-admin-policy") ?? false,
  );
  expect(line.textContent).toContain(text);
  expect(line.querySelector("a")?.getAttribute("href")).toBe("/$lang/admin/settings");
  expect(screen.queryByRole("switch")).toBeNull();
  expect(screen.queryByRole("button")).toBeNull();
});
