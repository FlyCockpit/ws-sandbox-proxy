// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enAgents from "@wssp/locales/src/en-US/agents.json";
import enCredentials from "@wssp/locales/src/en-US/credentials.json";
import enSdkKeys from "@wssp/locales/src/en-US/sdkKeys.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const fake = vi.hoisted(() => ({ consent: vi.fn(), publicClient: vi.fn() }));
vi.mock("@/lib/auth-client", () => ({
  authClient: { oauth2: { consent: fake.consent, publicClient: fake.publicClient } },
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/orpc", () => {
  const picker = (name: string) => ({
    infiniteOptions: (options: {
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: null }) => unknown;
    }) => ({
      queryKey: [name],
      ...options,
      queryFn: async () => ({ items: [], nextCursor: null }),
    }),
  });
  return {
    orpc: {
      sdkKeys: { list: { key: () => ["keys"] } },
      sandboxHosts: { listHosts: picker("hosts") },
      sandboxTemplates: { listRevisionChoices: picker("templates") },
      sandboxPools: { listUsable: picker("pools") },
    },
  };
});

import { McpConsentPage } from "./mcp-consent-page";

beforeEach(() => {
  vi.clearAllMocks();
  fake.publicClient.mockResolvedValue({
    data: { client_name: "Helpful Agent", client_id: "client" },
  });
  fake.consent.mockResolvedValue({ data: { redirect: false } });
});
afterEach(cleanup);
async function mount() {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    resources: { "en-US": { agents: enAgents, sdkKeys: enSdkKeys, credentials: enCredentials } },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <McpConsentPage
          lang="en-US"
          search={{
            client_id: "client",
            sig: "signed",
            scope: "sandboxes:read hosts:read hosts:execute offline_access",
            redirect_uri: "https://agent.example/cb",
          }}
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await screen.findByText("Helpful Agent is requesting access to your account.");
}
it("submits only the selected requested scopes, with host scopes off and own-only on by default", async () => {
  await mount();
  expect(screen.getByRole("checkbox", { name: "hosts:read" }).getAttribute("aria-checked")).toBe(
    "false",
  );
  expect(screen.getByRole("checkbox", { name: "hosts:execute" }).getAttribute("aria-checked")).toBe(
    "false",
  );
  expect(
    screen
      .getByRole("checkbox", { name: enSdkKeys.form.ownSandboxesOnly })
      .getAttribute("aria-checked"),
  ).toBe("true");
  expect(screen.queryByRole("checkbox", { name: "sandboxes:destroy" })).toBeNull();
  const user = userEvent.setup();
  await user.click(screen.getByRole("checkbox", { name: "hosts:read" }));
  await user.click(screen.getByRole("checkbox", { name: enAgents.consent.offline }));
  await user.click(screen.getByRole("button", { name: enAgents.consent.allow }));
  await waitFor(() =>
    expect(fake.consent).toHaveBeenCalledWith(
      expect.objectContaining({
        accept: true,
        scope: "hosts:read sandboxes:read",
        ownSandboxesOnly: true,
        resourceMode: "ALL_OWNED",
      }),
    ),
  );
});
it("denies with only the decision, without minting a credential", async () => {
  await mount();
  await userEvent.setup().click(screen.getByRole("button", { name: enAgents.consent.deny }));
  await waitFor(() => expect(fake.consent).toHaveBeenCalledWith({ accept: false }));
  expect(await screen.findByText(enAgents.consent.denied)).toBeTruthy();
});
