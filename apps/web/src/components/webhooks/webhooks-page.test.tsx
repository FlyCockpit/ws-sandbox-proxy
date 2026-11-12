// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enCredentials from "@wssp/locales/src/en-US/credentials.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enWebhooks from "@wssp/locales/src/en-US/webhooks.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Webhooks list page against a scripted fake server: the not-configured
 * state, the list, browser-side draft problems, and the show-once secret.
 */
const server = vi.hoisted(() => ({
  configured: true,
  endpoints: [] as Record<string, unknown>[],
  creates: [] as unknown[],
  createError: null as unknown,
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children, ...props }: { children: ReactNode; "aria-label"?: string }) => (
    <a href="#endpoint" aria-label={props["aria-label"]}>
      {children}
    </a>
  ),
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    webhooks: {
      key: () => ["webhooks"],
      status: {
        queryOptions: () => ({
          queryKey: ["webhooks", "status"],
          queryFn: async () => ({ configured: server.configured }),
        }),
      },
      list: {
        infiniteOptions: (options: {
          initialPageParam: unknown;
          getNextPageParam: (page: { nextCursor: string | null }) => unknown;
        }) => ({
          queryKey: ["webhooks", "list"],
          initialPageParam: options.initialPageParam,
          getNextPageParam: options.getNextPageParam,
          queryFn: async () => ({ items: structuredClone(server.endpoints), nextCursor: null }),
        }),
      },
      create: {
        call: async (input: unknown) => {
          server.creates.push(input);
          if (server.createError) throw server.createError;
          return { endpoint: { id: "whe_2" }, secret: `whsec_${"A".repeat(43)}=` };
        },
      },
    },
  },
}));

const { WebhooksPage } = await import("./webhooks-page");

function renderPage() {
  const i18n = createInstance();
  void i18n.init({
    lng: "en-US",
    resources: {
      "en-US": {
        webhooks: enWebhooks,
        common: enCommon,
        dashboard: enDashboard,
        credentials: enCredentials,
      },
    },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <WebhooksPage lang="en-US" />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  server.configured = true;
  server.endpoints = [];
  server.creates = [];
  server.createError = null;
});
afterEach(() => cleanup());

describe("WebhooksPage", () => {
  it("explains a server without DATA_ENCRYPTION_KEY and offers no create", async () => {
    server.configured = false;
    renderPage();
    expect(await screen.findByText(enWebhooks.notConfigured.title)).toBeTruthy();
    expect(screen.queryByRole("button", { name: enWebhooks.create.action })).toBeNull();
  });

  it("lists endpoints with their events and health", async () => {
    server.endpoints = [
      {
        id: "whe_1",
        url: "https://hooks.example.com/wssp",
        description: "ci",
        events: ["sandbox.ready"],
        operationKinds: "all",
        enabled: false,
        disabledReason: "sustained_failures",
        health: { consecutiveFailures: 21 },
      },
    ];
    renderPage();
    expect(await screen.findByText("https://hooks.example.com/wssp")).toBeTruthy();
    expect(screen.getByText(enWebhooks.event["sandbox.ready"])).toBeTruthy();
    expect(screen.getByText("21 consecutive failures")).toBeTruthy();
    expect(screen.getByText(enWebhooks.status.disabled)).toBeTruthy();
  });

  it("refuses an incomplete draft in the browser, then reveals the secret once", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enWebhooks.create.action }));
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    expect(await screen.findByText(enWebhooks.form.urlRequired)).toBeTruthy();
    expect(server.creates).toEqual([]);
    await user.type(screen.getByLabelText(enWebhooks.form.url), "https://hooks.example.com/x");
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    await waitFor(() => expect(server.creates).toHaveLength(1));
    expect(server.creates[0]).toEqual({
      url: "https://hooks.example.com/x",
      events: ["sandbox.ready", "sandbox.create_failed", "sandbox.destroyed"],
    });
    expect(await screen.findByText(enWebhooks.create.secretLabel)).toBeTruthy();
    // Masked by default: the secret is not in the document until revealed.
    expect(document.body.textContent).not.toContain("whsec_");
  });

  it("maps a blocked destination to its explanation", async () => {
    server.createError = { code: "BAD_REQUEST", data: { code: "webhook.destination_blocked" } };
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enWebhooks.create.action }));
    await user.type(screen.getByLabelText(enWebhooks.form.url), "https://10.0.0.1/x");
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    expect(await screen.findByText(enWebhooks.problem.destinationBlocked)).toBeTruthy();
  });
});
