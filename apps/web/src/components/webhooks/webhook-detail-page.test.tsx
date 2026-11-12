// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enCredentials from "@wssp/locales/src/en-US/credentials.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enWebhooks from "@wssp/locales/src/en-US/webhooks.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/** Webhook detail page against a scripted fake server. */
const server = vi.hoisted(() => ({
  endpoint: {} as Record<string, unknown>,
  calls: [] as { procedure: string; input: unknown }[],
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children }: { children: ReactNode }) => <a href="#back">{children}</a>,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/orpc", () => {
  const mutation = (procedure: string, result: () => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: unknown) => {
        server.calls.push({ procedure, input });
        return result();
      },
    }),
    call: async (input: unknown) => {
      server.calls.push({ procedure, input });
      return result();
    },
  });
  return {
    orpc: {
      webhooks: {
        key: () => ["webhooks"],
        get: {
          queryOptions: () => ({
            queryKey: ["webhooks", "get"],
            queryFn: async () => structuredClone(server.endpoint),
          }),
        },
        listDeliveries: {
          infiniteOptions: (options: {
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["webhooks", "deliveries"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async () => ({ items: [], nextCursor: null }),
          }),
        },
        update: mutation("update", () => server.endpoint),
        test: mutation("test", () => ({ deliveryId: "whd_1", eventId: `evt_${"0".repeat(32)}` })),
        delete: mutation("delete", () => ({ id: "whe_1", deleted: true })),
        rotateSecret: mutation("rotateSecret", () => ({
          endpoint: server.endpoint,
          secret: `whsec_${"B".repeat(43)}=`,
        })),
      },
    },
  };
});

const { WebhookDetailPage } = await import("./webhook-detail-page");

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
        <WebhookDetailPage lang="en-US" endpointId="whe_1" />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  server.calls = [];
  server.endpoint = {
    id: "whe_1",
    url: "https://hooks.example.com/wssp",
    description: null,
    events: ["sandbox.ready"],
    operationKinds: "all",
    payloadVersion: 1,
    enabled: false,
    disabledAt: "2026-11-02T00:00:00.000Z",
    disabledReason: "sustained_failures",
    secretVersion: 1,
    previousSecretExpiresAt: null,
    health: {
      consecutiveFailures: 20,
      failingSince: "2026-10-30T00:00:00.000Z",
      lastSuccessAt: null,
      lastFailureAt: "2026-11-02T00:00:00.000Z",
      lastFailureClass: "timeout",
    },
    createdAt: "2026-10-01T00:00:00.000Z",
    updatedAt: "2026-11-02T00:00:00.000Z",
  };
});
afterEach(() => cleanup());

describe("WebhookDetailPage", () => {
  it("explains a sustained-failure disable and re-enables with the full replacement body", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText(enWebhooks.status.disabledForFailures)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: enWebhooks.test.action }) as HTMLButtonElement).disabled,
    ).toBe(true);
    await user.click(screen.getByRole("button", { name: enWebhooks.toggle.enable }));
    await waitFor(() => expect(server.calls).toHaveLength(1));
    expect(server.calls[0]).toEqual({
      procedure: "update",
      input: {
        id: "whe_1",
        url: "https://hooks.example.com/wssp",
        description: null,
        events: ["sandbox.ready"],
        operationKinds: "all",
        enabled: true,
      },
    });
  });

  it("rotates with the chosen overlap and shows the new secret once, masked", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enWebhooks.rotate.action }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: enWebhooks.rotate.confirm }));
    await waitFor(() =>
      expect(server.calls.map((call) => call.procedure)).toEqual(["rotateSecret"]),
    );
    expect(server.calls[0]?.input).toEqual({ id: "whe_1", overlapSeconds: 86_400 });
    expect(await screen.findByText(enWebhooks.rotate.secretLabel)).toBeTruthy();
    expect(document.body.textContent).not.toContain("whsec_");
  });
});
