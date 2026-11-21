// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The sandbox detail "Recent connections" panel against a scripted fake
 * server: bounded pages with Load more, a layout-matching skeleton while
 * loading, the empty state, retry on failure, and metadata-only rows.
 */
const server = vi.hoisted(() => ({
  pages: [] as { items: Record<string, unknown>[]; nextCursor: string | null }[],
  inputs: [] as Record<string, unknown>[],
  error: null as unknown,
  gate: null as Promise<void> | null,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxes: {
      listConnectSessions: {
        infiniteOptions: (options: {
          input: (cursor: string | undefined) => Record<string, unknown>;
          initialPageParam: unknown;
          getNextPageParam: (page: { nextCursor: string | null }) => unknown;
        }) => ({
          queryKey: ["sandboxes", "listConnectSessions"],
          initialPageParam: options.initialPageParam,
          getNextPageParam: options.getNextPageParam,
          queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
            const input = options.input(pageParam);
            server.inputs.push(input);
            if (server.gate) await server.gate;
            if (server.error) throw server.error;
            const index = pageParam ? Number(pageParam) : 0;
            return structuredClone(server.pages[index] ?? { items: [], nextCursor: null });
          },
        }),
      },
    },
  },
}));

const { SandboxConnections, connectionIntentKey } = await import("./sandbox-connections");

function renderPanel() {
  const i18n = createInstance();
  void i18n.init({
    lng: "en-US",
    resources: {
      "en-US": { sandboxes: enSandboxes, common: enCommon, dashboard: enDashboard },
    },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <SandboxConnections lang="en-US" sandboxId="sbx_1" />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

const now = Date.now();
const row = (overrides: Record<string, unknown> = {}) => ({
  id: "c1",
  keyId: "key-1",
  keyName: "ci key",
  hostId: "host-1",
  origin: "DASHBOARD",
  openedAt: new Date(now - 2 * 3_600_000),
  closedAt: new Date(now - 3_600_000),
  status: "closed",
  closeIntent: "revoked",
  ptyChannels: 1,
  execChannels: 2,
  bytesIn: "2048",
  bytesOut: "1048576",
  ...overrides,
});

beforeEach(() => {
  server.pages = [];
  server.inputs = [];
  server.error = null;
  server.gate = null;
});
afterEach(() => cleanup());

describe("SandboxConnections", () => {
  it("shows a skeleton while loading, then the empty state", async () => {
    let release!: () => void;
    server.gate = new Promise((resolve) => {
      release = resolve;
    });
    const { container } = renderPanel();
    expect(screen.getByRole("heading", { name: enSandboxes.connections.heading })).toBeTruthy();
    expect(container.querySelector('[data-slot="skeleton"]')).not.toBeNull();
    release();
    expect(await screen.findByText(enSandboxes.connections.empty)).toBeTruthy();
    expect(server.inputs[0]).toEqual({ id: "sbx_1", limit: expect.any(Number), cursor: undefined });
    expect(server.inputs[0]?.limit).toBeLessThanOrEqual(100);
  });

  it("lists metadata per connection and pages with Load more", async () => {
    server.pages = [
      {
        items: [
          row(),
          row({
            id: "c0",
            keyName: null,
            origin: "CLI_LOGIN",
            status: "open",
            closedAt: null,
            closeIntent: null,
          }),
        ],
        nextCursor: "1",
      },
      {
        items: [row({ id: "c-old", status: "unknown", closedAt: null, closeIntent: null })],
        nextCursor: null,
      },
    ];
    const user = userEvent.setup();
    renderPanel();
    const list = await screen.findByRole("list", { name: enSandboxes.connections.label });
    const first = list.querySelector<HTMLElement>('[data-connection-id="c1"]')!;
    expect(within(first).getByText("ci key")).toBeTruthy();
    expect(within(first).getByText(enSandboxes.connections.origin.DASHBOARD)).toBeTruthy();
    expect(within(first).getByText(enSandboxes.connections.status.closed)).toBeTruthy();
    expect(first.querySelector("[data-close-intent]")?.textContent).toBe(
      `Ended: ${enSandboxes.connections.intent.revoked}`,
    );
    expect(first.textContent).toContain("1 shell · 2 commands · 2 KiB sent, 1 MiB received");
    const open = list.querySelector<HTMLElement>('[data-connection-id="c0"]')!;
    expect(within(open).getByText(enSandboxes.connections.unknownKey)).toBeTruthy();
    expect(within(open).getByText(enSandboxes.connections.status.open)).toBeTruthy();
    expect(open.querySelector("[data-close-intent]")).toBeNull();
    await user.click(screen.getByRole("button", { name: enCommon.actions.loadMore }));
    await waitFor(() =>
      expect(document.querySelector('[data-connection-id="c-old"]')).not.toBeNull(),
    );
    expect(
      document
        .querySelector('[data-connection-id="c-old"]')
        ?.getAttribute("data-connection-status"),
    ).toBe("unknown");
    expect(server.inputs.at(-1)).toMatchObject({ id: "sbx_1", cursor: "1" });
  });

  it("a failed load offers a retry that recovers", async () => {
    server.error = new Error("network");
    const user = userEvent.setup();
    renderPanel();
    const retry = await screen.findByRole("button", { name: enCommon.actions.tryAgain });
    server.error = null;
    await user.click(retry);
    expect(await screen.findByText(enSandboxes.connections.empty)).toBeTruthy();
  });

  it("every close intent has copy in every locale; unknown ones read as other", () => {
    expect(connectionIntentKey(null)).toBeNull();
    expect(connectionIntentKey("made_up")).toBe("sandboxes:connections.intent.other");
    for (const bundle of [enSandboxes, esSandboxes]) {
      for (const intent of [
        "client",
        "detached",
        "backpressure",
        "revoked",
        "superseded",
        "protocol_violation",
        "host_disconnected",
        "expired",
        "sandbox_stopped",
        "sandbox_destroyed",
        "lifecycle_unconfirmed",
        "shutdown",
      ]) {
        expect(connectionIntentKey(intent)).toBe(`sandboxes:connections.intent.${intent}`);
        expect((bundle.connections.intent as Record<string, string>)[intent]).toEqual(
          expect.any(String),
        );
      }
    }
  });
});
