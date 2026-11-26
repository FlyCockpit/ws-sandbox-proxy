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

/**
 * Webhooks list page against a scripted fake server: the not-configured
 * state, the list, browser-side draft problems, and the show-once secret.
 */
const server = vi.hoisted(() => ({
  configured: true,
  statusError: null as unknown,
  endpoints: [] as Record<string, unknown>[],
  creates: [] as unknown[],
  createError: null as unknown,
  /** When set, create waits for it (a request still in flight). */
  createGate: null as Promise<void> | null,
}));
/** The leave guard's last blocker options, and the navigate spy. */
const router = vi.hoisted(() => ({
  blocker: null as null | { shouldBlockFn: () => boolean; enableBeforeUnload: () => boolean },
  navigate: vi.fn(),
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => router.navigate,
  useBlocker: (opts: { shouldBlockFn: () => boolean; enableBeforeUnload: () => boolean }) => {
    router.blocker = opts;
    return { status: "idle" };
  },
  Link: ({
    children,
    disabled,
    ...props
  }: {
    children: ReactNode;
    disabled?: boolean;
    "aria-label"?: string;
    "data-webhooks-back"?: string;
    "data-webhook-cancel"?: string;
  }) => (
    // Like the router's Link: a disabled link has no href and says so.
    <a
      href={disabled ? undefined : "#endpoint"}
      aria-disabled={disabled ? true : undefined}
      aria-label={props["aria-label"]}
      data-webhooks-back={props["data-webhooks-back"]}
      data-webhook-cancel={props["data-webhook-cancel"]}
    >
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
          queryFn: async () => {
            if (server.statusError) throw server.statusError;
            return { configured: server.configured };
          },
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
          if (server.createGate) await server.createGate;
          if (server.createError) throw server.createError;
          return { endpoint: { id: "whe_2" }, secret: `whsec_${"A".repeat(43)}=` };
        },
      },
    },
  },
}));

const { WebhooksPage } = await import("./webhooks-page");
const { CreateWebhookPage } = await import("./create-webhook-page");

function renderPage(page: "list" | "create" = "list") {
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
        {page === "list" ? <WebhooksPage lang="en-US" /> : <CreateWebhookPage lang="en-US" />}
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  server.configured = true;
  server.statusError = null;
  server.endpoints = [];
  server.creates = [];
  server.createError = null;
  server.createGate = null;
  router.blocker = null;
  router.navigate.mockReset();
});
afterEach(() => cleanup());

describe("WebhooksPage", () => {
  it("explains a server without DATA_ENCRYPTION_KEY and offers no create", async () => {
    server.configured = false;
    renderPage();
    expect(await screen.findByText(enWebhooks.notConfigured.title)).toBeTruthy();
    expect(screen.queryByRole("link", { name: enWebhooks.create.action })).toBeNull();
  });

  it("a failed status read on the create page offers a retry, not 'not configured'", async () => {
    const user = userEvent.setup();
    server.statusError = new Error("network down");
    renderPage("create");
    expect(await screen.findByText(enWebhooks.create.statusFailed)).toBeTruthy();
    expect(screen.queryByText(enWebhooks.notConfigured.title)).toBeNull();
    server.statusError = null;
    await user.click(screen.getByRole("button", { name: enCommon.actions.tryAgain }));
    expect(await screen.findByRole("button", { name: enWebhooks.create.submit })).toBeTruthy();
  });

  it("the create page says 'not configured' only when the server says so", async () => {
    server.configured = false;
    renderPage("create");
    expect(await screen.findByText(enWebhooks.notConfigured.title)).toBeTruthy();
    expect(screen.queryByRole("button", { name: enWebhooks.create.submit })).toBeNull();
  });

  it("Add endpoint is a page of its own, not a dialog", async () => {
    renderPage();
    expect(await screen.findByRole("link", { name: enWebhooks.create.action })).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
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

  it("an enabled endpoint that keeps failing shows a Failing warning, not a calm Enabled", async () => {
    const endpoint = (id: string, consecutiveFailures: number) => ({
      id,
      url: `https://${id}.example.com/wssp`,
      description: null,
      events: ["sandbox.ready"],
      operationKinds: "all",
      enabled: true,
      disabledReason: null,
      health: { consecutiveFailures },
    });
    server.endpoints = [endpoint("failing", 53), endpoint("healthy", 0)];
    renderPage();
    await screen.findByText("https://failing.example.com/wssp");
    const card = (id: string) => document.querySelector<HTMLElement>(`[data-webhook-id="${id}"]`)!;
    const failing = within(card("failing"));
    const badge = failing.getByText(enWebhooks.status.failing);
    expect(badge.getAttribute("data-webhook-status")).toBe("failing");
    expect(badge.className).toContain("text-state-warning");
    expect(failing.queryByText(enWebhooks.status.enabled)).toBeNull();
    expect(failing.getByText("53 consecutive failures").className).toContain("text-state-warning");
    const healthy = within(card("healthy"));
    expect(healthy.getByText(enWebhooks.status.enabled).getAttribute("data-webhook-status")).toBe(
      "enabled",
    );
    expect(healthy.getByText(enWebhooks.list.healthy).className).toContain("text-muted-foreground");
  });

  it("refuses an incomplete draft in the browser, then reveals the secret once", async () => {
    const user = userEvent.setup();
    renderPage("create");
    await user.click(await screen.findByRole("button", { name: enWebhooks.create.submit }));
    // The error sits next to the URL field, which gets focus.
    expect(await screen.findByText(enWebhooks.form.urlRequired)).toBeTruthy();
    const url = screen.getByLabelText(enWebhooks.form.url);
    expect(url.getAttribute("aria-invalid")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(url));
    expect(server.creates).toEqual([]);
    await user.type(screen.getByLabelText(enWebhooks.form.url), "https://hooks.example.com/x");
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    await waitFor(() => expect(server.creates).toHaveLength(1));
    expect(server.creates[0]).toEqual({
      url: "https://hooks.example.com/x",
      events: ["sandbox.ready", "sandbox.create_failed", "sandbox.destroyed"],
    });
    expect(await screen.findByText(enWebhooks.create.secretLabel)).toBeTruthy();
    expect(screen.getByText(enWebhooks.create.createdTitle)).toBeTruthy();
    // Masked by default: the secret is not in the document until revealed.
    expect(document.body.textContent).not.toContain("whsec_");
  });

  it("holds Cancel, Back and navigation while the create is pending and while the secret shows", async () => {
    let release = () => {};
    server.createGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    renderPage("create");
    await user.type(
      await screen.findByLabelText(enWebhooks.form.url),
      "https://hooks.example.com/x",
    );
    const cancel = () => document.querySelector("[data-webhook-cancel]")!;
    const back = () => document.querySelector("[data-webhooks-back]")!;
    expect(cancel().getAttribute("aria-disabled")).toBeNull();
    expect(router.blocker?.shouldBlockFn()).toBe(false);
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    await waitFor(() => expect(server.creates).toHaveLength(1));
    // In flight: the secret is on its way, so nothing may leave the page.
    await waitFor(() => expect(cancel().getAttribute("aria-disabled")).toBe("true"));
    expect(cancel().hasAttribute("href")).toBe(false);
    expect(back().getAttribute("aria-disabled")).toBe("true");
    expect(router.blocker?.shouldBlockFn()).toBe(true);
    expect(router.blocker?.enableBeforeUnload()).toBe(true);
    release();
    expect(await screen.findByText(enWebhooks.create.secretLabel)).toBeTruthy();
    // Shown once: leaving still asks first.
    expect(router.blocker?.shouldBlockFn()).toBe(true);
    // Done confirms it is saved and opens the endpoint past the guard.
    await user.click(screen.getByRole("button", { name: enCredentials.reveal.done }));
    expect(router.navigate).toHaveBeenCalledWith({
      to: "/$lang/settings/webhooks/$endpointId",
      params: { lang: "en-US", endpointId: "whe_2" },
      ignoreBlocker: true,
    });
  });

  it("groups events by resource with a tri-state select-all per group", async () => {
    const user = userEvent.setup();
    renderPage("create");
    const sandboxes = (await screen.findByRole("group", {
      name: enWebhooks.eventGroup.sandbox,
    })) as HTMLElement;
    const all = screen.getByRole("checkbox", {
      name: enWebhooks.form.groupAll.replace("{{group}}", enWebhooks.eventGroup.sandbox),
    });
    // Description and operation kinds wait under Advanced.
    expect(
      [...document.querySelectorAll("details")].map(
        (node) => node.querySelector("summary")?.textContent,
      ),
    ).toEqual([`${enWebhooks.form.details}${enWebhooks.form.noDescription}`]);
    // The default (ready, create failed, destroyed) is some of the group: mixed.
    expect(all.getAttribute("aria-checked")).toBe("mixed");
    // Human label first, the raw event id as secondary text.
    expect(sandboxes.textContent).toContain(enWebhooks.event["sandbox.ready"]);
    expect(sandboxes.textContent).toContain("sandbox.ready");
    await user.click(all);
    expect(all.getAttribute("aria-checked")).toBe("true");
    await user.click(all);
    expect(all.getAttribute("aria-checked")).toBe("false");
    // Choosing nothing is refused next to the events.
    await user.type(screen.getByLabelText(enWebhooks.form.url), "https://hooks.example.com/x");
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    expect(await screen.findByText(enWebhooks.form.eventsRequired)).toBeTruthy();
    expect(server.creates).toEqual([]);
    const logins = screen.getByRole("checkbox", {
      name: enWebhooks.form.groupAll.replace("{{group}}", enWebhooks.eventGroup.credential),
    });
    await user.click(logins);
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    await waitFor(() => expect(server.creates).toHaveLength(1));
    expect(server.creates[0]).toMatchObject({
      events: [
        "credential.capture_failed",
        "credential.capture_lost",
        "credential.recovery_required",
        "credential.needs_login",
      ],
    });
  });

  it("maps a blocked destination to its explanation", async () => {
    server.createError = { code: "BAD_REQUEST", data: { code: "webhook.destination_blocked" } };
    const user = userEvent.setup();
    renderPage("create");
    await user.type(await screen.findByLabelText(enWebhooks.form.url), "https://10.0.0.1/x");
    await user.click(screen.getByRole("button", { name: enWebhooks.create.submit }));
    expect(await screen.findByText(enWebhooks.problem.destinationBlocked)).toBeTruthy();
  });
});
