vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import { type ReactNode, useState } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type FakeSandboxServer,
  fakeHost,
  fakeTemplate,
  newFakeSandboxServer,
  sandboxRow,
} from "@/test/sandbox-fake";

/**
 * Sandboxes list against a scripted fake server (real TanStack Query and
 * i18n): rows show exactly what the server reported — queued, unknown and
 * offline included — and every create entry links to the Create sandbox page
 * (its behaviour is covered in `create-sandbox-page.test.tsx`).
 */

const server = vi.hoisted(() => ({ current: null as unknown as FakeSandboxServer }));
const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
// CLI logins are covered by their own tests; here the server has them off.
vi.mock("@/components/logins/logins-shared", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/components/logins/logins-shared")>()),
  useLoginsAvailability: () => "unavailable",
}));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({
    children,
    className,
    to,
    params,
    ...rest
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: Record<string, string>;
    "aria-label"?: string;
  }) => (
    <a
      className={className}
      aria-label={rest["aria-label"]}
      href={Object.entries(params ?? {}).reduce(
        (path, [key, value]) => path.replace(`$${key}`, value),
        to,
      )}
    >
      {children}
    </a>
  ),
}));
vi.mock("@/utils/orpc", async () => {
  const { fakeSandboxOrpc } = await import("@/test/sandbox-fake");
  return {
    orpc: new Proxy(
      {},
      {
        get: (_, key) =>
          (fakeSandboxOrpc(server.current) as Record<string, unknown>)[key as string],
      },
    ),
  };
});

import { SandboxesPage } from "./sandboxes-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "sandboxes", "hosts"],
    defaultNS: "common",
    resources: {
      "en-US": { common: enCommon, dashboard: enDashboard, sandboxes: enSandboxes, hosts: enHosts },
      "es-MX": { common: esCommon, dashboard: esDashboard, sandboxes: esSandboxes, hosts: esHosts },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

/** Stands in for the route: `?status=` state, the way the URL holds it. */
function StatefulSandboxesPage({ lang }: { lang: string }) {
  const [status, setStatus] = useState<"active" | "deleted" | "all">("active");
  return <SandboxesPage lang={lang} status={status} onStatusChange={setStatus} />;
}

let client: QueryClient;
async function mount(lang = "en-US") {
  await i18n.changeLanguage(lang);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <StatefulSandboxesPage lang={lang} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) =>
  server.current.calls.filter((call) => call.procedure === procedure);
const row = (id: string) => document.querySelector<HTMLElement>(`li[data-sandbox-id="${id}"]`)!;

beforeEach(() => {
  server.current = newFakeSandboxServer();
  server.current.hosts = [
    fakeHost(),
    fakeHost({ id: "host-2", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
  ];
  server.current.templates = [
    fakeTemplate(),
    fakeTemplate({
      id: "tpl-2",
      templateId: "logical-2",
      sandboxHostId: "host-2",
      slug: "debian",
      label: "Debian",
    }),
  ];
  navigate.mockReset();
  toast.success.mockReset();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("sandboxes list", () => {
  it("loading shows a skeleton, then the onboarding checklist for an empty Active list", async () => {
    const view = await mount();
    expect(view.container.querySelector('[data-slot="skeleton"]')).not.toBeNull();
    expect(await screen.findByText(enSandboxes.onboarding.title)).toBeTruthy();
    expect(calls("list")[0]?.input).toMatchObject({ status: "active", limit: 50 });
    // Each step check is one bounded read (hosts: enough to find a ready one).
    expect(calls("listHosts:first")[0]?.input).toMatchObject({ limit: 20 });
    for (const procedure of ["listPools:first", "listTemplates:first"])
      expect(calls(procedure)[0]?.input, procedure).toMatchObject({ limit: 1 });
  });

  it("an enrolled host that cannot take sandboxes yet points at Hosts, not at enrolling another", async () => {
    server.current.hosts = [
      fakeHost({ egressGuard: { ok: false, reason: "guard_unreachable", leaseActive: false } }),
      fakeHost({ id: "host-2", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
    ];
    server.current.pools = [];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    const first = document.querySelector<HTMLElement>("[data-step-done]");
    expect(first?.dataset.stepDone).toBe("false");
    expect(screen.getByText(enSandboxes.onboarding.host.notReady)).toBeTruthy();
    expect(screen.getByRole("link", { name: enSandboxes.onboarding.host.openHosts })).toBeTruthy();
    expect(
      screen.getByRole("link", { name: enSandboxes.onboarding.host.poolsAction }),
    ).toBeTruthy();
  });

  it("a connected host with a running egress guard completes the first step", async () => {
    server.current.hosts = [fakeHost()];
    server.current.pools = [];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    const first = document.querySelector<HTMLElement>("[data-step-done]");
    expect(first?.dataset.stepDone).toBe("true");
  });

  it("the onboarding checklist marks what is done and counts a shared pool as a place to run", async () => {
    server.current.hosts = [];
    server.current.pools = [{ id: "pool-shared", slug: "team", label: "Team pool" }] as never;
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    const steps = [...document.querySelectorAll<HTMLElement>("[data-step-done]")].map(
      (step) => step.dataset.stepDone,
    );
    expect(steps[0]).toBe("true");
    expect(screen.queryByRole("link", { name: enSandboxes.onboarding.host.action })).toBeNull();
  });

  it("an empty Deleted list shows its own empty state, not the checklist", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.deleted }));
    expect(await screen.findByText(enSandboxes.empty.deletedTitle)).toBeTruthy();
    expect(screen.queryByText(enSandboxes.onboarding.title)).toBeNull();
  });

  it("a failed first load shows a retry that recovers", async () => {
    server.current.errors.list = [new Error("network")];
    const user = userEvent.setup();
    await mount();
    const retry = await screen.findByRole("button", { name: enCommon.actions.tryAgain });
    expect(screen.getByText(enDashboard.list.loadFailed)).toBeTruthy();
    server.current.sandboxes = [sandboxRow()];
    await user.click(retry);
    expect(await screen.findByText("quiet-otter")).toBeTruthy();
  });

  it.each([401, 403, 404])(
    "hides a previously loaded sandbox list after HTTP %s",
    async (status) => {
      server.current.sandboxes = [sandboxRow()];
      await mount();
      await screen.findByText("quiet-otter");
      server.current.errors.list = [Object.assign(new Error("denied"), { status })];
      await act(async () => {
        await client.refetchQueries({ queryKey: ["sandboxes", "list"] });
      });
      await screen.findByText(enDashboard.list.loadFailed);
      expect(screen.queryByText("quiet-otter")).toBeNull();
    },
  );

  it("retains real list rows with a retry after a transient failure", async () => {
    server.current.sandboxes = [sandboxRow()];
    await mount();
    await screen.findByText("quiet-otter");
    server.current.errors.list = [new Error("offline")];
    await act(async () => {
      await client.refetchQueries({ queryKey: ["sandboxes", "list"] });
    });
    await screen.findByText(enDashboard.list.loadFailed);
    expect(screen.getByText("quiet-otter")).toBeTruthy();
  });

  it("es-MX: the empty and error copy are localized", async () => {
    await mount("es-MX");
    expect(await screen.findByText(esSandboxes.onboarding.title)).toBeTruthy();
    cleanup();
    server.current.errors.list = [new Error("network")];
    await mount("es-MX");
    expect(await screen.findByText(esDashboard.list.loadFailed)).toBeTruthy();
  });

  it("shows state, host, template, labels, expiry and a link to the sandbox's page", async () => {
    server.current.sandboxes = [
      sandboxRow({
        metadata: { team: "infra", tier: "2" },
        template: { id: "tpl-old", slug: "old", label: "Old image", retiredAt: new Date() },
        leaseExpireAction: "DESTROY",
      }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const card = row("sbx-1");
    // The name is the card's heading; the id stays beneath it.
    expect(within(card).getByRole("heading").textContent).toBe("quiet-otter");
    expect(card.dataset.sandboxState).toBe("READY");
    expect(within(card).getByText(enSandboxes.state.READY)).toBeTruthy();
    expect(card.querySelector("[data-sandbox-host]")?.textContent).toBe(
      `Alpha (alpha) · ${enHosts.status.ready}`,
    );
    expect(card.querySelector("[data-sandbox-template]")?.textContent).toBe("Old image (archived)");
    expect(within(card).getByText("team=infra")).toBeTruthy();
    expect(within(card).getByText("tier=2")).toBeTruthy();
    expect(within(card).getByText(/then destroy$/)).toBeTruthy();
    const open = within(card).getByRole("link", { name: "Open sandbox sbx-1" });
    expect(open.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/sbx-1");
  });

  it("badges a stored disk (disk offload) and never a disk only on its host", async () => {
    const stored = {
      location: "host_and_store",
      offloadState: "stored",
      offloadFailure: null,
      offloadedAt: null,
      sizeBytes: 1024,
      eligibility: "any_host",
      offloadPin: "ANY",
      offloadPolicy: { mode: "on_stop" },
      offloadDueAt: null,
    };
    server.current.sandboxes = [
      sandboxRow({ id: "sbx-1", state: "STOPPED", disk: stored }),
      sandboxRow({ id: "sbx-2" }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const badge = row("sbx-1").querySelector<HTMLElement>("[data-disk-location]");
    expect(badge?.dataset.diskLocation).toBe("host_and_store");
    expect(badge?.textContent).toBe(enSandboxes.disk.location.host_and_store);
    expect(row("sbx-2").querySelector("[data-disk-location]")).toBeNull();
  });

  it("a stopped sandbox has no running lifetime, as on its detail page", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "STOPPED", leaseExpiresAt: new Date(Date.now() + 24 * 3_600_000) }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const lifetime = row("sbx-1").querySelector<HTMLElement>("[data-sandbox-lifetime]");
    expect(lifetime?.textContent).toBe(enSandboxes.lifetime.stopped);
    expect(row("sbx-1").textContent).not.toMatch(/then stop/);
  });

  it("a lease from READY shows its pending start, not the provisioning backstop", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "PROVISIONING",
        leasePendingReady: true,
        leaseExpiresAt: new Date(Date.now() + 2 * 3_600_000 + 5 * 60_000),
      }),
    ];
    await mount();
    await screen.findByText("quiet-otter");
    const card = row("sbx-1");
    expect(within(card).getByText(enSandboxes.lifetime.startsAtReady)).toBeTruthy();
    expect(card.textContent).not.toMatch(/in 2 hours/);
  });

  it("queued, unknown-outcome and offline-host states stay visible", async () => {
    const receipt = (id: string, kind: string, state: string) => ({
      id,
      kind,
      state,
      errorCode: null,
      createdAt: new Date(),
      completedAt: null,
    });
    server.current.sandboxes = [
      sandboxRow({
        id: "sbx-q",
        state: "REQUESTED",
        lastLifecycleOperation: receipt("op-q", "CREATE_SANDBOX", "QUEUED"),
        host: fakeHost({
          status: "DISCONNECTED",
          lastConnectedAt: new Date(Date.now() - 3_600_000),
        }),
      }),
      sandboxRow({
        id: "sbx-u",
        lastLifecycleOperation: receipt("op-u", "STOP_SANDBOX", "UNKNOWN_OUTCOME"),
        host: fakeHost({ lastHeartbeatAt: new Date(Date.now() - 5 * 60_000) }),
      }),
    ];
    await mount();
    await screen.findByText("sbx-q");
    const queued = row("sbx-q");
    expect(queued.dataset.sandboxState).toBe("REQUESTED");
    expect(within(queued).getByText(/Create: Queued/)).toBeTruthy();
    expect(queued.querySelector("[data-host-offline]")?.textContent).toContain(
      enHosts.status.offline,
    );
    const unknown = row("sbx-u");
    // A stale heartbeat is offline, never ready, even though the row says READY.
    expect(unknown.querySelector("[data-host-offline]")?.textContent).toContain(
      enHosts.status.stale,
    );
    expect(unknown.querySelector('[data-receipt-state="UNKNOWN_OUTCOME"]')?.textContent).toContain(
      "Stop: Outcome unknown",
    );
  });

  it("the Deleted filter asks the server for deleted sandboxes and offers no lifecycle action", async () => {
    server.current.sandboxes = [sandboxRow(), sandboxRow({ id: "sbx-gone", state: "DELETED" })];
    const user = userEvent.setup();
    await mount();
    await screen.findByText("quiet-otter");
    expect(screen.queryByText("sbx-gone")).toBeNull();
    await user.click(screen.getByRole("button", { name: enSandboxes.filter.deleted }));
    expect(await screen.findByText("sbx-gone")).toBeTruthy();
    expect(calls("list").at(-1)?.input).toMatchObject({ status: "deleted" });
    expect(within(row("sbx-gone")).queryByRole("button")).toBeNull();
  });
});

describe("create entries", () => {
  it("the header's Create sandbox opens the Create page (no dialog)", async () => {
    server.current.sandboxes = [sandboxRow()];
    await mount();
    await screen.findByText("quiet-otter");
    const create = screen.getByRole("link", { name: enSandboxes.create.action });
    expect(create.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/new");
    expect(create.className).toMatch(/h-11|min-h-\[44px\]/);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("the onboarding checklist's Create your first sandbox links to the Create page once ready", async () => {
    server.current.hosts = [fakeHost()];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    const cta = await screen.findByRole("link", { name: enSandboxes.onboarding.sandbox.action });
    expect(cta.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/new");
  });

  it("the onboarding CTA stays disabled until there is a place to run and a template", async () => {
    server.current.hosts = [];
    server.current.pools = [];
    server.current.templates = [fakeTemplate()];
    await mount();
    await screen.findByText(enSandboxes.onboarding.title);
    const cta = screen.getByRole("button", { name: enSandboxes.onboarding.sandbox.action });
    expect((cta as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByRole("link", { name: enSandboxes.onboarding.sandbox.action })).toBeNull();
  });
});
