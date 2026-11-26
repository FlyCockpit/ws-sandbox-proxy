const browserAuthority = vi.hoisted(() => ({ impersonatedBy: null as string | null }));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: {
      status: "authenticated",
      session: { session: { impersonatedBy: browserAuthority.impersonatedBy } },
    },
  }),
}));

import { selectChoices, selectOption } from "@/test/select-option";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import enTerminal from "@wssp/locales/src/en-US/terminal.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import {
  coded,
  type FakeSandboxServer,
  fakeHost,
  fakeTemplate,
  newFakeSandboxServer,
  sandboxRow,
} from "@/test/sandbox-fake";

/**
 * One sandbox's page against a scripted fake server (real TanStack Query,
 * i18n and dialogs). The host's progress is simulated by changing the fake
 * server's rows and refetching: the page must show each server-reported step
 * (never an assumed READY or DELETED), keep queued/unknown/offline visible,
 * send one idempotent request per intent, confirm destructive actions, and
 * treat another owner's sandbox as not found. File transfers go through the
 * cookie-session adapter against a stubbed `fetch`.
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
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({
    children,
    className,
    to,
    params,
    search,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: Record<string, string>;
    search?: Record<string, string>;
  }) => (
    <a
      className={className}
      data-search={search ? JSON.stringify(search) : undefined}
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

import { formatClock } from "@/lib/sandbox-status";
import { SandboxDetailPage } from "./sandbox-detail-page";
import { OPERATION_POLL_MS } from "./sandbox-files";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "sandboxes", "hosts", "terminal"],
    defaultNS: "common",
    resources: {
      "en-US": {
        common: enCommon,
        dashboard: enDashboard,
        sandboxes: enSandboxes,
        hosts: enHosts,
        terminal: enTerminal,
      },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

let client: QueryClient;
function mount(sandboxId = "sbx-1") {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <SandboxDetailPage lang="en-US" sandboxId={sandboxId} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) =>
  server.current.calls.filter((call) => call.procedure === procedure);
const sandbox = () => server.current.sandboxes[0]!;
const stateShown = () =>
  document.querySelector<HTMLElement>("[data-sandbox-state]")?.dataset.sandboxState;
/** The destroy prompt names the sandbox ("Type quiet-otter to confirm"). */
const DESTROY_PROMPT = new RegExp(`^${enSandboxes.destroy.prompt.replace("{{name}}", ".+")}$`);
const moreActions = () => screen.queryByRole("button", { name: enSandboxes.actionsLabel });
/**
 * Whether the page offers the header action `name`: a visible button, or an
 * item of the "Sandbox actions" menu (opened, read and closed again).
 */
async function offered(name: string): Promise<boolean> {
  if (screen.queryByRole("button", { name })) return true;
  const trigger = moreActions();
  if (!trigger) return false;
  const user = userEvent.setup();
  await user.click(trigger);
  const items = await screen.findAllByRole("menuitem");
  const found = items.some((item) => item.textContent === name);
  await user.keyboard("{Escape}");
  await waitFor(() => expect(screen.queryByRole("menu")).toBeNull());
  return found;
}
/** Runs the header action `name`: its button, or its item in the "Sandbox actions" menu. */
async function chooseAction(user: ReturnType<typeof userEvent.setup>, name: string) {
  const target = await waitFor(() => {
    const found = screen.queryByRole("button", { name }) ?? moreActions();
    if (!found) throw new Error(`no ${name} action`);
    return found;
  });
  await user.click(target);
  if (target === moreActions()) await user.click(await screen.findByRole("menuitem", { name }));
}
/** Refetch everything, then let TanStack Query's batched notifications render. */
const refetch = () =>
  act(async () => {
    await client.refetchQueries();
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
const keyOf = (call: { input: unknown } | undefined) =>
  (call?.input as { idempotencyKey?: string } | undefined)?.idempotencyKey;
const receipt = (kind: string, state: string) => ({
  id: `op-${kind}-${state}`,
  kind,
  state,
  errorCode: null,
  createdAt: new Date(),
  completedAt: null,
});

beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: true,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  browserAuthority.impersonatedBy = null;
  server.current = newFakeSandboxServer();
  server.current.hosts = [fakeHost()];
  server.current.templates = [fakeTemplate()];
  server.current.sandboxes = [sandboxRow()];
  navigate.mockReset();
  toast.success.mockReset();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("reading a sandbox", () => {
  it("has exactly one page heading, the sandbox name, and its full ID copyable under Advanced", async () => {
    mount();
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("quiet-otter");
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
    const advanced = document.querySelector<HTMLElement>(
      'section[aria-labelledby="sandbox-overview"] [data-advanced-details]',
    )!;
    expect(advanced.hasAttribute("open")).toBe(false);
    expect(
      within(advanced).getByRole("button", { name: `Copy ${enSandboxes.detail.sandboxId}` }),
    ).toBeTruthy();
  });

  it("shows this sandbox's recent CLI connections, one bounded page", async () => {
    server.current.connectSessions = [
      {
        id: "c-1",
        sandboxId: "sbx-1",
        keyId: "key-1",
        keyName: "ci key",
        hostId: "host-1",
        origin: "CLI_LOGIN",
        openedAt: new Date(Date.now() - 60_000),
        closedAt: null,
        status: "open",
        closeIntent: null,
        ptyChannels: 1,
        execChannels: 0,
        relayChannels: 0,
        forwardedPorts: [],
        bytesIn: "10",
        bytesOut: "20",
      },
      { id: "c-other", sandboxId: "sbx-other", keyName: "elsewhere" },
    ];
    mount();
    const panel = await screen.findByRole("region", { name: enSandboxes.connections.heading });
    expect(await within(panel).findByText("ci key")).toBeTruthy();
    expect(within(panel).queryByText("elsewhere")).toBeNull();
    const input = server.current.calls.find((call) => call.procedure === "listConnectSessions")
      ?.input as { id: string; limit: number };
    expect(input.id).toBe("sbx-1");
    expect(input.limit).toBeLessThanOrEqual(100);
  });

  it("shows the commands that connect to this sandbox", async () => {
    mount();
    const panel = await screen.findByRole("region", { name: enSandboxes.connect.heading });
    const commands = within(panel).getByRole("list", { name: enSandboxes.connect.label });
    expect(within(commands).getByText("wssp sandbox shell quiet-otter")).toBeTruthy();
    expect(within(commands).getByText("ssh quiet-otter.wssp")).toBeTruthy();
    expect(within(panel).getByText("wssp ssh-config --install", { selector: "code" })).toBeTruthy();
    expect(panel.textContent).toContain(enSandboxes.connect.sshSetup.replace(/<\/?code>/g, ""));
    expect(esSandboxes.connect.sshCommand).toBe(enSandboxes.connect.sshCommand);
  });

  it.each([401, 403, 404])(
    "hides previously loaded sandbox detail after HTTP %s",
    async (status) => {
      mount();
      await screen.findByRole("heading", { level: 1, name: "quiet-otter" });
      // The detail retries once on non-404 errors.
      server.current.errors.getSandbox = Array.from({ length: 2 }, () =>
        Object.assign(new Error("denied"), { status }),
      );
      await refetch();
      await waitFor(() =>
        expect(screen.queryByRole("heading", { level: 1, name: "quiet-otter" })).toBeNull(),
      );
      expect(screen.queryByRole("button", { name: enSandboxes.destroy.action })).toBeNull();
    },
  );

  it("retains sandbox detail with retry after a transient refetch failure", async () => {
    mount();
    await screen.findByRole("heading", { level: 1, name: "quiet-otter" });
    server.current.errors.getSandbox = [new Error("offline"), new Error("offline")];
    await refetch();
    await screen.findByText(enSandboxes.detail.loadFailed);
    expect(screen.getByRole("heading", { level: 1, name: "quiet-otter" })).toBeTruthy();
  });

  it("shows the terminal, but nothing connects until the owner attaches (C54)", async () => {
    const sockets = vi.fn();
    vi.stubGlobal("WebSocket", sockets);
    mount();
    await screen.findByRole("heading", { name: enTerminal.title });
    await refetch();
    expect(document.querySelectorAll("[data-terminal-status]")).toHaveLength(1);
    const attach = screen.getByRole("button", { name: enTerminal.actions.attach });
    expect((attach as HTMLButtonElement).disabled).toBe(false);
    expect(sockets).not.toHaveBeenCalled();
  });

  it("a stopped sandbox's terminal cannot be attached", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" })];
    mount();
    await screen.findByRole("heading", { name: enTerminal.title });
    const attach = screen.getByRole("button", { name: enTerminal.actions.attach });
    expect((attach as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(enTerminal.unavailable)).toBeTruthy();
  });

  it("another owner's (or a missing) sandbox is a plain not-found, with no actions", async () => {
    server.current.sandboxes = [];
    mount("sbx-foreign");
    expect(await screen.findByText(enSandboxes.detail.notFoundTitle)).toBeTruthy();
    expect(document.querySelector("[data-sandbox-missing]")).not.toBeNull();
    expect(calls("getSandbox")).toEqual([
      { procedure: "getSandbox", input: { id: "sbx-foreign" } },
    ]);
    expect(screen.queryByRole("button", { name: enSandboxes.destroy.action })).toBeNull();
    expect(calls("getTemplate")).toEqual([]);
  });

  it("a failed load (not a 404) offers a retry that recovers", async () => {
    // The page retries a failed read once (never a 404) before showing the error.
    server.current.errors.getSandbox = [new Error("network"), new Error("network")];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enCommon.actions.tryAgain }));
    expect(await screen.findByText(enSandboxes.lifetime.title)).toBeTruthy();
    expect(screen.queryByText(enSandboxes.detail.notFoundTitle)).toBeNull();
  });

  it("an archived template revision is shown through getTemplateRevision", async () => {
    const retiredAt = new Date();
    server.current.templates = [fakeTemplate({ retiredAt, sandboxHostId: null, host: null })];
    server.current.sandboxes = [
      sandboxRow({
        state: "STOPPED",
        template: {
          id: "tpl-1",
          revisionId: "tpl-1",
          revision: 1,
          slug: "ubuntu",
          label: "Ubuntu",
          archivedAt: null,
          retiredAt,
        },
      }),
    ];
    mount();
    // Short, under Advanced; the full value goes on the clipboard.
    await screen.findByText("sha256:abababababab…");
    expect(calls("getTemplateRevision")).toEqual([
      { procedure: "getTemplateRevision", input: { id: "tpl-1" } },
    ]);
    expect(document.querySelector("p[data-sandbox-template]")?.textContent).toBe(
      "Ubuntu (archived)",
    );
    // The template name links to Templates.
    expect(document.querySelector("p[data-sandbox-template] a")?.getAttribute("href")).toBe(
      "/en-US/dashboard/templates",
    );
    expect(screen.getByText("UID 1000, GID 1000, /home/user, /bin/bash")).toBeTruthy();
  });

  it("shows the recorded egress allowlist: static CIDRs and domain grants (C37)", async () => {
    server.current.sandboxes = [
      sandboxRow({
        egress: { mode: "allowlist", domains: ["registry.example.com"], cidrs: ["128.66.0.0/24"] },
      }),
    ];
    mount();
    await screen.findByText(enSandboxes.egress.title);
    const section = document.querySelector('[data-sandbox-egress="allowlist"]');
    expect(section).not.toBeNull();
    expect(within(section as HTMLElement).getByText(enSandboxes.egress.cidrs)).toBeTruthy();
    expect(section?.querySelector('[data-egress-cidr="128.66.0.0/24"]')?.textContent).toBe(
      "128.66.0.0/24",
    );
    expect(within(section as HTMLElement).getByText(enSandboxes.egress.domains)).toBeTruthy();
    expect(section?.querySelector('[data-egress-domain="registry.example.com"]')?.textContent).toBe(
      "registry.example.com",
    );
    expect(section?.textContent).toContain(enSandboxes.egress.domainsHint);
    // SEED-4: the recorded names are the request, not live grant state.
    expect(enSandboxes.egress.domains).toBe("Requested domains");
    expect(section?.textContent).not.toContain("Allowed domains");
    expect(section?.querySelector("[data-egress-domains-lapse]")?.textContent).toBe(
      enSandboxes.egress.domainsLapse,
    );
    expect(section?.textContent).toContain(enSandboxes.egress.immutable);
  });

  it("a deny-all egress policy says so (also the read-back for pre-policy sandboxes)", async () => {
    server.current.sandboxes = [
      sandboxRow({ egress: { mode: "allowlist", domains: [], cidrs: [] } }),
    ];
    mount();
    await screen.findByText(enSandboxes.egress.title);
    const section = document.querySelector('[data-sandbox-egress="deny-all"]');
    expect(section).not.toBeNull();
    expect(section?.textContent).toContain(enSandboxes.egress.denyAll);
    expect(section?.querySelector("[data-egress-cidr]")).toBeNull();
    expect(section?.querySelector("[data-egress-domain]")).toBeNull();
  });

  it("open egress shows the mode and the unused fallback grants", async () => {
    server.current.sandboxes = [
      sandboxRow({
        egress: { mode: "open", domains: [], cidrs: [] },
        egressRequest: { mode: "open", domains: ["registry.example.com"], cidrs: [] },
      }),
    ];
    mount();
    await screen.findByText(enSandboxes.egress.title);
    const section = document.querySelector('[data-sandbox-egress="open"]');
    expect(section?.querySelector('[data-egress-mode="open"]')?.textContent).toBe(
      enSandboxes.egress.mode.open,
    );
    expect(section?.textContent).toContain(enSandboxes.egress.openHint);
    expect(section?.querySelector("[data-egress-domain]")).toBeNull();
    expect(
      section?.querySelector('[data-egress-fallback-domain="registry.example.com"]'),
    ).not.toBeNull();
    expect(section?.textContent).toContain(enSandboxes.egress.fallbackHint);
    expect(section?.querySelector("[data-egress-reason]")).toBeNull();
  });

  it.each(["node_policy", "host_unsupported"] as const)(
    "an open request placed as an allowlist explains why (%s) and lists refused grants",
    async (reason) => {
      server.current.sandboxes = [
        sandboxRow({
          egress: { mode: "allowlist", domains: ["registry.example.com"], cidrs: [] },
          egressRequest: {
            mode: "open",
            domains: ["registry.example.com", "blocked.example.com"],
            cidrs: [],
          },
          egressModeReason: reason,
          egressDeniedGrants: ["blocked.example.com"],
        }),
      ];
      mount();
      await screen.findByText(enSandboxes.egress.title);
      const section = document.querySelector('[data-sandbox-egress="allowlist"]');
      expect(section?.querySelector('[data-egress-mode="allowlist"]')?.textContent).toBe(
        enSandboxes.egress.mode.allowlist,
      );
      expect(section?.querySelector(`[data-egress-reason="${reason}"]`)?.textContent).toBe(
        enSandboxes.egress.reason[reason],
      );
      expect(section?.querySelector('[data-egress-domain="registry.example.com"]')).not.toBeNull();
      expect(
        section?.querySelector('[data-egress-denied="blocked.example.com"]')?.textContent,
      ).toBe("blocked.example.com");
      expect(section?.textContent).toContain(enSandboxes.egress.denied);
      // Effective allowlist: the request's grants are not repeated as fallback grants.
      expect(section?.querySelector("[data-egress-fallback]")).toBeNull();
    },
  );

  it("a waiting create shows its requested mode, not the deny-all read-back", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "WAITING_FOR_CAPACITY",
        egress: { mode: "allowlist", domains: [], cidrs: [] },
        egressRequest: { mode: "open", domains: [], cidrs: [] },
      }),
    ];
    mount();
    await screen.findByText(enSandboxes.egress.title);
    const section = document.querySelector('[data-sandbox-egress="open"]');
    expect(section?.querySelector("[data-egress-pending]")?.textContent).toBe(
      enSandboxes.egress.pending,
    );
  });

  it.each([
    ["open_egress_not_permitted", "revoked", "data-egress-revoked"],
    ["egress_guard_unavailable", "guardUnavailable", "data-egress-guard-unavailable"],
  ] as const)("a %s refusal is explained next to the error", async (code, key, attribute) => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED", lastErrorCode: code })];
    mount();
    const hint = await waitFor(() => {
      const found = document.querySelector(`[${attribute}]`);
      if (!found) throw new Error("no hint");
      return found;
    });
    expect(hint.textContent).toBe(enSandboxes.egress[key]);
  });

  it("shows effective guest root, the degrade reason and the guest-attested note", async () => {
    server.current.sandboxes = [
      sandboxRow({
        guestSudo: false,
        guestSudoRequested: true,
        guestSudoReason: "node_policy",
        guestRoot: false,
      }),
    ];
    mount();
    await screen.findByText(enSandboxes.guestRoot.title);
    const card = document.querySelector('[data-sandbox-guest-sudo="off"]');
    expect(card?.querySelector('[data-guest-sudo-reason="node_policy"]')?.textContent).toBe(
      enSandboxes.guestRoot.reason.node_policy,
    );
    expect(card?.querySelector("[data-guest-root]")).toBeNull();
    expect(card?.querySelector("[data-guest-root-hint]")).toBeNull();
  });

  it("a guestRoot sandbox is marked and its results are labelled guest-attested", async () => {
    mount();
    await screen.findByText(enSandboxes.guestRoot.title);
    const card = document.querySelector('[data-sandbox-guest-sudo="on"]');
    expect(card?.querySelector("[data-guest-root]")?.textContent).toBe(
      enSandboxes.guestRoot.mayRunAsRoot,
    );
    expect(card?.querySelector("[data-guest-root-hint]")?.textContent).toBe(
      enSandboxes.guestRoot.attested,
    );
  });

  it("a guest_sudo_not_permitted refusal is explained next to the error", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "STOPPED", lastErrorCode: "guest_sudo_not_permitted" }),
    ];
    mount();
    const hint = await waitFor(() => {
      const found = document.querySelector("[data-guest-sudo-revoked]");
      if (!found) throw new Error("no hint");
      return found;
    });
    expect(hint.textContent).toBe(enSandboxes.guestRoot.revoked);
  });

  it("links to this sandbox's operations", async () => {
    mount();
    const link = await screen.findByRole("link", { name: enSandboxes.detail.operations });
    expect(link.getAttribute("href")).toBe("/en-US/dashboard/operations");
    expect(link.getAttribute("data-search")).toBe(JSON.stringify({ sandboxId: "sbx-1" }));
  });

  it("an offline host and an unknown outcome stay visible", async () => {
    server.current.sandboxes = [
      sandboxRow({
        host: fakeHost({
          status: "DISCONNECTED",
          lastConnectedAt: new Date(Date.now() - 3_600_000),
        }),
        lastLifecycleOperation: receipt("STOP_SANDBOX", "UNKNOWN_OUTCOME"),
      }),
    ];
    mount();
    const banner = await waitFor(() => {
      const found = document.querySelector("[data-host-offline]");
      if (!found) throw new Error("no banner");
      return found;
    });
    expect(banner.textContent).toContain(enHosts.status.offline);
    const shown = document.querySelector('[data-receipt-state="UNKNOWN_OUTCOME"]');
    expect(shown?.textContent).toContain("Stop: Outcome unknown");
    expect(shown?.textContent).toContain(enSandboxes.receipt.hint.UNKNOWN_OUTCOME);
  });

  it("an expiry the host enforced offline is shown next to requested and effective", async () => {
    const at = new Date(Date.now() - 60_000);
    server.current.sandboxes = [
      sandboxRow({
        state: "STOPPED",
        leaseRevision: 3,
        leaseExpiresAtEffective: at,
        leaseExpireActionEffective: "STOP",
        hostExpiryConfirmedAt: new Date(),
        hostExpiryRevision: 3,
        hostExpiryAction: "STOP",
      }),
    ];
    mount();
    const shown = await waitFor(() => {
      const found = document.querySelector("[data-host-expiry]");
      if (!found) throw new Error("no host expiry");
      return found;
    });
    expect(shown.getAttribute("data-host-expiry")).toBe("3");
    expect(shown.textContent).toContain("the host stopped this VM");
    expect(shown.textContent).toContain("revision 3");
    expect(document.querySelector("[data-lease-effective]")).not.toBeNull();
    expect(document.querySelector("[data-lease-requested]")).not.toBeNull();
  });

  it("a lease from READY shows its pending start, not the provisioning backstop", async () => {
    // Accepted for 5 minutes; until READY the stored deadline is the backstop
    // (timeout plus the provision maximum), about two hours out.
    const backstop = new Date(Date.now() + 2 * 3_600_000 + 5 * 60_000);
    server.current.sandboxes = [
      sandboxRow({
        state: "PROVISIONING",
        leasePendingReady: true,
        leaseExpiresAt: backstop,
        leaseExpiresAtRequested: backstop,
        leaseExpiresAtEffective: null,
        leaseExpireActionEffective: null,
      }),
    ];
    mount();
    const deadline = await waitFor(() => {
      const found = document.querySelector("[data-lease-deadline]");
      if (!found) throw new Error("no deadline");
      return found;
    });
    expect(deadline.textContent).toBe(enSandboxes.lifetime.startsAtReady);
    expect(document.querySelector("[data-lease-requested]")?.textContent).toBe(
      enSandboxes.lifetime.startsAtReady,
    );
    expect(document.body.textContent).not.toMatch(/in 2 hours/);
  });

  it("a destroy the host enforced offline stays visible on the deleted sandbox", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "DELETED",
        host: null,
        sandboxHostId: null,
        hostExpiryConfirmedAt: new Date(),
        hostExpiryRevision: 2,
        hostExpiryAction: "DESTROY",
      }),
    ];
    mount();
    const shown = await waitFor(() => {
      const found = document.querySelector("[data-host-expiry]");
      if (!found) throw new Error("no host expiry");
      return found;
    });
    expect(shown.textContent).toContain("the host destroyed this VM");
    expect(document.querySelector("[data-lease-effective]")).toBeNull();
  });

  it("an offline stop expiry followed by an explicit destroy still reads as a stop", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "DELETED",
        host: null,
        sandboxHostId: null,
        hostExpiryConfirmedAt: new Date(),
        hostExpiryRevision: 1,
        hostExpiryAction: "STOP",
        lastLifecycleOperation: receipt("KILL_SANDBOX", "SUCCEEDED"),
      }),
    ];
    mount();
    const shown = await waitFor(() => {
      const found = document.querySelector("[data-host-expiry]");
      if (!found) throw new Error("no host expiry");
      return found;
    });
    expect(shown.textContent).toContain("the host stopped this VM");
    expect(shown.textContent).not.toContain("destroyed");
  });

  it("a missing instance and a quarantined host are explained", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "ERROR",
        lastErrorCode: "instance_missing",
        host: fakeHost({ quarantinedAt: new Date() }),
      }),
    ];
    mount();
    const banner = await waitFor(() => {
      const found = document.querySelector("[data-host-quarantined]");
      if (!found) throw new Error("no banner");
      return found;
    });
    expect(banner.textContent).toContain("Host Alpha is quarantined");
    expect(document.querySelector("[data-instance-missing]")?.textContent).toBe(
      enSandboxes.lifetime.instanceMissing,
    );
  });

  it("a never-issued allocation explains released capacity without claiming a lost disk", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "ERROR", lastErrorCode: "host_effect_not_issued" }),
    ];
    mount();
    await waitFor(() =>
      expect(document.querySelector("[data-effect-not-issued]")?.textContent).toBe(
        enSandboxes.lifetime.hostEffectNotIssued,
      ),
    );
    expect(document.querySelector("[data-instance-missing]")).toBeNull();
    expect(document.querySelector("[data-start-not-issued]")).toBeNull();
  });

  it("a refused cold start offers retry and never the destroy hint", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "STOPPED", lastErrorCode: "host_effect_not_issued" }),
    ];
    mount();
    await waitFor(() =>
      expect(document.querySelector("[data-start-not-issued]")?.textContent).toBe(
        enSandboxes.lifetime.startNotIssued,
      ),
    );
    expect(document.querySelector("[data-effect-not-issued]")).toBeNull();
    expect(document.body.textContent).not.toContain(enSandboxes.lifetime.hostEffectNotIssued);
  });

  it("a carry-cap stop explains the disconnect expiry, not a never-issued effect", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "ERROR", lastErrorCode: "host_disconnect_expired" }),
    ];
    mount();
    await waitFor(() =>
      expect(document.querySelector("[data-host-disconnect-expired]")?.textContent).toBe(
        enSandboxes.lifetime.hostDisconnectExpired,
      ),
    );
    expect(document.querySelector("[data-effect-not-issued]")).toBeNull();
  });

  it("a host expiry failure shows the host's reason", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "ERROR",
        lastErrorCode: "expiry_failed",
        expiryFailureReason: "unknown_outcome: stop failed",
      }),
    ];
    mount();
    const shown = await waitFor(() => {
      const found = document.querySelector("[data-expiry-failed]");
      if (!found) throw new Error("no expiry failure");
      return found;
    });
    expect(shown.textContent).toBe(
      enSandboxes.lifetime.expiryFailed.replace("{{reason}}", "unknown_outcome: stop failed"),
    );
    expect(document.querySelector("[data-instance-missing]")).toBeNull();
  });

  it("no offline expiry notice before the host confirmed one", async () => {
    mount();
    await screen.findByText(enSandboxes.lifetime.title);
    expect(document.querySelector("[data-host-expiry]")).toBeNull();
    expect(document.querySelector("[data-host-quarantined]")).toBeNull();
  });
});

describe("lifecycle", () => {
  it("create → pending → ready: each step is what the server reported", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "REQUESTED",
        lastLifecycleOperation: receipt("CREATE_SANDBOX", "QUEUED"),
      }),
    ];
    mount();
    await waitFor(() => expect(stateShown()).toBe("REQUESTED"));
    expect(document.querySelector('[data-receipt-state="QUEUED"]')?.textContent).toContain(
      "Create: Queued",
    );
    expect(screen.getByText(enSandboxes.stateHint.starting)).toBeTruthy();
    // Stop and destroy can interrupt boot; guest work still requires readiness.
    expect(await offered(enSandboxes.stop.action)).toBe(true);
    expect(await offered(enSandboxes.renew.action)).toBe(false);
    expect(screen.queryByRole("heading", { name: enSandboxes.files.title })).toBeNull();
    expect(await offered(enSandboxes.destroy.action)).toBe(true);

    Object.assign(sandbox(), {
      state: "PROVISIONING",
      lastLifecycleOperation: receipt("CREATE_SANDBOX", "RUNNING"),
    });
    await refetch();
    expect(stateShown()).toBe("PROVISIONING");
    expect(await offered(enSandboxes.stop.action)).toBe(true);

    Object.assign(sandbox(), {
      state: "READY",
      lastLifecycleOperation: receipt("CREATE_SANDBOX", "SUCCEEDED"),
    });
    await refetch();
    expect(stateShown()).toBe("READY");
    expect(await offered(enSandboxes.stop.action)).toBe(true);
    expect(screen.getByRole("heading", { name: enSandboxes.files.title })).toBeTruthy();
  });

  it.each(["REQUESTED", "SCHEDULED", "PROVISIONING"] as const)(
    "Stop can be confirmed during %s without offering guest actions",
    async (state) => {
      server.current.sandboxes = [
        sandboxRow({ state, lastLifecycleOperation: receipt("CREATE_SANDBOX", "RUNNING") }),
      ];
      const user = userEvent.setup();
      mount();
      await user.click(await screen.findByRole("button", { name: enSandboxes.stop.action }));
      const confirm = screen.getByRole("alertdialog");
      expect(within(confirm).getByText(enSandboxes.stop.bootDescription)).toBeTruthy();
      expect(within(confirm).queryByText(enSandboxes.stop.description)).toBeNull();
      await user.click(within(confirm).getByRole("button", { name: enSandboxes.stop.confirm }));
      await waitFor(() => expect(calls("stopSandbox")).toHaveLength(1));
      await waitFor(() => expect(stateShown()).toBe("STOPPING"));
      expect(await offered(enSandboxes.start.action)).toBe(false);
      Object.assign(sandbox(), { state: "DELETED", sandboxHostId: null, host: null });
      await refetch();
      expect(stateShown()).toBe("DELETED");
      expect(await offered(enSandboxes.start.action)).toBe(false);
    },
  );

  it("stop is confirmed, keeps the disk, and shows STOPPING until the host reports STOPPED", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.stop.action }));
    const confirm = screen.getByRole("alertdialog");
    expect(within(confirm).getByText(enSandboxes.stop.description)).toBeTruthy();
    expect(within(confirm).queryByText(enSandboxes.stop.bootDescription)).toBeNull();
    // The dialog names the disk's offload policy (the fake's default, on_stop).
    expect(confirm.querySelector("[data-stop-offload-policy]")?.textContent).toBe(
      `${enSandboxes.stop.offloadPolicy} ${enSandboxes.disk.policy.on_stop}`,
    );
    await user.click(within(confirm).getByRole("button", { name: enCommon.actions.cancel }));
    expect(calls("stopSandbox")).toEqual([]);

    await user.click(screen.getByRole("button", { name: enSandboxes.stop.action }));
    await user.click(
      within(screen.getByRole("alertdialog")).getByRole("button", {
        name: enSandboxes.stop.confirm,
      }),
    );
    await waitFor(() => expect(calls("stopSandbox")).toHaveLength(1));
    expect(calls("killSandbox")).toEqual([]);
    await waitFor(() => expect(stateShown()).toBe("STOPPING"));
    expect(document.querySelector('[data-receipt-kind="STOP_SANDBOX"]')).not.toBeNull();

    Object.assign(sandbox(), {
      state: "STOPPED",
      lastLifecycleOperation: receipt("STOP_SANDBOX", "SUCCEEDED"),
    });
    await refetch();
    expect(stateShown()).toBe("STOPPED");
    expect(screen.getByText(enSandboxes.stateHint.stopped)).toBeTruthy();
    expect(await offered(enSandboxes.start.action)).toBe(true);
  });

  it.each([enSandboxes, esSandboxes])(
    "Stop copy uses the locale's visible state labels",
    (locale) => {
      expect(locale.stop.bootDescription).toContain(locale.state.STOPPED);
      expect(locale.stop.bootDescription).toContain(locale.state.DELETED);
      expect(locale.stop.description).toContain(locale.state.STOPPED);
      expect(locale.stop.description).not.toContain(locale.state.DELETED);
    },
  );

  it("a create waiting for capacity never claims a host, a lifetime or a VM to delete", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "WAITING_FOR_CAPACITY",
        originPoolId: "pool-1",
        sandboxHostId: null,
        storagePoolId: null,
        storagePoolName: null,
        host: null,
        leaseExpiresAt: null,
        leaseExpiresAtRequested: null,
        leaseRevision: 0,
      }),
    ];
    const user = userEvent.setup();
    mount();
    const host = await waitFor(() => {
      const node = document.querySelector("[data-sandbox-host]");
      expect(node).not.toBeNull();
      return node!;
    });
    expect(host.textContent).toBe(enSandboxes.fields.noHostWaiting);
    expect(document.body.textContent).not.toContain(enSandboxes.fields.noHost);
    expect(screen.getByText(enSandboxes.lifetime.waiting)).toBeTruthy();
    expect(document.body.textContent).not.toContain(enSandboxes.lifetime.ack.pending);
    expect(await offered(enSandboxes.destroy.action)).toBe(false);
    await chooseAction(user, enSandboxes.destroy.waitingAction);
    const confirm = screen.getByRole("alertdialog");
    expect(within(confirm).getByText(enSandboxes.destroy.waitingTitle)).toBeTruthy();
    expect(within(confirm).getByText(enSandboxes.destroy.waitingDescription)).toBeTruthy();
    expect(confirm.textContent).not.toContain(enSandboxes.destroy.description);
    const button = within(confirm).getByRole("button", {
      name: enSandboxes.destroy.waitingConfirm,
    });
    await user.type(within(confirm).getByLabelText(DESTROY_PROMPT), "quiet-otter");
    await user.click(button);
    await waitFor(() => expect(calls("killSandbox")).toHaveLength(1));
  });

  it.each(["KILL_SANDBOX", "STOP_SANDBOX"])(
    "offers confirmed destroy for UNKNOWN %s in STOPPING",
    async (kind) => {
      server.current.sandboxes = [
        sandboxRow({ state: "STOPPING", lastLifecycleOperation: receipt(kind, "UNKNOWN_OUTCOME") }),
      ];
      const user = userEvent.setup();
      mount();
      await chooseAction(user, enSandboxes.destroy.action);
      const confirm = screen.getByRole("alertdialog");
      expect(within(confirm).getByText(enSandboxes.destroy.recoveryDescription)).toBeTruthy();
      const button = within(confirm).getByRole("button", { name: enSandboxes.destroy.confirm });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      await user.type(within(confirm).getByLabelText(DESTROY_PROMPT), "quiet-otter");
      await user.click(button);
      await waitFor(() => expect(calls("killSandbox")).toHaveLength(1));
      expect(calls("stopSandbox")).toHaveLength(0);
      expect(stateShown()).toBe("STOPPING");
    },
  );

  it.each(["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED"])(
    "offers type-confirmed destroy while a %s Stop is in flight",
    async (state) => {
      server.current.sandboxes = [
        sandboxRow({ state: "STOPPING", lastLifecycleOperation: receipt("STOP_SANDBOX", state) }),
      ];
      const user = userEvent.setup();
      mount();
      await chooseAction(user, enSandboxes.destroy.action);
      const confirm = screen.getByRole("alertdialog");
      const button = within(confirm).getByRole("button", { name: enSandboxes.destroy.confirm });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      await user.type(within(confirm).getByLabelText(DESTROY_PROMPT), "quiet-otter");
      await user.click(button);
      await waitFor(() => expect(calls("killSandbox")).toHaveLength(1));
      expect(calls("stopSandbox")).toHaveLength(0);
      expect(stateShown()).toBe("STOPPING");
    },
  );

  it.each(["CREATE_SANDBOX", "RECONNECT_SANDBOX"])(
    "does not offer destroy for UNKNOWN %s in STOPPING",
    async (kind) => {
      server.current.sandboxes = [
        sandboxRow({ state: "STOPPING", lastLifecycleOperation: receipt(kind, "UNKNOWN_OUTCOME") }),
      ];
      mount();
      await waitFor(() => expect(stateShown()).toBe("STOPPING"));
      expect(await offered(enSandboxes.destroy.action)).toBe(false);
    },
  );

  it.each(["QUEUED", "DISPATCHED", "ACCEPTED", "RUNNING", "CANCEL_REQUESTED", "SUCCEEDED"])(
    "does not offer destroy for %s Kill in STOPPING",
    async (state) => {
      server.current.sandboxes = [
        sandboxRow({ state: "STOPPING", lastLifecycleOperation: receipt("KILL_SANDBOX", state) }),
      ];
      mount();
      await waitFor(() => expect(stateShown()).toBe("STOPPING"));
      expect(await offered(enSandboxes.destroy.action)).toBe(false);
    },
  );

  it("UNKNOWN destroy recovery uses a fresh key after an accepted response was lost", async () => {
    server.current.lostResponses.killSandbox = 1;
    const user = userEvent.setup();
    mount();
    const destroyOnce = async () => {
      await chooseAction(user, enSandboxes.destroy.action);
      const dialog = screen.getByRole("alertdialog");
      await user.clear(within(dialog).getByLabelText(DESTROY_PROMPT));
      await user.type(within(dialog).getByLabelText(DESTROY_PROMPT), "quiet-otter");
      await user.click(within(dialog).getByRole("button", { name: enSandboxes.destroy.confirm }));
    };
    await destroyOnce();
    await waitFor(() => expect(calls("killSandbox")).toHaveLength(1));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    const earlier = sandbox().lastLifecycleOperation as { state: string };
    earlier.state = "UNKNOWN_OUTCOME";
    await refetch();
    await destroyOnce();
    await waitFor(() => expect(calls("killSandbox")).toHaveLength(2));
    expect(keyOf(calls("killSandbox")[1])).not.toBe(keyOf(calls("killSandbox")[0]));
  });

  it("renames through a Sheet, lowercasing as the user types, and shows name_taken inline", async () => {
    server.current.sandboxes = [sandboxRow(), sandboxRow({ id: "sbx-2", name: "brisk-heron" })];
    const user = userEvent.setup();
    mount();
    await chooseAction(user, enSandboxes.rename.action);
    const sheet = screen.getByRole("dialog");
    const field = within(sheet).getByLabelText(enSandboxes.rename.label);
    expect(field.getAttribute("autocomplete")).toBe("off");
    await user.clear(field);
    await user.type(field, "Brisk-Heron");
    expect((field as HTMLInputElement).value).toBe("brisk-heron");
    await user.click(within(sheet).getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() =>
      expect(within(sheet).getByRole("alert").textContent).toBe(enSandboxes.problem.nameTaken),
    );
    await user.clear(field);
    await user.type(field, "nightly-build");
    await user.click(within(sheet).getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() => expect(calls("updateSandbox")).toHaveLength(2));
    expect(calls("updateSandbox")[1]!.input).toEqual({ id: "sbx-1", name: "nightly-build" });
    await waitFor(() =>
      expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("nightly-build"),
    );
  });

  it("an invalid name is refused in the Sheet before any request", async () => {
    const user = userEvent.setup();
    mount();
    await chooseAction(user, enSandboxes.rename.action);
    const sheet = screen.getByRole("dialog");
    const field = within(sheet).getByLabelText(enSandboxes.rename.label);
    await user.clear(field);
    await user.type(field, "wssp-reserved");
    await user.click(within(sheet).getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() => expect(within(sheet).getByText(enSandboxes.draft.name)).toBeTruthy());
    expect(calls("updateSandbox")).toEqual([]);
  });

  it("destroy confirms the name captured when the dialog opened (F8)", async () => {
    const user = userEvent.setup();
    mount();
    await chooseAction(user, enSandboxes.destroy.action);
    // A rename lands (another tab) and the page refetches while the dialog is open.
    server.current.sandboxes[0]!.name = "renamed-elsewhere";
    await refetch();
    const confirm = screen.getByRole("alertdialog");
    const destroy = within(confirm).getByRole("button", { name: enSandboxes.destroy.confirm });
    await user.type(within(confirm).getByLabelText(DESTROY_PROMPT), "quiet-otter");
    expect((destroy as HTMLButtonElement).disabled).toBe(false);
  });

  it("destroy needs the typed sandbox name, is distinct from stop, and never shows DELETED early", async () => {
    const user = userEvent.setup();
    mount();
    await chooseAction(user, enSandboxes.destroy.action);
    const confirm = screen.getByRole("alertdialog");
    expect(within(confirm).getByText(enSandboxes.destroy.description)).toBeTruthy();
    const destroy = within(confirm).getByRole("button", { name: enSandboxes.destroy.confirm });
    expect((destroy as HTMLButtonElement).disabled).toBe(true);
    await user.type(within(confirm).getByLabelText(DESTROY_PROMPT), "quiet-otter-2");
    expect((destroy as HTMLButtonElement).disabled).toBe(true);
    await user.clear(within(confirm).getByLabelText(DESTROY_PROMPT));
    await user.type(within(confirm).getByLabelText(DESTROY_PROMPT), "quiet-otter");
    await user.click(destroy);
    await waitFor(() => expect(calls("killSandbox")).toHaveLength(1));
    expect(calls("stopSandbox")).toEqual([]);
    // The server answered STOPPING; the page does not assume the VM is gone.
    await waitFor(() => expect(stateShown()).toBe("STOPPING"));
    expect(screen.queryByText(enSandboxes.state.DELETED)).toBeNull();

    Object.assign(sandbox(), {
      state: "DELETED",
      sandboxHostId: null,
      host: null,
      lastLifecycleOperation: receipt("KILL_SANDBOX", "SUCCEEDED"),
    });
    await refetch();
    expect(stateShown()).toBe("DELETED");
    expect(await offered(enSandboxes.destroy.action)).toBe(false);
    expect(screen.queryByText(enSandboxes.lifetime.title)).toBeNull();
  });

  it("renewal: requested moves at once, the host acknowledgement arrives later", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    const renewDialog = screen.getByRole("dialog");
    // The hint never names a default that differs from the preselected choice.
    expect(renewDialog.textContent).not.toMatch(/Five minutes by default/);
    expect(within(renewDialog).getByText(enSandboxes.lifetime.hint)).toBeTruthy();
    await selectOption(
      user,
      within(renewDialog).getByLabelText(enSandboxes.lifetime.field),
      /^(4 hours|4 horas)$/,
    );
    expect(within(renewDialog).queryByRole("radio")).toBeNull();
    await user.click(within(renewDialog).getByRole("button", { name: enSandboxes.renew.submit }));
    await waitFor(() => expect(calls("setSandboxTimeout")).toHaveLength(1));
    const input = calls("setSandboxTimeout")[0]!.input as {
      id: string;
      timeoutMs: number;
      idempotencyKey: string;
    };
    expect(input).toMatchObject({ id: "sbx-1", timeoutMs: 240 * 60_000 });
    expect(input).not.toHaveProperty("onExpire");
    // Delay: the host has not acknowledged the new term yet.
    await waitFor(() =>
      expect(document.querySelector("[data-lease-effective]")?.textContent).toBe(
        enSandboxes.lifetime.notAcknowledged,
      ),
    );
    expect(document.querySelector("[data-lease-effective]")?.getAttribute("data-lease-ack")).toBe(
      "pending",
    );
    expect(document.querySelector("[data-lease-requested]")?.textContent).toMatch(
      /in 4 hours, then stop/,
    );
    expect(screen.getByText("Revision 2")).toBeTruthy();

    // The acknowledgement arrives.
    Object.assign(sandbox(), {
      leaseExpiresAtEffective: sandbox().leaseExpiresAtRequested,
      leaseExpireActionEffective: sandbox().leaseExpireActionRequested,
    });
    await refetch();
    expect(document.querySelector("[data-lease-effective]")?.getAttribute("data-lease-ack")).toBe(
      "acknowledged",
    );
  });

  it("two expiry cycles: each expiry is shown, and each cold start is its own request", async () => {
    const user = userEvent.setup();
    mount();
    await screen.findByRole("button", { name: enSandboxes.stop.action });
    for (const cycle of [1, 2]) {
      // The lifetime ran out and the host stopped the VM (expiry action: stop).
      Object.assign(sandbox(), {
        state: "STOPPED",
        generation: cycle + 1,
        lastLifecycleOperation: receipt("STOP_SANDBOX", "SUCCEEDED"),
      });
      await refetch();
      expect(stateShown()).toBe("STOPPED");
      expect(await offered(enSandboxes.stop.action)).toBe(false);
      await user.click(screen.getByRole("button", { name: enSandboxes.start.action }));
      const startDialog = screen.getByRole("dialog");
      await user.click(
        within(startDialog).getByRole("button", { name: enSandboxes.start.confirm }),
      );
      await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(cycle));
      // The default start keeps the remembered lease: no timeout is sent.
      expect(calls("reconnectSandbox")[cycle - 1]!.input).toMatchObject({
        id: "sbx-1",
        mode: "cold",
      });
      expect(calls("reconnectSandbox")[cycle - 1]!.input).not.toHaveProperty("timeoutMs");
      // Still STOPPED until the host reports the boot.
      expect(stateShown()).toBe("STOPPED");
      Object.assign(sandbox(), {
        state: "READY",
        leaseRevision: Number(sandbox().leaseRevision) + 1,
        lastLifecycleOperation: receipt("RECONNECT_SANDBOX", "SUCCEEDED"),
      });
      await refetch();
      expect(stateShown()).toBe("READY");
    }
    const [first, second] = calls("reconnectSandbox");
    expect(keyOf(first)).not.toBe(keyOf(second));
  });

  it("a lost stop response is retried with the same key; a state conflict gets a new one", async () => {
    server.current.errors.stopSandbox = [new Error("network"), coded("sandbox.state_conflict")];
    const user = userEvent.setup();
    mount();
    const stopOnce = async () => {
      await user.click(await screen.findByRole("button", { name: enSandboxes.stop.action }));
      await user.click(
        within(screen.getByRole("alertdialog")).getByRole("button", {
          name: enSandboxes.stop.confirm,
        }),
      );
    };
    await stopOnce();
    expect((await screen.findByRole("alert")).textContent).toBe(enSandboxes.problem.generic);
    await stopOnce();
    await waitFor(() =>
      expect(
        document.querySelector("[data-action-problem]")?.getAttribute("data-action-problem"),
      ).toBe("stateChanged"),
    );
    await stopOnce();
    await waitFor(() => expect(calls("stopSandbox")).toHaveLength(3));
    const [lost, conflicted, fresh] = calls("stopSandbox").map(keyOf);
    expect(conflicted).toBe(lost);
    expect(fresh).not.toBe(lost);
    await waitFor(() => expect(stateShown()).toBe("STOPPING"));
  });

  it("an uncertain stop on one sandbox is never replayed on another cached sandbox", async () => {
    server.current.sandboxes = [sandboxRow(), sandboxRow({ id: "sbx-2" })];
    const user = userEvent.setup();
    const view = mount("sbx-1");
    const page = (id: string) => (
      <QueryClientProvider client={client}>
        <I18nextProvider i18n={i18n}>
          <SandboxDetailPage lang="en-US" sandboxId={id} />
        </I18nextProvider>
      </QueryClientProvider>
    );
    const shows = (id: string) =>
      waitFor(() => expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(id));
    await shows("quiet-otter");
    // Visit B once so it is cached, then come back to A.
    view.rerender(page("sbx-2"));
    await shows("sbx-2");
    view.rerender(page("sbx-1"));
    await shows("quiet-otter");
    const stopOnce = async () => {
      await user.click(await screen.findByRole("button", { name: enSandboxes.stop.action }));
      await user.click(
        within(screen.getByRole("alertdialog")).getByRole("button", {
          name: enSandboxes.stop.confirm,
        }),
      );
    };
    // A's stop is applied, but its response is lost: the intent stays uncertain.
    server.current.lostResponses.stopSandbox = 1;
    await stopOnce();
    expect((await screen.findByRole("alert")).textContent).toBe(enSandboxes.problem.generic);
    // Straight to cached B: the same detail component stays mounted.
    view.rerender(page("sbx-2"));
    await shows("sbx-2");
    await stopOnce();
    await waitFor(() => expect(calls("stopSandbox")).toHaveLength(2));
    const [onA, onB] = calls("stopSandbox");
    expect(onA!.input).toMatchObject({ id: "sbx-1" });
    expect(onB!.input).toMatchObject({ id: "sbx-2" });
    expect(keyOf(onB)).not.toBe(keyOf(onA));
  });

  it("a renewal that committed but lost its response is replayed after the refetch shows the new revision", async () => {
    server.current.lostResponses.setSandboxTimeout = 1;
    const user = userEvent.setup();
    mount();
    const renewOnce = async () => {
      await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: enSandboxes.renew.submit }),
      );
    };
    await renewOnce();
    expect((await screen.findByRole("alert")).textContent).toBe(enSandboxes.problem.generic);
    // The server applied it: the refetch shows the revision that renewal made.
    await waitFor(() => expect(screen.getByText("Revision 2")).toBeTruthy());
    await renewOnce();
    await waitFor(() => expect(calls("setSandboxTimeout")).toHaveLength(2));
    const [lost, retried] = calls("setSandboxTimeout").map((call) => call.input);
    expect(retried).toEqual(lost);
    // A replay, not a second renewal.
    expect(sandbox().leaseRevision).toBe(2);
  });

  it("an uncertain renewal reopens on its own choice and replays the same intent", async () => {
    server.current.errors.setSandboxTimeout = [new Error("network")];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    const first = within(screen.getByRole("dialog"));
    // Not the default: one hour is left, so Renew starts lower than this.
    expect(first.getByLabelText(enSandboxes.lifetime.field).textContent).not.toContain("4 hours");
    await selectOption(user, first.getByLabelText(enSandboxes.lifetime.field), /^4 hours$/);
    await user.click(first.getByRole("button", { name: enSandboxes.renew.submit }));
    expect((await screen.findByRole("alert")).textContent).toBe(enSandboxes.problem.generic);
    expect(screen.queryByRole("dialog")).toBeNull();
    // Reopened: the uncertain choice, not a recomputed default.
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    const again = within(screen.getByRole("dialog"));
    expect(again.getByLabelText(enSandboxes.lifetime.field).textContent).toContain("4 hours");
    await user.click(again.getByRole("button", { name: enSandboxes.renew.submit }));
    await waitFor(() => expect(calls("setSandboxTimeout")).toHaveLength(2));
    const [lost, retried] = calls("setSandboxTimeout").map((call) => call.input);
    expect(retried).toEqual(lost);
    expect(lost).toMatchObject({ timeoutMs: 4 * 3_600_000 });
    // Settled by the success: the next opening starts from the lease again.
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: enSandboxes.renew.submit }),
    );
    await waitFor(() => expect(calls("setSandboxTimeout")).toHaveLength(3));
    const third = calls("setSandboxTimeout")[2]!.input as { idempotencyKey: string };
    expect(third.idempotencyKey).not.toBe((lost as { idempotencyKey: string }).idempotencyKey);
  });

  it("a cold start that committed but lost its response is replayed after the generation moved", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" })];
    server.current.lostResponses.reconnectSandbox = 1;
    const user = userEvent.setup();
    mount();
    const startOnce = async () => {
      await user.click(await screen.findByRole("button", { name: enSandboxes.start.action }));
      await user.click(
        within(screen.getByRole("dialog")).getByRole("button", { name: enSandboxes.start.confirm }),
      );
    };
    await startOnce();
    expect((await screen.findByRole("alert")).textContent).toBe(enSandboxes.problem.generic);
    // The start it queued is in flight: the page says Starting, never a second Start.
    await waitFor(() =>
      expect(
        document.querySelector("[data-sandbox-display]")?.getAttribute("data-sandbox-display"),
      ).toBe("STARTING"),
    );
    expect(await offered(enSandboxes.start.action)).toBe(false);
    // The boot it queued has begun (a new generation), but the host's answer is
    // unknown: Start is offered again, and the retry replays the first request.
    Object.assign(sandbox(), { state: "STOPPED", generation: 2 });
    Object.assign(sandbox().lastLifecycleOperation as object, { state: "UNKNOWN_OUTCOME" });
    await refetch();
    await startOnce();
    await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(2));
    const [lost, retried] = calls("reconnectSandbox");
    expect(keyOf(retried)).toBe(keyOf(lost));
    expect(server.current.operations.filter((op) => op.kind === "RECONNECT_SANDBOX")).toHaveLength(
      1,
    );
  });
});

type FetchCall = { method: string; url: string; headers: Record<string, string> };

function stubFetch(respond: (call: FetchCall, index: number) => Response) {
  const log: FetchCall[] = [];
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    const call = {
      method: init?.method ?? "GET",
      url: String(input),
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
    };
    log.push(call);
    return respond(call, log.length - 1);
  });
  return log;
}

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const STORED_DISK = {
  location: "store",
  offloadState: "stored",
  offloadFailure: null,
  offloadedAt: "2026-11-06T12:00:00.000Z",
  sizeBytes: 5 * 2 ** 30,
  eligibility: "any_host",
  offloadPin: "ANY",
  offloadPolicy: { mode: "on_stop" },
  offloadDueAt: null,
};

describe("disk offload (C8)", () => {
  it("an OFFLOADED sandbox shows its stored disk and restores through a cold start", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "OFFLOADED", sandboxHostId: null, host: null, disk: STORED_DISK }),
    ];
    const user = userEvent.setup();
    mount();
    await waitFor(() => expect(stateShown()).toBe("OFFLOADED"));
    const badge = document.querySelector<HTMLElement>("[data-disk-location]");
    expect(badge?.dataset.diskLocation).toBe("store");
    expect(badge?.textContent).toBe(enSandboxes.disk.location.store);
    expect(screen.getByText(enSandboxes.disk.locationHint.store)).toBeTruthy();
    // No stop for a hostless sandbox; Start reads Restore.
    expect(await offered(enSandboxes.stop.action)).toBe(false);
    await user.click(screen.getByRole("button", { name: enSandboxes.start.restoreAction }));
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText(enSandboxes.start.restoreDescription)).toBeTruthy();
    await user.click(
      within(dialog).getByRole("button", { name: enSandboxes.start.restoreConfirm }),
    );
    await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
    expect(calls("reconnectSandbox")[0]!.input).toMatchObject({ id: "sbx-1", mode: "cold" });
    expect(calls("reconnectSandbox")[0]!.input).not.toHaveProperty("overrideCreatorAllowlist");
    // A restore keeps the remembered lease too unless the user picks one.
    expect(calls("reconnectSandbox")[0]!.input).not.toHaveProperty("timeoutMs");
  });

  it("no allowed host: offers the creator-key override, which warns and sends overrideCreatorAllowlist", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "OFFLOADED", sandboxHostId: null, host: null, disk: STORED_DISK }),
    ];
    server.current.errors.reconnectSandbox = [coded("restore_no_allowed_host")];
    const user = userEvent.setup();
    mount();
    expect(await offered(enSandboxes.restoreOverride.action)).toBe(false);
    await user.click(await screen.findByRole("button", { name: enSandboxes.start.restoreAction }));
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", {
        name: enSandboxes.start.restoreConfirm,
      }),
    );
    await waitFor(() =>
      expect(document.querySelector("[data-action-problem]")?.textContent).toBe(
        enSandboxes.problem.restoreNoAllowedHost,
      ),
    );
    await user.click(screen.getByRole("button", { name: enSandboxes.restoreOverride.action }));
    const confirm = screen.getByRole("alertdialog");
    expect(within(confirm).getByText(enSandboxes.restoreOverride.description)).toBeTruthy();
    expect(enSandboxes.restoreOverride.description).toContain(
      "The SDK key that created this sandbox will lose access to it.",
    );
    await user.click(
      within(confirm).getByRole("button", { name: enSandboxes.restoreOverride.confirm }),
    );
    await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(2));
    const [first, second] = calls("reconnectSandbox");
    expect(second!.input).toMatchObject({ mode: "cold", overrideCreatorAllowlist: true });
    // A different intent: never the refused request's key.
    expect(keyOf(second)).not.toBe(keyOf(first));
  });

  it("a restore whose wait ended without room also offers the override", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "OFFLOADED",
        sandboxHostId: null,
        host: null,
        disk: STORED_DISK,
        lastLifecycleOperation: {
          ...receipt("RECONNECT_SANDBOX", "FAILED"),
          errorCode: "restore_no_allowed_host",
        },
      }),
    ];
    mount();
    expect(
      await screen.findByRole("button", { name: enSandboxes.restoreOverride.action }),
    ).toBeTruthy();
    expect(screen.getByText(enSandboxes.restoreOverride.hint)).toBeTruthy();
  });

  it("a restore whose wait ended on a busy login explains it and links to the logins page", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "OFFLOADED",
        sandboxHostId: null,
        host: null,
        disk: STORED_DISK,
        lastLifecycleOperation: {
          ...receipt("RECONNECT_SANDBOX", "FAILED"),
          errorCode: "credential.busy",
        },
      }),
    ];
    mount();
    expect(await screen.findByText(enSandboxes.restoreLoginWait.busy)).toBeTruthy();
    const banner = document.querySelector("[data-restore-login-wait]");
    expect(banner?.getAttribute("data-restore-login-wait")).toBe("busy");
    expect(
      within(banner as HTMLElement)
        .getByRole("link", { name: enSandboxes.restoreLoginWait.logins })
        .getAttribute("href"),
    ).toBe("/en-US/settings/logins");
    // A login refusal is not a host problem: no creator-key override.
    expect(await offered(enSandboxes.restoreOverride.action)).toBe(false);
  });

  it("destroy warns that it deletes the stored copy only when one exists", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "STOPPED",
        disk: { ...STORED_DISK, location: "host_and_store" },
      }),
    ];
    const user = userEvent.setup();
    mount();
    await chooseAction(user, enSandboxes.destroy.action);
    expect(
      within(screen.getByRole("alertdialog")).getByText(enSandboxes.destroy.storedCopy),
    ).toBeTruthy();
    cleanup();
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" })];
    mount();
    await chooseAction(user, enSandboxes.destroy.action);
    expect(document.querySelector("[data-destroy-stored-copy]")).toBeNull();
  });

  it("a restore's host-reported phase shows under the receipt", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "PROVISIONING",
        disk: STORED_DISK,
        lastLifecycleOperation: {
          ...receipt("RECONNECT_SANDBOX", "RUNNING"),
          progressPhase: "fetching_disk",
        },
      }),
    ];
    mount();
    await waitFor(() =>
      expect(document.querySelector("[data-receipt-phase]")?.textContent).toBe(
        enSandboxes.capture.phase.fetching_disk,
      ),
    );
  });

  it("a pending restore cleanup offers Retry cleanup, sent once by id", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "ERROR", lastErrorCode: "restore_cleanup_pending", disk: STORED_DISK }),
    ];
    const user = userEvent.setup();
    mount();
    const retry = await screen.findByRole("button", { name: enSandboxes.retryCleanup.action });
    await user.click(retry);
    await waitFor(() => expect(calls("retryCleanup")).toHaveLength(1));
    expect(calls("retryCleanup")[0]!.input).toEqual({ id: "sbx-1" });
  });

  it("Retry cleanup is not offered for another error", async () => {
    server.current.sandboxes = [sandboxRow({ state: "ERROR", lastErrorCode: "instance_missing" })];
    mount();
    await waitFor(() => expect(stateShown()).toBe("ERROR"));
    expect(await offered(enSandboxes.retryCleanup.action)).toBe(false);
  });

  it("the restore pin is edited in a Sheet and saved through setOffloadPin", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" })];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.disk.pin.change }));
    const sheet = screen.getByRole("dialog");
    await user.click(
      within(sheet).getByRole("radio", { name: new RegExp(enSandboxes.disk.pin.OWN_HOSTS) }),
    );
    await user.click(within(sheet).getByRole("button", { name: enSandboxes.disk.pin.save }));
    await waitFor(() => expect(calls("setOffloadPin")).toHaveLength(1));
    expect(calls("setOffloadPin")[0]!.input).toEqual({ id: "sbx-1", offloadPin: "OWN_HOSTS" });
    expect(toast.success).toHaveBeenCalledWith(enSandboxes.disk.pin.saved);
  });

  it("every disk label exists in es-MX too", () => {
    for (const location of ["host", "host_and_store", "store"] as const)
      expect(esSandboxes.disk.location[location]).toBeTruthy();
    expect(esSandboxes.restoreOverride.description).toBeTruthy();
    expect(esSandboxes.destroy.storedCopy).toBeTruthy();
  });
});

describe("files", () => {
  it("an upload goes through the cookie-session adapter and its receipt is followed", async () => {
    const log = stubFetch((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers"))
        return json(201, { id: "5b3a4f5e-0000-4000-8000-000000000001" });
      if (call.method === "PUT") return json(200, {});
      server.current.operations.push({ id: "op-put", kind: "PUT_FILE", state: "QUEUED" });
      return json(202, { operationId: "op-put" });
    });
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.upload(
      screen.getByLabelText(enSandboxes.files.upload.file),
      new File(["hello"], "hello.txt"),
    );
    await user.type(
      screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!,
      "/home/user/hello.txt",
    );
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    const accepted = await waitFor(() => {
      const found = document.querySelector('[data-upload="accepted"]');
      if (!found) throw new Error("not accepted");
      return found;
    });
    expect(accepted.textContent).toContain("Queued");
    expect(log.map((call) => `${call.method} ${new URL(call.url).pathname}`)).toEqual([
      "POST /api/dashboard/transfers",
      "PUT /api/dashboard/transfers/5b3a4f5e-0000-4000-8000-000000000001",
      "POST /api/dashboard/transfers/5b3a4f5e-0000-4000-8000-000000000001/commit",
    ]);
    for (const call of log) expect(call.headers.authorization).toBeUndefined();
    server.current.operations.find((op) => op.id === "op-put")!.state = "SUCCEEDED";
    await refetch();
    expect(document.querySelector('[data-upload="accepted"]')?.textContent).toContain("Done");
  });

  it("a revoked session mid-upload is explained and nothing is committed", async () => {
    const log = stubFetch((call) => {
      if (call.method === "POST") return json(201, { id: "5b3a4f5e-0000-4000-8000-000000000002" });
      if (call.method === "PUT") return json(403, { error: { code: "FORBIDDEN" } });
      return json(200, {});
    });
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.upload(screen.getByLabelText(enSandboxes.files.upload.file), new File(["x"], "x"));
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!, "/tmp/x");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    await waitFor(() =>
      expect(document.querySelector("[data-upload-problem]")?.textContent).toBe(
        enSandboxes.files.problem.forbidden,
      ),
    );
    expect(log.some((call) => call.url.endsWith("/commit"))).toBe(false);
    expect(log.at(-1)?.method).toBe("DELETE");
  });

  it("a server cap below the file size refuses the upload before any byte is sent", async () => {
    const log = stubFetch(() => json(413, { error: { code: "PAYLOAD_TOO_LARGE" } }));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.upload(screen.getByLabelText(enSandboxes.files.upload.file), new File(["xy"], "y"));
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!, "/tmp/y");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    await waitFor(() =>
      expect(
        document.querySelector("[data-upload-problem]")?.getAttribute("data-upload-problem"),
      ).toBe("tooLarge"),
    );
    expect(log.map((call) => call.method)).toEqual(["POST"]);
  });

  it("a bad guest path is refused in the browser", async () => {
    const log = stubFetch(() => json(500, {}));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.upload(screen.getByLabelText(enSandboxes.files.upload.file), new File(["x"], "x"));
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!, "relative/x");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    expect(await screen.findByText(enSandboxes.files.badPath)).toBeTruthy();
    expect(log).toEqual([]);
    // The error sits next to its field, which is marked invalid and focused.
    const field = screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!;
    expect(field.getAttribute("aria-invalid")).toBe("true");
    expect(field.getAttribute("aria-describedby")).toContain(
      screen.getByText(enSandboxes.files.badPath).id,
    );
    expect(document.activeElement).toBe(field);
  });

  it("an upload without a file says so at the file field and focuses it", async () => {
    stubFetch(() => json(500, {}));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    const error = await screen.findByText(enSandboxes.files.upload.noFile);
    const file = screen.getByLabelText(enSandboxes.files.upload.file);
    expect(file.getAttribute("aria-invalid")).toBe("true");
    expect(file.getAttribute("aria-describedby")).toBe(error.id);
    expect(document.activeElement).toBe(file);
  });

  it("a download is captured, checked, then offered from the cookie-session content route", async () => {
    const log = stubFetch(
      () => new Response(null, { status: 200, headers: { "content-length": "2048" } }),
    );
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[1]!, "/etc/hostname");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.download.submit }));
    await waitFor(() => expect(calls("readFile")).toHaveLength(1));
    expect(calls("readFile")[0]!.input).toMatchObject({ id: "sbx-1", path: "/etc/hostname" });
    await waitFor(() =>
      expect(document.querySelector('[data-download="pending"]')?.textContent).toContain("Queued"),
    );
    // Not offered before the capture succeeds.
    expect(document.querySelector("[data-download-link]")).toBeNull();
    expect(log).toEqual([]);
    server.current.operations.at(-1)!.state = "SUCCEEDED";
    await refetch();
    const link = await waitFor(() => {
      const found = document.querySelector<HTMLAnchorElement>("[data-download-link]");
      if (!found) throw new Error("no link");
      return found;
    });
    const opId = String(server.current.operations.at(-1)!.id);
    expect(link.getAttribute("href")).toBe(
      `https://app.example.test/api/dashboard/operations/${opId}/content`,
    );
    expect(log).toEqual([
      {
        method: "HEAD",
        url: `https://app.example.test/api/dashboard/operations/${opId}/content`,
        headers: {},
      },
    ]);
    expect(document.querySelector('[data-download="ready"]')?.textContent).toContain("2 KiB");
  });

  it("TQ-UX1/E-29 after the one save the link is gone and the page says to prepare again", async () => {
    const log = stubFetch(
      () => new Response(null, { status: 200, headers: { "content-length": "2048" } }),
    );
    // jsdom cannot navigate; the browser's own save is not under test.
    const stopNavigation = (event: Event) => {
      if (event.target instanceof Element && event.target.closest("a")) event.preventDefault();
    };
    window.addEventListener("click", stopNavigation);
    try {
      const user = userEvent.setup();
      mount();
      await screen.findByRole("heading", { name: enSandboxes.files.title });
      await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[1]!, "/etc/hostname");
      await user.click(screen.getByRole("button", { name: enSandboxes.files.download.submit }));
      await waitFor(() => expect(calls("readFile")).toHaveLength(1));
      server.current.operations.at(-1)!.state = "SUCCEEDED";
      await refetch();
      const link = await screen.findByRole("link", { name: enSandboxes.files.download.save });
      await user.click(link);
      await waitFor(() =>
        expect(document.querySelector('[data-download="saved"]')?.textContent).toBe(
          enSandboxes.files.download.saved,
        ),
      );
      expect(document.querySelector("[data-download-link]")).toBeNull();
      expect(document.querySelector('[data-download="ready"]')).toBeNull();
      // The save re-checked the capture first (a second HEAD).
      expect(log.filter((entry) => entry.method === "HEAD")).toHaveLength(2);
      // Preparing again offers a fresh link.
      await user.click(screen.getByRole("button", { name: enSandboxes.files.download.submit }));
      await waitFor(() => expect(calls("readFile")).toHaveLength(2));
      server.current.operations.at(-1)!.state = "SUCCEEDED";
      await refetch();
      await screen.findByRole("link", { name: enSandboxes.files.download.save });
      expect(document.querySelector('[data-download="saved"]')).toBeNull();
    } finally {
      window.removeEventListener("click", stopNavigation);
    }
  });

  it("E-29 a save of a capture that is already gone shows why instead of failing silently", async () => {
    let heads = 0;
    stubFetch(() =>
      ++heads === 1
        ? new Response(null, { status: 200, headers: { "content-length": "2048" } })
        : new Response(null, { status: 410 }),
    );
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[1]!, "/etc/hostname");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.download.submit }));
    await waitFor(() => expect(calls("readFile")).toHaveLength(1));
    server.current.operations.at(-1)!.state = "SUCCEEDED";
    await refetch();
    await user.click(await screen.findByRole("link", { name: enSandboxes.files.download.save }));
    await waitFor(() =>
      expect(document.querySelector("[data-download-problem]")?.textContent).toBe(
        enSandboxes.files.problem.expired,
      ),
    );
    expect(document.querySelector("[data-download-link]")).toBeNull();
    expect(document.querySelector('[data-download="saved"]')).toBeNull();
  });

  it("an expired capture is explained instead of offered", async () => {
    stubFetch(() => new Response(null, { status: 410 }));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[1]!, "/etc/hostname");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.download.submit }));
    await waitFor(() => expect(calls("readFile")).toHaveLength(1));
    server.current.operations.at(-1)!.state = "SUCCEEDED";
    await refetch();
    await waitFor(() =>
      expect(document.querySelector("[data-download-problem]")?.textContent).toBe(
        enSandboxes.files.problem.expired,
      ),
    );
    expect(document.querySelector("[data-download-link]")).toBeNull();
  });

  it("an upload receipt the server refuses to read is explained, stops polling, and can be re-checked", async () => {
    stubFetch((call) => {
      if (call.method === "POST" && call.url.endsWith("/transfers"))
        return json(201, { id: "5b3a4f5e-0000-4000-8000-000000000003" });
      if (call.method === "PUT") return json(200, {});
      server.current.operations.push({ id: "op-put", kind: "PUT_FILE", state: "QUEUED" });
      return json(202, { operationId: "op-put" });
    });
    const forbidden = () => Object.assign(new Error("forbidden"), { code: "FORBIDDEN" });
    server.current.errors.getOperation = [forbidden(), forbidden(), forbidden()];
    // The receipt poll runs on fake time, so "stops polling" needs no real wait.
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.upload(screen.getByLabelText(enSandboxes.files.upload.file), new File(["x"], "x"));
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!, "/tmp/x");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    const problem = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-receipt-problem="forbidden"]');
      if (!found) throw new Error("no receipt problem");
      return found;
    });
    expect(problem.textContent).toContain(enSandboxes.files.receiptFailed);
    // Not a silent "Queued": the accepted line is replaced by the problem.
    expect(document.querySelector('[data-upload="accepted"]')).toBeNull();
    const reads = calls("getOperation").length;
    await act(async () => {
      await vi.advanceTimersByTimeAsync(OPERATION_POLL_MS + 300);
    });
    expect(calls("getOperation")).toHaveLength(reads);
    server.current.errors.getOperation = [];
    await user.click(within(problem).getByRole("button", { name: enCommon.actions.tryAgain }));
    await waitFor(() =>
      expect(document.querySelector('[data-upload="accepted"]')?.textContent).toContain("Queued"),
    );
  });

  it("a download receipt that is gone is explained instead of staying pending", async () => {
    stubFetch(() => json(500, {}));
    const user = userEvent.setup();
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    server.current.errors.getOperation = [
      Object.assign(new Error("not found"), { code: "NOT_FOUND", status: 404 }),
    ];
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[1]!, "/etc/hostname");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.download.submit }));
    await waitFor(() =>
      expect(document.querySelector('[data-receipt-problem="notFound"]')).not.toBeNull(),
    );
    expect(document.querySelector('[data-download="pending"]')).toBeNull();
  });

  it("files are not offered unless the sandbox is ready", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED" })];
    mount();
    expect(await screen.findByText(enSandboxes.files.unavailable)).toBeTruthy();
    expect(screen.queryByRole("heading", { name: enSandboxes.files.title })).toBeNull();
  });
});

it.each([
  [null, null, "chosen host"],
  ["retained-pool-id", "Team pool", "own or shared pool"],
  ["retained-pool-id", null, "pool without a live share"],
] as const)(
  "names the placement in words (pool %s, label %s: %s), keeping IDs under Advanced, without pool discovery or env readback",
  async (poolId, label, _case) => {
    server.current.sandboxes = [
      sandboxRow({
        originPoolId: poolId,
        placementPoolLabel: label,
        templateRevisionId: "exact-revision-id",
        envs: { APP: "synthetic-detail-private-env" },
      }),
    ];
    mount();
    const placement = await waitFor(() => {
      const node = document.querySelector("[data-placement]");
      expect(node).not.toBeNull();
      return node!;
    });
    expect(placement.textContent).toBe(
      poolId === null
        ? enSandboxes.detail.placementHost.replace("{{label}}", "Alpha")
        : label
          ? enSandboxes.detail.placementPool.replace("{{label}}", label)
          : enSandboxes.detail.placementSharedPool,
    );
    // Prose, not monospace; the IDs stay one click away and copy in full.
    expect(placement.className).not.toContain("font-mono");
    const advanced = document.querySelector<HTMLElement>(
      'section[aria-labelledby="sandbox-overview"] [data-advanced-details]',
    )!;
    expect(advanced.textContent).toContain(enSandboxes.detail.revisionId);
    expect(advanced.textContent).toContain("exact-re…");
    if (poolId) expect(advanced.textContent).toContain(enSandboxes.detail.poolId);
    expect(document.querySelector("[data-revision-label]")?.textContent).toMatch(/ v\d+$/);
    expect(document.body.textContent).not.toContain("synthetic-detail-private-env");
    expect(calls("listPools")).toHaveLength(0);
  },
);

it("renewal lifetime choices respect a lowered server maximum", async () => {
  server.current.maxTimeoutMs = 17 * 60_000;
  const user = userEvent.setup();
  mount();
  await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
  const popup = within(screen.getByRole("dialog"));
  const field = popup.getByLabelText(enSandboxes.lifetime.field);
  expect((await selectChoices(user, field)).map((option) => option.textContent)).toEqual([
    "5 minutes",
    "15 minutes",
  ]);
  await selectOption(user, field, /^(15 minutes|15 minutos)$/);
  await user.click(popup.getByRole("button", { name: enSandboxes.renew.submit }));
  // 15 minutes ends before the current hour does: the dialog asks again first.
  expect(calls("setSandboxTimeout")).toHaveLength(0);
  await user.click(await popup.findByRole("button", { name: enSandboxes.renew.shortenConfirm }));
  await waitFor(() => expect(calls("setSandboxTimeout")).toHaveLength(1));
  expect(calls("setSandboxTimeout")[0]?.input).toMatchObject({ timeoutMs: 15 * 60_000 });
});

it.each(["READY", "STOPPED"])(
  "%s lifetime discovery has an inline retry that restores choices",
  async (state) => {
    server.current.sandboxes = [sandboxRow({ state })];
    server.current.maxTimeoutMs = 17 * 60_000;
    server.current.errors.getLimits = [new Error("network")];
    const user = userEvent.setup();
    mount();
    await user.click(
      await screen.findByRole("button", {
        name: state === "READY" ? enSandboxes.renew.action : enSandboxes.start.action,
      }),
    );
    const popup = within(screen.getByRole("dialog"));
    await popup.findByText(enSandboxes.lifetime.limitsFailed);
    await user.click(popup.getByRole("button", { name: enCommon.actions.tryAgain }));
    await waitFor(() => expect(popup.queryByText(enSandboxes.lifetime.limitsFailed)).toBeNull());
    const field = popup.getByLabelText(enSandboxes.lifetime.field);
    expect((await selectChoices(user, field)).map((option) => option.textContent)).toEqual([
      // A start offers its remembered lease first.
      ...(state === "STOPPED" ? ["Keep its lifetime (5 minutes, then stop)"] : []),
      "5 minutes",
      "15 minutes",
    ]);
    expect(calls("getLimits")).toHaveLength(2);
  },
);

describe("Start and Restore keep the remembered lease by default", () => {
  const twoHours = 2 * 3_600_000;

  it.each([
    ["STOPPED", enSandboxes.start.action, enSandboxes.start.confirm],
    ["OFFLOADED", enSandboxes.start.restoreAction, enSandboxes.start.restoreConfirm],
  ])(
    "%s: the dialog shows the remembered lease and sends no timeout",
    async (state, open, confirm) => {
      server.current.sandboxes = [
        sandboxRow({
          state,
          leaseExpireAction: "DESTROY",
          rememberedLeaseTimeoutMs: twoHours,
          ...(state === "OFFLOADED" ? { sandboxHostId: null, host: null, disk: STORED_DISK } : {}),
        }),
      ];
      const user = userEvent.setup();
      mount();
      await user.click(await screen.findByRole("button", { name: open }));
      const popup = within(screen.getByRole("dialog"));
      const field = popup.getByLabelText(enSandboxes.lifetime.field);
      expect(field.textContent).toContain("Keep its lifetime (2 hours, then destroy)");
      expect(popup.getByText(enSandboxes.lifetime.keepHint)).toBeTruthy();
      await user.click(popup.getByRole("button", { name: confirm }));
      await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
      const input = calls("reconnectSandbox")[0]!.input;
      expect(input).toMatchObject({ id: "sbx-1", mode: "cold" });
      expect(input).not.toHaveProperty("timeoutMs");
    },
  );

  it.each([
    ["STOPPED", enSandboxes.start.action, enSandboxes.start.confirm],
    ["OFFLOADED", enSandboxes.start.restoreAction, enSandboxes.start.restoreConfirm],
  ])("%s: an explicit lifetime is sent as chosen", async (state, open, confirm) => {
    server.current.sandboxes = [
      sandboxRow({
        state,
        rememberedLeaseTimeoutMs: twoHours,
        ...(state === "OFFLOADED" ? { sandboxHostId: null, host: null, disk: STORED_DISK } : {}),
      }),
    ];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: open }));
    const popup = within(screen.getByRole("dialog"));
    await selectOption(user, popup.getByLabelText(enSandboxes.lifetime.field), /^30 minutes$/);
    await user.click(popup.getByRole("button", { name: confirm }));
    await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
    expect(calls("reconnectSandbox")[0]!.input).toMatchObject({
      id: "sbx-1",
      mode: "cold",
      timeoutMs: 30 * 60_000,
    });
  });

  it("a lifetime picked on one sandbox never carries over to another cached sandbox", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "STOPPED", rememberedLeaseTimeoutMs: twoHours }),
      sandboxRow({ id: "sbx-2", state: "STOPPED", rememberedLeaseTimeoutMs: twoHours }),
    ];
    const user = userEvent.setup();
    const view = mount("sbx-1");
    const page = (id: string) => (
      <QueryClientProvider client={client}>
        <I18nextProvider i18n={i18n}>
          <SandboxDetailPage lang="en-US" sandboxId={id} />
        </I18nextProvider>
      </QueryClientProvider>
    );
    const field = () =>
      within(screen.getByRole("dialog")).getByLabelText(enSandboxes.lifetime.field);
    const shows = (name: string) =>
      waitFor(() => expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(name));
    // Visit B once so it is cached, then come back to A.
    await shows("quiet-otter");
    view.rerender(page("sbx-2"));
    await shows("sbx-2");
    view.rerender(page("sbx-1"));
    await shows("quiet-otter");
    // Pick 5 minutes on A, then cancel.
    await user.click(await screen.findByRole("button", { name: enSandboxes.start.action }));
    await selectOption(user, field(), /^5 minutes$/);
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: enCommon.actions.cancel }),
    );
    // Same component, cached B: its Start keeps B's own lease.
    view.rerender(page("sbx-2"));
    await shows("sbx-2");
    await user.click(await screen.findByRole("button", { name: enSandboxes.start.action }));
    expect(field().textContent).toContain("Keep its lifetime (2 hours, then stop)");
    await user.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: enSandboxes.start.confirm }),
    );
    await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
    expect(calls("reconnectSandbox")[0]!.input).toMatchObject({ id: "sbx-2", mode: "cold" });
    expect(calls("reconnectSandbox")[0]!.input).not.toHaveProperty("timeoutMs");
  });

  it("a remembered unlimited lease reads as no time limit", async () => {
    server.current.sandboxes = [sandboxRow({ state: "STOPPED", rememberedLeaseTimeoutMs: 0 })];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.start.action }));
    const field = within(screen.getByRole("dialog")).getByLabelText(enSandboxes.lifetime.field);
    expect(field.textContent).toContain(enSandboxes.lifetime.keepUnlimited);
  });
});

describe("S0 sensitive session unavailable", () => {
  it("an impersonated snapshot keeps metadata but mounts no file or terminal IO", async () => {
    browserAuthority.impersonatedBy = "administrator";
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    expect(screen.getAllByText(enSandboxes.sensitiveAccessUnavailable).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: enSandboxes.files.upload.submit })).toBeNull();
    expect(screen.queryByRole("button", { name: enSandboxes.files.download.submit })).toBeNull();
    expect(document.querySelector("[data-download-link]")).toBeNull();
    expect(calls("getOperation")).toEqual([]);
    expect(calls("readFile")).toEqual([]);
    expect(calls("createSession")).toEqual([]);
    expect(fetch).not.toHaveBeenCalled();
    expect(calls("getSandbox").length).toBeGreaterThan(0);
    expect(toast.error).not.toHaveBeenCalled();
  });
  it("a server 401 remains signed-out rather than inferred impersonation", async () => {
    const user = userEvent.setup();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ error: { code: "UNAUTHORIZED" } }), { status: 401 }),
        ),
    );
    mount();
    await screen.findByRole("heading", { name: enSandboxes.files.title });
    await user.upload(screen.getByLabelText(enSandboxes.files.upload.file), new File(["x"], "x"));
    await user.type(screen.getAllByLabelText(enSandboxes.files.guestPath)[0]!, "/tmp/x");
    await user.click(screen.getByRole("button", { name: enSandboxes.files.upload.submit }));
    await waitFor(() =>
      expect(document.querySelector("[data-upload-problem]")?.textContent).toBe(
        enSandboxes.files.problem.signedOut,
      ),
    );
    expect(screen.queryByText(enSandboxes.sensitiveAccessUnavailable)).toBeNull();
  });
});

it("shows the actual allocation through stop/cold start and template refetches", async () => {
  server.current.sandboxes = [sandboxRow({ cpuCount: 2, memoryMiB: 3072 })];
  server.current.templates = [fakeTemplate({ cpuCount: 8, memoryMiB: 8192 })];
  mount();
  await waitFor(() =>
    expect(document.querySelector("[data-sandbox-allocation]")?.textContent).toBe(
      "2 vCPU · 3 GiB memory · 32 GiB disk",
    ),
  );
  await waitFor(() => expect(calls("getTemplateRevision")).toHaveLength(1));
  server.current.templates = [fakeTemplate({ cpuCount: 4, memoryMiB: 4096 })];
  sandbox().state = "STOPPED";
  await refetch();
  expect(document.querySelector("[data-sandbox-allocation]")?.textContent).toBe(
    "2 vCPU · 3 GiB memory · 32 GiB disk",
  );
  sandbox().state = "READY";
  sandbox().generation = 2;
  await refetch();
  expect(document.querySelector("[data-sandbox-allocation]")?.textContent).toBe(
    "2 vCPU · 3 GiB memory · 32 GiB disk",
  );
});

it("shows accepted pool grace and pinned access-loss deletion notice without foreign storage identity", async () => {
  server.current.sandboxes = [
    sandboxRow({
      originPoolId: "opaque-pool",
      acceptedGraceSeconds: 259200,
      accessGraceUntil: "2030-01-03T00:00:00.000Z",
      host: null,
      storagePoolId: null,
      storagePoolName: null,
      storageMarker: null,
    }),
  ];
  mount();
  await waitFor(() =>
    expect(document.querySelector("[data-accepted-grace]")?.textContent).toBe("3 days"),
  );
  expect(screen.getByText(enSandboxes.fields.acceptedGrace)).toBeTruthy();
  expect(document.querySelector("[data-access-grace]")?.textContent).toContain("Pool access lost");
  expect(document.querySelector("[data-sandbox-storage]")?.textContent).not.toContain("private");
});

it("announces restoration only after the durable loss deadline clears, without automatically restarting", async () => {
  server.current.sandboxes = [
    sandboxRow({
      originPoolId: "opaque-pool",
      acceptedGraceSeconds: 259200,
      accessGraceUntil: "2030-01-03T00:00:00.000Z",
    }),
  ];
  mount();
  await screen.findByText(/Pool access lost/);
  expect(screen.queryByText(enSandboxes.sharing.restored)).toBeNull();
  server.current.sandboxes[0]!.accessGraceUntil = null;
  await act(() => client.invalidateQueries({ queryKey: ["sandboxes"] }));
  await screen.findByText(enSandboxes.sharing.restored);
  expect(calls("connectSandbox")).toHaveLength(0);
});

describe("header summary and structure (design review #7)", () => {
  it("a ready sandbox: one primary Open terminal, Stop visible, the rest in the menu, and an index", async () => {
    mount();
    const open = await screen.findByRole("link", { name: enSandboxes.openTerminal });
    expect(open.getAttribute("href")).toBe("#sandbox-section-terminal");
    expect(document.getElementById("sandbox-section-terminal")).not.toBeNull();
    expect(screen.getByRole("button", { name: enSandboxes.stop.action })).toBeTruthy();
    // Destroy, Rename and Reconnect are not header buttons.
    for (const name of [
      enSandboxes.destroy.action,
      enSandboxes.rename.action,
      enSandboxes.reconnect.action,
    ])
      expect(screen.queryByRole("button", { name })).toBeNull();
    const user = userEvent.setup();
    await user.click(moreActions()!);
    const items = await screen.findAllByRole("menuitem");
    expect(items.map((item) => item.textContent)).toEqual([
      enSandboxes.renew.action,
      enSandboxes.reconnect.action,
      enSandboxes.rename.action,
      enSandboxes.destroy.action,
    ]);
    // The destructive item sits in its own section after a separator.
    expect(screen.getByRole("separator")).toBeTruthy();
    await user.keyboard("{Escape}");
    const index = screen.getByRole("navigation", { name: enSandboxes.sections.label });
    expect(
      within(index)
        .getAllByRole("link")
        .map((link) => link.getAttribute("href")),
    ).toEqual([
      "#sandbox-section-overview",
      "#sandbox-section-terminal",
      "#sandbox-section-previews",
      "#sandbox-section-files",
      "#sandbox-section-configuration",
      "#sandbox-section-activity",
    ]);
    // "Operations for this sandbox" is a real (outlined) link button, not body text.
    expect(screen.getByRole("link", { name: enSandboxes.detail.operations }).className).toContain(
      "border",
    );
  });

  it("the lifetime summary is an absolute time with what is left and Renew", async () => {
    const at = Date.now() + 2 * 3_600_000 + 30 * 60_000;
    server.current.sandboxes = [sandboxRow({ leaseExpiresAt: new Date(at) })];
    mount();
    const summary = await waitFor(() => {
      const found = document.querySelector<HTMLElement>("[data-lifetime-summary]");
      if (!found) throw new Error("no summary");
      return found;
    });
    // The page's own formatter: past midnight it adds the day, so a fixed
    // hour:minute expectation would fail late in the evening.
    expect(summary.textContent).toContain(`Stops at ${formatClock(at, "en-US", Date.now())}`);
    expect(summary.textContent).toMatch(/\(in 2 hr 29 min|\(in 2 hr 30 min/);
    expect(
      within(summary).getByRole("button", { name: enSandboxes.renew.action }).textContent,
    ).toBe(enSandboxes.summary.renew);
  });

  it("a stopped sandbox never says when it stops: it says what a start gives it", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "STOPPED",
        leaseExpiresAt: new Date(Date.now() + 4 * 3_600_000),
        leaseExpiresAtRequested: new Date(Date.now() + 4 * 3_600_000),
        rememberedLeaseTimeoutMs: 2 * 3_600_000,
      }),
    ];
    mount();
    const summary = await waitFor(() => {
      const found = document.querySelector<HTMLElement>("[data-lifetime-summary]");
      if (!found) throw new Error("no summary");
      return found;
    });
    expect(summary.textContent).toContain(
      enSandboxes.summary.stopped.replace("{{lifetime}}", "2 hours"),
    );
    expect(document.body.textContent).not.toMatch(/in 4 hours/);
    expect(document.querySelector("[data-lease-deadline]")?.textContent).toBe(
      enSandboxes.lifetime.stopped,
    );
    // Start is the primary action of a stopped sandbox.
    expect(
      screen.getByRole("button", { name: enSandboxes.start.action }).dataset.primaryAction,
    ).toBe("start");
  });

  it("a start in flight reads Starting with its steps, and offers no second Start", async () => {
    server.current.sandboxes = [
      sandboxRow({
        state: "STOPPED",
        lastLifecycleOperation: receipt("RECONNECT_SANDBOX", "ACCEPTED"),
      }),
    ];
    mount();
    await waitFor(() =>
      expect(
        document.querySelector("[data-sandbox-display]")?.getAttribute("data-sandbox-display"),
      ).toBe("STARTING"),
    );
    expect(stateShown()).toBe("STOPPED");
    expect(screen.getByText(enSandboxes.displayHint.STARTING)).toBeTruthy();
    expect(await offered(enSandboxes.start.action)).toBe(false);
    expect(document.querySelector('[data-step="creating"]')?.getAttribute("data-step-status")).toBe(
      "current",
    );
    // The receipt names the operation Start, not Reconnect.
    expect(document.querySelector("[data-receipt-kind]")?.textContent).toContain(
      `${enSandboxes.receipt.kind.RECONNECT_SANDBOX}: ${enSandboxes.receipt.state.ACCEPTED}`,
    );
    expect(enSandboxes.receipt.kind.RECONNECT_SANDBOX).toBe("Start");
  });

  it("a destroy in flight reads Destroying, never Stopping", async () => {
    server.current.sandboxes = [
      sandboxRow({ state: "STOPPING", lastLifecycleOperation: receipt("KILL_SANDBOX", "RUNNING") }),
    ];
    mount();
    await waitFor(() =>
      expect(document.querySelector("[data-sandbox-display]")?.textContent).toBe(
        enSandboxes.displayState.DESTROYING,
      ),
    );
    expect(screen.queryByText(enSandboxes.state.STOPPING)).toBeNull();
    expect(screen.getByText(enSandboxes.displayHint.DESTROYING)).toBeTruthy();
  });

  it.each([
    ["REQUESTED", "QUEUED", "placed"],
    ["REQUESTED", "DISPATCHED", "creating"],
    ["PROVISIONING", "RUNNING", "booting"],
  ])("a %s create with a %s receipt is at step %s, with elapsed time", async (state, op, step) => {
    server.current.sandboxes = [
      sandboxRow({
        state,
        lastLifecycleOperation: {
          ...receipt("CREATE_SANDBOX", op),
          createdAt: new Date(Date.now() - 75_000),
        },
      }),
    ];
    mount();
    const progress = await waitFor(() => {
      const found = document.querySelector<HTMLElement>("[data-provision-progress]");
      if (!found) throw new Error("no progress");
      return found;
    });
    expect(progress.querySelector('[aria-current="step"]')?.getAttribute("data-step")).toBe(step);
    expect(progress.textContent).toMatch(/1 min 1\d sec so far/);
  });
});

describe("renew (design review #2)", () => {
  it("starts at the current lifetime or the next step up, and shows Now → New", async () => {
    // One hour left; the sandbox runs with a two-hour lifetime.
    server.current.sandboxes = [sandboxRow({ rememberedLeaseTimeoutMs: 2 * 3_600_000 })];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    const popup = within(screen.getByRole("dialog"));
    expect(popup.getByLabelText(enSandboxes.lifetime.field).textContent).toContain("2 hours");
    expect(popup.getByText(enSandboxes.renew.now)).toBeTruthy();
    expect(document.querySelector("[data-renew-now]")?.textContent).toMatch(/^stops at /);
    expect(document.querySelector("[data-renew-next]")?.textContent).toMatch(/^stops at /);
    await user.click(popup.getByRole("button", { name: enSandboxes.renew.submit }));
    await waitFor(() => expect(calls("setSandboxTimeout")).toHaveLength(1));
    expect(calls("setSandboxTimeout")[0]?.input).toMatchObject({ timeoutMs: 2 * 3_600_000 });
    // The toast says what changed.
    await waitFor(() => expect(toast.success).toHaveBeenCalled());
    expect(toast.success.mock.calls.at(-1)?.[0]).toMatch(/^Lifetime renewed\. It now stops at /);
  });

  it("never defaults to a shorter lifetime than what is left", async () => {
    server.current.sandboxes = [
      sandboxRow({ leaseExpiresAt: new Date(Date.now() + 3 * 3_600_000) }),
    ];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    expect(
      within(screen.getByRole("dialog")).getByLabelText(enSandboxes.lifetime.field).textContent,
    ).toContain("4 hours");
  });

  it("a choice that ends earlier asks again, and Back keeps the lifetime", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enSandboxes.renew.action }));
    const popup = within(screen.getByRole("dialog"));
    await selectOption(user, popup.getByLabelText(enSandboxes.lifetime.field), /^5 minutes$/);
    await user.click(popup.getByRole("button", { name: enSandboxes.renew.submit }));
    expect(await popup.findByText(enSandboxes.renew.shortenTitle)).toBeTruthy();
    await user.click(popup.getByRole("button", { name: enCommon.actions.back }));
    expect(popup.getByLabelText(enSandboxes.lifetime.field)).toBeTruthy();
    expect(calls("setSandboxTimeout")).toHaveLength(0);
  });
});

it("Reconnect explains itself in a confirmation before it sends a warm reconnect", async () => {
  const user = userEvent.setup();
  mount();
  await chooseAction(user, enSandboxes.reconnect.action);
  const confirm = await screen.findByRole("alertdialog");
  expect(within(confirm).getByText(enSandboxes.reconnect.description)).toBeTruthy();
  expect(calls("reconnectSandbox")).toHaveLength(0);
  await user.click(within(confirm).getByRole("button", { name: enSandboxes.reconnect.confirm }));
  await waitFor(() => expect(calls("reconnectSandbox")).toHaveLength(1));
  expect(calls("reconnectSandbox")[0]?.input).toMatchObject({ id: "sbx-1", mode: "warm" });
});

it("destroy shows the name to type as text: no placeholder and no copy button (design review #21)", async () => {
  const user = userEvent.setup();
  mount();
  await chooseAction(user, enSandboxes.destroy.action);
  const confirm = await screen.findByRole("alertdialog");
  const input = within(confirm).getByLabelText("Type quiet-otter to confirm") as HTMLInputElement;
  expect(input.placeholder).toBe("");
  expect(input.value).toBe("");
  expect(within(confirm).queryByRole("button", { name: /copy/i })).toBeNull();
  // The confirm button is named apart from the menu item that opened the dialog.
  expect(within(confirm).getByRole("button", { name: enSandboxes.destroy.confirm })).toBeTruthy();
  expect(enSandboxes.destroy.confirm).not.toBe(enSandboxes.destroy.action);
});

describe("ports & previews, connect and usage (design review #4, #11, #22)", () => {
  it("offers the CLI port forward and says sharing is CLI/API only", async () => {
    mount();
    const card = await waitFor(() => {
      const found = document.querySelector<HTMLElement>("[data-sandbox-ports]");
      if (!found) throw new Error("no ports card");
      return found;
    });
    expect(within(card).getByText("wssp sandbox forward quiet-otter 8080")).toBeTruthy();
    expect(within(card).getByRole("button", { name: enSandboxes.ports.copyForward })).toBeTruthy();
    expect(within(card).getByText(enSandboxes.ports.cliOnly)).toBeTruthy();
    expect(within(card).getByText(enSandboxes.ports.noTunnel)).toBeTruthy();
    expect(card.querySelector('[data-docs-link="tunnels"]')?.getAttribute("href")).toBe(
      "https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/guide/tunnels.md",
    );
  });

  it("a sandbox with preview ports gets one link command per declared port", async () => {
    server.current.sandboxes = [sandboxRow({ tunnelEnabled: true, tunnelPorts: [3000, 5173] })];
    mount();
    const card = await waitFor(() => {
      const found = document.querySelector<HTMLElement>("[data-tunnel-ports]");
      if (!found) throw new Error("no tunnel ports");
      return found;
    });
    expect(card.textContent).toContain("3000, 5173");
    expect(within(card).getByText("wssp sandbox ports link sbx-1 3000")).toBeTruthy();
    expect(within(card).getByText("wssp sandbox ports link sbx-1 5173")).toBeTruthy();
  });

  it("every connect command is a copy field, with a pointer to get the CLI", async () => {
    mount();
    const panel = await screen.findByRole("region", { name: enSandboxes.connect.heading });
    for (const name of [
      enSandboxes.connect.copyShell,
      enSandboxes.connect.copySsh,
      enSandboxes.connect.copySetup,
    ])
      expect(within(panel).getByRole("button", { name })).toBeTruthy();
    expect(
      within(panel).getByText(enSandboxes.connect.getCli, { selector: "summary" }),
    ).toBeTruthy();
    expect(
      within(panel).getByText(
        "curl --proto '=https' --tlsv1.2 -fsSL --max-time 120 https://app.example.test/install.sh | sh",
      ),
    ).toBeTruthy();
    expect(within(panel).getByText("wssp login --server https://app.example.test")).toBeTruthy();
  });

  it("usage labels allocation apart from measured use and shows running time since the start", async () => {
    server.current.sandboxes = [
      sandboxRow({
        lastLifecycleOperation: {
          ...receipt("CREATE_SANDBOX", "SUCCEEDED"),
          completedAt: new Date(Date.now() - 2 * 3_600_000 - 5 * 60_000),
        },
      }),
    ];
    mount();
    const usage = await screen.findByRole("region", { name: enSandboxes.usage.title });
    expect(within(usage).getByText(enSandboxes.usage.allocated)).toBeTruthy();
    expect(within(usage).getByText(enSandboxes.usage.measuredNone)).toBeTruthy();
    expect(usage.querySelector("[data-sandbox-running]")?.textContent).toBe(
      "2 hr 5 min since the last start",
    );
  });
});
