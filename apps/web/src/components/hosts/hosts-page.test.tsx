vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider, useInfiniteQuery } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider, useTranslation } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Hosts page against a scripted fake server: real TanStack Query, real i18n
 * (en-US), real dialogs. The fake server records every call so tests can
 * assert what the browser sent and that each refusal triggers a refetch.
 */

type FakeHost = {
  retainedRootCount: number;
  storagePools: import("@/lib/host-status").StorageSummary[];
  capacity: {
    memoryBudgetMiB: number | null;
    memoryReservedMiB: number;
    memoryAvailableMiB: number | null;
    memoryOvercommittedMiB: number | null;
    maxCpuCount: number | null;
    maxMemoryMiB: number | null;
    current: boolean;
    vcpuBudget: number | null;
    vcpuReserved: number;
    vcpuAvailable: number | null;
    vcpuOvercommitted: number | null;
  };
  id: string;
  slug: string;
  label: string;
  status: "DISCONNECTED" | "CONNECTED" | "STALE" | "REVOKED";
  lastConnectedAt: Date | null;
  lastHeartbeatAt: Date | null;
  deletionRequestedAt: Date | null;
  quarantinedAt?: Date | null;
  quarantineReason?: string | null;
  connectionCount: number;
  liveCount: number;
  liveSandboxCount: number;
  drained: boolean;
  draining: boolean;
  drainOffload?: boolean;
  egressEnforcement: boolean;
  egressOpen: boolean;
  openEgressForOthers: boolean;
  guestSudoForOthers: boolean;
  egressGuard: { ok: boolean; reason: string | null; leaseActive: boolean };
  daemonRuntime: "FAKE" | "INCUS_KVM" | "UNSUPPORTED" | null;
  daemonVersion: string | null;
  createdAt: Date;
  updatedAt: Date;
};

const server = vi.hoisted(() => ({
  hosts: [] as FakeHost[],
  calls: [] as { procedure: string; input: unknown }[],
  listError: null as unknown,
  listPending: false,
  mutationError: null as unknown,
  deletePending: false,
}));

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://api.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: { lang?: string };
  }) => (
    <a className={className} href={to.replace("$lang", params?.lang ?? "$lang")}>
      {children}
    </a>
  ),
}));

vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  const failOr = async <T,>(value: () => T): Promise<T> => {
    if (server.mutationError) {
      const error = server.mutationError;
      server.mutationError = null;
      throw error;
    }
    return value();
  };
  const find = (id: string) => {
    const host = server.hosts.find((row) => row.id === id);
    if (!host) throw Object.assign(new Error("Sandbox host not found."), { code: "NOT_FOUND" });
    return host;
  };
  return {
    orpc: {
      sandboxHosts: {
        listHosts: {
          key: () => ["sandboxHosts", "listHosts"],
          infiniteOptions: (options: {
            input: (cursor: string | undefined) => unknown;
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["sandboxHosts", "listHosts", "infinite"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
              record("listHosts", options.input(pageParam));
              if (server.listPending) return new Promise(() => undefined);
              if (server.listError) throw server.listError;
              return { items: structuredClone(server.hosts), nextCursor: null };
            },
          }),
        },
        updateHost: {
          mutationOptions: () => ({
            mutationFn: (input: { id: string; label?: string }) => {
              record("updateHost", input);
              return failOr(() => {
                const host = find(input.id);
                if (input.label) host.label = input.label;
                return structuredClone(host);
              });
            },
          }),
        },
        setHostDraining: {
          mutationOptions: () => ({
            mutationFn: (input: { id: string; draining: boolean; offload?: boolean }) => {
              record("setHostDraining", input);
              return failOr(() => {
                const host = find(input.id);
                host.draining = input.draining;
                host.drainOffload = input.draining && input.offload === true;
                return { id: host.id, draining: host.draining, drained: host.drained };
              });
            },
          }),
        },
        forgetHost: {
          mutationOptions: () => ({
            mutationFn: (input: { id: string }) => {
              record("forgetHost", input);
              return failOr(() => {
                const host = find(input.id);
                host.deletionRequestedAt = new Date();
                return { ok: true as const, pending: true, detached: 2, copiesForgotten: 1 };
              });
            },
          }),
        },
        deleteHost: {
          mutationOptions: () => ({
            mutationFn: (input: { id: string }) => {
              record("deleteHost", input);
              return failOr(() => {
                const host = find(input.id);
                if (server.deletePending) host.deletionRequestedAt = new Date();
                else server.hosts = server.hosts.filter((row) => row !== host);
                return { ok: true as const, pending: server.deletePending };
              });
            },
          }),
        },
      },
    },
  };
});

import {
  GUARD_FIREWALL_COMMAND,
  GUARD_INSTALL_COMMAND,
  HOST_HEARTBEAT_STALE_AFTER_MS,
} from "@/lib/host-status";
import { orpc } from "@/utils/orpc";
import { HostCard, HostsPage } from "./hosts-page";

/**
 * The full host card as host detail shows it, one per listed host. The Hosts
 * list itself renders compact rows (`mountPage`); everything a host card owns
 * (capacity, storage, network, actions) is exercised through this.
 */
function HostCards({ lang }: { lang: string }) {
  const { t } = useTranslation("hosts");
  const query = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      input: (cursor: string | undefined) => ({ limit: 50, cursor }),
      initialPageParam: undefined as string | undefined,
      getNextPageParam: (lastPage: { nextCursor: string | null }) =>
        lastPage.nextCursor ?? undefined,
    }),
  });
  const now = Date.now();
  const hosts = query.data?.pages.flatMap((page) => page.items) ?? [];
  if (hosts.length === 0) return null;
  return (
    <ul aria-label={t("listRegion")}>
      {query.data?.pages
        .flatMap((page) => page.items)
        .map((host) => (
          <HostCard key={host.id} host={host} now={now} lang={lang} locale={lang} />
        ))}
    </ul>
  );
}

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "hosts"],
    defaultNS: "common",
    resources: {
      "en-US": { common: enCommon, dashboard: enDashboard, hosts: enHosts },
      "es-MX": { common: esCommon, dashboard: esDashboard, hosts: esHosts },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

function fakeHost(overrides: Partial<FakeHost> = {}): FakeHost {
  const now = new Date();
  return {
    id: "host-1",
    slug: "desk-01",
    label: "Desk",
    status: "CONNECTED",
    lastConnectedAt: new Date(now.getTime() - 60_000),
    lastHeartbeatAt: new Date(now.getTime() - 2_000),
    deletionRequestedAt: null,
    connectionCount: 1,
    retainedRootCount: 0,
    storagePools: [],
    liveCount: 0,
    liveSandboxCount: 0,
    drained: false,
    draining: false,
    egressEnforcement: true,
    egressOpen: true,
    openEgressForOthers: false,
    guestSudoForOthers: true,
    egressGuard: { ok: true, reason: null, leaseActive: true },
    daemonRuntime: "INCUS_KVM",
    daemonVersion: "1.0.0",
    createdAt: now,
    updatedAt: now,
    capacity: {
      memoryBudgetMiB: 4096,
      memoryReservedMiB: 2048,
      memoryAvailableMiB: 2048,
      memoryOvercommittedMiB: 0,
      maxCpuCount: 4,
      maxMemoryMiB: 4096,
      current: true,
      vcpuBudget: 8,
      vcpuReserved: 2,
      vcpuAvailable: 6,
      vcpuOvercommitted: 0,
    },
    ...overrides,
  };
}

let client: QueryClient;
function render_(node: ReactNode) {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>{node}</I18nextProvider>
    </QueryClientProvider>,
  );
}
/** Host cards (host detail's view of each host). */
function mount(lang = "en-US") {
  return render_(<HostCards lang={lang} />);
}
/** The Hosts list page: compact rows, Add host. */
function mountPage(lang = "en-US") {
  return render_(<HostsPage lang={lang} />);
}

async function confirmDrain(user: ReturnType<typeof userEvent.setup>) {
  const confirm = await screen.findByRole("alertdialog");
  await user.click(within(confirm).getByRole("button", { name: enHosts.drain.drain }));
}

const listCalls = () => server.calls.filter((call) => call.procedure === "listHosts").length;
const card = (id: string) => document.querySelector<HTMLElement>(`li[data-host-id="${id}"]`)!;
const statusOf = (id: string) =>
  card(id).querySelector("[data-host-status]")?.getAttribute("data-host-status");

beforeEach(async () => {
  await i18n.changeLanguage("en-US");
  server.hosts = [];
  server.calls = [];
  server.listError = null;
  server.listPending = false;
  server.mutationError = null;
  server.deletePending = false;
  toast.success.mockReset();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

describe("hosts page query states", () => {
  it("pending shows the skeleton, not the empty state", () => {
    server.listPending = true;
    mountPage();
    expect(document.querySelector('[data-slot="skeleton"]')).not.toBeNull();
    expect(screen.queryByText(enHosts.empty.title)).toBeNull();
  });

  it("a failed first load shows a retry, not an empty list", async () => {
    server.listError = new Error("network");
    mountPage();
    expect(await screen.findByText(enDashboard.list.loadFailed)).toBeTruthy();
    expect(screen.queryByText(enHosts.empty.title)).toBeNull();
    expect(screen.getByRole("button", { name: enCommon.actions.tryAgain })).toBeTruthy();
  });

  it("an empty server result shows the empty state and enrollment commands", async () => {
    mountPage();
    expect(await screen.findByText(enHosts.empty.title)).toBeTruthy();
    expect(
      screen.getByText("wssp login --slug my-host --server https://api.example.test"),
    ).toBeTruthy();
    expect(screen.getAllByText("wssp connect").length).toBeGreaterThan(0);
    const enroll = document.querySelector<HTMLElement>('[aria-labelledby="hosts-enroll-title"]')!;
    const link = within(enroll).getByRole("link", { name: enHosts.enroll.tokenLink });
    expect(link.getAttribute("href")).toBe("/en-US/settings/host-credentials");
    expect(screen.queryByRole("list", { name: enHosts.listRegion })).toBeNull();
  });

  it("renders each connection state distinctly; only a fresh heartbeat is ready", async () => {
    const now = Date.now();
    server.hosts = [
      fakeHost({ id: "ready" }),
      fakeHost({
        id: "stale",
        lastHeartbeatAt: new Date(now - HOST_HEARTBEAT_STALE_AFTER_MS - 5_000),
      }),
      fakeHost({ id: "nobeat", lastHeartbeatAt: null }),
      fakeHost({
        id: "offline",
        status: "DISCONNECTED",
        lastConnectedAt: new Date(now - 3_600_000),
      }),
      fakeHost({ id: "reconnecting", status: "DISCONNECTED", lastConnectedAt: new Date(now) }),
      fakeHost({
        id: "quarantined",
        status: "DISCONNECTED",
        lastConnectedAt: new Date(now),
        quarantinedAt: new Date(now - 600_000),
        quarantineReason: "lease_mismatch",
      }),
      fakeHost({
        id: "never",
        status: "DISCONNECTED",
        lastConnectedAt: null,
        lastHeartbeatAt: null,
        daemonRuntime: null,
        daemonVersion: null,
      }),
      fakeHost({ id: "revoked", status: "REVOKED" }),
      fakeHost({ id: "deleting", deletionRequestedAt: new Date(now) }),
    ];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    expect(Object.fromEntries(server.hosts.map((host) => [host.id, statusOf(host.id)]))).toEqual({
      ready: "ready",
      stale: "stale",
      nobeat: "stale",
      offline: "offline",
      reconnecting: "reconnecting",
      quarantined: "quarantined",
      never: "never",
      revoked: "revoked",
      deleting: "deleting",
    });
    expect(within(card("ready")).getByText(enHosts.status.ready)).toBeTruthy();
    // E3-B-02: a running daemon the server refuses is never told to start.
    expect(within(card("quarantined")).getByText(enHosts.statusHint.quarantined)).toBeTruthy();
    expect(
      within(card("quarantined")).getByText(enHosts.quarantineReason.lease_mismatch),
    ).toBeTruthy();
    expect(within(card("quarantined")).queryByText(enHosts.statusHint.offline)).toBeNull();
    expect(enHosts.statusHint.quarantined).not.toMatch(/wssp connect/);
    expect(within(card("reconnecting")).getByText(enHosts.statusHint.reconnecting)).toBeTruthy();
    expect(within(card("stale")).getByText(enHosts.statusHint.stale)).toBeTruthy();
    // Freshness is advisory: the relay still dispatches to a registered
    // socket whose heartbeat is old, so the copy must not promise otherwise.
    expect(enHosts.statusHint.stale).not.toMatch(/no new work|until it reconnects/i);
    expect(within(card("never")).getByText(enHosts.daemon.notReported)).toBeTruthy();
    expect(within(card("never")).getByText(enHosts.heartbeat.never)).toBeTruthy();
    expect(within(card("ready")).getByText("Incus KVM · Version 1.0.0")).toBeTruthy();
    // A host pending deletion offers no controls but Forget (offload plan
    // §8.2: a deletion stuck on a dead host).
    expect(
      within(card("deleting"))
        .queryAllByRole("button")
        .map((button) => button.textContent),
    ).toEqual([enHosts.forget.action]);
    expect(within(card("deleting")).getByText(enHosts.statusHint.deleting)).toBeTruthy();
  });

  it("shows live count without a configurable count denominator", async () => {
    server.hosts = [fakeHost({ liveSandboxCount: 3 })];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    expect(card("host-1").querySelector("[data-host-capacity]")?.textContent).toBe("3 live");
    expect(card("host-1").querySelector("[data-host-capacity-limits]")).toBeNull();
  });

  it("shows capacity, the live count and the draining / drained badges", async () => {
    server.hosts = [
      fakeHost({ id: "busy", liveSandboxCount: 4, liveCount: 4, drained: false }),
      fakeHost({ id: "draining", draining: true, liveSandboxCount: 2, drained: false }),
      fakeHost({ id: "last-one", draining: true, liveSandboxCount: 1, drained: false }),
      fakeHost({ id: "drained", draining: true, liveSandboxCount: 0, drained: true }),
      fakeHost({ id: "idle", liveSandboxCount: 0, drained: false }),
    ];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    expect(card("busy").querySelector("[data-host-capacity]")?.textContent).toBe("4 live");
    expect(card("draining").querySelector("[data-host-drain]")?.textContent).toBe("Draining");
    expect(
      within(card("draining")).getByText("No new work is admitted. 2 live sandboxes remain."),
    ).toBeTruthy();
    // M7-S3: one live sandbox reads in the singular.
    expect(
      within(card("last-one")).getByText("No new work is admitted. 1 live sandbox remains."),
    ).toBeTruthy();
    expect(card("drained").querySelector("[data-host-drain]")?.textContent).toBe("Drained");
    expect(within(card("drained")).getByText(enHosts.drain.drainedHint)).toBeTruthy();
    // `drained` alone (drain off) is not a badge.
    expect(card("idle").querySelector("[data-host-drain]")).toBeNull();
    expect(
      within(card("draining")).getByRole("button", { name: enHosts.drain.undrain }),
    ).toBeTruthy();
    expect(within(card("idle")).getByRole("button", { name: enHosts.drain.drain })).toBeTruthy();
  });
});

describe("egress enforcement (E-06)", () => {
  it("badges a reporting host that can't create sandboxes and explains why per runtime", async () => {
    server.hosts = [
      fakeHost({ id: "old-incus", egressEnforcement: false }),
      fakeHost({ id: "fake", egressEnforcement: false, daemonRuntime: "FAKE" }),
      fakeHost({ id: "capable" }),
      fakeHost({ id: "unreported", egressEnforcement: false, daemonRuntime: null }),
      fakeHost({ id: "unsupported", egressEnforcement: false, daemonRuntime: "UNSUPPORTED" }),
    ];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    expect(card("old-incus").querySelector("[data-host-egress]")?.textContent).toBe(
      enHosts.egress.badge,
    );
    expect(within(card("old-incus")).getByText(enHosts.egress.incusHint)).toBeTruthy();
    // D-7 (HR-1): the hint names the daemon log as the source of the reason
    // and no longer asserts that the Incus version is always the cause.
    expect(enHosts.egress.incusHint).toContain("daemon's log names the reason");
    expect(enHosts.egress.incusHint).not.toMatch(/need Incus 6\.14/);
    expect(within(card("fake")).getByText(enHosts.egress.fakeHint)).toBeTruthy();
    // Inverse: a capable host, one that never reported, and an unsupported
    // runtime (its own hint) carry no egress badge.
    for (const id of ["capable", "unreported", "unsupported"]) {
      expect(card(id).querySelector("[data-host-egress]"), id).toBeNull();
      expect(card(id).querySelector("[data-host-egress-hint]"), id).toBeNull();
    }
  });
});

describe("network guard and open-egress consent (default-open egress)", () => {
  it("guest root consent for other users' sandboxes defaults to allowed and names the command", async () => {
    server.hosts = [fakeHost({ id: "on" }), fakeHost({ id: "off", guestSudoForOthers: false })];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const on = card("on").querySelector("[data-host-network]") as HTMLElement;
    expect(on.querySelector('[data-host-guest-sudo-for-others="on"]')?.textContent).toBe(
      enHosts.egress.guestSudoForOthersOn,
    );
    expect(on.querySelector("[data-host-guest-sudo-hint]")?.textContent).toBe(
      enHosts.egress.guestSudoForOthersHint.replace(
        "{{command}}",
        "wssp config set-allow-guest-sudo-for-others on|off|default",
      ),
    );
    const off = card("off").querySelector("[data-host-network]") as HTMLElement;
    expect(off.querySelector('[data-host-guest-sudo-for-others="off"]')?.textContent).toBe(
      enHosts.egress.guestSudoForOthersOff,
    );
  });

  it("a running guard shows no hint; consent defaults to off", async () => {
    server.hosts = [fakeHost({ id: "ok" })];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const network = card("ok").querySelector("[data-host-network]") as HTMLElement;
    expect(network.querySelector('[data-host-guard="running"]')?.textContent).toBe(
      enHosts.egress.guard.state.running,
    );
    expect(network.querySelector('[data-host-open-for-others="off"]')?.textContent).toBe(
      enHosts.egress.off,
    );
    expect(network.textContent).toContain(
      enHosts.egress.openForOthersHint.replace(
        "{{command}}",
        "wssp config set-open-egress-for-others on|off",
      ),
    );
    expect(network.querySelector("[data-host-guard-hint]")).toBeNull();
    expect(network.querySelector("[data-host-open-warning]")).toBeNull();
    expect(card("ok").querySelector("[data-host-guard-badge]")).toBeNull();
  });

  it.each([
    ["guard_unreachable", { ok: false, reason: "guard_unreachable", leaseActive: false }],
    ["guard_quarantined", { ok: false, reason: "guard_quarantined", leaseActive: false }],
    ["guard_outdated", { ok: false, reason: "guard_outdated", leaseActive: false }],
    ["guard_root_source", { ok: false, reason: "guard_root_source", leaseActive: false }],
    ["guard_lease_expired", { ok: true, reason: null, leaseActive: false }],
    ["unknown", { ok: false, reason: null, leaseActive: false }],
    ["unknown", { ok: false, reason: "guard_from_the_future", leaseActive: false }],
  ] as const)(
    "an unhealthy guard (%s) is explained with the install command",
    async (state, egressGuard) => {
      server.hosts = [fakeHost({ id: "down", egressGuard: { ...egressGuard } })];
      mount();
      await screen.findByRole("list", { name: enHosts.listRegion });
      const host = card("down");
      expect(host.querySelector("[data-host-guard-badge]")?.textContent).toBe(
        enHosts.egress.guard.badge,
      );
      expect(host.querySelector(`[data-host-guard="${state}"]`)?.textContent).toBe(
        enHosts.egress.guard.state[state],
      );
      const hint = host.querySelector(`[data-host-guard-hint="${state}"]`) as HTMLElement;
      expect(hint.textContent).toContain(enHosts.egress.guard.reason[state]);
      expect(hint.textContent).toContain(enHosts.egress.guard.blocked);
      expect(hint.querySelector("code")?.textContent).toBe(GUARD_INSTALL_COMMAND);
      expect(GUARD_INSTALL_COMMAND).toMatch(
        /^\S+ "\$\(command -v wssp\)" guard install --daemon-user "\$USER"$/,
      );
    },
  );

  it("a second daemon on the Incus server is named, with no guard install command", async () => {
    server.hosts = [
      fakeHost({
        id: "shared",
        egressGuard: { ok: false, reason: "incus_server_shared", leaseActive: false },
      }),
    ];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const host = card("shared");
    expect(host.querySelector('[data-host-guard="incus_server_shared"]')?.textContent).toBe(
      enHosts.egress.guard.state.incus_server_shared,
    );
    const hint = host.querySelector('[data-host-guard-hint="incus_server_shared"]') as HTMLElement;
    expect(hint.textContent).toContain(enHosts.egress.guard.reason.incus_server_shared);
    expect(hint.textContent).toContain(enHosts.egress.guard.blocked);
    expect(hint.querySelector("code")).toBeNull();
  });

  it("a host firewall that blocks sandboxes shows the --configure-ufw fix", async () => {
    server.hosts = [
      fakeHost({
        id: "fw",
        egressGuard: { ok: false, reason: "host_firewall_blocks_sandboxes", leaseActive: false },
      }),
    ];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const host = card("fw");
    expect(
      host.querySelector('[data-host-guard="host_firewall_blocks_sandboxes"]')?.textContent,
    ).toBe(enHosts.egress.guard.state.host_firewall_blocks_sandboxes);
    const hint = host.querySelector(
      '[data-host-guard-hint="host_firewall_blocks_sandboxes"]',
    ) as HTMLElement;
    expect(hint.textContent).toContain(enHosts.egress.guard.reason.host_firewall_blocks_sandboxes);
    expect(hint.textContent).toContain(enHosts.egress.guard.firewall);
    expect(hint.querySelector("code")?.textContent).toBe(GUARD_FIREWALL_COMMAND);
    expect(GUARD_FIREWALL_COMMAND).toMatch(/guard install --daemon-user "\$USER" --configure-ufw$/);
  });

  it("an offline host does not claim a guard failure", async () => {
    server.hosts = [
      fakeHost({
        id: "off",
        status: "DISCONNECTED",
        egressGuard: { ok: false, reason: null, leaseActive: false },
      }),
    ];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    expect(card("off").querySelector('[data-host-guard="offline"]')).not.toBeNull();
    expect(card("off").querySelector("[data-host-guard-hint]")).toBeNull();
    expect(card("off").querySelector("[data-host-guard-badge]")).toBeNull();
  });

  it("consent on warns about traffic from the node; no open capability says so", async () => {
    server.hosts = [fakeHost({ id: "shared", openEgressForOthers: true, egressOpen: false })];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const host = card("shared");
    expect(host.querySelector('[data-host-open-for-others="on"]')?.textContent).toBe(
      enHosts.egress.on,
    );
    expect(host.querySelector("[data-host-open-warning]")?.textContent).toBe(
      enHosts.egress.openForOthersWarning,
    );
    expect(host.querySelector("[data-host-open-unsupported]")?.textContent).toBe(
      enHosts.egress.openUnsupported,
    );
  });
});

describe("stale timer", () => {
  it("turns a silent host stale on time with no refetch, even while the server is down", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    server.hosts = [fakeHost({ lastHeartbeatAt: new Date(Date.now() - 25_000) })];
    mountPage();
    await screen.findByRole("list", { name: enHosts.listRegion });
    expect(statusOf("host-1")).toBe("ready");
    server.listError = new Error("server down");
    const before = listCalls();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4_000);
    });
    expect(statusOf("host-1")).toBe("ready");
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2_000);
    });
    // No refetch has happened (the refetch interval is 15 s), yet it is stale.
    expect(listCalls()).toBe(before);
    expect(statusOf("host-1")).toBe("stale");
  });
});

describe("mutations", () => {
  it("host editing sends only label and keeps capacity local", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost()];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.edit.action }));
    expect(screen.queryByRole("spinbutton")).toBeNull();
    const label = await screen.findByLabelText(enHosts.edit.label);
    await user.clear(label);
    await user.type(label, "Renamed");
    await user.click(screen.getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() =>
      expect(server.calls.filter((c) => c.procedure === "updateHost")).toEqual([
        { procedure: "updateHost", input: { id: "host-1", label: "Renamed" } },
      ]),
    );
  });

  it("drain sends only the host ID and flag, then shows the badge after refetch", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost({ liveSandboxCount: 1, drained: false })];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.drain.drain }));
    // Draining is confirmed first, and nothing is sent until then.
    expect(server.calls.some((call) => call.procedure === "setHostDraining")).toBe(false);
    await confirmDrain(user);
    await waitFor(() =>
      expect(card("host-1").querySelector("[data-host-drain]")?.textContent).toBe("Draining"),
    );
    expect(server.calls.find((call) => call.procedure === "setHostDraining")).toEqual({
      procedure: "setHostDraining",
      input: { id: "host-1", draining: true, offload: false },
    });
    expect(toast.success).toHaveBeenCalledWith(enHosts.drain.drainDone);
    await user.click(screen.getByRole("button", { name: enHosts.drain.undrain }));
    await waitFor(() => expect(card("host-1").querySelector("[data-host-drain]")).toBeNull());
  });

  it("drain with the offload switch asks to offload, and says so while draining", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost({ liveSandboxCount: 1, drained: false })];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.drain.drain }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("switch", { name: /Offload stopped sandboxes/ }));
    await confirmDrain(user);
    await waitFor(() =>
      expect(server.calls.find((call) => call.procedure === "setHostDraining")).toEqual({
        procedure: "setHostDraining",
        input: { id: "host-1", draining: true, offload: true },
      }),
    );
    expect(await within(card("host-1")).findByText(enHosts.drain.offloadingHint)).toBeTruthy();
  });

  it("forget is offered only for an unreachable host", async () => {
    server.hosts = [fakeHost()];
    mount();
    await screen.findByRole("button", { name: enHosts.delete.action });
    expect(screen.queryByRole("button", { name: enHosts.forget.action })).toBeNull();
  });

  it("forget of an offline host needs the typed slug and reports detached sandboxes", async () => {
    const user = userEvent.setup();
    const long = new Date(Date.now() - 24 * 3_600_000);
    server.hosts = [
      fakeHost({ status: "DISCONNECTED", lastConnectedAt: long, lastHeartbeatAt: long }),
    ];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.forget.action }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: enHosts.forget.confirm });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    await user.type(within(dialog).getByRole("textbox"), "desk-01");
    await user.click(confirm);
    await waitFor(() =>
      expect(toast.success).toHaveBeenCalledWith(
        "2 sandboxes now restore from the image store. Deletion is pending until the host's remaining sandboxes and work are gone.",
      ),
    );
    expect(server.calls.find((call) => call.procedure === "forgetHost")).toEqual({
      procedure: "forgetHost",
      input: { id: "host-1" },
    });
  });

  it("a forget refused as unsafe lists the sandboxes that may still run there", async () => {
    const user = userEvent.setup();
    const long = new Date(Date.now() - 24 * 3_600_000);
    server.hosts = [
      fakeHost({ status: "DISCONNECTED", lastConnectedAt: long, lastHeartbeatAt: long }),
    ];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.forget.action }));
    const dialog = await screen.findByRole("alertdialog");
    await user.type(within(dialog).getByRole("textbox"), "desk-01");
    server.mutationError = Object.assign(new Error("unsafe"), {
      code: "CONFLICT",
      data: { code: "sandbox.host_forget_unsafe", sandboxIds: ["sbx-a", "sbx-b"] },
    });
    await user.click(within(dialog).getByRole("button", { name: enHosts.forget.confirm }));
    expect(await within(card("host-1")).findByText(enHosts.problem.forgetUnsafe)).toBeTruthy();
    const listed = card("host-1").querySelector("[data-host-forget-unsafe]");
    expect([...(listed?.querySelectorAll("li") ?? [])].map((li) => li.textContent)).toEqual([
      "sbx-a",
      "sbx-b",
    ]);
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("an inaccessible host (NOT_FOUND) is explained and the list refetched", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost()];
    mount();
    const drain = await screen.findByRole("button", { name: enHosts.drain.drain });
    server.mutationError = Object.assign(new Error("gone"), { code: "NOT_FOUND", status: 404 });
    const before = listCalls();
    server.hosts = [];
    await user.click(drain);
    await confirmDrain(user);
    await waitFor(() => expect(listCalls()).toBeGreaterThan(before));
    // The refetch removed the host, so its card (and message) is gone.
    await waitFor(() => expect(document.querySelector('li[data-host-id="host-1"]')).toBeNull());
  });

  it("a server policy refusal (FORBIDDEN) is explained, never treated as success", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost()];
    mount();
    const drain = await screen.findByRole("button", { name: enHosts.drain.drain });
    server.mutationError = Object.assign(new Error("2fa"), { code: "FORBIDDEN", status: 403 });
    await user.click(drain);
    await confirmDrain(user);
    expect(await within(card("host-1")).findByRole("alert")).toHaveProperty(
      "textContent",
      enHosts.problem.forbidden,
    );
    expect(toast.success).not.toHaveBeenCalled();
    expect(card("host-1").querySelector("[data-host-drain]")).toBeNull();
  });

  it("delete is unavailable while sandboxes are live, and explains why", async () => {
    server.hosts = [fakeHost({ liveSandboxCount: 1, drained: false })];
    mount();
    const button = await screen.findByRole("button", { name: enHosts.delete.action });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(button.getAttribute("aria-describedby")).toBe("host-delete-blocked-host-1");
    expect(screen.getByText(enHosts.delete.blockedLive)).toBeTruthy();
  });

  it("delete of an idle host needs the typed slug; a pending result is explained", async () => {
    const user = userEvent.setup();
    server.deletePending = true;
    server.hosts = [fakeHost()];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.delete.action }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: enCommon.actions.delete });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    await user.type(within(dialog).getByRole("textbox"), "desk-01");
    await user.click(confirm);
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith(enHosts.delete.pending));
    expect(server.calls.find((call) => call.procedure === "deleteHost")).toEqual({
      procedure: "deleteHost",
      input: { id: "host-1" },
    });
    await waitFor(() => expect(statusOf("host-1")).toBe("deleting"));
  });

  it("a delete refused with host_delete_conflict is explained and refetched", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost()];
    mount();
    await user.click(await screen.findByRole("button", { name: enHosts.delete.action }));
    const dialog = await screen.findByRole("alertdialog");
    await user.type(within(dialog).getByRole("textbox"), "desk-01");
    server.mutationError = Object.assign(new Error("conflict"), {
      code: "CONFLICT",
      data: { code: "sandbox.host_delete_conflict" },
    });
    const before = listCalls();
    await user.click(within(dialog).getByRole("button", { name: enCommon.actions.delete }));
    expect(await within(card("host-1")).findByText(enHosts.problem.pendingDeletion)).toBeTruthy();
    await waitFor(() => expect(listCalls()).toBeGreaterThan(before));
  });
});

describe("commands and layout", () => {
  it.each(["en-US", "es-MX"])(
    "%s explains optional CA trust next to enrollment and connect snippets",
    async (lang) => {
      server.hosts = [fakeHost()];
      await i18n.changeLanguage(lang);
      mount(lang);
      const copy = lang === "en-US" ? enHosts : esHosts;
      await screen.findByRole("list", { name: copy.listRegion });
      for (const flag of [
        "--ca-file <path>",
        "WSSP_CA_FILE",
        "--sandbox-memory-mib",
        "--max-sandbox-cpu-count",
      ]) {
        // Once in the host's own connect snippet.
        const flags = screen.getAllByText(flag, { selector: "code" });
        expect(flags).toHaveLength(1);
        for (const code of flags) expect(code.className).toContain("whitespace-nowrap");
      }
    },
  );

  it("the list is compact rows linking to each host; Add host opens the enrollment dialog", async () => {
    const user = userEvent.setup();
    server.hosts = [fakeHost(), fakeHost({ id: "host-2", slug: "desk-02", label: "Desk 2" })];
    mountPage();
    const list = await screen.findByRole("list", { name: enHosts.listRegion });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      const link = within(row).getByRole("link");
      expect(link.getAttribute("href")).toBe("/en-US/settings/hosts/$hostId");
      expect(link.className).toContain("min-h-11");
      // No full card: no actions, storage or connect commands in the list.
      expect(within(row).queryByRole("button")).toBeNull();
      expect(row.querySelector('[data-slot="copy-field"]')).toBeNull();
      expect(row.querySelector('[data-host-meter="memory"]')).not.toBeNull();
      // The vCPU number is the daemon's schedulable budget (by default CPU
      // threads × 2), never presented as bare vCPU or as CPU threads.
      const vcpu = row.querySelector<HTMLElement>('[data-host-meter="vcpu"]')!;
      expect(vcpu.textContent).toContain(enHosts.row.vcpu);
      expect(enHosts.row.vcpu).toBe("vCPU budget");
      expect(vcpu.getAttribute("title")).toBe(
        enHosts.vmCapacity.vcpuBudgetHint
          .replaceAll("{{multiplier}}", "2")
          .replaceAll("{{max}}", "8192"),
      );
      expect(vcpu.getAttribute("title")).toContain("2 × the host's CPU threads");
    }
    expect(document.querySelector("[data-host-enroll]")).toBeNull();
    await user.click(screen.getByRole("button", { name: enHosts.enroll.action }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(enHosts.enroll.title)).toBeTruthy();
    expect(
      within(dialog).getByText("wssp login --slug my-host --server https://api.example.test"),
    ).toBeTruthy();
    for (const flag of ["--ca-file <path>", "--sandbox-memory-mib"])
      expect(within(dialog).getByText(flag, { selector: "code" })).toBeTruthy();
  });

  it("per-host connect commands are copyable, nonsecret and link to Host credentials", async () => {
    server.hosts = [fakeHost()];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const host = card("host-1");
    const values = [...host.querySelectorAll('[data-slot="copy-field-value"]')].map(
      (node) => node.textContent,
    );
    expect(values).toEqual([
      "wssp login --slug desk-01 --server https://api.example.test",
      "wssp connect",
      "wssp connect --server https://api.example.test --host-id host-1 --host-token-env WSSP_HOST_TOKEN",
    ]);
    for (const field of host.querySelectorAll('[data-slot="copy-field"]'))
      expect(
        within(field as HTMLElement).getByRole("button", { name: enHosts.connect.copyCommand }),
      ).toBeTruthy();
    expect(document.body.innerHTML).not.toMatch(/wssp_(host|device|sdk)_/);
    expect(
      within(host).getByRole("link", { name: enHosts.enroll.tokenLink }).getAttribute("href"),
    ).toBe("/en-US/settings/host-credentials");
    // No credential inputs and no host shell / exec controls.
    expect(document.querySelector('input[type="password"]')).toBeNull();
    expect(screen.queryByRole("button", { name: /shell|terminal|exec/i })).toBeNull();
  });

  it("wraps and shrinks at phone widths: no fixed widths, 44px actions, self-scrolling commands", async () => {
    server.hosts = [fakeHost({ label: "x".repeat(160), slug: "a".repeat(60) })];
    mount();
    await screen.findByRole("list", { name: enHosts.listRegion });
    const host = card("host-1");
    expect(host.className).toMatch(/\bmin-w-0\b/);
    for (const button of within(host)
      .getAllByRole("button")
      .filter((b) => !b.closest('[data-slot="copy-field"]')))
      expect(button.className).toMatch(/\bh-11\b/);
    const actions = within(host).getByRole("button", { name: enHosts.edit.action }).parentElement!;
    expect(actions.className).toMatch(/\bflex-wrap\b/);
    for (const text of host.querySelectorAll("p.truncate"))
      expect(text.className).toMatch(/\btruncate\b/);
    for (const code of host.querySelectorAll('[data-slot="copy-field-value"]'))
      expect(code.className).toMatch(/\bmin-w-0\b.*\boverflow-x-auto\b/);
    // Only the 44px copy buttons carry a min width; nothing forces >= 100px.
    expect(document.body.innerHTML).not.toMatch(
      /\bmin-w-\[\d{3,}px\]|\bw-screen\b|\bw-\[\d{3,}px\]/,
    );
  });
});

it.each(["en-US", "es-MX"])(
  "%s shows server memory independently from slots, including shrunk budgets",
  async (lang) => {
    server.hosts = [
      fakeHost({
        liveSandboxCount: 1,
        capacity: {
          memoryBudgetMiB: 4096,
          memoryReservedMiB: 3072,
          memoryAvailableMiB: 1024,
          memoryOvercommittedMiB: 0,
          maxCpuCount: 4,
          maxMemoryMiB: 4096,
          current: true,
          vcpuBudget: 8,
          vcpuReserved: 2,
          vcpuAvailable: 6,
          vcpuOvercommitted: 0,
        },
      }),
    ];
    await i18n.changeLanguage(lang);
    mount(lang);
    await screen.findByText("Desk");
    const field = (name: string) =>
      document.querySelector(`[data-capacity-field="${name}"]`)?.textContent;
    expect(field("memoryBudgetMiB")).toBe("4096 MiB");
    expect(field("memoryReservedMiB")).toBe("3072 MiB");
    expect(field("memoryAvailableMiB")).toBe("1024 MiB");
    expect(field("maxCpuCount")).toBe("4 vCPU");
    expect(field("vcpuBudget")).toBe("8 vCPU");
    const budgetHint = document.querySelector("[data-vcpu-budget-hint]")?.textContent;
    expect(budgetHint).toBe(
      (lang === "en-US" ? enHosts : esHosts).vmCapacity.vcpuBudgetHint
        .replaceAll("{{multiplier}}", "2")
        .replaceAll("{{max}}", "8192"),
    );
    server.hosts[0]!.capacity = {
      ...server.hosts[0]!.capacity,
      memoryBudgetMiB: 2048,
      maxMemoryMiB: 2048,
      memoryAvailableMiB: 0,
      memoryOvercommittedMiB: 1024,
      current: false,
    };
    // Both the page timer and a query refetch preserve the server's numeric projection.
    await act(() => client.invalidateQueries());
    await waitFor(() => expect(field("memoryOvercommittedMiB")).toBe("1024 MiB"));
    expect(field("memoryReservedMiB")).toBe("3072 MiB");
    expect(field("memoryAvailableMiB")).toBe("0 MiB");
    expect(
      document.querySelector("[data-capacity-state]")?.getAttribute("data-capacity-state"),
    ).toBe("stale");
  },
);

it("marks a never-reported budget separately from zero available memory", async () => {
  server.hosts = [
    fakeHost({
      capacity: {
        memoryBudgetMiB: null,
        memoryReservedMiB: 1024,
        memoryAvailableMiB: null,
        memoryOvercommittedMiB: null,
        maxCpuCount: null,
        maxMemoryMiB: null,
        current: false,
        vcpuBudget: null,
        vcpuReserved: 0,
        vcpuAvailable: null,
        vcpuOvercommitted: null,
      },
    }),
  ];
  mount();
  await screen.findByText("Desk");
  expect(document.querySelector("[data-capacity-state]")?.getAttribute("data-capacity-state")).toBe(
    "never",
  );
  expect(document.querySelector('[data-capacity-field="memoryAvailableMiB"]')?.textContent).toBe(
    enHosts.daemon.notReported,
  );
  expect(document.querySelector('[data-capacity-field="memoryReservedMiB"]')?.textContent).toBe(
    "1024 MiB",
  );
});

it.each(["en-US", "es-MX"])(
  "%s separates zero healthy disk budget, drain and retained roots",
  async (lang) => {
    const copy = lang === "en-US" ? enHosts : esHosts;
    const pool: import("@/lib/host-status").StorageSummary = {
      id: "storage-1",
      name: "default",
      marker: "original-marker",
      capacityGiB: 0,
      totalBasedCapacityGiB: 160,
      capacitySource: "implicit",
      derivationTotalBytes: 200 * 2 ** 30,
      derivationFreeBytes: 10 * 2 ** 30,
      derivationCommittedBytes: 33 * 2 ** 30,
      derivationActualBytes: 0,
      derivationHeadroomBytes: 10 * 2 ** 30,
      implicitCeilingGiB: 0,
      draining: true,
      health: "healthy",
      reason: null,
      totalBytes: 200 * 2 ** 30,
      usedBytes: 190 * 2 ** 30,
      freeBytes: 10 * 2 ** 30,
      diskReservedGiB: 33,
      reportedAt: new Date().toISOString(),
    };
    server.hosts = [
      fakeHost({
        retainedRootCount: 1,
        liveSandboxCount: 0,
        draining: true,
        drained: true,
        storagePools: [pool],
      }),
    ];
    await i18n.changeLanguage(lang);
    mount(lang);
    const card = await screen.findByText("default");
    expect(card.closest("[data-storage-state]")?.getAttribute("data-storage-state")).toBe(
      "healthy",
    );
    expect(screen.getByText(copy.storage.draining)).toBeTruthy();
    expect(screen.getByText(copy.storage.limited)).toBeTruthy();
    expect(screen.getByText(copy.storage.overcommitted.replace("{{value}}", "33"))).toBeTruthy();
    expect(screen.getByText(copy.drain.drainedHint)).toBeTruthy();
    // IEC units, not raw byte counts; the storage identity sits under Advanced.
    if (lang === "en-US")
      expect(screen.getByText("190 GiB used of 200 GiB (10 GiB free)")).toBeTruthy();
    expect(document.body.textContent).not.toContain(String(190 * 2 ** 30));
    const storage = card.closest<HTMLElement>("[data-storage-state]")!;
    const advanced = storage.querySelector("details[data-advanced-details]")!;
    expect(advanced.hasAttribute("open")).toBe(false);
    expect(advanced.textContent).toContain("original…");
    server.hosts[0]!.storagePools[0] = {
      ...pool,
      reportedAt: new Date(Date.now() - 16000).toISOString(),
    };
    await act(() => client.invalidateQueries());
    await waitFor(() => expect(screen.getByText(copy.storage.stale)).toBeTruthy());
  },
);
