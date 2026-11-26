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
import enCredentials from "@wssp/locales/src/en-US/credentials.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHostCredentials from "@wssp/locales/src/en-US/hostCredentials.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Host credentials page against a scripted fake server: real TanStack Query,
 * real i18n (en-US), real dialogs. The fake server records every call, so the
 * tests assert what the browser sent and where a minted secret did (and did
 * not) end up: DOM, query/mutation caches, storage, URL and console.
 */

type FakeHostSummary = {
  id: string;
  slug: string;
  label: string;
  status: "DISCONNECTED" | "CONNECTED" | "STALE" | "REVOKED";
  lastConnectedAt: Date | null;
  lastHeartbeatAt: Date | null;
  deletionRequestedAt: Date | null;
};

const server = vi.hoisted(() => ({
  hosts: [] as FakeHostSummary[],
  tokens: [] as Record<string, unknown>[],
  devices: [] as Record<string, unknown>[],
  calls: [] as { procedure: string; input: unknown }[],
  listError: null as unknown,
  mintError: null as unknown,
  revokeError: null as unknown,
  /** The next N revokes fail with a transport error. */
  revokeFailures: 0,
  mintGate: null as Promise<void> | null,
  secrets: [] as string[],
  pickerPageSize: 100,
  seq: 0,
}));

const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://api.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  useBlocker: () => ({ status: "idle" }),
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

const auth = vi.hoisted(() => ({ ownerId: "owner-1" as string | null }));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state:
      auth.ownerId === null
        ? { status: "anonymous" }
        : { status: "authenticated", session: { user: { id: auth.ownerId } } },
  }),
}));
vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  const takeError = (key: "listError" | "mintError" | "revokeError") => {
    const error = server[key];
    if (key !== "listError") server[key] = null;
    return error;
  };
  const withHost = <T extends { sandboxHostId: string | null }>(row: T) => ({
    ...row,
    host: server.hosts.find((host) => host.id === row.sandboxHostId) ?? null,
  });
  const page = (procedure: string, rows: () => Record<string, unknown>[]) => ({
    key: () => ["sandboxHosts", procedure],
    infiniteOptions: (options: {
      input: (cursor: string | undefined) => unknown;
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: string | null }) => unknown;
    }) => ({
      queryKey: ["sandboxHosts", procedure, "infinite"],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
        record(procedure, options.input(pageParam));
        const error = takeError("listError");
        if (error) throw error;
        return {
          items: structuredClone(
            rows()
              .filter((row) => row.revokedAt == null)
              .map((row) => withHost(row as { sandboxHostId: string | null })),
          ),
          nextCursor: null,
        };
      },
    }),
  });
  const revoke = (procedure: string, rows: () => Record<string, unknown>[]) => ({
    call: async (input: { id: string }) => {
      record(procedure, input);
      if (server.revokeFailures > 0) {
        server.revokeFailures -= 1;
        throw Object.assign(new Error("network"), { code: "INTERNAL_SERVER_ERROR" });
      }
      const error = takeError("revokeError");
      if (error) throw error;
      const row = rows().find((item) => item.id === input.id && item.revokedAt == null);
      if (!row) throw Object.assign(new Error("not found"), { code: "NOT_FOUND" });
      row.revokedAt = new Date();
      // The relay closes the live socket: the host goes offline.
      const host = server.hosts.find((item) => item.id === row.sandboxHostId);
      if (host) host.status = "DISCONNECTED";
      return withHost(row as { sandboxHostId: string | null });
    },
  });
  return {
    orpc: {
      settings: { getAll: { key: () => ["settings", "getAll"] } },
      sandboxHosts: {
        listHosts: {
          key: () => ["sandboxHosts", "listHosts"],
          infiniteOptions: (options: {
            input: (cursor: string | undefined) => { limit: number; cursor?: string };
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["sandboxHosts", "listHosts", "infinite"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
              const input = options.input(pageParam);
              record("listHosts", input);
              // The fake pages by `pickerPageSize` (the real limit is 100).
              const start = Number(input.cursor ?? 0);
              const end = start + server.pickerPageSize;
              return {
                items: structuredClone(server.hosts.slice(start, end)),
                nextCursor: end < server.hosts.length ? String(end) : null,
              };
            },
          }),
        },
        listHostTokens: page("listHostTokens", () => server.tokens),
        listDeviceCredentials: page("listDeviceCredentials", () => server.devices),
        revokeHostToken: revoke("revokeHostToken", () => server.tokens),
        revokeDeviceCredential: revoke("revokeDeviceCredential", () => server.devices),
        createHostToken: {
          call: async (input: { hostId: string; name: string; expiresAt: Date | null }) => {
            record("createHostToken", input);
            if (server.mintGate) await server.mintGate;
            const error = takeError("mintError");
            if (error) throw error;
            server.seq += 1;
            const secret = `wssp_host_SECRET${server.seq}${"x".repeat(30)}`;
            server.secrets.push(secret);
            const token = {
              id: `token-${server.seq}`,
              name: input.name,
              lookupPrefix: `wssp_host_lookup${server.seq}`,
              sandboxHostId: input.hostId,
              lastUsedAt: null,
              revokedAt: null,
              expiresAt: input.expiresAt,
              createdAt: new Date(),
            };
            server.tokens.unshift(token);
            return { token: withHost(token), secret };
          },
        },
      },
    },
  };
});

import { ORPHAN_REVOKE_RETRY_MS } from "@/hooks/use-one-time-secret";
import { useOrphanCredentials } from "@/stores/orphan-credentials";
import { HostCredentialsPage } from "./host-credentials-page";

// Real dialogs and queries: under a loaded parallel run the default 1 s wait
// for async UI is too tight (a timing flake, not a behavior difference).
configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "hosts", "hostCredentials", "credentials"],
    defaultNS: "common",
    resources: {
      "en-US": {
        common: enCommon,
        dashboard: enDashboard,
        hosts: enHosts,
        hostCredentials: enHostCredentials,
        credentials: enCredentials,
      },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

function fakeHost(overrides: Partial<FakeHostSummary> = {}): FakeHostSummary {
  return {
    id: "host-1",
    slug: "desk-01",
    label: "Desk",
    status: "CONNECTED",
    lastConnectedAt: new Date(Date.now() - 60_000),
    lastHeartbeatAt: new Date(Date.now() - 2_000),
    deletionRequestedAt: null,
    ...overrides,
  };
}

let client: QueryClient;
function mount() {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <HostCredentialsPage lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) => server.calls.filter((call) => call.procedure === procedure);
const row = (id: string) => document.querySelector<HTMLElement>(`li[data-credential-id="${id}"]`)!;
const dialog = () => screen.getByRole("dialog");

/** Map-backed Storage (Node's own global `localStorage` shadows jsdom's). */
function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (key) => map.get(key) ?? null,
    key: (index) => [...map.keys()][index] ?? null,
    removeItem: (key) => void map.delete(key),
    setItem: (key, value) => void map.set(key, String(value)),
  };
}

/** Everything a secret could leak into besides the open reveal panel. */
function persistedSurfaces(): string {
  const storage = (store: Storage) =>
    Array.from({ length: store.length }, (_, index) => {
      const key = store.key(index) ?? "";
      return `${key}=${store.getItem(key)}`;
    }).join("\n");
  const safe = (value: unknown) => {
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  };
  return [
    safe(
      client
        .getQueryCache()
        .getAll()
        .map((query) => query.state),
    ),
    safe(
      client
        .getMutationCache()
        .getAll()
        .map((mutation) => mutation.state),
    ),
    storage(window.localStorage),
    storage(window.sessionStorage),
    window.location.href,
    document.cookie,
  ].join("\n");
}

let consoleCalls: unknown[][];
beforeEach(() => {
  server.hosts = [fakeHost()];
  server.tokens = [];
  server.devices = [];
  server.calls = [];
  server.listError = null;
  server.mintError = null;
  server.revokeError = null;
  server.revokeFailures = 0;
  server.mintGate = null;
  auth.ownerId = "owner-1";
  useOrphanCredentials.getState().clear();
  server.secrets = [];
  server.pickerPageSize = 100;
  server.seq = 0;
  navigate.mockReset();
  toast.success.mockReset();
  consoleCalls = [];
  vi.stubGlobal("localStorage", memoryStorage());
  vi.stubGlobal("sessionStorage", memoryStorage());
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    vi.spyOn(console, level).mockImplementation((...args: unknown[]) => {
      consoleCalls.push(args);
    });
  }
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

/**
 * Releases a gated mint on fake time, so the orphan revoke retry waits
 * (`ORPHAN_REVOKE_RETRY_MS`) are skipped instead of slept through.
 */
async function releaseOnFakeTime(release: () => void) {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  await act(async () => {
    release();
  });
}

/** Elapses every orphan revoke retry wait. */
async function elapseRevokeRetries() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ORPHAN_REVOKE_RETRY_MS.reduce((sum, ms) => sum + ms, 0));
  });
}

/** The inline one-time secret panel on the page (outside any dialog). */
function reveal(): HTMLElement {
  const panel = document.querySelector<HTMLElement>("[data-one-time-secret]");
  if (!panel) throw new Error("no inline secret panel");
  expect(panel.closest("[role=dialog]")).toBeNull();
  return panel;
}

async function openMintAndFill(user: ReturnType<typeof userEvent.setup>, name = "rack-7") {
  await user.click(await screen.findByRole("button", { name: enHostCredentials.mint.action }));
  const form = within(dialog());
  await user.type(form.getByLabelText(enCredentials.form.name), name);
  await form.findByRole("combobox", { name: enHostCredentials.mint.host });
  await selectOption(user, form.getByLabelText(enHostCredentials.mint.host), "Desk (desk-01)");
}

describe("host credentials lists", () => {
  it("a failed first load shows a retry; retrying loads the lists", async () => {
    server.listError = Object.assign(new Error("network"), { code: "INTERNAL_SERVER_ERROR" });
    const user = userEvent.setup();
    mount();
    const retries = await screen.findAllByRole("button", { name: enCommon.actions.tryAgain });
    expect(retries).toHaveLength(2);
    expect(screen.queryByText(enHostCredentials.empty.title)).toBeNull();
    server.listError = null;
    for (const retry of retries) await user.click(retry);
    expect(await screen.findByText(enHostCredentials.empty.title)).toBeTruthy();
    expect(screen.getByText(enHostCredentials.devices.emptyTitle)).toBeTruthy();
    expect(navigate).not.toHaveBeenCalled();
  });

  it("shows tokens and device credentials with host status, last use and expiry, never a digest", async () => {
    const now = Date.now();
    server.tokens = [
      {
        id: "token-a",
        name: "rack token",
        lookupPrefix: "wssp_host_abcdefghijkl",
        sandboxHostId: "host-1",
        lastUsedAt: new Date(now - 3 * 60_000),
        revokedAt: null,
        expiresAt: new Date(now + 2 * 86_400_000),
        createdAt: new Date(now - 86_400_000),
        secretDigest: "DIGEST-SHOULD-NOT-RENDER",
      },
    ];
    server.devices = [
      {
        id: "device-a",
        lookupPrefix: "wssp_device_mnopqrstuvwx",
        sandboxHostId: "host-1",
        lastUsedAt: null,
        revokedAt: null,
        createdAt: new Date(now - 86_400_000),
      },
    ];
    mount();
    await screen.findByRole("list", { name: enHostCredentials.tokens.title });
    const token = row("token-a");
    expect(within(token).getByText("rack token")).toBeTruthy();
    expect(within(token).getByText("wssp_host_abcdefghijkl…")).toBeTruthy();
    expect(token.querySelector("[data-host-status]")?.getAttribute("data-host-status")).toBe(
      "ready",
    );
    expect(token.querySelector("[data-last-used]")?.textContent).toBe("3 minutes ago");
    expect(token.querySelector("[data-expiry]")?.textContent).toBe("in 2 days");
    const device = row("device-a");
    expect(within(device).getByText("Device login for desk-01")).toBeTruthy();
    expect(device.querySelector("[data-last-used]")?.textContent).toBe(
      enCredentials.dates.neverUsed,
    );
    expect(document.body.innerHTML).not.toContain("DIGEST-SHOULD-NOT-RENDER");
  });
});

describe("minting a host token", () => {
  it("rejects an incomplete form in the browser without a request", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enHostCredentials.mint.action }));
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    // Each error sits under its field (aria-invalid + described by it); Name gets focus.
    const name = within(dialog()).getByLabelText(enCredentials.form.name);
    await waitFor(() => expect(name.getAttribute("aria-invalid")).toBe("true"));
    // focusFirstInvalidField moves focus one animation frame after the submit.
    await waitFor(() => expect(document.activeElement).toBe(name));
    const host = within(dialog()).getByLabelText(enHostCredentials.mint.host);
    expect(host.getAttribute("aria-invalid")).toBe("true");
    const describedText = (element: HTMLElement) =>
      (element.getAttribute("aria-describedby") ?? "")
        .split(" ")
        .map((id) => document.getElementById(id)?.textContent ?? "")
        .join(" ");
    expect(describedText(name)).toContain(enCredentials.draft.nameRequired);
    expect(describedText(host)).toContain(enCredentials.draft.noHost);
    expect(calls("createHostToken")).toHaveLength(0);
  });

  it("after a failed submit, a corrected form creates the token (no stuck submit)", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enHostCredentials.mint.action }));
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await within(dialog()).findAllByRole("alert");
    await user.type(within(dialog()).getByLabelText(enCredentials.form.name), "rack");
    await selectOption(
      user,
      within(dialog()).getByLabelText(enHostCredentials.mint.host),
      "Desk (desk-01)",
    );
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("createHostToken")).toHaveLength(1);
  });

  it("offers only hosts that can take a token (not pending deletion)", async () => {
    server.hosts = [
      fakeHost(),
      fakeHost({ id: "host-2", slug: "gone", label: "Gone", deletionRequestedAt: new Date() }),
    ];
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    expect(
      (
        await selectChoices(user, within(dialog()).getByLabelText(enHostCredentials.mint.host))
      ).some((option) => option.textContent?.includes("Gone (gone)")),
    ).toBe(false);
  });

  it("pages the host picker with Load more instead of stopping at one page", async () => {
    server.hosts = [fakeHost(), fakeHost({ id: "host-2", slug: "rack-02", label: "Rack" })];
    server.pickerPageSize = 1;
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    expect(
      (
        await selectChoices(user, within(dialog()).getByLabelText(enHostCredentials.mint.host))
      ).some((option) => option.textContent?.includes("Rack (rack-02)")),
    ).toBe(false);
    await user.click(
      within(dialog()).getByRole("button", { name: enHostCredentials.mint.moreHosts }),
    );
    await selectOption(
      user,
      within(dialog()).getByLabelText(enHostCredentials.mint.host),
      "Rack (rack-02)",
    );
    expect(calls("listHosts").map((call) => call.input)).toEqual([
      { limit: 100, cursor: undefined },
      { limit: 100, cursor: "1" },
    ]);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("createHostToken")[0]?.input).toMatchObject({ hostId: "host-2" });
  });

  it("mint → inline masked reveal → show → copy → done leaves the secret nowhere", async () => {
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user, "  rack-7  ");
    await selectOption(
      user,
      within(dialog()).getByLabelText(enCredentials.form.expiry),
      enCredentials.expiry["30d"],
    );
    const before = Date.now();
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    // M7-S4: the dialog closes and the secret is shown inline on the page.
    await screen.findByText(enCredentials.reveal.onceWarning);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    for (const flag of ["--sandbox-memory-mib", "--max-sandbox-cpu-count"]) {
      expect(screen.getByText(flag, { selector: "code" }).className).toContain("whitespace-nowrap");
    }
    const panel = reveal();
    expect(calls("createHostToken")).toHaveLength(1);
    const sent = calls("createHostToken")[0]?.input as {
      hostId: string;
      name: string;
      expiresAt: Date;
    };
    expect(sent.hostId).toBe("host-1");
    expect(sent.name).toBe("rack-7");
    expect(sent.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 30 * 86_400_000);
    expect(sent.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 30 * 86_400_000);
    const secret = server.secrets[0]!;
    // Masked until the owner asks to see it.
    expect(document.body.innerHTML).not.toContain(secret);
    await user.click(within(panel).getByRole("button", { name: enCredentials.reveal.show }));
    expect(within(panel).getByText(secret)).toBeTruthy();
    // The nonsecret connect command names the env var, never the token.
    const command =
      "wssp host run --server https://api.example.test --host-id host-1 --host-token-env WSSP_HOST_TOKEN";
    expect(within(panel).getByText(command)).toBeTruthy();
    await user.click(within(panel).getByRole("button", { name: enCredentials.reveal.copy }));
    expect(await navigator.clipboard.readText()).toBe(secret);
    expect(within(panel).getByText(enCredentials.reveal.copied)).toBeTruthy();
    // While shown, it is in the DOM only — no cache, storage, URL or log.
    expect(persistedSurfaces()).not.toContain(secret);
    // A stray Escape cannot lose it: only an explicit Done dismisses it.
    await user.keyboard("{Escape}");
    expect(within(reveal()).getByText(secret)).toBeTruthy();
    // No second mint while this secret is still on screen.
    expect(
      (screen.getByRole("button", { name: enHostCredentials.mint.action }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    await user.click(within(panel).getByRole("button", { name: enCredentials.reveal.done }));
    expect(document.querySelector("[data-one-time-secret]")).toBeNull();
    expect(document.body.innerHTML).not.toContain(secret);
    expect(persistedSurfaces()).not.toContain(secret);
    expect(JSON.stringify(consoleCalls)).not.toContain(secret);
    // The new token is listed by prefix; the list refetched after the mint.
    await waitFor(() => expect(row("token-1")).toBeTruthy());
    expect(document.body.innerHTML).not.toContain(secret);
    // Reopening the dialog starts a fresh form, not the old secret.
    await user.click(screen.getByRole("button", { name: enHostCredentials.mint.action }));
    expect(within(dialog()).queryByText(enCredentials.reveal.onceWarning)).toBeNull();
    expect(document.body.innerHTML).not.toContain(secret);
  });

  it("a reload (remount) cannot reveal the secret again", async () => {
    const user = userEvent.setup();
    const view = mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await screen.findByText(enCredentials.reveal.onceWarning);
    const secret = server.secrets[0]!;
    // Navigation away unmounts the page; a reload builds everything afresh.
    view.unmount();
    expect(document.body.innerHTML).not.toContain(secret);
    mount();
    await waitFor(() => expect(row("token-1")).toBeTruthy());
    expect(screen.queryByText(enCredentials.reveal.onceWarning)).toBeNull();
    expect(document.body.innerHTML).not.toContain(secret);
    expect(persistedSurfaces()).not.toContain(secret);
  });

  it("pagehide drops a revealed secret (no back-forward-cache restore)", async () => {
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await screen.findByText(enCredentials.reveal.onceWarning);
    await user.click(within(reveal()).getByRole("button", { name: enCredentials.reveal.show }));
    const secret = server.secrets[0]!;
    expect(document.body.innerHTML).toContain(secret);
    act(() => {
      window.dispatchEvent(new Event("pagehide"));
    });
    expect(document.body.innerHTML).not.toContain(secret);
  });

  it("closing while the mint is in flight never reveals it and revokes the orphan", async () => {
    let release!: () => void;
    server.mintGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await act(async () => {
      release();
    });
    await waitFor(() => expect(calls("revokeHostToken")).toHaveLength(1));
    expect(calls("revokeHostToken")[0]?.input).toEqual({ id: "token-1" });
    expect(document.body.innerHTML).not.toContain(server.secrets[0]!);
    expect(persistedSurfaces()).not.toContain(server.secrets[0]!);
  });

  it("pagehide while the mint is in flight discards it: never revealed on restore, and revoked", async () => {
    let release!: () => void;
    server.mintGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await waitFor(() => expect(calls("createHostToken")).toHaveLength(1));
    // Back-forward cache: the page is hidden, not unmounted, then restored.
    act(() => {
      window.dispatchEvent(new Event("pagehide"));
    });
    await act(async () => {
      release();
    });
    await waitFor(() => expect(calls("revokeHostToken")).toHaveLength(1));
    expect(calls("revokeHostToken")[0]?.input).toEqual({ id: "token-1" });
    expect(document.querySelector("[data-one-time-secret]")).toBeNull();
    expect(document.body.innerHTML).not.toContain(server.secrets[0]!);
  });

  it("a failed orphan revoke is retried, then reported with a manual revoke", async () => {
    let release!: () => void;
    server.mintGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.revokeFailures = 3;
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
    await releaseOnFakeTime(release);
    await elapseRevokeRetries();
    const alert = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-orphan-id="token-1"]');
      if (!found) throw new Error("no orphan alert");
      return found;
    });
    // Bounded: three automatic attempts, then the owner is told.
    expect(calls("revokeHostToken")).toHaveLength(3);
    expect(alert.textContent).toContain("rack-7");
    expect(document.body.innerHTML).not.toContain(server.secrets[0]!);
    await user.click(within(alert).getByRole("button", { name: enCredentials.orphan.retry }));
    await waitFor(() => expect(document.querySelector("[data-orphan-id]")).toBeNull());
    expect(calls("revokeHostToken")).toHaveLength(4);
    expect(server.tokens[0]?.revokedAt).not.toBeNull();
  });

  /** Mint, cancel while in flight, leave the page, and let every revoke fail. */
  async function orphanAfterLeaving() {
    let release!: () => void;
    server.mintGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.revokeFailures = 3;
    const user = userEvent.setup();
    const view = mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
    view.unmount();
    await releaseOnFakeTime(release);
    await elapseRevokeRetries();
    await waitFor(() => expect(useOrphanCredentials.getState().entries).toHaveLength(1));
    expect(calls("revokeHostToken")).toHaveLength(3);
    return user;
  }

  it("a failed orphan revoke after leaving the page is shown again on return, holding no secret", async () => {
    const user = await orphanAfterLeaving();
    // The retained queue holds only nonsecret strings: no secret, result or callback.
    const { entries } = useOrphanCredentials.getState();
    expect(entries).toEqual([
      { ownerId: "owner-1", scope: "hostToken", id: "token-1", label: "rack-7" },
    ]);
    expect(JSON.stringify(entries)).not.toContain(server.secrets[0]!);
    expect(persistedSurfaces()).not.toContain(server.secrets[0]!);
    mount();
    const alert = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-orphan-id="token-1"]');
      if (!found) throw new Error("no orphan alert");
      return found;
    });
    expect(alert.textContent).toContain("rack-7");
    await user.click(within(alert).getByRole("button", { name: enCredentials.orphan.retry }));
    await waitFor(() => expect(document.querySelector("[data-orphan-id]")).toBeNull());
    expect(calls("revokeHostToken").at(-1)?.input).toEqual({ id: "token-1" });
    expect(useOrphanCredentials.getState().entries).toEqual([]);
  });

  it("another owner never sees the queued orphan, and signing out clears it", async () => {
    await orphanAfterLeaving();
    auth.ownerId = "owner-2";
    const view = mount();
    await waitFor(() => expect(row("token-1")).toBeTruthy());
    expect(document.querySelector("[data-orphan-id]")).toBeNull();
    await waitFor(() => expect(useOrphanCredentials.getState().entries).toEqual([]));
    view.unmount();

    const store = useOrphanCredentials.getState();
    store.add({ ownerId: "owner-2", scope: "hostToken", id: "token-9", label: "x" }, store.epoch);
    auth.ownerId = null;
    mount();
    await waitFor(() => expect(useOrphanCredentials.getState().entries).toEqual([]));
    expect(document.querySelector("[data-orphan-id]")).toBeNull();
  });

  it.each([
    ["sign-out from the menu", () => useOrphanCredentials.getState().clear()],
    [
      "the session ending",
      () => {
        auth.ownerId = null;
        return mount();
      },
    ],
    [
      "signing out and back in as the same owner",
      () => {
        useOrphanCredentials.getState().clear();
        return mount();
      },
    ],
    [
      "another owner signing in",
      () => {
        auth.ownerId = "owner-2";
        return mount();
      },
    ],
  ])(
    "a cleanup still retrying during %s never queues the orphan afterwards",
    async (_name, change) => {
      let release!: () => void;
      server.mintGate = new Promise<void>((resolve) => {
        release = resolve;
      });
      server.revokeFailures = 3;
      const user = userEvent.setup();
      const view = mount();
      await openMintAndFill(user);
      await user.click(
        within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }),
      );
      await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
      view.unmount();
      await releaseOnFakeTime(release);
      await waitFor(() => expect(calls("revokeHostToken")).toHaveLength(1));
      // The change lands inside the first retry wait (500 ms of fake time).
      await act(async () => {
        change();
      });
      await elapseRevokeRetries();
      await waitFor(() => expect(calls("revokeHostToken")).toHaveLength(3));
      await act(async () => {
        await vi.advanceTimersByTimeAsync(100);
      });
      expect(useOrphanCredentials.getState().entries).toEqual([]);
      expect(document.querySelector("[data-orphan-id]")).toBeNull();
    },
  );

  it("a first host page with only excluded hosts still offers Load more", async () => {
    server.hosts = [
      fakeHost({ id: "host-gone", slug: "gone", label: "Gone", deletionRequestedAt: new Date() }),
      fakeHost(),
    ];
    server.pickerPageSize = 1;
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enHostCredentials.mint.action }));
    const more = await within(dialog()).findByRole("button", {
      name: enHostCredentials.mint.moreHosts,
    });
    expect(within(dialog()).queryByText(enHostCredentials.mint.noHosts)).toBeNull();
    await user.click(more);
    expect(
      await within(dialog()).findByRole("combobox", { name: enHostCredentials.mint.host }),
    ).toBeTruthy();
  });

  it("the connect command uses automatic local capacity defaults", async () => {
    server.hosts = [fakeHost()];
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(
      within(reveal()).getByText(
        "wssp host run --server https://api.example.test --host-id host-1 --host-token-env WSSP_HOST_TOKEN",
      ),
    ).toBeTruthy();
  });

  it("a refused mint is explained, keeps the form, and a retry succeeds", async () => {
    server.mintError = Object.assign(new Error("Host was removed during token mint."), {
      code: "CONFLICT",
    });
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    const alert = await within(dialog()).findByRole("alert");
    expect(alert.textContent).toBe(enCredentials.problem.changed);
    expect(
      (within(dialog()).getByLabelText(enCredentials.form.name) as HTMLInputElement).value,
    ).toBe("rack-7");
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("createHostToken")).toHaveLength(2);
  });

  it("a forced-2FA refusal redirects to Security settings instead of an error", async () => {
    server.mintError = Object.assign(new Error("Two-factor authentication setup is required."), {
      code: "FORBIDDEN",
      data: { code: "auth.two_factor_required" },
    });
    const user = userEvent.setup();
    mount();
    await openMintAndFill(user);
    await user.click(within(dialog()).getByRole("button", { name: enHostCredentials.mint.submit }));
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({
        to: "/$lang/settings/security",
        params: { lang: "en-US" },
      }),
    );
    expect(within(dialog()).queryByRole("alert")).toBeNull();
  });
});

describe("revoking", () => {
  const liveToken = () => ({
    id: "token-a",
    name: "rack token",
    lookupPrefix: "wssp_host_abcdefghijkl",
    sandboxHostId: "host-1",
    lastUsedAt: null,
    revokedAt: null,
    expiresAt: null,
    createdAt: new Date(),
  });

  it("requires confirmation; cancel sends nothing", async () => {
    server.tokens = [liveToken()];
    const user = userEvent.setup();
    mount();
    await screen.findByRole("list", { name: enHostCredentials.tokens.title });
    await user.click(within(row("token-a")).getByRole("button", { name: "Revoke rack token" }));
    const confirm = await screen.findByRole("alertdialog");
    expect(within(confirm).getByText("Revoke rack token?")).toBeTruthy();
    await user.click(within(confirm).getByRole("button", { name: enCommon.actions.cancel }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(calls("revokeHostToken")).toHaveLength(0);
  });

  it("revoking a live host's token refreshes the list and the host's status", async () => {
    server.tokens = [liveToken()];
    const user = userEvent.setup();
    mount();
    await screen.findByRole("list", { name: enHostCredentials.tokens.title });
    expect(
      row("token-a").querySelector("[data-host-status]")?.getAttribute("data-host-status"),
    ).toBe("ready");
    server.devices = [
      {
        id: "device-a",
        lookupPrefix: "wssp_device_mnopqrstuvwx",
        sandboxHostId: "host-1",
        lastUsedAt: null,
        revokedAt: null,
        createdAt: new Date(),
      },
    ];
    const invalidated: unknown[] = [];
    const original = client.invalidateQueries.bind(client);
    vi.spyOn(client, "invalidateQueries").mockImplementation((filters, options) => {
      invalidated.push(filters?.queryKey);
      return original(filters, options);
    });
    await user.click(within(row("token-a")).getByRole("button", { name: "Revoke rack token" }));
    const confirm = await screen.findByRole("alertdialog");
    const listsBefore = calls("listDeviceCredentials").length;
    await user.click(within(confirm).getByRole("button", { name: enCredentials.revoke.confirm }));
    await waitFor(() =>
      expect(calls("revokeHostToken")).toEqual([
        { procedure: "revokeHostToken", input: { id: "token-a" } },
      ]),
    );
    await waitFor(() =>
      expect(document.querySelector('li[data-credential-id="token-a"]')).toBeNull(),
    );
    // Sibling lists (and the Hosts page) are refetched: the device row no
    // longer shows the host ready because its live connection was closed (it
    // connected a minute ago, so it reads as reconnecting, not offline).
    await waitFor(() => expect(calls("listDeviceCredentials").length).toBeGreaterThan(listsBefore));
    await waitFor(() =>
      expect(
        row("device-a").querySelector("[data-host-status]")?.getAttribute("data-host-status"),
      ).toBe("reconnecting"),
    );
    // The Hosts page's list is invalidated too, so its status catches up.
    expect(invalidated).toContainEqual(["sandboxHosts", "listHosts"]);
    expect(toast.success).toHaveBeenCalledWith(enHostCredentials.revoke.tokenDone);
  });

  it("revokes a device credential after confirmation", async () => {
    server.devices = [
      {
        id: "device-a",
        lookupPrefix: "wssp_device_mnopqrstuvwx",
        sandboxHostId: "host-1",
        lastUsedAt: null,
        revokedAt: null,
        createdAt: new Date(),
      },
    ];
    const user = userEvent.setup();
    mount();
    await screen.findByRole("list", { name: enHostCredentials.devices.title });
    await user.click(
      within(row("device-a")).getByRole("button", { name: "Revoke Device login for desk-01" }),
    );
    const confirm = await screen.findByRole("alertdialog");
    expect(within(confirm).getByText("Revoke the device credential for desk-01?")).toBeTruthy();
    await user.click(within(confirm).getByRole("button", { name: enCredentials.revoke.confirm }));
    await waitFor(() =>
      expect(calls("revokeDeviceCredential")).toEqual([
        { procedure: "revokeDeviceCredential", input: { id: "device-a" } },
      ]),
    );
    expect(await screen.findByText(enHostCredentials.devices.emptyTitle)).toBeTruthy();
  });

  it("a revoke refused as already gone is explained and the list refetched", async () => {
    server.tokens = [liveToken()];
    server.revokeError = Object.assign(new Error("Host token not found."), { code: "NOT_FOUND" });
    const user = userEvent.setup();
    mount();
    await screen.findByRole("list", { name: enHostCredentials.tokens.title });
    const before = calls("listHostTokens").length;
    await user.click(within(row("token-a")).getByRole("button", { name: "Revoke rack token" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: enCredentials.revoke.confirm,
      }),
    );
    expect((await within(row("token-a")).findByRole("alert")).textContent).toBe(
      enCredentials.problem.notFound,
    );
    await waitFor(() => expect(calls("listHostTokens").length).toBeGreaterThan(before));
  });

  it("a list refused by forced 2FA redirects to Security settings", async () => {
    server.listError = Object.assign(new Error("Two-factor authentication setup is required."), {
      code: "FORBIDDEN",
      data: { code: "auth.two_factor_required" },
    });
    mount();
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({
        to: "/$lang/settings/security",
        params: { lang: "en-US" },
      }),
    );
  });
});
