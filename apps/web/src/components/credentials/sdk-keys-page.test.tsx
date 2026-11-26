import { selectOption } from "@/test/select-option";

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
import enSdkKeys from "@wssp/locales/src/en-US/sdkKeys.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * SDK keys page against a scripted fake server (real TanStack Query, i18n and
 * dialogs): scope dependency and allowlist rules block bad mints in the
 * browser, a minted key is revealed once and disposed, and revokes confirm.
 */

const server = vi.hoisted(() => ({
  keys: [] as Record<string, unknown>[],
  hosts: [] as Record<string, unknown>[],
  templates: [] as Record<string, unknown>[],
  pools: [] as Record<string, unknown>[],
  calls: [] as { procedure: string; input: unknown }[],
  listError: null as unknown,
  pickerError: null as unknown,
  pickerPageSize: 100,
  mintError: null as unknown,
  mintGate: null as Promise<void> | null,
  /** The next N revokes fail with a transport error. */
  revokeFailures: 0,
  secrets: [] as string[],
  seq: 0,
  allowNoExpiry: true,
  maxLifetimeDays: 90,
  policyError: null as unknown,
}));

const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className}>{children}</a>
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
  // Cursor-paged pickers: the cursor is the next row index; the page size is
  // `server.pickerPageSize` (the real procedure takes `limit`, at most 100).
  const picker = (procedure: string, rows: () => Record<string, unknown>[]) => ({
    key: () => [procedure],
    infiniteOptions: (options: {
      input: (cursor: string | undefined) => { limit: number; cursor?: string };
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: string | null }) => unknown;
    }) => ({
      queryKey: [procedure, "infinite"],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
        const input = options.input(pageParam);
        record(procedure, input);
        if (server.pickerError && procedure !== "listPools") throw server.pickerError;
        const start = Number(input.cursor ?? 0);
        const size = Math.min(input.limit, server.pickerPageSize);
        const all = rows();
        return {
          items: structuredClone(all.slice(start, start + size)),
          nextCursor: start + size < all.length ? String(start + size) : null,
        };
      },
    }),
  });
  const mocked = {
    orpc: {
      settings: { getAll: { key: () => ["settings", "getAll"] } },
      sandboxPools: { listUsable: picker("listPools", () => server.pools) },
      logins: {
        listLogins: {
          infiniteOptions: (options: {
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["listLogins", "infinite"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async () => ({
              items: [{ id: "cred_1", name: "work" }],
              nextCursor: null,
            }),
          }),
        },
      },
      sandboxHosts: { listHosts: picker("listHosts", () => server.hosts) },
      sandboxTemplates: {
        listRevisionChoices: picker("listRevisionChoices", () =>
          server.templates.map((row) => ({
            ...row,
            availability: row.availability ?? [{ hostId: row.sandboxHostId, status: "AVAILABLE" }],
          })),
        ),
      },
      sdkKeys: {
        list: {
          key: () => ["sdkKeys", "list"],
          infiniteOptions: (options: {
            input: (cursor: string | undefined) => unknown;
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["sdkKeys", "list", "infinite"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
              record("list", options.input(pageParam));
              if (server.listError) throw server.listError;
              return {
                items: structuredClone(server.keys.filter((key) => key.revokedAt == null)),
                nextCursor: null,
              };
            },
          }),
        },
        create: {
          call: async (input: Record<string, unknown>) => {
            record("create", input);
            if (server.mintGate) await server.mintGate;
            const error = server.mintError;
            server.mintError = null;
            if (error) throw error;
            server.seq += 1;
            const secret = `wssp_sdk_SECRET${server.seq}${"y".repeat(30)}`;
            server.secrets.push(secret);
            const key = {
              id: `key-${server.seq}`,
              name: input.name,
              resourceMode: input.resourceMode,
              scopes: input.scopes,
              lookupPrefix: `wssp_sdk_lookup${server.seq}`,
              lastUsedAt: null,
              revokedAt: null,
              expiresAt: input.expiresAt,
              createdAt: new Date(),
              hostAllowlist: (input.hostIds as string[]).map((id) => ({ id, slug: id, label: id })),
              revisionAllowlist: (input.templateRevisionIds as string[]).map((id) => ({
                id,
                label: id,
              })),
            };
            server.keys.unshift(key);
            return { key, secret };
          },
        },
        revoke: {
          call: async (input: { id: string }) => {
            record("revoke", input);
            if (server.revokeFailures > 0) {
              server.revokeFailures -= 1;
              throw Object.assign(new Error("network"), { code: "INTERNAL_SERVER_ERROR" });
            }
            const key = server.keys.find((row) => row.id === input.id && row.revokedAt == null);
            if (!key) throw Object.assign(new Error("SDK key not found."), { code: "NOT_FOUND" });
            key.revokedAt = new Date();
            return { ok: true };
          },
        },
      },
    },
  };
  return {
    orpc: {
      ...mocked.orpc,
      agentTokens: {
        ...mocked.orpc.sdkKeys,
        expiryPolicy: {
          queryOptions: () => ({
            queryKey: ["agentTokens", "expiryPolicy"],
            queryFn: async () => {
              if (server.policyError) throw server.policyError;
              return {
                allowNoExpiry: server.allowNoExpiry,
                maxLifetimeDays: server.maxLifetimeDays,
              };
            },
          }),
        },
      },
    },
  };
});

import enAgents from "@wssp/locales/src/en-US/agents.json";
import { ORPHAN_REVOKE_RETRY_MS } from "@/hooks/use-one-time-secret";
import { useOrphanCredentials } from "@/stores/orphan-credentials";
import { CredentialGrantEditor, ScopePicker, SdkKeysPage } from "./sdk-keys-page";

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
    ns: ["common", "dashboard", "sdkKeys", "credentials"],
    defaultNS: "common",
    resources: {
      "en-US": {
        common: enCommon,
        dashboard: enDashboard,
        sdkKeys: enSdkKeys,
        agents: enAgents,
        credentials: enCredentials,
      },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

let client: QueryClient;
function mount(agent = false) {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <SdkKeysPage lang="en-US" agent={agent} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) => server.calls.filter((call) => call.procedure === procedure);
const dialog = () => screen.getByRole("dialog");
const row = (id: string) => document.querySelector<HTMLElement>(`li[data-credential-id="${id}"]`)!;
const scopeBox = (scope: string) => within(dialog()).getByRole("checkbox", { name: scope });

beforeEach(() => {
  server.allowNoExpiry = true;
  server.maxLifetimeDays = 90;
  server.policyError = null;
  server.pools = [];
  server.keys = [];
  server.hosts = [
    { id: "host-a", slug: "alpha", label: "Alpha", deletionRequestedAt: null },
    { id: "host-b", slug: "beta", label: "Beta", deletionRequestedAt: null },
    { id: "host-x", slug: "gone", label: "Gone", deletionRequestedAt: new Date() },
  ];
  server.templates = [
    { id: "tpl-a", slug: "ubuntu", label: "Ubuntu", sandboxHostId: "host-a", retiredAt: null },
    { id: "tpl-b", slug: "debian", label: "Debian", sandboxHostId: "host-b", retiredAt: null },
    { id: "tpl-old", slug: "old", label: "Old", sandboxHostId: "host-a", retiredAt: new Date() },
  ];
  server.calls = [];
  server.listError = null;
  server.pickerError = null;
  server.pickerPageSize = 100;
  server.mintError = null;
  server.mintGate = null;
  auth.ownerId = "owner-1";
  useOrphanCredentials.getState().clear();
  server.revokeFailures = 0;
  server.secrets = [];
  server.seq = 0;
  navigate.mockReset();
  toast.success.mockReset();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
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

async function openMint(user: ReturnType<typeof userEvent.setup>, name = "ci") {
  await user.click(await screen.findByRole("button", { name: enSdkKeys.mint.action }));
  await user.type(within(dialog()).getByLabelText(enCredentials.form.name), name);
}

const submit = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(within(dialog()).getByRole("button", { name: enSdkKeys.mint.submit }));

describe("sdk key list", () => {
  it("a failed first load shows a retry that recovers", async () => {
    server.listError = new Error("network");
    const user = userEvent.setup();
    mount();
    const retry = await screen.findByRole("button", { name: enCommon.actions.tryAgain });
    expect(screen.getByText(enDashboard.list.loadFailed)).toBeTruthy();
    server.listError = null;
    await user.click(retry);
    expect(await screen.findByText(enSdkKeys.empty.title)).toBeTruthy();
  });

  it("shows scopes, restriction, last use and expiry, and no digest", async () => {
    const now = Date.now();
    server.keys = [
      {
        id: "key-z",
        name: "ci key",
        resourceMode: "ALLOWLIST",
        poolMode: "ALL_USABLE",
        poolIds: [],
        scopes: ["sandboxes:read", "sandboxes:create", "sandboxes:manage", "sandboxes:destroy"],
        lookupPrefix: "wssp_sdk_abcdefghijkl",
        lastUsedAt: new Date(now - 2 * 3_600_000),
        revokedAt: null,
        expiresAt: new Date(now - 60_000),
        createdAt: new Date(now - 86_400_000),
        hostAllowlist: [{ id: "host-a", slug: "desk-01", label: "Desk" }],
        revisionAllowlist: [
          { id: "tpl-a", label: "ubuntu-24.04" },
          { id: "tpl-b", label: "debian-13" },
        ],
        secretDigest: "DIGEST-NOT-SHOWN",
      },
    ];
    mount();
    await screen.findByRole("list", { name: enSdkKeys.title });
    const key = row("key-z");
    expect(within(key).getByText("wssp_sdk_abcdefghijkl…")).toBeTruthy();
    expect([...key.querySelectorAll("[data-scope]")].map((node) => node.textContent)).toEqual([
      "sandboxes:read",
      "sandboxes:create",
      "sandboxes:manage",
      "sandboxes:destroy",
    ]);
    // M7-S11: the allowlist names each host and template, not just counts.
    expect(key.querySelector("[data-allowlist=hosts]")?.textContent).toBe("Hosts: Desk (desk-01)");
    expect(key.querySelector("[data-allowlist=templates]")?.textContent).toBe(
      "Template versions: ubuntu-24.04 · tpl-a and debian-13 · tpl-b",
    );
    expect(key.querySelector("[data-last-used]")?.textContent).toBe("2 hours ago");
    expect(key.querySelector("[data-expiry]")?.textContent).toBe(enCredentials.dates.expired);
    expect(key.getAttribute("data-expired")).toBe("true");
    expect(document.body.innerHTML).not.toContain("DIGEST-NOT-SHOWN");
  });

  it("marks a CLI-login key and shows its live-sandbox limit; a dashboard key shows neither", async () => {
    const now = Date.now();
    const base = {
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      poolIds: [],
      scopes: ["sandboxes:read"],
      lastUsedAt: null,
      revokedAt: null,
      expiresAt: new Date(now + 86_400_000),
      createdAt: new Date(now - 86_400_000),
      hostAllowlist: [],
      revisionAllowlist: [],
    };
    server.keys = [
      {
        ...base,
        id: "key-cli",
        name: "wssp login",
        lookupPrefix: "wssp_sdk_cliloginkey1",
        origin: "CLI_LOGIN",
        maxLiveSandboxes: 3,
      },
      {
        ...base,
        id: "key-dash",
        name: "dashboard key",
        lookupPrefix: "wssp_sdk_dashboardk1",
        origin: "DASHBOARD",
        maxLiveSandboxes: null,
      },
    ];
    mount();
    await screen.findByRole("list", { name: enSdkKeys.title });
    const cli = row("key-cli");
    expect(within(cli).getByText(enSdkKeys.list.cliLogin)).toBeTruthy();
    expect(cli.querySelector("[data-max-live-sandboxes]")?.textContent).toBe(
      "Up to 3 live sandboxes",
    );
    const dashboard = row("key-dash");
    expect(within(dashboard).queryByText(enSdkKeys.list.cliLogin)).toBeNull();
    expect(dashboard.querySelector("[data-max-live-sandboxes]")).toBeNull();
  });
});

describe("scope dependency validation", () => {
  it("a scope that grants nothing alone is flagged and cannot be submitted", async () => {
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("operations:cancel"));
    expect(dialog().querySelector('[data-scope-needs="operations:cancel"]')).not.toBeNull();
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toContain(
      enCredentials.draft.unusableScopes,
    );
    expect(calls("create")).toHaveLength(0);
    // A discovery scope now supplies LIST_PROCESSES cancellation authority.
    await user.click(scopeBox("commands:read"));
    expect(dialog().querySelector('[data-scope-needs="commands:read"]')).toBeNull();
    expect(dialog().querySelector('[data-scope-needs="operations:cancel"]')).toBeNull();
    await user.click(scopeBox("operations:read"));
    await user.click(scopeBox("commands:execute"));
    expect(dialog().querySelector("[data-scope-needs]")).toBeNull();
    await submit(user);
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("create")).toHaveLength(1);
    // Sent in canonical order, with no allowlists for an all-owned key.
    expect(calls("create")[0]?.input).toMatchObject({
      name: "ci",
      scopes: ["commands:read", "commands:execute", "operations:read", "operations:cancel"],
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      poolIds: [],
      hostIds: [],
      templateRevisionIds: [],
    });
  });

  it("no scopes cannot be submitted", async () => {
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toContain(
      enCredentials.draft.noScopes,
    );
    expect(calls("create")).toHaveLength(0);
  });
});

describe("resource allowlists", () => {
  it("pages hosts and active templates with Load more instead of stopping at one page", async () => {
    server.pickerPageSize = 1;
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("sandboxes:create"));
    await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
    await within(dialog()).findByRole("checkbox", { name: "Alpha (alpha)" });
    expect(within(dialog()).queryByRole("checkbox", { name: "Beta (beta)" })).toBeNull();
    // Templates are requested as active only (the server refuses retired ones).
    expect(calls("listRevisionChoices")[0]?.input).toMatchObject({ limit: 100, hostIds: [] });
    await user.click(within(dialog()).getByRole("button", { name: enSdkKeys.form.moreHosts }));
    await user.click(await within(dialog()).findByRole("checkbox", { name: "Beta (beta)" }));
    expect(calls("listHosts").map((call) => call.input)).toEqual([
      { limit: 100, cursor: undefined },
      { limit: 100, cursor: "1" },
    ]);
    // Beta's template is on the second template page.
    expect(within(dialog()).queryByRole("checkbox", { name: /Debian \(debian\)/ })).toBeNull();
    await user.click(within(dialog()).getByRole("button", { name: enSdkKeys.form.moreTemplates }));
    await user.click(await within(dialog()).findByRole("checkbox", { name: /Debian \(debian\)/ }));
    await submit(user);
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("create")[0]?.input).toMatchObject({
      hostIds: ["host-b"],
      templateRevisionIds: ["tpl-b"],
    });
  });

  it("a server refusal of the template/host pairing is explained and reloads the pickers", async () => {
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("sandboxes:create"));
    await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
    await user.click(await within(dialog()).findByRole("checkbox", { name: "Alpha (alpha)" }));
    await user.click(within(dialog()).getByRole("checkbox", { name: /Ubuntu \(ubuntu\)/ }));
    const before = calls("listRevisionChoices").length;
    server.mintError = Object.assign(new Error("off host"), {
      code: "BAD_REQUEST",
      data: { code: "sdk_key.template_not_on_selected_host" },
    });
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toBe(
      enCredentials.problem.templateOffHost,
    );
    await waitFor(() => expect(calls("listRevisionChoices").length).toBeGreaterThan(before));
    expect(screen.queryByText(enCredentials.reveal.onceWarning)).toBeNull();
  });

  it("offers only selectable hosts and their active templates, and needs both", async () => {
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("sandboxes:create"));
    await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
    await user.click(within(dialog()).getByRole("radio", { name: enSdkKeys.poolMode.SELECTED }));
    await within(dialog()).findByRole("checkbox", { name: "Alpha (alpha)" });
    expect(within(dialog()).queryByRole("checkbox", { name: "Gone (gone)" })).toBeNull();
    expect(within(dialog()).getByText(enSdkKeys.form.pickHostFirst)).toBeTruthy();
    await submit(user);
    const alert = await within(dialog()).findByRole("alert");
    expect(alert.textContent).toContain(enCredentials.draft.noHosts);
    expect(alert.textContent).toContain(enCredentials.draft.noTemplates);
    await user.click(within(dialog()).getByRole("checkbox", { name: "Alpha (alpha)" }));
    // Only Alpha's active template; never Beta's or a retired one.
    expect(within(dialog()).getByRole("checkbox", { name: /Ubuntu \(ubuntu\)/ })).toBeTruthy();
    expect(within(dialog()).queryByRole("checkbox", { name: /Debian \(debian\)/ })).toBeNull();
    expect(within(dialog()).queryByRole("checkbox", { name: "Old (old)" })).toBeNull();
    await user.click(within(dialog()).getByRole("checkbox", { name: /Ubuntu \(ubuntu\)/ }));
    // Deselecting the host drops its template: the pair must stay consistent.
    await user.click(within(dialog()).getByRole("checkbox", { name: "Alpha (alpha)" }));
    await user.click(within(dialog()).getByRole("checkbox", { name: "Beta (beta)" }));
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toContain(
      enCredentials.draft.noTemplates,
    );
    expect(calls("create")).toHaveLength(0);
    await user.click(within(dialog()).getByRole("checkbox", { name: /Debian \(debian\)/ }));
    await selectOption(
      user,
      within(dialog()).getByLabelText(enCredentials.form.expiry),
      enCredentials.expiry.never,
    );
    await submit(user);
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("create")[0]?.input).toEqual({
      name: "ci",
      scopes: ["sandboxes:create"],
      ownSandboxesOnly: false,
      resourceMode: "ALLOWLIST",
      poolMode: "SELECTED",
      poolIds: [],
      hostIds: ["host-b"],
      templateRevisionIds: ["tpl-b"],
      expiresAt: null,
    });
  });

  it("a failed resource load shows a retry and blocks an allowlist mint", async () => {
    server.pickerError = new Error("network");
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("sandboxes:read"));
    await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
    expect((await within(dialog()).findAllByText(enSdkKeys.form.resourcesFailed))[0]).toBeTruthy();
    await submit(user);
    await within(dialog()).findByRole("alert");
    expect(calls("create")).toHaveLength(0);
    server.pickerError = null;
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.tryAgain }));
    expect(await within(dialog()).findByRole("checkbox", { name: "Alpha (alpha)" })).toBeTruthy();
  });
});

describe("one-time reveal", () => {
  it("mint → inline reveal → copy → done disposes the key; Escape cannot lose it; a remount cannot show it", async () => {
    const user = userEvent.setup();
    const view = mount();
    await openMint(user);
    await user.click(scopeBox("hosts:read"));
    const before = Date.now();
    await submit(user);
    // M7-S4: the dialog closes; the key is shown inline on the page.
    await screen.findByText(enCredentials.reveal.onceWarning);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    const panel = document.querySelector<HTMLElement>("[data-one-time-secret]")!;
    expect(panel.closest("[role=dialog]")).toBeNull();
    const sent = calls("create")[0]?.input as { expiresAt: Date };
    // Default expiry: 90 days from submit.
    expect(sent.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 90 * 86_400_000);
    const secret = server.secrets[0]!;
    expect(document.body.innerHTML).not.toContain(secret);
    await user.click(within(panel).getByRole("button", { name: enCredentials.reveal.show }));
    expect(within(panel).getByText(secret)).toBeTruthy();
    await user.click(within(panel).getByRole("button", { name: enCredentials.reveal.copy }));
    expect(await navigator.clipboard.readText()).toBe(secret);
    const caches = () =>
      JSON.stringify([
        client
          .getQueryCache()
          .getAll()
          .map((query) => query.state),
        client
          .getMutationCache()
          .getAll()
          .map((mutation) => mutation.state),
      ]);
    expect(caches()).not.toContain(secret);
    // A stray Escape does not dismiss it; no second mint while it is shown.
    await user.keyboard("{Escape}");
    expect(within(panel).getByText(secret)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: enSdkKeys.mint.action }) as HTMLButtonElement).disabled,
    ).toBe(true);
    await user.click(within(panel).getByRole("button", { name: enCredentials.reveal.done }));
    expect(document.querySelector("[data-one-time-secret]")).toBeNull();
    expect(document.body.innerHTML).not.toContain(secret);
    await waitFor(() => expect(row("key-1")).toBeTruthy());
    view.unmount();
    mount();
    await waitFor(() => expect(row("key-1")).toBeTruthy());
    expect(document.body.innerHTML).not.toContain(secret);
    expect(caches()).not.toContain(secret);
  });

  it("pagehide while the mint is in flight discards it and revokes the key", async () => {
    let release!: () => void;
    server.mintGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("hosts:read"));
    await submit(user);
    await waitFor(() => expect(calls("create")).toHaveLength(1));
    act(() => {
      window.dispatchEvent(new Event("pagehide"));
    });
    await act(async () => {
      release();
    });
    await waitFor(() => expect(calls("revoke")).toHaveLength(1));
    expect(calls("revoke")[0]?.input).toEqual({ id: "key-1" });
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
    await openMint(user);
    await user.click(scopeBox("hosts:read"));
    await submit(user);
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
    await releaseOnFakeTime(release);
    await elapseRevokeRetries();
    const alert = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-orphan-id="key-1"]');
      if (!found) throw new Error("no orphan alert");
      return found;
    });
    expect(calls("revoke")).toHaveLength(3);
    await user.click(within(alert).getByRole("button", { name: enCredentials.orphan.retry }));
    await waitFor(() => expect(document.querySelector("[data-orphan-id]")).toBeNull());
    expect(server.keys[0]?.revokedAt).not.toBeNull();
  });

  it("a failed orphan revoke after leaving the page is shown again on return, holding no secret", async () => {
    let release!: () => void;
    server.mintGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.revokeFailures = 3;
    const user = userEvent.setup();
    const view = mount();
    await openMint(user);
    await user.click(scopeBox("hosts:read"));
    await submit(user);
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
    view.unmount();
    await releaseOnFakeTime(release);
    await elapseRevokeRetries();
    await waitFor(() => expect(useOrphanCredentials.getState().entries).toHaveLength(1));
    const { entries } = useOrphanCredentials.getState();
    expect(entries).toEqual([
      { ownerId: "owner-1", scope: "sdkKey", id: "key-1", label: expect.any(String) },
    ]);
    for (const entry of entries)
      for (const value of Object.values(entry)) expect(typeof value).toBe("string");
    expect(JSON.stringify(entries)).not.toContain(server.secrets[0]!);
    mount();
    const alert = await waitFor(() => {
      const found = document.querySelector<HTMLElement>('[data-orphan-id="key-1"]');
      if (!found) throw new Error("no orphan alert");
      return found;
    });
    await user.click(within(alert).getByRole("button", { name: enCredentials.orphan.retry }));
    await waitFor(() => expect(document.querySelector("[data-orphan-id]")).toBeNull());
    expect(server.keys[0]?.revokedAt).not.toBeNull();
    expect(useOrphanCredentials.getState().entries).toEqual([]);
  });

  it("a refused mint is explained and retrying works", async () => {
    server.mintError = Object.assign(new Error("One or more hosts are not owned"), {
      code: "FORBIDDEN",
    });
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("hosts:read"));
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toBe(
      enCredentials.problem.forbidden,
    );
    await submit(user);
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect(calls("create")).toHaveLength(2);
    expect(navigate).not.toHaveBeenCalled();
  });

  it("a forced-2FA refusal on mint redirects to Security settings", async () => {
    server.mintError = Object.assign(new Error("Two-factor authentication setup is required."), {
      code: "FORBIDDEN",
      data: { code: "auth.two_factor_required" },
    });
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("hosts:read"));
    await submit(user);
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({
        to: "/$lang/settings/security",
        params: { lang: "en-US" },
      }),
    );
  });
});

describe("revoking an SDK key", () => {
  it("needs confirmation, then revokes and refetches", async () => {
    server.keys = [
      {
        id: "key-z",
        name: "ci key",
        resourceMode: "ALL_OWNED",
        poolMode: "ALL_USABLE",
        poolIds: [],
        scopes: ["hosts:read"],
        lookupPrefix: "wssp_sdk_abcdefghijkl",
        lastUsedAt: null,
        revokedAt: null,
        expiresAt: null,
        createdAt: new Date(),
        hostAllowlist: [],
        revisionAllowlist: [],
      },
    ];
    const user = userEvent.setup();
    mount();
    await screen.findByRole("list", { name: enSdkKeys.title });
    await user.click(within(row("key-z")).getByRole("button", { name: "Revoke" }));
    const confirm = await screen.findByRole("alertdialog");
    expect(within(confirm).getByText("Revoke ci key?")).toBeTruthy();
    expect(calls("revoke")).toHaveLength(0);
    const action = within(confirm).getByRole("button", { name: enCredentials.revoke.confirm });
    expect((action as HTMLButtonElement).disabled).toBe(true);
    await user.type(within(confirm).getByLabelText(enSdkKeys.revoke.typePrompt), "wrong");
    expect((action as HTMLButtonElement).disabled).toBe(true);
    await user.clear(within(confirm).getByLabelText(enSdkKeys.revoke.typePrompt));
    await user.type(within(confirm).getByLabelText(enSdkKeys.revoke.typePrompt), "ci key");
    await user.click(action);
    await waitFor(() =>
      expect(calls("revoke")).toEqual([{ procedure: "revoke", input: { id: "key-z" } }]),
    );
    expect(await screen.findByText(enSdkKeys.empty.title)).toBeTruthy();
    expect(toast.success).toHaveBeenCalledWith(enSdkKeys.revoke.done);
  });

  it("a list refused by forced 2FA redirects to Security settings", async () => {
    server.listError = Object.assign(new Error("2FA"), {
      code: "FORBIDDEN",
      data: { code: "auth.two_factor_required" },
    });
    mount();
    await act(async () => undefined);
    await waitFor(() => expect(navigate).toHaveBeenCalledTimes(1));
  });
});

it("mints selected pool grants alongside independent host/revision grants with a paged picker", async () => {
  server.pools = [
    { id: "pool-a", slug: "a", label: "Pool A" },
    { id: "pool-b", slug: "b", label: "Pool B" },
  ];
  server.pickerPageSize = 1;
  const user = userEvent.setup();
  mount();
  await openMint(user);
  await user.click(scopeBox("sandboxes:create"));
  await user.click(scopeBox("pools:read"));
  await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
  await user.click(within(dialog()).getByRole("radio", { name: enSdkKeys.poolMode.SELECTED }));
  await within(dialog()).findByRole("checkbox", { name: /Pool A \(a\)/ });
  expect(within(dialog()).queryByRole("checkbox", { name: /Pool B \(b\)/ })).toBeNull();
  await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.loadMore }));
  await user.click(await within(dialog()).findByRole("checkbox", { name: /Pool B \(b\)/ }));
  await user.click(within(dialog()).getByRole("checkbox", { name: "Alpha (alpha)" }));
  await user.click(within(dialog()).getByRole("checkbox", { name: /Ubuntu \(ubuntu\)/ }));
  await submit(user);
  await screen.findByText(enCredentials.reveal.onceWarning);
  expect(calls("create")[0]?.input).toMatchObject({
    poolIds: ["pool-b"],
    hostIds: ["host-a"],
    templateRevisionIds: ["tpl-a"],
  });
});

it("distinguishes same-label exact revisions and verified/pending selected-host associations", async () => {
  server.templates = [
    {
      id: "rev-exact-1",
      slug: "ubuntu",
      label: "Ubuntu",
      retiredAt: null,
      availability: [{ hostId: "host-a", status: "AVAILABLE" }],
    },
    {
      id: "rev-exact-2",
      slug: "ubuntu",
      label: "Ubuntu",
      retiredAt: null,
      availability: [{ hostId: "host-a", status: "PENDING" }],
    },
  ];
  server.pools = [{ id: "pool-exact", slug: "lab", label: "Lab" }];
  const user = userEvent.setup();
  mount();
  await openMint(user);
  await user.click(scopeBox("sandboxes:create"));
  await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
  await user.click(await within(dialog()).findByRole("checkbox", { name: "Alpha (alpha)" }));
  const verified = within(dialog()).getByRole("checkbox", {
    name: /Ubuntu.*rev-exact-1.*Alpha.*Verified image/,
  });
  const pending = within(dialog()).getByRole("checkbox", {
    name: /Ubuntu.*rev-exact-2.*Alpha.*Verification pending/,
  });
  expect(verified.closest("label")?.className).toContain("min-h-11");
  await user.click(pending);
  await user.click(within(dialog()).getByRole("radio", { name: enSdkKeys.poolMode.SELECTED }));
  await user.click(within(dialog()).getByRole("checkbox", { name: /Lab.*pool-exact/ }));
  await submit(user);
  await waitFor(() => expect(calls("create")).toHaveLength(1));
  expect(calls("create")[0]?.input).toMatchObject({
    hostIds: ["host-a"],
    templateRevisionIds: ["rev-exact-2"],
    poolIds: ["pool-exact"],
  });
  expect(await screen.findByText(enCredentials.reveal.onceWarning)).toBeTruthy();
  expect(row("key-1").querySelector("[data-allowlist=templates]")?.textContent).toContain(
    "rev-exact-2",
  );
});

it("does not mint with a selected pool removed from the loaded choices", async () => {
  server.pools = [{ id: "pool-a", slug: "a", label: "Pool A" }];
  const user = userEvent.setup();
  mount();
  await openMint(user);
  await user.click(scopeBox("sandboxes:create"));
  const form = within(dialog());
  await user.click(form.getByRole("radio", { name: /Only selected hosts/ }));
  await user.click(await form.findByRole("checkbox", { name: "Alpha (alpha)" }));
  await user.click(form.getByRole("checkbox", { name: /Ubuntu.*tpl-a/ }));
  await user.click(form.getByRole("radio", { name: enSdkKeys.poolMode.SELECTED }));
  await user.click(await form.findByRole("checkbox", { name: /Pool A/ }));
  server.pools = [];
  await act(() => client.invalidateQueries({ queryKey: ["listPools"] }));
  await submit(user);
  expect(await form.findByText(enCredentials.draft.unknownPool)).toBeTruthy();
  expect(calls("create")).toHaveLength(0);
});

it("mints the selected seven-day expiry instead of the default ninety days", async () => {
  const user = userEvent.setup();
  mount();
  await openMint(user);
  await user.click(scopeBox("hosts:read"));
  await selectOption(
    user,
    within(dialog()).getByLabelText(enCredentials.form.expiry),
    enCredentials.expiry["7d"],
  );
  expect(within(dialog()).getByLabelText(enCredentials.form.expiry).textContent).toContain(
    enCredentials.expiry["7d"],
  );
  const before = Date.now();
  await submit(user);
  await screen.findByText(enCredentials.reveal.onceWarning);
  const sent = calls("create")[0]?.input as { expiresAt: Date };
  expect(sent.expiresAt.getTime()).toBeGreaterThanOrEqual(before + 7 * 86400000);
  expect(sent.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 7 * 86400000);
});

it("identifies owned pools in both selected grants and revision discovery", async () => {
  server.pools = [{ id: "pool-owned", slug: "owned", label: "My pool" }];
  const user = userEvent.setup();
  mount();
  await openMint(user);
  await user.click(within(dialog()).getByRole("radio", { name: enSdkKeys.poolMode.SELECTED }));
  await within(dialog()).findByText(enSdkKeys.form.ownedPool);
  await user.click(within(dialog()).getByRole("radio", { name: /Only selected hosts/ }));
  expect(within(dialog()).getByRole("option", { name: /My pool/ }).textContent).toContain(
    enSdkKeys.form.ownedPool,
  );
});

it("mints own-sandboxes-only when the checkbox is selected", async () => {
  const user = userEvent.setup();
  mount();
  await openMint(user);
  await user.click(scopeBox("sandboxes:read"));
  const ownOnly = within(dialog()).getByRole("checkbox", { name: enSdkKeys.form.ownSandboxesOnly });
  expect(ownOnly.getAttribute("aria-checked")).toBe("false");
  await user.click(ownOnly);
  await submit(user);
  await screen.findByText(enCredentials.reveal.onceWarning);
  expect(calls("create")[0]?.input).toMatchObject({ ownSandboxesOnly: true });
});

it("uses the deployment expiry policy for agent tokens and submits own-only by default", async () => {
  const user = userEvent.setup();
  mount(true);
  await user.click(screen.getByRole("button", { name: enAgents.mint.action }));
  await user.type(await within(dialog()).findByLabelText(enCredentials.form.name), "helper");
  expect(
    within(dialog())
      .getByRole("checkbox", { name: enSdkKeys.form.ownSandboxesOnly })
      .getAttribute("aria-checked"),
  ).toBe("true");
  expect(within(dialog()).getByLabelText(enCredentials.form.expiry).textContent).toContain(
    enCredentials.expiry["90d"],
  );
  await user.click(scopeBox("hosts:read"));
  await user.click(within(dialog()).getByLabelText(enCredentials.form.expiry));
  // The select's popup renders asynchronously: wait for it before asserting its options.
  expect(await screen.findByRole("option", { name: enAgents.expiry.never })).toBeTruthy();
  expect(screen.queryByRole("option", { name: enCredentials.expiry["365d"] })).toBeNull();
  await user.click(screen.getByRole("option", { name: enCredentials.expiry["30d"] }));
  await user.click(within(dialog()).getByRole("button", { name: enAgents.mint.submit }));
  await screen.findByText(enCredentials.reveal.onceWarning);
  expect(calls("create")[0]?.input).toMatchObject({
    ownSandboxesOnly: true,
    expiresAt: expect.any(Date),
  });
  const input = calls("create")[0]?.input as { expiresAt: Date };
  expect(input.expiresAt.getTime() - Date.now()).toBeGreaterThan(29 * 86400000);
});

it("shows the active agent-token cap refusal", async () => {
  server.mintError = { code: "CONFLICT", data: { code: "agent_token.limit" } };
  const user = userEvent.setup();
  mount(true);
  await user.click(screen.getByRole("button", { name: enAgents.mint.action }));
  await user.type(await within(dialog()).findByLabelText(enCredentials.form.name), "helper");
  await user.click(scopeBox("hosts:read"));
  await user.click(within(dialog()).getByRole("button", { name: enAgents.mint.submit }));
  expect(await screen.findByText(enCredentials.problem.agentLimit)).toBeTruthy();
});

it("offers only requested scopes in the shared scope picker", async () => {
  const change = vi.fn();
  render(
    <I18nextProvider i18n={i18n}>
      <ScopePicker offered={["hosts:read", "hosts:execute"]} value={[]} onChange={change} />
    </I18nextProvider>,
  );
  expect(screen.getAllByRole("checkbox")).toHaveLength(2);
  expect(screen.queryByRole("checkbox", { name: "sandboxes:destroy" })).toBeNull();
  await userEvent.setup().click(screen.getByRole("checkbox", { name: "hosts:execute" }));
  expect(change).toHaveBeenCalledWith(["hosts:execute"]);
});

it("consent defaults host scopes off and own-only on, submits a subset, and can deny without a valid form", async () => {
  const onConsent = vi.fn();
  const deny = vi.fn();
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <CredentialGrantEditor
          lang="en-US"
          mode="consent"
          consentName="client"
          requestedScopes={["hosts:read", "hosts:execute", "sandboxes:read"]}
          onConsent={onConsent}
          onClose={deny}
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  const user = userEvent.setup();
  expect(screen.getByRole("checkbox", { name: "hosts:execute" }).getAttribute("aria-checked")).toBe(
    "false",
  );
  expect(screen.getByRole("checkbox", { name: "hosts:read" }).getAttribute("aria-checked")).toBe(
    "false",
  );
  expect(
    screen
      .getByRole("checkbox", { name: enSdkKeys.form.ownSandboxesOnly })
      .getAttribute("aria-checked"),
  ).toBe("true");
  await user.click(screen.getByRole("checkbox", { name: "hosts:read" }));
  await user.click(screen.getByRole("checkbox", { name: "sandboxes:read" }));
  await user.click(screen.getByRole("button", { name: enAgents.consent.allow }));
  await waitFor(() =>
    expect(onConsent).toHaveBeenCalledWith(
      expect.objectContaining({ scopes: ["hosts:read"], ownSandboxesOnly: true }),
    ),
  );
  await user.click(screen.getByRole("checkbox", { name: "hosts:read" }));
  await user.click(screen.getByRole("button", { name: enAgents.consent.deny }));
  expect(deny).toHaveBeenCalledOnce();
});

it("only offers no expiry when allowed, warns, and lists Never expires after mint", async () => {
  const user = userEvent.setup();
  mount(true);
  await user.click(screen.getByRole("button", { name: enAgents.mint.action }));
  await user.type(await within(dialog()).findByLabelText(enCredentials.form.name), "helper");
  await user.click(scopeBox("hosts:read"));
  await selectOption(
    user,
    within(dialog()).getByLabelText(enCredentials.form.expiry),
    enAgents.expiry.never,
  );
  expect(within(dialog()).getByText(enAgents.expiry.warning)).toBeTruthy();
  await user.click(within(dialog()).getByRole("button", { name: enAgents.mint.submit }));
  await screen.findByText(enCredentials.reveal.onceWarning);
  expect(calls("create")[0]?.input).toMatchObject({ expiresAt: null });
  await screen.findByText(enCredentials.dates.noExpiry);
});

it("filters presets, hides no expiry when disabled, and submits a bounded custom date", async () => {
  server.allowNoExpiry = false;
  server.maxLifetimeDays = 7;
  const user = userEvent.setup();
  mount(true);
  await user.click(screen.getByRole("button", { name: enAgents.mint.action }));
  await user.type(await within(dialog()).findByLabelText(enCredentials.form.name), "helper");
  await user.click(scopeBox("hosts:read"));
  await user.click(within(dialog()).getByLabelText(enCredentials.form.expiry));
  // Wait for the asynchronously rendered popup, so the absent options are checked on an open list.
  const custom = await screen.findByRole("option", { name: enAgents.expiry.custom });
  expect(screen.queryByRole("option", { name: enAgents.expiry.never })).toBeNull();
  expect(screen.queryByRole("option", { name: enCredentials.expiry["30d"] })).toBeNull();
  expect(screen.queryByRole("option", { name: enCredentials.expiry["90d"] })).toBeNull();
  await user.click(custom);
  const input = within(dialog()).getByLabelText(enAgents.expiry.customDate) as HTMLInputElement;
  expect(input.type).toBe("date");
  const { localDateInputValue, latestAgentTokenCustomDate } = await import(
    "@/lib/agent-token-expiry"
  );
  expect(input.min).toBe(localDateInputValue(new Date()));
  expect(input.max).toBe(localDateInputValue(latestAgentTokenCustomDate(new Date(), 7)));
  await user.click(within(dialog()).getByRole("button", { name: enAgents.mint.submit }));
  expect(calls("create")).toHaveLength(0);
  expect(await within(dialog()).findByText(enAgents.expiry.invalid)).toBeTruthy();
  const { fireEvent } = await import("@testing-library/react");
  fireEvent.change(input, { target: { value: input.max } });
  await user.click(within(dialog()).getByRole("button", { name: enAgents.mint.submit }));
  await screen.findByText(enCredentials.reveal.onceWarning);
  const sent = calls("create")[0]?.input as { expiresAt: Date };
  expect(sent.expiresAt.getTime()).toBeGreaterThan(Date.now());
  expect(sent.expiresAt.getTime()).toBeLessThanOrEqual(Date.now() + 7 * 86_400_000);
  expect(sent.expiresAt.getHours()).toBe(23);
});

it("marks an existing no-expiry agent token as blocked by policy, without hiding or revoking it", async () => {
  const now = Date.now();
  const base = {
    resourceMode: "ALL_OWNED",
    poolMode: "ALL_USABLE",
    poolIds: [],
    scopes: ["hosts:read"],
    lastUsedAt: null,
    revokedAt: null,
    createdAt: new Date(now - 86_400_000),
    hostAllowlist: [],
    revisionAllowlist: [],
    ownSandboxesOnly: true,
  };
  server.keys = [
    {
      ...base,
      id: "agent-never",
      name: "never",
      lookupPrefix: "wssp_agent_neverneverne",
      expiresAt: null,
      blockedByPolicy: true,
    },
    {
      ...base,
      id: "agent-dated",
      name: "dated",
      lookupPrefix: "wssp_agent_datedatedate",
      expiresAt: new Date(now + 7 * 86_400_000),
      blockedByPolicy: false,
    },
  ];
  mount(true);
  await screen.findByText("wssp_agent_neverneverne…");
  const blocked = row("agent-never");
  expect(blocked.getAttribute("data-blocked-by-policy")).toBe("true");
  expect(within(blocked).getByText(enAgents.expiry.blockedByPolicy)).toBeTruthy();
  expect(within(blocked).getByRole("button", { name: enCredentials.revoke.action })).toBeTruthy();
  const dated = row("agent-dated");
  expect(dated.getAttribute("data-blocked-by-policy")).toBeNull();
  expect(within(dated).queryByText(enAgents.expiry.blockedByPolicy)).toBeNull();
});

describe("sandboxes:connect scope", () => {
  it("the SDK key form offers it alone in its own described group, never preselected, and mints it only when ticked", async () => {
    const user = userEvent.setup();
    mount();
    await openMint(user);
    const box = scopeBox("sandboxes:connect");
    expect(box.getAttribute("aria-checked")).toBe("false");
    const group = dialog().querySelector<HTMLElement>('[data-scope-group="connect"]')!;
    expect([...group.querySelectorAll("[role=checkbox]")]).toEqual([box]);
    expect(within(group).getByText(enSdkKeys.scopeGroup.connect)).toBeTruthy();
    expect(group.querySelector('[data-scope-group-hint="connect"]')?.textContent).toBe(
      enSdkKeys.scopeGroupHint.connect,
    );
    // Selecting every sandbox scope in its group still leaves connect off.
    const sandboxes = dialog().querySelector<HTMLElement>('[data-scope-group="sandboxes"]')!;
    expect(within(sandboxes).queryByRole("checkbox", { name: "sandboxes:connect" })).toBeNull();
    await user.click(scopeBox("sandboxes:read"));
    await submit(user);
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect((calls("create")[0]?.input as { scopes: string[] } | undefined)?.scopes).not.toContain(
      "sandboxes:connect",
    );
  });

  it("ticking it mints it", async () => {
    const user = userEvent.setup();
    mount();
    await openMint(user);
    await user.click(scopeBox("sandboxes:connect"));
    await submit(user);
    await screen.findByText(enCredentials.reveal.onceWarning);
    expect((calls("create")[0]?.input as { scopes: string[] } | undefined)?.scopes).toContain(
      "sandboxes:connect",
    );
  });

  it("the agent-token form and the shared picker's default never offer it", async () => {
    const user = userEvent.setup();
    mount(true);
    await user.click(screen.getByRole("button", { name: enAgents.mint.action }));
    await within(dialog()).findByLabelText(enCredentials.form.name);
    expect(within(dialog()).queryByRole("checkbox", { name: "sandboxes:connect" })).toBeNull();
    expect(dialog().querySelector('[data-scope-group="connect"]')).toBeNull();
    cleanup();
    render(
      <I18nextProvider i18n={i18n}>
        <ScopePicker
          offered={["sandboxes:read", "sandboxes:connect"]}
          value={[]}
          onChange={vi.fn()}
        />
      </I18nextProvider>,
    );
    expect(screen.getAllByRole("checkbox")).toHaveLength(1);
    expect(screen.queryByRole("checkbox", { name: "sandboxes:connect" })).toBeNull();
  });

  it("a key that can connect shows its last connect; agent tokens and keys without the scope do not", async () => {
    const now = Date.now();
    const base = {
      resourceMode: "ALL_OWNED",
      poolMode: "ALL_USABLE",
      poolIds: [],
      lastUsedAt: null,
      revokedAt: null,
      expiresAt: null,
      createdAt: new Date(now - 86_400_000),
      hostAllowlist: [],
      revisionAllowlist: [],
      origin: "DASHBOARD",
    };
    server.keys = [
      {
        ...base,
        id: "key-connected",
        name: "ci",
        lookupPrefix: "wssp_sdk_connected01",
        scopes: ["sandboxes:connect"],
        lastConnectAt: new Date(now - 3 * 3_600_000),
      },
      {
        ...base,
        id: "key-never",
        name: "ci 2",
        lookupPrefix: "wssp_sdk_neverconn01",
        scopes: ["sandboxes:connect"],
        lastConnectAt: null,
      },
      {
        ...base,
        id: "key-plain",
        name: "reader",
        lookupPrefix: "wssp_sdk_plainreader",
        scopes: ["sandboxes:read"],
        lastConnectAt: null,
      },
    ];
    mount();
    await screen.findByRole("list", { name: enSdkKeys.title });
    expect(row("key-connected").querySelector("[data-last-connect]")?.textContent).toBe(
      "3 hours ago",
    );
    expect(row("key-never").querySelector("[data-last-connect]")?.textContent).toBe(
      enCredentials.dates.noRecentConnect,
    );
    expect(row("key-plain").querySelector("[data-last-connect]")).toBeNull();
  });
});
