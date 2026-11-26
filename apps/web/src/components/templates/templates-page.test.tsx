import { selectChoices, selectOption } from "@/test/select-option";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  configure,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import esTemplates from "@wssp/locales/src/es-MX/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Templates page against a scripted fake server (real TanStack Query, i18n and
 * dialogs): the register form refuses bad drafts in the browser, an image
 * check is visibly pending until the host answers, a refused image registers
 * nothing, a template on an unreachable host never reads as available, and
 * archive needs confirmation and explains an in-use refusal.
 */

const FP = `sha256:${"ab".repeat(32)}`;

const server = vi.hoisted(() => ({
  templates: [] as Record<string, unknown>[],
  revisions: null as Record<string, unknown>[] | null,
  availability: [] as Record<string, unknown>[],
  pageSize: 100,
  availabilityError: null as unknown,
  availabilityGate: null as Promise<void> | null,
  hosts: [] as Record<string, unknown>[],
  calls: [] as { procedure: string; input: unknown }[],
  listError: null as unknown,
  hostsError: null as unknown,
  createError: null as unknown,
  retireError: null as unknown,
  /** When set, createTemplate waits for this promise before answering. */
  createGate: null as Promise<void> | null,
  /** When set, listHosts waits for this promise before answering. */
  hostsGate: null as Promise<void> | null,
  imageMode: "off" as "off" | "s3",
  /** The latest build each template's empty-state note reads. */
  latestBuild: null as Record<string, unknown> | null,
  seq: 0,
}));

const webEnv = vi.hoisted(() => ({ VITE_DOCS_URL: undefined as string | undefined }));
vi.mock("@wssp/env/web", () => ({ env: webEnv }));

const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({
    children,
    className,
    to,
    search,
    onClick,
    "data-new-template": option,
  }: {
    children: ReactNode;
    className?: string;
    to?: string;
    search?: unknown;
    onClick?: () => void;
    "data-new-template"?: string;
  }) => (
    <a
      className={className}
      href="#link"
      data-to={to}
      data-search={search ? JSON.stringify(search) : undefined}
      data-new-template={option}
      onClick={onClick}
    >
      {children}
    </a>
  ),
}));

vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  type InfiniteOptions = {
    input: (cursor: string | undefined) => Record<string, unknown>;
    initialPageParam: unknown;
    getNextPageParam: (page: { nextCursor: string | null }) => unknown;
  };
  const infinite =
    (
      procedure: string,
      rows: (input: Record<string, unknown>) => unknown[],
      error: () => unknown,
    ) =>
    (options: InfiniteOptions) => ({
      queryKey: [procedure, "infinite", options.input(undefined)],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
        const input = options.input(pageParam);
        record(procedure, input);
        if (procedure === "listHosts" && server.hostsGate) await server.hostsGate;
        if (procedure === "listAvailability" && server.availabilityGate)
          await server.availabilityGate;
        if (error()) throw error();
        const all = rows(input);
        const start = Number(pageParam ?? 0);
        const size = Math.min(Number(input.limit), server.pageSize);
        return {
          items: structuredClone(all.slice(start, start + size)),
          nextCursor: start + size < all.length ? String(start + size) : null,
        };
      },
    });
  const createTemplateCall = async (input: Record<string, unknown>) => {
    record("createTemplate", input);
    if (server.createGate) await server.createGate;
    const error = server.createError;
    server.createError = null;
    if (error) throw error;
    server.seq += 1;
    const host = server.hosts.find((row) => row.id === input.hostId) ?? null;
    const template = {
      id: `tpl-new-${server.seq}`,
      sandboxHostId: input.hostId,
      archivedAt: null,
      retiredAt: null,
      slug: input.slug,
      label: input.label,
      imageRef: input.imageRef,
      incusFingerprint: FP,
      architecture: input.architecture,
      guestUid: input.guestUid,
      guestGid: input.guestGid,
      guestHome: input.guestHome,
      guestShell: input.guestShell,
      guestVersion: input.guestVersion ?? null,
      createdAt: new Date(),
      updatedAt: new Date(),
      host,
      sandboxCount: 0,
    };
    server.templates.unshift(template);
    return { ...structuredClone(template), firstRevisionId: `${String(template.id)}-revision` };
  };
  const retireTemplateCall = async (input: { id: string }) => {
    record("retireTemplate", input);
    const error = server.retireError;
    server.retireError = null;
    if (error) throw error;
    const row = server.templates.find((template) => template.id === input.id);
    if (row) Object.assign(row, { archivedAt: new Date() });
    return { ok: true };
  };
  return {
    orpc: {
      communityTemplates: {
        images: {
          queryOptions: () => ({
            queryKey: ["communityImages"],
            queryFn: async () => ({ images: [], disabledReason: null }),
          }),
        },
        create: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        setRefresh: { mutationOptions: () => ({ mutationFn: async () => ({ ok: true }) }) },
        refresh: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        retry: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
      },
      templateBuilds: {
        key: () => ["templateBuilds"],
        list: {
          queryOptions: () => ({
            queryKey: ["latestTemplateBuild"],
            queryFn: async () => ({
              items: server.latestBuild ? [server.latestBuild] : [],
              nextCursor: null,
            }),
          }),
          infiniteOptions: infinite(
            "listTemplateBuilds",
            () => [],
            () => null,
          ),
        },
      },
      settings: {
        getAll: { key: () => ["settings", "getAll"] },
        imagePolicy: {
          key: () => ["settings", "imagePolicy"],
          queryOptions: () => ({
            queryKey: ["settings", "imagePolicy"],
            queryFn: async () => ({
              mode: server.imageMode,
              imagePlacement: "ANY_NODE" as const,
              quotas: { maxStoredGiB: null, downloadsPerHour: null },
              usage: { storedBytes: "0", downloadsLastHour: 0 },
            }),
          }),
        },
      },
      sandboxPools: {
        listUsable: {
          queryOptions: () => ({
            queryKey: ["listUsablePools"],
            queryFn: async () => ({ items: [], nextCursor: null }),
          }),
          infiniteOptions: infinite(
            "listUsablePools",
            () => [{ id: "pool-a", slug: "shared", label: "Shared pool" }],
            () => null,
          ),
        },
        getUsable: {
          queryOptions: () => ({
            queryKey: ["getUsablePool"],
            queryFn: async () => ({ id: "pool-a", label: "Shared pool", memberCount: 1 }),
          }),
        },
        hostPolicy: {
          queryOptions: () => ({
            queryKey: ["poolHostPolicy"],
            queryFn: async () => ({
              viewer: "owner",
              hosts: 1,
              ownHosts: 1,
              images: "all",
              builds: "all",
              openEgress: "all",
              guestSudo: "all",
              allowForeignBuilds: null,
            }),
          }),
        },
        listUsableMembers: {
          queryOptions: () => ({
            queryKey: ["listUsableMembersFlat"],
            queryFn: async () => ({ items: [], nextCursor: null }),
          }),
          infiniteOptions: infinite(
            "listUsableMembers",
            () => [{ id: "member-a", poolId: "pool-a" }],
            () => null,
          ),
        },
      },
      sandboxHosts: {
        listHosts: {
          key: () => ["listHosts"],
          queryOptions: () => ({
            queryKey: ["listHostsFlat"],
            queryFn: async () => ({ items: server.hosts, nextCursor: null }),
          }),
          infiniteOptions: infinite(
            "listHosts",
            () => server.hosts,
            () => server.hostsError,
          ),
        },
      },
      sandboxTemplates: {
        listRevisions: {
          key: () => ["listRevisions"],
          infiniteOptions: infinite(
            "listRevisions",
            (input) =>
              server.revisions?.filter((row) => row.templateId === input.templateId) ??
              server.templates
                .filter((row) => row.id === input.templateId)
                .map((row) => ({
                  ...row,
                  id: `${row.id}-revision`,
                  templateId: row.id,
                  revision: 1,
                })),
            () => null,
          ),
        },
        listAvailability: {
          key: () => ["listAvailability"],
          infiniteOptions: infinite(
            "listAvailability",
            (input) => server.availability.filter((row) => row.revisionId === input.revisionId),
            () => server.availabilityError,
          ),
        },
        listRevisionChoices: { key: () => ["listRevisionChoices"] },
        getImageSettings: { key: () => ["getImageSettings"] },
        pruneNow: {
          mutationOptions: () => ({
            mutationFn: async (input: Record<string, unknown>) => {
              record("pruneNow", input);
              return { retired: 0 };
            },
          }),
        },
        publishRevision: {
          mutationOptions: () => ({
            mutationFn: async (input: Record<string, unknown>) => {
              record("publishRevision", input);
              return { status: "queued" as const };
            },
          }),
        },
        setTag: {
          mutationOptions: () => ({
            mutationFn: async (input: Record<string, unknown>) => {
              record("setTag", input);
              return { ok: true };
            },
          }),
        },
        associateAvailability: {
          mutationOptions: () => ({
            mutationFn: async (input: Record<string, unknown>) => {
              record("associateAvailability", input);
              return { id: "availability" };
            },
          }),
        },
        retireRevision: {
          mutationOptions: () => ({
            mutationFn: async (input: Record<string, unknown>) => {
              record("retireRevision", input);
              return { ok: true };
            },
          }),
        },
        appendRevision: {
          call: async (input: Record<string, unknown>) => {
            record("appendRevision", input);
            return { id: "appended", ...input, revision: 2 };
          },
        },

        listTemplates: {
          key: () => ["listTemplates"],
          infiniteOptions: infinite(
            "listTemplates",
            (input) =>
              server.templates
                .filter((row) =>
                  input.status === "active"
                    ? row.archivedAt == null
                    : input.status === "retired"
                      ? row.archivedAt != null
                      : true,
                )
                .map((row) => ({ versions: { count: 1, latest: 1 }, ...row })),
            () => server.listError,
          ),
        },
        createTemplate: {
          call: createTemplateCall,
          mutationOptions: () => ({ mutationFn: createTemplateCall }),
        },
        retireTemplate: {
          mutationOptions: () => ({ mutationFn: retireTemplateCall }),
        },
      },
    },
  };
});

import { TemplatesPage } from "./templates-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "templates", "hosts"],
    defaultNS: "common",
    resources: {
      "en-US": { common: enCommon, dashboard: enDashboard, templates: enTemplates, hosts: enHosts },
      "es-MX": { common: esCommon, dashboard: esDashboard, templates: esTemplates, hosts: esHosts },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

function freshHost(overrides: Record<string, unknown> = {}) {
  return {
    id: "host-a",
    slug: "alpha",
    label: "Alpha",
    status: "CONNECTED",
    lastConnectedAt: new Date(Date.now() - 60_000),
    lastHeartbeatAt: new Date(),
    deletionRequestedAt: null,
    draining: false,
    ...overrides,
  };
}

function templateRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "tpl-a",
    sandboxHostId: "host-a",
    archivedAt: null,
    retiredAt: null,
    slug: "ubuntu",
    label: "Ubuntu",
    imageRef: "local:ubuntu",
    incusFingerprint: FP,
    architecture: "x86_64",
    guestUid: 1000,
    guestGid: 1000,
    guestHome: "/home/user",
    guestShell: "/bin/bash",
    guestVersion: null,
    createdAt: new Date(Date.now() - 86_400_000),
    updatedAt: new Date(),
    host: freshHost(),
    sandboxCount: 0,
    cpuCount: 1,
    memoryMiB: 1024,
    defaultDiskGiB: 32,
    minDiskGiB: 32,
    ...overrides,
  };
}

let client: QueryClient;
async function mount(lang = "en-US", initialChoosing = false) {
  await i18n.changeLanguage(lang);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <TemplatesPage lang={lang} initialChoosing={initialChoosing} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) => server.calls.filter((call) => call.procedure === procedure);
const dialog = () => screen.getByRole("dialog");
const card = (id: string) => document.querySelector<HTMLElement>(`li[data-template-id="${id}"]`);
const findCard = (id: string) =>
  waitFor(() => {
    const node = card(id);
    if (!node) throw new Error(`template ${id} not rendered`);
    return node;
  });

beforeEach(() => {
  server.imageMode = "off";
  server.latestBuild = null;
  server.revisions = null;
  server.availability = [];
  server.pageSize = 100;
  server.availabilityError = null;
  server.availabilityGate = null;
  webEnv.VITE_DOCS_URL = undefined;
  server.templates = [];
  server.hosts = [
    freshHost(),
    freshHost({ id: "host-b", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
    freshHost({ id: "host-x", slug: "gone", label: "Gone", deletionRequestedAt: new Date() }),
  ];
  server.calls = [];
  server.listError = null;
  server.hostsError = null;
  server.createError = null;
  server.retireError = null;
  server.createGate = null;
  server.hostsGate = null;
  server.seq = 0;
  navigate.mockReset();
  toast.success.mockReset();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

/** Opens a card's versions and builds (collapsed by default). */
async function expand(id: string) {
  const row = await findCard(id);
  fireEvent.click(within(row).getByRole("button", { name: enTemplates.card.showDetails }));
  return row;
}

/** Opens a card's More actions menu and picks one entry. */
async function overflow(user: ReturnType<typeof userEvent.setup>, label: string, item: string) {
  await user.click(
    within(card("tpl-a")!).getByRole("button", {
      name: enTemplates.card.more.replace("{{label}}", label),
    }),
  );
  await user.click(await screen.findByRole("menuitem", { name: item }));
}

describe("templates list", () => {
  it("loading shows a skeleton, then the translated empty state for active templates", async () => {
    const view = await mount();
    expect(view.container.querySelector('[data-slot="skeleton"]')).not.toBeNull();
    expect(await screen.findByText(enTemplates.empty.title)).toBeTruthy();
    expect(screen.getByText(enTemplates.requirements.image)).toBeTruthy();
    expect(calls("listTemplates")[0]?.input).toMatchObject({ status: "active", limit: 50 });
    // No docs base configured: the link goes to the repository's docs.
    expect(
      screen.getByRole("link", { name: enTemplates.requirements.docsLink }).getAttribute("href"),
    ).toBe("https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/operations/templates.md");
  });

  it("links the image docs below the configured docs base", async () => {
    webEnv.VITE_DOCS_URL = "https://docs.example.test/wssp/";
    await mount();
    const docs = await screen.findByRole("link", { name: enTemplates.requirements.docsLink });
    expect(docs.getAttribute("href")).toBe(
      "https://docs.example.test/wssp/operations/templates.md",
    );
    expect(docs.getAttribute("rel")).toBe("noreferrer");
  });

  it("a failed first load shows a retry that recovers", async () => {
    server.listError = new Error("network");
    const user = userEvent.setup();
    await mount();
    const retry = await screen.findByRole("button", { name: enCommon.actions.tryAgain });
    expect(screen.getByText(enDashboard.list.loadFailed)).toBeTruthy();
    expect(screen.queryByText(enTemplates.empty.title)).toBeNull();
    server.listError = null;
    server.templates = [templateRow()];
    await user.click(retry);
    expect(await screen.findByText("Ubuntu")).toBeTruthy();
  });

  it("es-MX: empty, error and requirements copy are localized", async () => {
    await mount("es-MX");
    expect(await screen.findByText(esTemplates.empty.title)).toBeTruthy();
    expect(screen.getByText(esTemplates.requirements.title)).toBeTruthy();
    expect(screen.getByText(esTemplates.requirements.image)).toBeTruthy();
    expect(
      screen.getByRole("link", { name: esTemplates.requirements.docsLink }).getAttribute("href"),
    ).toBe("https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/operations/templates.md");
    cleanup();
    server.listError = new Error("network");
    await mount("es-MX");
    expect(await screen.findByText(esDashboard.list.loadFailed)).toBeTruthy();
    expect(screen.getByRole("button", { name: esCommon.actions.tryAgain })).toBeTruthy();
  });

  it("shows logical identity and the separately pinned revision", async () => {
    server.templates = [templateRow({ guestVersion: "2026-09" })];
    await mount();
    const row = await expand("tpl-a");
    // `slug vN` leads; the revision cuid and fingerprint sit, short, under Advanced.
    await waitFor(() =>
      expect(row.querySelector("[data-revision-label]")?.textContent).toMatch(/^ubuntu v1/),
    );
    const advanced = row.querySelector<HTMLElement>("[data-advanced-details]")!;
    expect(advanced.hasAttribute("open")).toBe(false);
    expect(within(advanced).getByText("sha256:abababababab…")).toBeTruthy();
    expect(row.textContent).not.toContain(FP);
    expect(row.getAttribute("data-usability")).toBe("active");
    expect(
      within(row).getByText(enTemplates.builds.action).closest("a")?.getAttribute("data-search"),
    ).toBe(JSON.stringify({ template: "tpl-a" }));
    expect(calls("listRevisions")[0]?.input).toMatchObject({ templateId: "tpl-a", limit: 50 });
  });

  it("logical activity is separate from host availability", async () => {
    server.templates = [templateRow({ host: freshHost({ status: "DISCONNECTED" }) })];
    await mount();
    expect((await findCard("tpl-a")).getAttribute("data-usability")).toBe("active");
    expect(screen.queryByText(enTemplates.usability.usable)).toBeNull();
  });

  it("the Archived filter asks the server for retired templates and shows them archived", async () => {
    const user = userEvent.setup();
    server.imageMode = "s3";
    server.templates = [
      templateRow(),
      templateRow({
        id: "tpl-old",
        label: "Old",
        archivedAt: new Date(),
        sandboxHostId: null,
        host: null,
      }),
    ];
    await mount();
    await screen.findByText("Ubuntu");
    await expand("tpl-a");
    expect(screen.queryByText("Old")).toBeNull();
    // A live template's revision offers Publish; an archived one's never does.
    const publish = { name: enTemplates.images.publish.action };
    await waitFor(() => expect(within(card("tpl-a")!).getByRole("button", publish)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: enTemplates.filter.retired }));
    expect(await screen.findByText("Old")).toBeTruthy();
    expect(calls("listTemplates").at(-1)?.input).toMatchObject({ status: "retired" });
    const old = await expand("tpl-old");
    expect(old.getAttribute("data-usability")).toBe("archived");
    expect(old.querySelector("[data-template-status]")?.textContent).toBe(
      enTemplates.status.archived,
    );
    expect(old.querySelector("[data-template-host]")).toBeNull();
    // Still shows what it pinned; no archive control on an archived revision.
    await waitFor(() => expect(within(old).getByText("sha256:abababababab…")).toBeTruthy());
    expect(
      within(old).queryByRole("button", {
        name: enTemplates.card.more.replace("{{label}}", "Old"),
      }),
    ).toBeNull();
    expect(within(old).queryByRole("button", publish)).toBeNull();
  });
});

describe("archive a template", () => {
  it("can archive a logical template while pinned sandboxes retain their revision", async () => {
    server.templates = [templateRow({ sandboxCount: 2 })];
    const user = userEvent.setup();
    await mount();
    await findCard("tpl-a");
    await user.click(
      within(card("tpl-a")!).getByRole("button", {
        name: enTemplates.card.more.replace("{{label}}", "Ubuntu"),
      }),
    );
    const item = await screen.findByRole("menuitem", { name: enTemplates.archive.action });
    expect(item.getAttribute("aria-disabled")).not.toBe("true");
    // Archive sits apart from the other entries, in the destructive section.
    expect(item.getAttribute("data-variant")).toBe("destructive");
  });

  it("requires confirmation; cancel sends nothing; confirm archives and refetches", async () => {
    const user = userEvent.setup();
    server.templates = [templateRow()];
    await mount();
    await findCard("tpl-a");
    await overflow(user, "Ubuntu", enTemplates.archive.action);
    const confirm = await screen.findByRole("alertdialog");
    // Plain words, and the confirm looks as destructive as the action is.
    expect(confirm.textContent).toContain(
      enTemplates.archive.description.replace("{{label}}", "Ubuntu"),
    );
    expect(confirm.textContent).not.toContain("logical");
    const archiveButton = within(confirm).getByRole("button", {
      name: enTemplates.archive.confirm,
    });
    expect(archiveButton.className).toContain("destructive");
    await user.click(within(confirm).getByRole("button", { name: enCommon.actions.cancel }));
    expect(calls("retireTemplate")).toHaveLength(0);
    await overflow(user, "Ubuntu", enTemplates.archive.action);
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: enTemplates.archive.confirm,
      }),
    );
    await waitFor(() =>
      expect(calls("retireTemplate")).toEqual([
        { procedure: "retireTemplate", input: { id: "tpl-a" } },
      ]),
    );
    // Refetched under the Active filter: the archived revision leaves this view.
    await waitFor(() => expect(card("tpl-a")).toBeNull());
    expect(toast.success).toHaveBeenCalledWith("Ubuntu archived");
  });

  it("an in-use refusal from the server is explained and the list refetched", async () => {
    const user = userEvent.setup();
    server.templates = [templateRow()];
    await mount();
    await findCard("tpl-a");
    const before = calls("listTemplates").length;
    server.retireError = Object.assign(new Error("in use"), {
      code: "CONFLICT",
      data: { code: "sandbox.template_in_use" },
    });
    await overflow(user, "Ubuntu", enTemplates.archive.action);
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: enTemplates.archive.confirm,
      }),
    );
    expect((await within(card("tpl-a")!).findByRole("alert")).textContent).toBe(
      enTemplates.problem.inUse,
    );
    await waitFor(() => expect(calls("listTemplates").length).toBeGreaterThan(before));
    expect(card("tpl-a")?.getAttribute("data-usability")).toBe("active");
  });
});

it("manages an exact revision tag and verifies it on a selected host", async () => {
  server.templates = [templateRow()];
  const user = userEvent.setup();
  await mount();
  await expand("tpl-a");
  await user.click(await screen.findByRole("button", { name: enTemplates.manageRevision }));
  await user.clear(within(dialog()).getByLabelText(enTemplates.tagLabel));
  await user.type(within(dialog()).getByLabelText(enTemplates.tagLabel), "stable");
  await user.click(within(dialog()).getByRole("button", { name: enTemplates.setTag }));
  await waitFor(() =>
    expect(calls("setTag")[0]?.input).toEqual({
      templateId: "tpl-a",
      revisionId: "tpl-a-revision",
      tag: "stable",
    }),
  );
  await user.click(await screen.findByRole("button", { name: enTemplates.manageRevision }));
  await selectOption(
    user,
    within(dialog()).getByLabelText(enTemplates.form.host),
    /^Alpha \(alpha\)/,
  );
  await user.click(within(dialog()).getByRole("button", { name: enTemplates.verifyAvailability }));
  await waitFor(() =>
    expect(calls("associateAvailability")[0]?.input).toEqual({
      templateId: "tpl-a",
      revisionId: "tpl-a-revision",
      hostId: "host-a",
    }),
  );
});

it("marks a revision captured with guest root, and one built by wssp's base recipe", async () => {
  server.templates = [templateRow()];
  server.revisions = [
    {
      ...templateRow(),
      id: "revision-1",
      templateId: "tpl-a",
      revision: 1,
      capturedWithGuestRoot: true,
      builtWithWsspRecipe: false,
    },
    {
      ...templateRow(),
      id: "revision-2",
      templateId: "tpl-a",
      revision: 2,
      sourceKind: "BUILD",
      builtWithRoot: true,
      capturedWithGuestRoot: false,
      builtWithWsspRecipe: true,
    },
  ];
  await mount();
  await expand("tpl-a");
  await screen.findByText("ubuntu v1");
  const tainted = document.querySelector("[data-revision-guest-root]");
  expect(tainted?.textContent).toBe(enTemplates.builds.revisionBadge.guestRoot);
  expect(tainted?.getAttribute("title")).toBe(enTemplates.builds.revisionBadge.guestRootHint);
  expect(document.querySelectorAll("[data-revision-guest-root]")).toHaveLength(1);
  expect(document.querySelector("[data-revision-wssp-recipe]")?.textContent).toBe(
    enTemplates.builds.revisionBadge.wsspRecipe,
  );
});

it("a community template is wssp-managed: badges, no writes, no launch actions on its pins", async () => {
  server.templates = [templateRow({ communitySource: "ubuntu-26.04", communityRefresh: true })];
  server.revisions = [
    {
      ...templateRow(),
      id: "revision-1",
      templateId: "tpl-a",
      revision: 1,
      sourceKind: "UPSTREAM",
    },
    {
      ...templateRow(),
      id: "revision-2",
      templateId: "tpl-a",
      revision: 2,
      sourceKind: "BUILD",
      pendingVerifyBuildId: "build-1",
    },
  ];
  const user = userEvent.setup();
  await mount();
  await expand("tpl-a");
  await screen.findByText("ubuntu v1");
  const row = card("tpl-a")!;
  expect(row.querySelector("[data-community-badge]")?.textContent).toBe(
    enTemplates.community.badge,
  );
  expect(row.querySelector("[data-community-controls]")).toBeTruthy();
  expect(row.querySelector('[data-revision-source="UPSTREAM"]')?.textContent).toBe(
    enTemplates.builds.revisionBadge.upstream,
  );
  expect(row.querySelector("[data-revision-verifying]")?.textContent).toBe(
    enTemplates.builds.revisionBadge.verifying,
  );
  // wssp-managed: no build or register of new versions, no "with these defaults".
  expect(within(row).queryByText(enTemplates.builds.action)).toBeNull();
  expect(within(row).queryByText(enTemplates.appendWithSize)).toBeNull();
  const manage = within(row).getAllByRole("button", { name: enTemplates.manageRevision });
  await user.click(manage[0]!);
  expect(within(dialog()).queryByLabelText(enTemplates.tagLabel)).toBeNull();
  expect(
    within(dialog()).queryByRole("button", { name: enTemplates.verifyAvailability }),
  ).toBeNull();
  expect(within(dialog()).getByRole("button", { name: enTemplates.retireRevision })).toBeTruthy();
});

it("an upstream pin held on a host never reads as a verified image", async () => {
  server.templates = [templateRow({ communitySource: "ubuntu-26.04", communityRefresh: true })];
  server.revisions = [
    {
      ...templateRow(),
      id: "revision-1",
      templateId: "tpl-a",
      revision: 1,
      sourceKind: "UPSTREAM",
      image: null,
      builtWithWsspRecipe: false,
    },
    {
      ...templateRow(),
      id: "revision-2",
      templateId: "tpl-a",
      revision: 2,
      sourceKind: "BUILD",
      builtWithWsspRecipe: true,
    },
    {
      ...templateRow(),
      id: "revision-3",
      templateId: "tpl-a",
      revision: 3,
      sourceKind: "UPSTREAM",
    },
  ];
  const evidence = (id: string, revisionId: string) => ({
    id,
    revisionId,
    hostId: "host-a",
    Host: { id: "host-a", label: "Alpha", slug: "alpha" },
    status: "AVAILABLE",
  });
  server.availability = [
    evidence("evidence-1", "revision-1"),
    evidence("evidence-2", "revision-2"),
  ];
  await mount();
  await expand("tpl-a");
  await screen.findByText("ubuntu v1");
  const revision = (id: string) => document.querySelector<HTMLElement>(`[data-revision="${id}"]`)!;
  const upstream = await waitFor(() => {
    const row = revision("revision-1").querySelector<HTMLElement>("[data-availability]");
    expect(row).toBeTruthy();
    return row!;
  });
  expect(upstream.textContent).toContain(enTemplates.upstreamAvailability.AVAILABLE);
  expect(upstream.textContent).not.toContain(enTemplates.availability.AVAILABLE);
  expect(upstream.querySelector("[data-upstream-availability]")?.getAttribute("title")).toBe(
    enTemplates.upstreamAvailability.hint,
  );
  const built = await waitFor(() => {
    const row = revision("revision-2").querySelector<HTMLElement>("[data-availability]");
    expect(row).toBeTruthy();
    return row!;
  });
  expect(built.textContent).toContain(enTemplates.availability.AVAILABLE);
  expect(built.querySelector("[data-upstream-availability]")).toBeNull();
  await waitFor(() =>
    expect(revision("revision-3").textContent).toContain(enTemplates.upstreamAvailability.none),
  );
  expect(revision("revision-3").textContent).not.toContain(enTemplates.noAvailability);
});

it("pages exact revisions and host verification evidence independently", async () => {
  server.pageSize = 1;
  server.templates = [templateRow()];
  server.revisions = [
    { ...templateRow(), id: "revision-1", templateId: "tpl-a", revision: 1 },
    { ...templateRow(), id: "revision-2", templateId: "tpl-a", revision: 2 },
  ];
  server.availability = [
    {
      id: "evidence-1",
      revisionId: "revision-1",
      hostId: "host-a",
      Host: { id: "host-a", label: "Alpha", slug: "alpha" },
      status: "AVAILABLE",
    },
    {
      id: "evidence-2",
      revisionId: "revision-1",
      hostId: "host-b",
      Host: { id: "host-b", label: "Beta", slug: "beta" },
      status: "PENDING",
    },
  ];
  const user = userEvent.setup();
  await mount();
  await expand("tpl-a");
  await screen.findByText("ubuntu v1");
  expect(screen.queryByText("ubuntu v2")).toBeNull();
  const evidence = (await screen.findByText("Alpha")).closest<HTMLElement>("[data-availability]")!;
  expect(within(evidence).getByText("Verified image")).toBeTruthy();
  expect(evidence.textContent).toContain("Alpha (alpha)");
  expect(screen.queryByText("Verification pending")).toBeNull();
  await user.click(within(card("tpl-a")!).getByRole("button", { name: enTemplates.moreHosts }));
  expect(await screen.findByText("Verification pending")).toBeTruthy();
  await user.click(within(card("tpl-a")!).getByRole("button", { name: enTemplates.moreRevisions }));
  expect(await screen.findByText("ubuntu v2")).toBeTruthy();
  expect(calls("listRevisions").at(-1)?.input).toMatchObject({
    templateId: "tpl-a",
    cursor: "1",
    limit: 50,
  });
  expect(
    calls("listAvailability").find((call) => (call.input as { cursor?: string }).cursor)?.input,
  ).toMatchObject({ revisionId: "revision-1", cursor: "1", limit: 50 });
});

it("availability shows a skeleton, safe retry, and a translated empty association state", async () => {
  let release!: () => void;
  server.templates = [templateRow()];
  server.availabilityGate = new Promise<void>((resolve) => {
    release = resolve;
  });
  server.availabilityError = new Error("private-availability-detail");
  await mount();
  const row = await expand("tpl-a");
  await waitFor(() => expect(row.querySelector('[data-slot="skeleton"]')).toBeTruthy());
  await act(async () => release());
  const user = userEvent.setup();
  const retry = await within(row).findByRole("button", { name: enCommon.actions.tryAgain });
  expect(row.textContent).not.toContain("private-availability-detail");
  server.availabilityError = null;
  await user.click(retry);
  expect(await within(row).findByText(enTemplates.noAvailability)).toBeTruthy();
});

it("revision edits use a Sheet with paged hosts, safe selection and typed retirement", async () => {
  server.pageSize = 1;
  server.templates = [templateRow()];
  const user = userEvent.setup();
  await mount();
  await expand("tpl-a");
  await user.click(await screen.findByRole("button", { name: enTemplates.manageRevision }));
  const sheet = within(dialog());
  expect(dialog().getAttribute("data-slot")).toBe("sheet-content");
  for (const button of sheet.getAllByRole("button"))
    expect(button.className).toMatch(/h-11|min-h-\[44px\]/);
  const firstChoices = await selectChoices(user, sheet.getByLabelText(enTemplates.form.host));
  expect(firstChoices.some((option) => option.textContent?.includes("Alpha (alpha)"))).toBe(true);
  expect(firstChoices.some((option) => option.textContent?.includes("Beta (beta)"))).toBe(false);
  await user.click(sheet.getByRole("button", { name: enCommon.actions.loadMore }));
  await selectOption(user, sheet.getByLabelText(enTemplates.form.host), /^Beta \(beta\)/);
  const select = sheet.getByLabelText(enTemplates.form.host);
  server.hosts = [];
  await act(() => client.invalidateQueries());
  expect(
    (await selectChoices(user, select)).some((option) =>
      option.textContent?.includes("Beta (beta)"),
    ),
  ).toBe(false);
  expect(
    sheet.getByRole("button", { name: enTemplates.verifyAvailability }).hasAttribute("disabled"),
  ).toBe(true);
  await user.click(sheet.getByRole("button", { name: enTemplates.retireRevision }));
  const confirm = within(await screen.findByRole("alertdialog"));
  const action = confirm.getByRole("button", { name: enTemplates.retireRevision });
  expect(action.hasAttribute("disabled")).toBe(true);
  await user.type(confirm.getByLabelText(enTemplates.retirePrompt), "tpl-a-revision");
  await user.click(action);
  await waitFor(() => expect(calls("retireRevision")[0]?.input).toEqual({ id: "tpl-a-revision" }));
});

it("links a version's defaults to a new version on the register page", async () => {
  server.templates = [
    templateRow({ cpuCount: 2, memoryMiB: 2048, defaultDiskGiB: 48, minDiskGiB: 12 }),
  ];
  await mount();
  await expand("tpl-a");
  expect(await screen.findByText("Defaults: 2 vCPU · 2048 MiB · 48 GiB disk")).toBeTruthy();
  const link = screen.getByText(enTemplates.appendWithSize).closest("a")!;
  expect(link.getAttribute("data-to")).toBe("/$lang/dashboard/templates/new/register");
  expect(link.getAttribute("data-search")).toBe(
    JSON.stringify({ template: "tpl-a", from: "tpl-a-revision" }),
  );
});

describe("templates header and cards", () => {
  it("has one primary New template action and All builds as the secondary", async () => {
    await mount();
    await screen.findByText(enTemplates.empty.title);
    const header = document.querySelector<HTMLElement>("[data-page-actions]")!;
    expect(within(header).getAllByRole("button")).toHaveLength(1);
    expect(within(header).getByRole("button", { name: enTemplates.chooser.action })).toBeTruthy();
    expect(within(header).getByText(enTemplates.builds.viewAll).getAttribute("data-to")).toBe(
      "/$lang/dashboard/templates/builds",
    );
    expect(screen.getByText(enTemplates.subtitle)).toBeTruthy();
    // The old jargon sits behind the About disclosure, collapsed.
    const about = document.querySelector<HTMLDetailsElement>("[data-templates-about]")!;
    expect(about.open).toBe(false);
    expect(within(about).getByText(enTemplates.description)).toBeTruthy();
  });

  it("?new=true (the Create sandbox link) opens the New template chooser", async () => {
    await mount("en-US", true);
    const chooser = await screen.findByRole("dialog");
    expect(chooser.querySelectorAll("[data-new-template]")).toHaveLength(3);
  });

  it("New template offers the three ways, community first and recommended", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enTemplates.empty.title);
    // The empty list offers the same action next to its explanation.
    expect(document.querySelector("[data-empty-new-template]")).toBeTruthy();
    const header = document.querySelector<HTMLElement>("[data-page-actions]")!;
    await user.click(within(header).getByRole("button", { name: enTemplates.chooser.action }));
    const chooser = await screen.findByRole("dialog");
    const options = [...chooser.querySelectorAll<HTMLElement>("[data-new-template]")];
    expect(options.map((node) => node.getAttribute("data-new-template"))).toEqual([
      "community",
      "build",
      "register",
    ]);
    expect(options[0]?.textContent).toContain(enTemplates.chooser.recommended);
    expect(options[1]?.getAttribute("data-to")).toBe("/$lang/dashboard/templates/new/build");
    expect(options[2]?.getAttribute("data-to")).toBe("/$lang/dashboard/templates/new/register");
    expect(options[2]?.textContent).toContain(enTemplates.chooser.registerDetail);
    await user.click(options[0]!);
    expect(
      await screen.findByRole("heading", { name: enTemplates.community.dialog.title }),
    ).toBeTruthy();
    expect(document.querySelector("[data-new-template]")).toBeNull();
  });

  it("badges a template Ready only when it has a usable version", async () => {
    server.templates = [
      templateRow({ versions: { count: 2, latest: 3 } }),
      templateRow({
        id: "tpl-empty",
        slug: "empty",
        label: "Empty",
        versions: { count: 0, latest: null },
      }),
    ];
    await mount();
    const ready = await findCard("tpl-a");
    expect(ready.querySelector("[data-template-status]")?.textContent).toBe(
      enTemplates.status.ready,
    );
    expect(ready.querySelector("[data-template-summary]")?.textContent).toContain(
      "2 versions · latest v3",
    );
    const empty = await findCard("tpl-empty");
    expect(empty.querySelector("[data-template-status]")?.textContent).toBe(
      enTemplates.status.noVersions,
    );
    expect(empty.querySelector("[data-template-summary]")?.textContent).toContain(
      enTemplates.card.noVersions,
    );
    // Compact: versions and builds load only when opened.
    expect(calls("listRevisions")).toHaveLength(0);
    // With no build yet, it says how to make it usable and offers the build.
    await waitFor(() =>
      expect(empty.querySelector("[data-empty-template='none']")?.textContent).toContain(
        enTemplates.card.noVersionsHint,
      ),
    );
    expect(ready.querySelector("[data-empty-template]")).toBeNull();
  });

  it("a template whose build failed links that build, says why and offers Build again", async () => {
    server.templates = [
      templateRow({
        id: "tpl-empty",
        slug: "empty",
        label: "Empty",
        versions: { count: 0, latest: null },
      }),
    ];
    server.latestBuild = {
      id: "build-1",
      templateId: "tpl-empty",
      state: "FAILED",
      errorCode: "build_placement_failed",
    };
    await mount();
    const card = await findCard("tpl-empty");
    await waitFor(() => expect(card.querySelector("[data-empty-template='FAILED']")).toBeTruthy());
    const note = card.querySelector<HTMLElement>("[data-empty-template]")!;
    expect(note.textContent).toContain(enTemplates.card.noVersionsLastBuild);
    expect(note.textContent).toContain(enTemplates.builds.error.build_placement_failed);
    expect(within(note).getByRole("link", { name: enTemplates.card.viewBuild })).toBeTruthy();
    expect(within(note).getByRole("link", { name: enTemplates.card.buildAgain })).toBeTruthy();
    // Nothing is removed: the template stays listed.
    expect(card.querySelector("[data-template-status]")?.textContent).toBe(
      enTemplates.status.noVersions,
    );
  });

  it("keeps Prune now and Archive in the card's More actions menu", async () => {
    server.imageMode = "s3";
    server.templates = [templateRow()];
    const user = userEvent.setup();
    await mount();
    const row = await findCard("tpl-a");
    expect(within(row).queryByRole("button", { name: enTemplates.images.prune.action })).toBeNull();
    expect(within(row).queryByRole("button", { name: enTemplates.archive.action })).toBeNull();
    await waitFor(() =>
      expect(
        within(row).getByRole("button", {
          name: enTemplates.card.more.replace("{{label}}", "Ubuntu"),
        }),
      ).toBeTruthy(),
    );
    await user.click(
      within(row).getByRole("button", {
        name: enTemplates.card.more.replace("{{label}}", "Ubuntu"),
      }),
    );
    const items = (await screen.findAllByRole("menuitem")).map((item) => item.textContent);
    expect(items).toEqual([
      enTemplates.card.registerVersion,
      enTemplates.images.settings.action,
      enTemplates.images.prune.action,
      enTemplates.archive.action,
    ]);
  });
});
