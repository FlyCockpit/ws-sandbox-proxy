import { openSelect, selectChoices, selectOption } from "@/test/select-option";

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
  seq: 0,
}));

const webEnv = vi.hoisted(() => ({ VITE_DOCS_URL: undefined as string | undefined }));
vi.mock("@wssp/env/web", () => ({ env: webEnv }));

const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className} href="#link">
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
        setRefresh: { mutationOptions: () => ({ mutationFn: async () => ({ ok: true }) }) },
        refresh: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        retry: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
      },
      templateBuilds: {
        key: () => ["templateBuilds"],
        list: {
          queryOptions: () => ({
            queryKey: ["latestTemplateBuild"],
            queryFn: async () => ({ items: [], nextCursor: null }),
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
              mode: "off" as const,
              imagePlacement: "ANY_NODE" as const,
              quotas: { maxStoredGiB: null, downloadsPerHour: null },
              usage: { storedBytes: "0", downloadsLastHour: 0 },
            }),
          }),
        },
      },
      sandboxPools: {
        listUsable: {
          infiniteOptions: infinite(
            "listUsablePools",
            () => [{ id: "pool-a", slug: "shared", label: "Shared pool" }],
            () => null,
          ),
        },
        listUsableMembers: {
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
              server.templates.filter((row) =>
                input.status === "active"
                  ? row.archivedAt == null
                  : input.status === "retired"
                    ? row.archivedAt != null
                    : true,
              ),
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
    diskGiB: 32,
    ...overrides,
  };
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
        <TemplatesPage lang={lang} />
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

async function openRegister(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: enTemplates.register.action }));
  await within(dialog()).findByRole("combobox", { name: enTemplates.form.host });
}

async function fillValid(user: ReturnType<typeof userEvent.setup>, hostId = "host-a") {
  await selectOption(
    user,
    within(dialog()).getByLabelText(enTemplates.form.host),
    hostId === "host-a" ? /^Alpha \(alpha\)/ : /^Beta \(beta\)/,
  );
  await user.type(within(dialog()).getByLabelText(enTemplates.form.label), "Ubuntu dev");
  await user.type(within(dialog()).getByLabelText(enTemplates.form.slug), "ubuntu-dev");
  await user.type(within(dialog()).getByLabelText(enTemplates.form.imageRef), "local:ubuntu-dev");
}

const submit = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(within(dialog()).getByRole("button", { name: enTemplates.register.submit }));

describe("templates list", () => {
  it("loading shows a skeleton, then the translated empty state for active templates", async () => {
    const view = await mount();
    expect(view.container.querySelector('[data-slot="skeleton"]')).not.toBeNull();
    expect(await screen.findByText(enTemplates.empty.title)).toBeTruthy();
    expect(screen.getByText(enTemplates.requirements.image)).toBeTruthy();
    expect(calls("listTemplates")[0]?.input).toMatchObject({ status: "active", limit: 50 });
    // No docs base configured: the repository path is text, never a guessed URL.
    expect(screen.queryByRole("link", { name: enTemplates.requirements.docsLink })).toBeNull();
    expect(document.querySelector("[data-docs-path]")?.textContent).toBe(
      enTemplates.requirements.docsPath.replace("{{path}}", "docs/operations/templates.md"),
    );
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
    expect(document.querySelector("[data-docs-path]")?.textContent).toContain(
      "docs/operations/templates.md",
    );
    cleanup();
    server.listError = new Error("network");
    await mount("es-MX");
    expect(await screen.findByText(esDashboard.list.loadFailed)).toBeTruthy();
    expect(screen.getByRole("button", { name: esCommon.actions.tryAgain })).toBeTruthy();
  });

  it("shows logical identity and the separately pinned revision", async () => {
    server.templates = [templateRow({ guestVersion: "2026-09" })];
    await mount();
    const row = await findCard("tpl-a");
    // `slug vN` leads; the revision cuid and fingerprint sit, short, under Advanced.
    await waitFor(() =>
      expect(row.querySelector("[data-revision-label]")?.textContent).toMatch(/^ubuntu v1/),
    );
    const advanced = row.querySelector<HTMLElement>("[data-advanced-details]")!;
    expect(advanced.hasAttribute("open")).toBe(false);
    expect(within(advanced).getByText("sha256:abababababab…")).toBeTruthy();
    expect(row.textContent).not.toContain(FP);
    expect(row.getAttribute("data-usability")).toBe("active");
    expect(within(row).getByRole("button", { name: enTemplates.appendRevision })).toBeTruthy();
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
    expect(screen.queryByText("Old")).toBeNull();
    await user.click(screen.getByRole("button", { name: enTemplates.filter.retired }));
    expect(await screen.findByText("Old")).toBeTruthy();
    expect(calls("listTemplates").at(-1)?.input).toMatchObject({ status: "retired" });
    const old = card("tpl-old")!;
    expect(old.getAttribute("data-usability")).toBe("archived");
    expect(old.querySelector("[data-template-host]")).toBeNull();
    // Still shows what it pinned; no archive control on an archived revision.
    await waitFor(() => expect(within(old).getByText("sha256:abababababab…")).toBeTruthy());
    expect(within(old).queryByRole("button", { name: enTemplates.archive.action })).toBeNull();
  });
});

describe("register a template", () => {
  it("refuses an invalid draft in the browser without asking the host", async () => {
    const user = userEvent.setup();
    await mount();
    await openRegister(user);
    // The disconnected host is offered but marked; the one pending deletion is not offered.
    expect(
      (await openSelect(user, within(dialog()).getByLabelText(enTemplates.form.host))).getByRole(
        "option",
        { name: /Beta \(beta\) · not connected/ },
      ),
    ).toBeTruthy();
    expect(screen.queryByRole("option", { name: /Gone/ })).toBeNull();
    await user.keyboard("{Escape}");
    await user.type(within(dialog()).getByLabelText(enTemplates.form.slug), "Bad_Slug");
    await user.type(
      within(dialog()).getByLabelText(enTemplates.form.imageRef),
      `sha256:${"a".repeat(64)}`,
    );
    const uid = within(dialog()).getByLabelText(enTemplates.form.guestUid);
    await user.clear(uid);
    await user.type(uid, "0");
    await submit(user);
    const alert = await within(dialog()).findByRole("alert");
    expect(
      [...alert.querySelectorAll("[data-draft-problem]")].map((node) =>
        node.getAttribute("data-draft-problem"),
      ),
    ).toEqual(["noHost", "slug", "label", "guestUid", "imageRef"]);
    // An offline host is refused before the request too.
    await selectOption(
      user,
      within(dialog()).getByLabelText(enTemplates.form.host),
      /^Beta \(beta\)/,
    );
    expect(within(dialog()).getByRole("alert").textContent).toContain(
      enTemplates.draft.hostUnavailable,
    );
    expect(calls("createTemplate")).toHaveLength(0);
  });

  it("a form left open past the stale window still registers on a host that kept heartbeating", async () => {
    // What the picker read when the dialog opened is now older than the
    // stale window; the host has kept heartbeating on the server.
    server.hosts[0]!.lastHeartbeatAt = new Date(Date.now() - 40_000);
    const user = userEvent.setup();
    await mount();
    await openRegister(user);
    await fillValid(user);
    server.hosts[0]!.lastHeartbeatAt = new Date();
    await submit(user);
    await waitFor(() => expect(calls("createTemplate")).toHaveLength(1));
    expect(calls("createTemplate")[0]?.input).toMatchObject({ hostId: "host-a" });
    expect(within(dialog()).queryByText(enTemplates.draft.hostUnavailable)).toBeNull();
  });

  it("cancelling while the host is re-checked registers nothing afterwards", async () => {
    server.hosts[0]!.lastHeartbeatAt = new Date(Date.now() - 40_000);
    const user = userEvent.setup();
    await mount();
    await openRegister(user);
    await fillValid(user);
    let release!: () => void;
    server.hostsGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.hosts[0]!.lastHeartbeatAt = new Date();
    const before = calls("listHosts").length;
    await submit(user);
    await waitFor(() => expect(calls("listHosts").length).toBeGreaterThan(before));
    await user.click(within(dialog()).getByRole("button", { name: enCommon.actions.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    // The fresh reading now says the host is ready; the closed form must not act on it.
    await act(async () => {
      release();
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(calls("createTemplate")).toEqual([]);
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("the image check is visibly pending, then shows the resolved fingerprint and host", async () => {
    let release!: () => void;
    server.createGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enTemplates.empty.title);
    await openRegister(user);
    await fillValid(user);
    await submit(user);
    const pending = await within(dialog()).findByRole("status");
    expect(pending.getAttribute("data-image-check")).toBe("pending");
    expect(pending.textContent).toBe("Checking the image on Alpha…");
    expect(
      within(dialog()).getByRole("button", { name: enTemplates.register.pending }),
    ).toHaveProperty("disabled", true);
    // Nothing is listed while the host has not answered.
    expect(card("tpl-new-1")).toBeNull();
    release();
    const result = await within(dialog()).findByRole("region", {
      name: enTemplates.register.resultLabel,
    });
    expect(result.textContent).toContain("ubuntu-dev v1");
    expect(result.textContent).not.toContain("tpl-new-1-revision");
    expect(calls("createTemplate")[0]?.input).toEqual({
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      hostId: "host-a",
      envs: {},
      slug: "ubuntu-dev",
      label: "Ubuntu dev",
      imageRef: "local:ubuntu-dev",
      architecture: "x86_64",
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
    });
    await user.click(within(result).getByRole("button", { name: enTemplates.register.close }));
    await waitFor(() => expect(card("tpl-new-1")?.getAttribute("data-usability")).toBe("active"));
  });

  it("an image the host refuses registers nothing, explains why, and can be retried", async () => {
    const user = userEvent.setup();
    await mount();
    await screen.findByText(enTemplates.empty.title);
    await openRegister(user);
    await fillValid(user);
    server.createError = Object.assign(new Error("image alias `ubuntu-dev` not found"), {
      code: "BAD_REQUEST",
      data: { code: "sandbox.template_image_rejected" },
    });
    await submit(user);
    const failed = await waitFor(() => {
      const node = dialog().querySelector<HTMLElement>('[data-image-check="failed"]');
      expect(node).not.toBeNull();
      return node!;
    });
    expect(failed.textContent).toContain(enTemplates.problem.imageRejected);
    expect(failed.textContent).not.toContain("image alias `ubuntu-dev` not found");
    expect(
      within(dialog()).queryByRole("region", { name: enTemplates.register.resultLabel }),
    ).toBeNull();
    // The list was refetched and has no template: a refused image never appears.
    await waitFor(() => expect(calls("listTemplates").length).toBeGreaterThan(1));
    expect(screen.getByText(enTemplates.empty.title)).toBeTruthy();
    // The form keeps the draft; a retry registers.
    await submit(user);
    expect(
      await within(dialog()).findByRole("region", { name: enTemplates.register.resultLabel }),
    ).toBeTruthy();
    expect(calls("createTemplate")).toHaveLength(2);
  });

  it("a host that cannot answer is explained and the host list reloaded", async () => {
    const user = userEvent.setup();
    await mount();
    await openRegister(user);
    await fillValid(user);
    const before = calls("listHosts").length;
    server.createError = Object.assign(new Error("Host could not verify the image."), {
      code: "CONFLICT",
      data: { code: "sandbox.host_unavailable" },
    });
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toBe(
      enTemplates.problem.hostUnavailable,
    );
    await waitFor(() => expect(calls("listHosts").length).toBeGreaterThan(before));
  });

  it("a forced-2FA refusal redirects to Security settings", async () => {
    const user = userEvent.setup();
    await mount();
    await openRegister(user);
    await fillValid(user);
    server.createError = Object.assign(new Error("2FA"), {
      code: "FORBIDDEN",
      data: { code: "auth.two_factor_required" },
    });
    await submit(user);
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({
        to: "/$lang/settings/security",
        params: { lang: "en-US" },
      }),
    );
    expect(dialog().querySelector('[data-image-check="failed"]')).toBeNull();
  });
});

describe("archive a template", () => {
  it("can archive a logical template while pinned sandboxes retain their revision", async () => {
    server.templates = [templateRow({ sandboxCount: 2 })];
    await mount();
    const row = await findCard("tpl-a");
    expect(within(row).getByRole("button", { name: enTemplates.archive.action })).toHaveProperty(
      "disabled",
      false,
    );
  });

  it("requires confirmation; cancel sends nothing; confirm archives and refetches", async () => {
    const user = userEvent.setup();
    server.templates = [templateRow()];
    await mount();
    const row = await findCard("tpl-a");
    await user.click(within(row).getByRole("button", { name: enTemplates.archive.action }));
    const confirm = await screen.findByRole("alertdialog");
    await user.click(within(confirm).getByRole("button", { name: enCommon.actions.cancel }));
    expect(calls("retireTemplate")).toHaveLength(0);
    await user.click(within(row).getByRole("button", { name: enTemplates.archive.action }));
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
    const row = await findCard("tpl-a");
    const before = calls("listTemplates").length;
    server.retireError = Object.assign(new Error("in use"), {
      code: "CONFLICT",
      data: { code: "sandbox.template_in_use" },
    });
    await user.click(within(row).getByRole("button", { name: enTemplates.archive.action }));
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
  expect(within(row).queryByRole("button", { name: enTemplates.appendRevision })).toBeNull();
  expect(within(row).queryByRole("button", { name: enTemplates.appendWithSize })).toBeNull();
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
  const row = await findCard("tpl-a");
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

it.each(["en-US", "es-MX"])(
  "%s bounds private revision envs and clears form/mutation state after a definite refusal",
  async (lang) => {
    await i18n.changeLanguage(lang);
    const copy = lang === "en-US" ? enTemplates : esTemplates;
    const user = userEvent.setup();
    await mount(lang);
    await user.click(screen.getByRole("button", { name: copy.register.action }));
    const form = within(dialog());
    await form.findByRole("combobox", { name: copy.form.host });
    await selectOption(user, form.getByLabelText(copy.form.host), /^Alpha \(alpha\)/);
    await user.type(form.getByLabelText(copy.form.label), "Image");
    await user.type(form.getByLabelText(copy.form.slug), "image");
    await user.type(form.getByLabelText(copy.form.imageRef), "local:image");
    const env = form.getByLabelText(copy.form.envs) as HTMLTextAreaElement;
    await user.click(env);
    await user.paste(JSON.stringify({ APP: "x".repeat(4097) }));
    await user.click(form.getByRole("button", { name: copy.register.submit }));
    expect(await form.findByText(copy.draft.envs)).toBeTruthy();
    expect(calls("createTemplate")).toHaveLength(0);
    await user.clear(env);
    const sentinel = "synthetic-template-private-env";
    await user.paste(JSON.stringify({ APP: sentinel }));
    server.createError = Object.assign(new Error(sentinel), {
      code: "BAD_REQUEST",
      data: { code: "sandbox.template_image_rejected" },
    });
    const storage = vi.spyOn(Storage.prototype, "setItem");
    await user.click(form.getByRole("button", { name: copy.register.submit }));
    await form.findByText(copy.problem.imageRejected);
    expect(env.value).toBe("");
    await waitFor(() =>
      expect(
        JSON.stringify(
          client
            .getMutationCache()
            .getAll()
            .map((mutation) => mutation.state),
        ),
      ).not.toContain(sentinel),
    );
    expect(form.getByRole("alert").textContent).not.toContain(sentinel);
    expect(JSON.stringify(storage.mock.calls)).not.toContain(sentinel);
    expect(JSON.stringify(toast.success.mock.calls)).not.toContain(sentinel);
  },
);

it("appends explicitly prefilled size as a new revision without changing the source", async () => {
  server.templates = [templateRow({ cpuCount: 2, memoryMiB: 2048, diskGiB: 48 })];
  const user = userEvent.setup();
  await mount();
  expect(await screen.findByText("Defaults: 2 vCPU · 2048 MiB · 48 GiB")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: enTemplates.appendWithSize }));
  const form = within(dialog());
  const cpu = form.getByLabelText(enTemplates.form.cpuCount);
  const memory = form.getByLabelText(enTemplates.form.memoryMiB);
  const disk = form.getByLabelText(enTemplates.form.diskGiB);
  expect((disk as HTMLInputElement).value).toBe("48");
  await user.clear(disk);
  await user.type(disk, "64");
  expect((cpu as HTMLInputElement).value).toBe("2");
  expect((memory as HTMLInputElement).value).toBe("2048");
  expect(cpu.getAttribute("inputmode")).toBe("numeric");
  expect(memory.getAttribute("inputmode")).toBe("numeric");
  expect(cpu.getAttribute("min")).toBe("1");
  expect(cpu.getAttribute("max")).toBe("32");
  expect(memory.getAttribute("step")).toBe("256");
  await selectOption(user, form.getByLabelText(enTemplates.form.host), /^Alpha \(alpha\)/);
  await user.type(form.getByLabelText(enTemplates.form.imageRef), "local:ubuntu-dev");
  await user.clear(memory);
  await user.type(memory, "3072");
  await submit(user);
  await waitFor(() => expect(calls("appendRevision")).toHaveLength(1));
  expect(calls("appendRevision")[0]?.input).toMatchObject({
    templateId: "tpl-a",
    cpuCount: 2,
    memoryMiB: 3072,
    diskGiB: 64,
  });
  expect(server.templates[0]).toMatchObject({ cpuCount: 2, memoryMiB: 2048, diskGiB: 48 });
  expect(calls("createTemplate")).toHaveLength(0);
});

it("pool registration labels, helps and validates an exact fingerprint instead of an alias", async () => {
  const user = userEvent.setup();
  await mount();
  await openRegister(user);
  await fillValid(user);
  await user.click(within(dialog()).getByRole("checkbox", { name: enHosts.sharing.imageTarget }));
  expect(within(dialog()).queryByLabelText(enTemplates.form.imageRef)).toBeNull();
  const image = within(dialog()).getByLabelText(enTemplates.form.poolImageRef);
  expect(within(dialog()).getByText(enTemplates.form.poolImageRefHint)).toBeTruthy();
  await submit(user);
  expect(await within(dialog()).findByText(enTemplates.draft.noPoolMember)).toBeTruthy();
  expect(within(dialog()).queryByText(enTemplates.draft.noHost)).toBeNull();
  expect(within(dialog()).queryByText(enTemplates.draft.imageRef)).toBeNull();
  await selectOption(
    user,
    within(dialog()).getByLabelText(enHosts.sharing.choosePool),
    /Shared pool/,
  );
  await selectOption(
    user,
    within(dialog()).getByLabelText(enHosts.sharing.chooseMember),
    // Numbered, never the member's ID or its host.
    enHosts.sharing.memberOption.replace("{{n}}", "1"),
  );
  await submit(user);
  expect(await within(dialog()).findAllByText(enTemplates.draft.poolImageRef)).not.toHaveLength(0);
  expect(within(dialog()).queryByText(enTemplates.draft.imageRef)).toBeNull();
  await user.clear(image);
  await user.type(image, FP);
  await submit(user);
  await waitFor(() => expect(calls("createTemplate")).toHaveLength(1));
  expect(calls("createTemplate")[0]!.input).toMatchObject({
    poolId: "pool-a",
    memberId: "member-a",
    imageRef: FP,
  });
});
