// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { HOST_STATUS_REFETCH_MS } from "@/lib/host-status";
import { selectOption } from "@/test/select-option";

/**
 * Build template page: inline Dockerfile errors from the recipe package
 * before anything is sent, the create body (target, tag, KEY=value args,
 * egress lines), the COPY context flow (hash before acceptance, upload after),
 * secret-name warnings, the pool pre-flight, and a disabled deployment.
 */

const server = vi.hoisted(() => ({
  calls: [] as { procedure: string; input: unknown }[],
  usage: null as Record<string, unknown> | null,
  needsContext: false,
  pool: { id: "pool_a", label: "Pool A", slug: "pool-a", memberCount: 1 },
  members: [] as Record<string, unknown>[],
  host: {} as Record<string, unknown>,
  templates: [] as { id: string; slug: string; versions: { count: number } }[],
  createError: null as unknown,
  templateError: null as unknown,
}));
const navigate = vi.hoisted(() => vi.fn());
const transfers = vi.hoisted(() => ({
  hashBuildContext: vi.fn(async (file: Blob) => ({ sha256: "c".repeat(64), bytes: file.size })),
  uploadBuildContext: vi.fn(async () => {}),
}));

vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className} href="#link">
      {children}
    </a>
  ),
}));
vi.mock("@/lib/sandbox-transfers", () => transfers);
vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  const query = (key: string, data: () => unknown) => ({
    queryOptions: () => ({ queryKey: [key], queryFn: async () => data() }),
  });
  return {
    orpc: {
      templateBuilds: {
        key: () => ["templateBuilds"],
        usage: query("usage", () => server.usage),
        create: {
          call: async (input: Record<string, unknown>) => {
            record("create", input);
            if (server.createError) throw server.createError;
            return {
              build: { id: "build_new" },
              joined: false,
              cacheHit: false,
              needsContext: server.needsContext,
            };
          },
        },
      },
      sandboxTemplates: {
        getTemplate: {
          queryOptions: () => ({
            queryKey: ["template"],
            queryFn: async () => {
              if (server.templateError) throw server.templateError;
              return { id: "tpl_1", label: "Base", archivedAt: null };
            },
          }),
        },
        listTemplates: query("templates", () => ({ items: server.templates, nextCursor: null })),
      },
      sandboxHosts: {
        listHosts: query("hosts", () => ({
          items: [
            {
              id: "host_a",
              label: "Host A",
              slug: "host-a",
              deletionRequestedAt: null,
              ...server.host,
            },
          ],
          nextCursor: null,
        })),
      },
      sandboxPools: {
        listUsable: query("pools", () => ({ items: [server.pool], nextCursor: null })),
        getUsable: query("pool", () => server.pool),
        listUsableMembers: query("members", () => ({ items: server.members, nextCursor: null })),
      },
    },
  };
});

import { BuildTemplateForm, BuildTemplatePage } from "./build-template-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "templates"],
    defaultNS: "common",
    resources: { "en-US": { common: enCommon, templates: enTemplates } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

beforeEach(() => {
  server.calls = [];
  server.needsContext = false;
  server.pool = { id: "pool_a", label: "Pool A", slug: "pool-a", memberCount: 1 };
  server.members = [];
  server.host = {};
  server.templates = [
    { id: "tpl_base", slug: "base", versions: { count: 1 } },
    { id: "tpl_empty", slug: "empty", versions: { count: 0 } },
  ];
  server.createError = null;
  server.templateError = null;
  server.usage = {
    enabled: true,
    reason: null,
    maxMinutes: 60,
    maxConcurrent: 2,
    minutesPerMonth: 1000,
    contextMaxBytes: 1024,
    contextWaitMaxMs: 1000,
    openEgress: false,
    imageMode: "s3",
    allowForeignBuilds: false,
    usage: { activeBuilds: 0, minutesUsedThisMonth: 0 },
  };
  navigate.mockReset();
  transfers.hashBuildContext.mockClear();
  transfers.uploadBuildContext.mockClear();
});
afterEach(() => cleanup());

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  lastClient = client;
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <BuildTemplateForm lang="en-US" template={{ id: "tpl_1", label: "Base" }} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

let lastClient: QueryClient | null = null;

/** Build args through the KeyValueEditor's .env text mode. */
async function typeArgs(user: ReturnType<typeof userEvent.setup>, text: string) {
  await user.click(screen.getAllByRole("button", { name: ".env text" })[0] as HTMLElement);
  fireEvent.change(screen.getByRole("textbox", { name: "Build args" }), {
    target: { value: text },
  });
}

const source = () => screen.getByLabelText("Dockerfile") as HTMLTextAreaElement;
const creates = () => server.calls.filter((call) => call.procedure === "create");

async function chooseHost(user: ReturnType<typeof userEvent.setup>) {
  await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
  await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Host A/);
}

describe("BuildTemplateForm", () => {
  it("shows a refused instruction inline with its line and sends nothing", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nADD x /x\n" } });
    expect(
      await screen.findByText(/^Line 2, column \d+: This instruction is not supported/),
    ).toBeTruthy();
    await chooseHost(user);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    expect(creates()).toEqual([]);
  });

  it("creates the build with target, tag, args and egress lines, then opens it", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nARG V\nRUN echo $V\n" } });
    await typeArgs(user, "V=1");
    await chooseHost(user);
    await selectOption(
      user,
      screen.getByRole("combobox", { name: "Network egress" }),
      "Allowlist only",
    );
    await user.click(screen.getByRole("button", { name: "pypi" }));
    await user.click(screen.getByRole("button", { name: "Start build" }));
    await waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]?.input).toMatchObject({
      template: { id: "tpl_1" },
      tag: "latest",
      sandboxHostId: "host_a",
      buildArgs: { V: "1" },
      dockerfile:
        "FROM base\nARG V\nRUN echo $V\n# wssp:egress-mode allowlist\n# wssp:egress-preset pypi\n",
    });
    expect(creates()[0]?.input).not.toHaveProperty("contextSha256");
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({
        to: "/$lang/dashboard/templates/builds/$buildId",
        params: { lang: "en-US", buildId: "build_new" },
      }),
    );
    expect(transfers.uploadBuildContext).not.toHaveBeenCalled();
  });

  it("refuses build args text with a line that is not KEY=value instead of dropping it", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nARG V\nARG W\nRUN echo $V\n" } });
    await typeArgs(user, "V=1\nW");
    await chooseHost(user);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    expect(creates()).toEqual([]);
    const text = screen.getByRole("textbox", { name: "Build args" });
    expect(text.getAttribute("aria-invalid")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(text));
    fireEvent.change(text, { target: { value: "V=1\nW=2" } });
    await user.click(screen.getByRole("button", { name: "Start build" }));
    await waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]?.input).toMatchObject({ buildArgs: { V: "1", W: "2" } });
  });

  it("needs a .tar for COPY, hashes it before acceptance and uploads it after", async () => {
    const user = userEvent.setup();
    server.needsContext = true;
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nCOPY app/ /app/\n" } });
    await chooseHost(user);
    expect(
      await screen.findByText("This recipe has COPY steps, so it needs a build context."),
    ).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Start build" }));
    expect(creates()).toEqual([]);
    const tar = new File([new Uint8Array(2048)], "context.tar", { type: "application/x-tar" });
    await user.upload(screen.getByLabelText("Build context (.tar)"), tar);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    await waitFor(() => expect(creates()).toHaveLength(1));
    expect(transfers.hashBuildContext).toHaveBeenCalledTimes(1);
    expect(creates()[0]?.input).toMatchObject({
      contextSha256: "c".repeat(64),
      contextBytes: 2048,
    });
    await waitFor(() => expect(transfers.uploadBuildContext).toHaveBeenCalledTimes(1));
    const uploads = transfers.uploadBuildContext.mock.calls as unknown as [unknown, unknown][];
    expect(uploads[0]?.[1]).toMatchObject({
      buildId: "build_new",
      file: tar,
    });
  });

  it("warns about secret-looking build args and ENV names", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nENV API_KEY=x\n" } });
    await typeArgs(user, "GITHUB_TOKEN=y");
    expect(
      await screen.findByText(/These names look like secrets: API_KEY, GITHUB_TOKEN/),
    ).toBeTruthy();
  });

  it("explains a disabled deployment and cannot submit", async () => {
    server.usage = { ...server.usage, enabled: false, reason: "lease_ceiling" };
    renderPage();
    expect(
      await screen.findByText("This server's lease limit is too short for builds."),
    ).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Start build" }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it("refuses a pool with no hosts before submit and says what to do", async () => {
    const user = userEvent.setup();
    server.pool = { ...server.pool, memberCount: 0 };
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nRUN true\n" } });
    await user.click(screen.getByRole("button", { name: "A pool" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Pool A/);
    expect(
      await screen.findByText(/Pool A has no hosts, so nothing can run this build/),
    ).toBeTruthy();
    const submit = screen.getByRole("button", { name: "Start build" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    expect(creates()).toEqual([]);
  });

  it("refuses a pool whose hosts are all switched off for it", async () => {
    const user = userEvent.setup();
    server.pool = { ...server.pool, memberCount: 1 };
    server.members = [{ id: "m1", enabled: false, Host: { status: "CONNECTED" } }];
    renderPage();
    await user.click(screen.getByRole("button", { name: "A pool" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Pool A/);
    expect(await screen.findByText(/Every host in Pool A is switched off/)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Start build" }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it("builds on a usable pool and says where it runs and what it reserves", async () => {
    const user = userEvent.setup();
    server.members = [{ id: "m1", enabled: true, Host: { status: "CONNECTED" } }];
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nRUN true\n" } });
    await user.click(screen.getByRole("button", { name: "A pool" }));
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Pool A/);
    expect(
      await screen.findByText(
        "Builds on Pool A · reserves up to 30 build minutes (0 of 1000 used this month)",
      ),
    ).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Start build" }));
    await waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]?.input).toMatchObject({ poolId: "pool_a" });
  });

  it("needs a target, marks the picker invalid and focuses the first invalid field", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nRUN true\n" } });
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
    await user.click(screen.getByRole("button", { name: "Start build" }));
    expect(await screen.findByText("Choose where the build runs.")).toBeTruthy();
    const picker = screen.getByRole("combobox", { name: "Build on" });
    expect(picker.getAttribute("aria-invalid")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(picker));
    expect(creates()).toEqual([]);
  });
});

describe("BuildTemplateForm FROM and ARG errors", () => {
  it("says at the Dockerfile that FROM must name one of your templates, before submit", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM ubuntu:24.04\nRUN true\n" } });
    await waitFor(() => expect(source().getAttribute("aria-invalid")).toBe("true"));
    // The error is the field's description, and suggests a template that works.
    const describedBy = (source().getAttribute("aria-describedby") ?? "").split(" ");
    const described = describedBy.map((id) => document.getElementById(id)?.textContent).join(" ");
    expect(described).toContain(
      "FROM ubuntu:24.04 isn't one of your templates. FROM must name one of your templates, not a registry image. For example: FROM base.",
    );
    await chooseHost(user);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    expect(creates()).toEqual([]);
    await waitFor(() => expect(document.activeElement).toBe(source()));
  });

  it("a template with no ready version is refused at FROM too", async () => {
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM empty\nRUN true\n" } });
    expect(
      await screen.findByText(/^FROM empty names a template with no ready version yet/),
    ).toBeTruthy();
  });

  it("maps the server's template miss to the Dockerfile, not the footer", async () => {
    const user = userEvent.setup();
    server.createError = {
      code: "NOT_FOUND",
      status: 404,
      data: { code: "sandbox.template_not_found" },
    };
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base:v9\nRUN true\n" } });
    await chooseHost(user);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    expect(
      await screen.findByText(
        /^FROM base:v9 didn't match a ready version of one of your templates/,
      ),
    ).toBeTruthy();
    expect(document.querySelector("[data-build-problem]")).toBeNull();
    expect(screen.queryByText(enTemplates.builds.problem.notFound)).toBeNull();
    // Editing the Dockerfile clears the server's refusal.
    fireEvent.change(source(), { target: { value: "FROM base\nRUN true\n" } });
    await waitFor(() => expect(screen.queryByText(/^FROM base:v9 didn't match/)).toBeNull());
  });

  it("names the build arg no ARG declares, with the line that fixes it", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nRUN true\n" } });
    await typeArgs(user, "NODE_VERSION=22");
    expect(
      await screen.findByText(
        "Build arg NODE_VERSION is not declared. Add the line ARG NODE_VERSION to the Dockerfile, or remove the arg.",
      ),
    ).toBeTruthy();
  });
});

describe("BuildTemplateForm host pre-flight", () => {
  it("a connected host with a fresh heartbeat gets no 'isn't connected' warning", async () => {
    const user = userEvent.setup();
    server.host = {
      status: "CONNECTED",
      lastConnectedAt: new Date().toISOString(),
      lastHeartbeatAt: new Date().toISOString(),
      draining: false,
    };
    renderPage();
    await chooseHost(user);
    expect(document.querySelector("[data-build-preflight]")).toBeNull();
  });

  it("polls the host list like the Hosts page, so a heartbeat never ages into 'offline'", async () => {
    renderPage();
    await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
    const hostsQuery = lastClient?.getQueryCache().find({ queryKey: ["hosts"] });
    expect(hostsQuery?.options).toMatchObject({ refetchInterval: HOST_STATUS_REFETCH_MS });
  });

  it("a host that really stopped reporting still warns", async () => {
    const user = userEvent.setup();
    server.host = {
      status: "CONNECTED",
      lastConnectedAt: new Date(Date.now() - 600_000).toISOString(),
      lastHeartbeatAt: new Date(Date.now() - 600_000).toISOString(),
    };
    renderPage();
    await chooseHost(user);
    expect(document.querySelector("[data-build-preflight='hostOffline']")).toBeTruthy();
  });
});

describe("build arg values", () => {
  it("are sent exactly as typed: a newline in a value stays a newline", async () => {
    const user = userEvent.setup();
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nARG V\nRUN echo $V\n" } });
    // A double-quoted .env value understands `\n`.
    await typeArgs(user, 'V="two\\nlines"');
    await chooseHost(user);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    await waitFor(() => expect(creates()).toHaveLength(1));
    expect(creates()[0]?.input).toMatchObject({ buildArgs: { V: "two\nlines" } });
  });
});

describe("leaving mid-hash", () => {
  it("aborts the hash and sends no create once the page is gone", async () => {
    const user = userEvent.setup();
    let release: (value: { sha256: string; bytes: number }) => void = () => {};
    let signal: AbortSignal | undefined;
    transfers.hashBuildContext.mockImplementationOnce(
      (_file: Blob, options?: { signal?: AbortSignal }) => {
        signal = options?.signal;
        return new Promise((resolve) => {
          release = resolve;
        });
      },
    );
    server.needsContext = true;
    renderPage();
    fireEvent.change(source(), { target: { value: "FROM base\nCOPY app/ /app/\n" } });
    await chooseHost(user);
    const tar = new File([new Uint8Array(16)], "context.tar", { type: "application/x-tar" });
    await user.upload(screen.getByLabelText("Build context (.tar)"), tar);
    await user.click(screen.getByRole("button", { name: "Start build" }));
    await waitFor(() => expect(transfers.hashBuildContext).toHaveBeenCalledTimes(1));
    cleanup();
    expect(signal?.aborted).toBe(true);
    release({ sha256: "c".repeat(64), bytes: 16 });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(creates()).toEqual([]);
  });
});

describe("BuildTemplatePage (new version)", () => {
  function renderVersionPage() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <I18nextProvider i18n={i18n}>
          <BuildTemplatePage lang="en-US" templateId="tpl_1" />
        </I18nextProvider>
      </QueryClientProvider>,
    );
    return client;
  }
  const failed = "This template couldn't be loaded. It may have been archived.";

  it("keeps the form and its draft when a template refetch fails, with a retry", async () => {
    const client = renderVersionPage();
    await waitFor(() => expect(screen.getByLabelText("Dockerfile")).toBeTruthy());
    fireEvent.change(source(), { target: { value: "FROM base\nRUN true\n" } });
    server.templateError = new Error("network down");
    await client.refetchQueries({ queryKey: ["template"] });
    expect(await screen.findByText(failed)).toBeTruthy();
    expect(source().value).toBe("FROM base\nRUN true\n");
  });

  it("hides the form when the refetch says the template is gone", async () => {
    const client = renderVersionPage();
    await waitFor(() => expect(screen.getByLabelText("Dockerfile")).toBeTruthy());
    server.templateError = { status: 404, code: "NOT_FOUND" };
    await client.refetchQueries({ queryKey: ["template"] });
    expect(await screen.findByText(failed)).toBeTruthy();
    expect(screen.queryByLabelText("Dockerfile")).toBeNull();
  });
});
