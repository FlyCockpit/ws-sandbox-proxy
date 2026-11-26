import { selectOption } from "@/test/select-option";

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
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import esTemplates from "@wssp/locales/src/es-MX/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Register an existing image, as a page, against a scripted fake server:
 * Essential fields first with the slug derived from the name, inline errors
 * with focus on the first invalid field, the host's image check visibly
 * pending, a refused image registers nothing, environment defaults are
 * KEY=value rows sent as the API's JSON map (and cleared after a definite
 * refusal), a version prefilled from another version's size, and pool-member
 * registration by exact fingerprint.
 */

const FP = `sha256:${"ab".repeat(32)}`;

const server = vi.hoisted(() => ({
  hosts: [] as Record<string, unknown>[],
  calls: [] as { procedure: string; input: unknown }[],
  createError: null as unknown,
  createGate: null as Promise<void> | null,
  hostsGate: null as Promise<void> | null,
  template: null as Record<string, unknown> | null,
  revision: null as Record<string, unknown> | null,
  templateError: null as unknown,
}));

const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to?: string }) => (
    <a className={className} href="#link" data-to={to}>
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
  const infinite = (procedure: string, rows: () => unknown[]) => (options: InfiniteOptions) => ({
    queryKey: [procedure, "infinite", options.input(undefined)],
    initialPageParam: options.initialPageParam,
    getNextPageParam: options.getNextPageParam,
    queryFn: async () => {
      record(procedure, options.input(undefined));
      if (procedure === "listHosts" && server.hostsGate) await server.hostsGate;
      return { items: structuredClone(rows()), nextCursor: null };
    },
  });
  const single = (procedure: string, row: () => unknown) => ({
    queryOptions: ({ input }: { input: unknown }) => ({
      queryKey: [procedure, input],
      queryFn: async () => {
        record(procedure, input);
        if (procedure === "getTemplate" && server.templateError) throw server.templateError;
        const value = row();
        if (!value) throw Object.assign(new Error("not found"), { code: "NOT_FOUND" });
        return structuredClone(value);
      },
    }),
  });
  return {
    orpc: {
      settings: { getAll: { key: () => ["settings", "getAll"] } },
      sandboxHosts: { listHosts: { infiniteOptions: infinite("listHosts", () => server.hosts) } },
      sandboxPools: {
        listUsable: {
          infiniteOptions: infinite("listUsablePools", () => [
            { id: "pool-a", slug: "shared", label: "Shared pool" },
          ]),
        },
        listUsableMembers: {
          infiniteOptions: infinite("listUsableMembers", () => [
            { id: "member-a", poolId: "pool-a" },
          ]),
        },
      },
      sandboxTemplates: {
        listTemplates: { key: () => ["listTemplates"] },
        listRevisions: { key: () => ["listRevisions"] },
        listAvailability: { key: () => ["listAvailability"] },
        listRevisionChoices: { key: () => ["listRevisionChoices"] },
        getTemplate: single("getTemplate", () => server.template),
        getTemplateRevision: single("getTemplateRevision", () => server.revision),
        createTemplate: {
          call: async (input: Record<string, unknown>) => {
            record("createTemplate", input);
            if (server.createGate) await server.createGate;
            const error = server.createError;
            server.createError = null;
            if (error) throw error;
            return { id: "tpl-new", slug: input.slug, label: input.label, firstRevisionId: "r" };
          },
        },
        appendRevision: {
          call: async (input: Record<string, unknown>) => {
            record("appendRevision", input);
            return { id: "appended", ...input, revision: 2 };
          },
        },
      },
    },
  };
});

import { RegisterTemplatePage } from "./register-template-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "templates", "hosts"],
    defaultNS: "common",
    resources: {
      "en-US": { common: enCommon, templates: enTemplates, hosts: enHosts },
      "es-MX": { common: esCommon, templates: esTemplates, hosts: esHosts },
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

let client: QueryClient;
async function mount(props: { templateId?: string; fromRevisionId?: string } = {}, lang = "en-US") {
  await i18n.changeLanguage(lang);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <RegisterTemplatePage lang={lang} {...props} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await screen.findByRole("form");
  return view;
}

const calls = (procedure: string) => server.calls.filter((call) => call.procedure === procedure);
const page = () => within(screen.getByRole("form"));

beforeEach(() => {
  server.hosts = [
    freshHost(),
    freshHost({ id: "host-b", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
    freshHost({ id: "host-x", slug: "gone", label: "Gone", deletionRequestedAt: new Date() }),
  ];
  server.calls = [];
  server.createError = null;
  server.createGate = null;
  server.hostsGate = null;
  server.template = null;
  server.revision = null;
  server.templateError = null;
  navigate.mockReset();
  toast.success.mockReset();
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

async function fillValid(user: ReturnType<typeof userEvent.setup>) {
  await waitFor(() => expect(page().getByLabelText(enTemplates.form.host)).toBeTruthy());
  await selectOption(user, page().getByLabelText(enTemplates.form.host), /^Alpha \(alpha\)/);
  await user.type(page().getByLabelText(enTemplates.form.label), "Ubuntu dev");
  await user.type(page().getByLabelText(enTemplates.form.imageRef), "local:ubuntu-dev");
}

const submit = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(page().getByRole("button", { name: enTemplates.register.submit }));

/** Environment rows through the KeyValueEditor's .env text mode. */
function typeEnv(label: string, text: string, textMode = enCommon.forms.keyValue.textMode) {
  const editor = screen.getByRole("group", { name: label });
  fireEvent.click(within(editor).getByRole("button", { name: textMode }));
  fireEvent.change(screen.getByRole("textbox", { name: label }), { target: { value: text } });
}

describe("register an existing image", () => {
  it("puts the essentials first and the expert fields in collapsed sections with summaries", async () => {
    await mount();
    const sections = [...document.querySelectorAll<HTMLDetailsElement>("[data-advanced]")];
    expect(sections.map((node) => node.getAttribute("data-advanced"))).toEqual([
      "size",
      "env",
      "guest",
      "details",
    ]);
    expect(sections.every((node) => !node.open)).toBe(true);
    const summary = (name: string) =>
      document.querySelector(`[data-advanced="${name}"] [data-slot="advanced-section-summary"]`)
        ?.textContent;
    expect(summary("size")).toBe("1 vCPU · 1024 MiB · 32 GiB disk");
    expect(summary("env")).toBe(enTemplates.registerPage.summary.envNone);
    expect(summary("guest")).toBe("uid 1000 · gid 1000 · /home/user · /bin/bash");
    expect(screen.queryByText(/JSON/)).toBeNull();
    // The old dialog's "Default environment (JSON)" textarea is gone.
    expect(screen.queryByRole("textbox", { name: /environment/i })).toBeNull();
  });

  it("derives the slug from the name until it is edited", async () => {
    const user = userEvent.setup();
    await mount();
    await user.type(page().getByLabelText(enTemplates.form.label), "Ubuntu Dev 26");
    const slug = page().getByLabelText(enTemplates.form.slug) as HTMLInputElement;
    expect(slug.value).toBe("ubuntu-dev-26");
    await user.clear(slug);
    await user.type(slug, "mine");
    await user.type(page().getByLabelText(enTemplates.form.label), "!");
    expect(slug.value).toBe("mine");
  });

  it("refuses an invalid draft inline, focuses the first invalid field, and asks no host", async () => {
    const user = userEvent.setup();
    await mount();
    await waitFor(() => expect(page().getByLabelText(enTemplates.form.host)).toBeTruthy());
    const uid = page().getByLabelText(enTemplates.form.guestUid);
    await user.clear(uid);
    await user.type(uid, "0");
    await user.type(page().getByLabelText(enTemplates.form.imageRef), `sha256:${"a".repeat(64)}`);
    await submit(user);
    expect((await page().findByText(enTemplates.draft.noHost)).getAttribute("role")).toBe("alert");
    const host = page().getByLabelText(enTemplates.form.host);
    expect(host.getAttribute("aria-invalid")).toBe("true");
    expect(document.activeElement).toBe(host);
    const image = page().getByLabelText(enTemplates.form.imageRef);
    expect(image.getAttribute("aria-invalid")).toBe("true");
    expect(page().getByText(enTemplates.draft.imageRef)).toBeTruthy();
    expect(page().getByLabelText(enTemplates.form.label).getAttribute("aria-invalid")).toBe("true");
    // An invalid field in a closed section opens it when it is the first one.
    expect(uid.getAttribute("aria-invalid")).toBe("true");
    expect(page().getByText(enTemplates.draft.guestUid)).toBeTruthy();
    // An offline host is refused before the request too.
    await selectOption(user, page().getByLabelText(enTemplates.form.host), /^Beta \(beta\)/);
    expect(await page().findByText(enTemplates.draft.hostUnavailable)).toBeTruthy();
    expect(calls("createTemplate")).toHaveLength(0);
  });

  it("opens a closed section to focus the first invalid field in it", async () => {
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    const uid = page().getByLabelText(enTemplates.form.guestUid);
    fireEvent.change(uid, { target: { value: "0" } });
    await submit(user);
    await waitFor(() => expect(document.activeElement).toBe(uid));
    expect(document.querySelector<HTMLDetailsElement>('[data-advanced="guest"]')?.open).toBe(true);
    expect(calls("createTemplate")).toHaveLength(0);
  });

  it("a form left open past the stale window still registers on a host that kept heartbeating", async () => {
    server.hosts[0]!.lastHeartbeatAt = new Date(Date.now() - 40_000);
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    server.hosts[0]!.lastHeartbeatAt = new Date();
    await submit(user);
    await waitFor(() => expect(calls("createTemplate")).toHaveLength(1));
    expect(calls("createTemplate")[0]?.input).toMatchObject({ hostId: "host-a" });
  });

  it("cancelling while the host is re-checked registers nothing afterwards", async () => {
    server.hosts[0]!.lastHeartbeatAt = new Date(Date.now() - 40_000);
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    let release!: () => void;
    server.hostsGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    server.hosts[0]!.lastHeartbeatAt = new Date();
    const before = calls("listHosts").length;
    await submit(user);
    await waitFor(() => expect(calls("listHosts").length).toBeGreaterThan(before));
    await user.click(page().getByRole("button", { name: enCommon.actions.cancel }));
    expect(navigate).toHaveBeenCalledWith({
      to: "/$lang/dashboard/templates",
      params: { lang: "en-US" },
    });
    await act(async () => {
      release();
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(calls("createTemplate")).toEqual([]);
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("says what will happen, shows the check pending, then the next steps", async () => {
    let release!: () => void;
    server.createGate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    await mount();
    expect(screen.getByText(enTemplates.registerPage.status)).toBeTruthy();
    await fillValid(user);
    expect(
      screen.getByText(enTemplates.registerPage.statusHost.replace("{{host}}", "Alpha")),
    ).toBeTruthy();
    await submit(user);
    const pending = await waitFor(() => {
      const node = document.querySelector<HTMLElement>('[data-image-check="pending"]');
      expect(node).not.toBeNull();
      return node!;
    });
    expect(pending.textContent).toBe("Checking the image on Alpha…");
    expect(page().getByRole("button", { name: enTemplates.register.pending })).toHaveProperty(
      "disabled",
      true,
    );
    release();
    const result = await screen.findByRole("region", { name: enTemplates.register.resultLabel });
    expect(result.textContent).toContain("ubuntu-dev v1");
    expect(
      within(result).getByText(enTemplates.registerPage.openTemplates).getAttribute("data-to"),
    ).toBe("/$lang/dashboard/templates");
    expect(within(result).getByText(enTemplates.registerPage.startSandbox)).toBeTruthy();
    expect(calls("createTemplate")[0]?.input).toEqual({
      cpuCount: 1,
      memoryMiB: 1024,
      defaultDiskGiB: 32,
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
  });

  it("an image the host refuses registers nothing, explains why, and can be retried", async () => {
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    server.createError = Object.assign(new Error("image alias `ubuntu-dev` not found"), {
      code: "BAD_REQUEST",
      data: { code: "sandbox.template_image_rejected" },
    });
    await submit(user);
    const failed = await waitFor(() => {
      const node = document.querySelector<HTMLElement>('[data-image-check="failed"]');
      expect(node).not.toBeNull();
      return node!;
    });
    expect(failed.textContent).toContain(enTemplates.problem.imageRejected);
    expect(failed.textContent).not.toContain("image alias `ubuntu-dev` not found");
    expect(screen.queryByRole("region", { name: enTemplates.register.resultLabel })).toBeNull();
    await submit(user);
    expect(
      await screen.findByRole("region", { name: enTemplates.register.resultLabel }),
    ).toBeTruthy();
    expect(calls("createTemplate")).toHaveLength(2);
  });

  it("a host that cannot answer is explained and the host list reloaded", async () => {
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    const before = calls("listHosts").length;
    server.createError = Object.assign(new Error("Host could not verify the image."), {
      code: "CONFLICT",
      data: { code: "sandbox.host_unavailable" },
    });
    await submit(user);
    expect(await screen.findByText(enTemplates.problem.hostUnavailable)).toBeTruthy();
    await waitFor(() => expect(calls("listHosts").length).toBeGreaterThan(before));
  });

  it("a forced-2FA refusal redirects to Security settings", async () => {
    const user = userEvent.setup();
    await mount();
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
    expect(document.querySelector('[data-image-check="failed"]')).toBeNull();
  });

  it("sends KEY=value environment rows as the API's JSON map and flags reserved names", async () => {
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    typeEnv(enTemplates.registerPage.envLabel, "HOME=/root\nAPP_MODE=dev");
    expect(
      await screen.findByText(
        enCommon.forms.keyValue.errors.reservedKey.replace("{{key}}", "HOME"),
      ),
    ).toBeTruthy();
    await submit(user);
    expect(calls("createTemplate")).toHaveLength(0);
    typeEnv(enTemplates.registerPage.envLabel, "APP_MODE=dev\nGREETING=hello world");
    await submit(user);
    await waitFor(() => expect(calls("createTemplate")).toHaveLength(1));
    expect(calls("createTemplate")[0]?.input).toMatchObject({
      envs: { APP_MODE: "dev", GREETING: "hello world" },
    });
  });

  it("refuses .env text with a line that is not KEY=value instead of dropping it", async () => {
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    typeEnv(enTemplates.registerPage.envLabel, "FOO=bar\nREQUIRED_SECRET");
    await submit(user);
    expect(calls("createTemplate")).toHaveLength(0);
    const text = screen.getByRole("textbox", { name: enTemplates.registerPage.envLabel });
    expect(
      screen.getByText(
        enCommon.forms.keyValue.errors.line
          .replace("{{line}}", "2")
          .replace("{{reason}}", enCommon.forms.keyValue.errors.lineReasons["missing-equals"]),
      ),
    ).toBeTruthy();
    expect(document.activeElement).toBe(text);
    fireEvent.change(text, { target: { value: "FOO=bar\nREQUIRED_SECRET=s3" } });
    await submit(user);
    await waitFor(() => expect(calls("createTemplate")).toHaveLength(1));
    expect(calls("createTemplate")[0]?.input).toMatchObject({
      envs: { FOO: "bar", REQUIRED_SECRET: "s3" },
    });
  });

  it.each(["en-US", "es-MX"])(
    "%s bounds private environment defaults and clears them after a definite refusal",
    async (lang) => {
      const copy = lang === "en-US" ? enTemplates : esTemplates;
      const textMode = (lang === "en-US" ? enCommon : esCommon).forms.keyValue.textMode;
      const user = userEvent.setup();
      await mount({}, lang);
      await waitFor(() => expect(page().getByLabelText(copy.form.host)).toBeTruthy());
      await selectOption(user, page().getByLabelText(copy.form.host), /^Alpha \(alpha\)/);
      await user.type(page().getByLabelText(copy.form.label), "Image");
      await user.type(page().getByLabelText(copy.form.imageRef), "local:image");
      typeEnv(copy.registerPage.envLabel, `APP=${"x".repeat(4097)}`, textMode);
      await user.click(page().getByRole("button", { name: copy.register.submit }));
      expect(await page().findByText(copy.draft.envs)).toBeTruthy();
      expect(calls("createTemplate")).toHaveLength(0);
      const sentinel = "synthetic-template-private-env";
      typeEnv(copy.registerPage.envLabel, `APP=${sentinel}`, textMode);
      server.createError = Object.assign(new Error(sentinel), {
        code: "BAD_REQUEST",
        data: { code: "sandbox.template_image_rejected" },
      });
      const storage = vi.spyOn(Storage.prototype, "setItem");
      await user.click(page().getByRole("button", { name: copy.register.submit }));
      await screen.findByText(copy.problem.imageRejected);
      // The definite refusal clears the private values from the form and the mutation.
      expect(document.body.textContent).not.toContain(sentinel);
      expect(
        [...document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea")]
          .map((node) => node.value)
          .join(" "),
      ).not.toContain(sentinel);
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
      expect(JSON.stringify(storage.mock.calls)).not.toContain(sentinel);
      expect(JSON.stringify(toast.success.mock.calls)).not.toContain(sentinel);
    },
  );

  it("adds a version with another version's size prefilled, without changing the source", async () => {
    server.template = { id: "tpl-a", slug: "ubuntu", label: "Ubuntu", archivedAt: null };
    server.revision = {
      id: "rev-1",
      templateId: "tpl-a",
      cpuCount: 2,
      memoryMiB: 2048,
      defaultDiskGiB: 48,
      minDiskGiB: 12,
    };
    const user = userEvent.setup();
    await mount({ templateId: "tpl-a", fromRevisionId: "rev-1" });
    expect(screen.getByRole("heading", { name: "Add a version to Ubuntu" })).toBeTruthy();
    expect(page().queryByLabelText(enTemplates.form.label)).toBeNull();
    expect(page().queryByLabelText(enTemplates.form.slug)).toBeNull();
    const cpu = page().getByLabelText(enTemplates.form.cpuCount) as HTMLInputElement;
    const memory = page().getByLabelText(enTemplates.form.memoryMiB) as HTMLInputElement;
    const disk = page().getByLabelText(enTemplates.form.defaultDiskGiB) as HTMLInputElement;
    const minDisk = page().getByLabelText(enTemplates.form.minDiskGiB) as HTMLInputElement;
    expect([cpu.value, memory.value, disk.value, minDisk.value]).toEqual(["2", "2048", "48", "12"]);
    expect(cpu.getAttribute("inputmode")).toBe("numeric");
    expect(cpu.getAttribute("min")).toBe("1");
    expect(cpu.getAttribute("max")).toBe("32");
    expect(memory.getAttribute("step")).toBe("256");
    await user.clear(disk);
    await user.type(disk, "64");
    await user.clear(memory);
    await user.type(memory, "3072");
    await waitFor(() => expect(page().getByLabelText(enTemplates.form.host)).toBeTruthy());
    await selectOption(user, page().getByLabelText(enTemplates.form.host), /^Alpha \(alpha\)/);
    await user.type(page().getByLabelText(enTemplates.form.imageRef), "local:ubuntu-dev");
    await submit(user);
    await waitFor(() => expect(calls("appendRevision")).toHaveLength(1));
    expect(calls("appendRevision")[0]?.input).toMatchObject({
      templateId: "tpl-a",
      cpuCount: 2,
      memoryMiB: 3072,
      defaultDiskGiB: 64,
      minDiskGiB: 12,
    });
    expect(server.revision).toMatchObject({ memoryMiB: 2048, defaultDiskGiB: 48 });
    expect(calls("createTemplate")).toHaveLength(0);
  });

  it("pool registration labels, helps and validates an exact fingerprint instead of an alias", async () => {
    const user = userEvent.setup();
    await mount();
    await fillValid(user);
    await user.click(page().getByRole("button", { name: enTemplates.registerPage.wherePool }));
    expect(page().queryByLabelText(enTemplates.form.imageRef)).toBeNull();
    const image = page().getByLabelText(enTemplates.form.poolImageRef);
    expect(page().getByText(enTemplates.form.poolImageRefHint)).toBeTruthy();
    await submit(user);
    expect(await page().findByText(enTemplates.draft.noPoolMember)).toBeTruthy();
    expect(page().queryByText(enTemplates.draft.noHost)).toBeNull();
    expect(page().queryByText(enTemplates.draft.imageRef)).toBeNull();
    await selectOption(user, page().getByLabelText(enHosts.sharing.choosePool), /Shared pool/);
    await selectOption(
      user,
      page().getByLabelText(enHosts.sharing.chooseMember),
      enHosts.sharing.memberOption.replace("{{n}}", "1"),
    );
    await submit(user);
    expect(await page().findAllByText(enTemplates.draft.poolImageRef)).not.toHaveLength(0);
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

  it("a failed template refetch keeps the version form and its draft, with a retry", async () => {
    server.template = { id: "tpl-a", slug: "ubuntu", label: "Ubuntu", archivedAt: null };
    const user = userEvent.setup();
    await mount({ templateId: "tpl-a" });
    await user.type(page().getByLabelText(enTemplates.form.imageRef), "local:ubuntu-dev");
    server.templateError = new Error("network down");
    await client.refetchQueries({ queryKey: ["getTemplate"] });
    expect(await screen.findByText(enTemplates.registerPage.templateFailed)).toBeTruthy();
    expect((page().getByLabelText(enTemplates.form.imageRef) as HTMLInputElement).value).toBe(
      "local:ubuntu-dev",
    );
  });

  it("a template refetch that says not found hides the version form", async () => {
    server.template = { id: "tpl-a", slug: "ubuntu", label: "Ubuntu", archivedAt: null };
    await mount({ templateId: "tpl-a" });
    server.template = null;
    await client.refetchQueries({ queryKey: ["getTemplate"] });
    expect(await screen.findByText(enTemplates.registerPage.templateFailed)).toBeTruthy();
    expect(screen.queryByRole("form")).toBeNull();
  });
});
