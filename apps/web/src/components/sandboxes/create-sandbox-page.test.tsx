import { openSelect, selectChoices, selectOption } from "@/test/select-option";

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
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
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
} from "@/test/sandbox-fake";

/**
 * The Create sandbox page against a scripted fake server (real TanStack
 * Query, Form and i18n). Every behaviour of the dialog it replaced is kept:
 * one request per intent (a lost response replays the first key and input),
 * definite refusals release the intent and keep the typed environment in
 * the open form only (owner decision 2026-11-26), quoted pool grace, guest sudo, egress, capacity
 * wait and revision pinning. New: safe defaults (the only pool preselected,
 * one hour then stop), inline name rules that never rewrite what was typed,
 * KEY=value environment rows, and size sliders capped by the placement.
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
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: Record<string, string>;
  }) => (
    <a
      className={className}
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

import { CreateSandboxPage } from "./create-sandbox-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 30_000 });

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

let client: QueryClient;
async function mount(lang = "en-US", initialHostId?: string) {
  await i18n.changeLanguage(lang);
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <CreateSandboxPage lang={lang} initialHostId={initialHostId} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

type User = ReturnType<typeof userEvent.setup>;
const calls = (procedure: string) =>
  server.current.calls.filter((call) => call.procedure === procedure);
const page = () => document.querySelector<HTMLFormElement>('form[data-slot="form-page"]')!;
const form = () => within(page());
/** The fields (without the sticky action bar, which repeats a refusal). */
const body = () => within(page().querySelector<HTMLElement>('[data-slot="form-page-body"]')!);
/** The action bar's echo of a refusal shown at a field. */
const summary = () => page().querySelector<HTMLElement>("[data-create-summary]");
const created = (index = 0) => calls("createSandbox")[index]?.input as Record<string, unknown>;

/** Open an Advanced section (a closed `<details>`) by its data name. */
async function openSection(user: User, name: string) {
  const details = page().querySelector<HTMLDetailsElement>(`details[data-section="${name}"]`)!;
  if (!details.open) await user.click(details.querySelector("summary")!);
  return within(details);
}

/** Mount and wait until the template and placement pickers have loaded. */
async function openCreate(user: User, lang = "en-US") {
  await mount(lang);
  const copy = lang === "en-US" ? enSandboxes : esSandboxes;
  await waitFor(() =>
    expect(
      (form().getByRole("combobox", { name: copy.create.template }) as HTMLButtonElement).disabled,
    ).toBe(false),
  );
  void user;
}

async function pickHost(user: User, name: RegExp = /^Alpha · /) {
  if (!page().querySelector("[data-host-fields]"))
    await user.click(form().getByRole("button", { name: enSandboxes.create.placementHost }));
  await selectOption(
    user,
    await form().findByRole("combobox", { name: enSandboxes.create.host }),
    name,
  );
}

async function pickTemplate(user: User, label = /^Ubuntu \(ubuntu\)$/) {
  await selectOption(
    user,
    form().getByRole("combobox", { name: enSandboxes.create.template }),
    label,
  );
}

async function chooseRevision(user: User, revisionId: string) {
  const template = server.current.templates.find((row) => row.id === revisionId)!;
  await pickTemplate(user, new RegExp(`^${template.label} \\(${template.slug}\\)$`));
  const version = await openSection(user, "version");
  await selectOption(
    user,
    await version.findByRole("combobox", { name: enSandboxes.create.revision }),
    new RegExp(`^Revision ${template.revision} · `),
  );
}

/** A size field's typed input ("vCPUs", "Memory" …); the slider shares its label. */
const sizeInput = (
  scope: ReturnType<typeof within>,
  label: string,
  inputLabel: string = enCommon.forms.range.inputLabel,
) => scope.getByRole("textbox", { name: `${label} ${inputLabel}` }) as HTMLInputElement;
/** Type a size and leave the field, which commits it. */
async function typeSize(user: User, input: HTMLInputElement, text: string) {
  await user.clear(input);
  await user.type(input, text);
  await user.tab();
}
/** Put vCPU above the pool's cap: chosen while waiting for room, then the wait is dropped. */
async function cpuAbovePoolCap(user: User, cpu: string) {
  const wait = await openSection(user, "wait");
  await selectOption(
    user,
    wait.getByLabelText(enSandboxes.create.capacityWait),
    enSandboxes.create.wait["1h"],
  );
  const size = await openSection(user, "size");
  await typeSize(user, sizeInput(size, "vCPUs"), cpu);
  await selectOption(
    user,
    wait.getByLabelText(enSandboxes.create.capacityWait),
    enSandboxes.create.wait.none,
  );
  return size;
}

const submit = (user: User) =>
  user.click(form().getByRole("button", { name: enSandboxes.create.submit }));

/** Fill the environment rows as KEY / value pairs. */
async function typeEnv(user: User, key: string, value: string) {
  const envs = await openSection(user, "envs");
  await user.click(envs.getByRole("button", { name: enSandboxes.create.envAdd }));
  const keys = envs.getAllByRole("textbox", { name: /^Key, row \d+$/ });
  await user.type(keys[keys.length - 1]!, key);
  const values = envs.getAllByLabelText(/^Value(, row \d+| for .+)$/);
  await user.click(values[values.length - 1]!);
  await user.paste(value);
}
/** The env editor's text inputs (an empty editor shows one blank row). */
const envValues = () =>
  [
    ...page().querySelectorAll<HTMLInputElement>('[data-section="envs"] input:not([type="file"])'),
  ].map((input) => input.value);

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

describe("defaults and layout", () => {
  it("one usable pool is the default placement and is preselected; lifetime is one hour then stop", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    const user = userEvent.setup();
    await openCreate(user);
    const pool = await form().findByRole("combobox", { name: enSandboxes.create.pool });
    await waitFor(() => expect(pool.textContent).toContain(`Lab · ${enHosts.sharing.owned}`));
    expect(
      form()
        .getByRole("button", { name: enSandboxes.create.placementPool })
        .getAttribute("aria-pressed"),
    ).toBe("true");
    expect(form().getByLabelText(enSandboxes.lifetime.field).textContent).toContain("1 hour");
    expect(
      form()
        .getByRole("radio", { name: enSandboxes.lifetime.stopOption })
        .getAttribute("aria-checked"),
    ).toBe("true");
    expect(page().querySelector("[data-create-status]")?.textContent).toBe(
      "Pool Lab · template size · stops after 1 hour",
    );
    await pickTemplate(user);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({
      poolId: "pool-1",
      template: "template/logical-1",
      timeoutMs: 3_600_000,
      lifecycle: { onTimeout: "stop" },
    });
    expect(created()).not.toHaveProperty("sandboxHostId");
  });

  it("a submit while pools load doesn't freeze Pool: no pools still falls back to the only host", async () => {
    server.current.pools = [];
    server.current.hosts = [fakeHost()];
    let release = () => {};
    server.current.gates.listPools = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    await mount();
    await submit(user);
    expect(calls("createSandbox")).toHaveLength(0);
    release();
    await waitFor(() =>
      expect(
        form()
          .getByRole("button", { name: enSandboxes.create.placementHost })
          .getAttribute("aria-pressed"),
      ).toBe("true"),
    );
    await pickTemplate(user);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ sandboxHostId: "host-1" });
  });

  it("while the pickers load, Template and Where it runs draw their loaded controls, disabled", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    let release = () => {};
    const loaded = new Promise<void>((resolve) => {
      release = resolve;
    });
    for (const procedure of ["listTemplates", "listPools", "listHosts"])
      server.current.gates[procedure] = loaded;
    await mount();
    /** The shape of both sections: their controls, and no skeleton standing in for one. */
    const shape = () => {
      const template = form().getByRole("combobox", { name: enSandboxes.create.template });
      const pool = form().getByRole("combobox", { name: enSandboxes.create.pool });
      const sections = [template.closest("fieldset")!, pool.closest("fieldset")!];
      return {
        skeletons: sections.flatMap((section) => [
          ...section.querySelectorAll('[data-slot="skeleton"]'),
        ]).length,
        placementPool: form()
          .getByRole("button", { name: enSandboxes.create.placementPool })
          .getAttribute("aria-pressed"),
        trustLine: page().querySelector("[data-pool-trust-line]") !== null,
        disabled: [(template as HTMLButtonElement).disabled, (pool as HTMLButtonElement).disabled],
      };
    };
    const loading = shape();
    expect(loading).toEqual({
      skeletons: 0,
      placementPool: "true",
      trustLine: true,
      disabled: [true, true],
    });
    release();
    await waitFor(() =>
      expect(
        (form().getByRole("combobox", { name: enSandboxes.create.pool }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    await waitFor(() =>
      expect(
        (form().getByRole("combobox", { name: enSandboxes.create.template }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    expect(shape()).toEqual({ ...loading, disabled: [false, false] });
  });

  it("without pools the placement is Host, and the only usable host is preselected", async () => {
    server.current.hosts = [
      fakeHost(),
      fakeHost({ id: "host-3", slug: "rack", label: "Draining rack", draining: true }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    expect(
      form()
        .getByRole("button", { name: enSandboxes.create.placementHost })
        .getAttribute("aria-pressed"),
    ).toBe("true");
    await waitFor(() =>
      expect(form().getByRole("combobox", { name: enSandboxes.create.host }).textContent).toContain(
        "Alpha · Available",
      ),
    );
    await pickTemplate(user);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ sandboxHostId: "host-1" });
  });

  it("?host= starts on that host even when a pool is usable", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.hosts = [fakeHost(), fakeHost({ id: "host-2", slug: "beta", label: "Beta" })];
    const user = userEvent.setup();
    await mount("en-US", "host-2");
    await waitFor(() =>
      expect(form().getByRole("combobox", { name: enSandboxes.create.host }).textContent).toContain(
        "Beta",
      ),
    );
    expect(
      form()
        .getByRole("button", { name: enSandboxes.create.placementHost })
        .getAttribute("aria-pressed"),
    ).toBe("true");
    await pickTemplate(user);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ sandboxHostId: "host-2" });
  });

  it("host and pool options read as a status: labels only, no slugs or raw ids", async () => {
    server.current.hosts = [
      fakeHost({ liveSandboxCount: 3 }),
      fakeHost({ id: "host-2", slug: "beta", label: "Beta", status: "DISCONNECTED" }),
      fakeHost({ id: "host-3", slug: "rack", label: "Draining rack", draining: true }),
      fakeHost({
        id: "host-4",
        slug: "bare",
        label: "Bare",
        storagePools: [],
      }),
    ];
    server.current.pools = [
      { id: "pool-raw-id", slug: "lab", label: "Lab" },
      { id: "pool-b", slug: "b", label: "Pool B", owner: { name: "Ada" } },
    ];
    const user = userEvent.setup();
    await openCreate(user);
    const pools = await selectChoices(
      user,
      await form().findByRole("combobox", { name: enSandboxes.create.pool }),
    );
    expect(pools.map((option) => option.textContent)).toEqual([
      enSandboxes.create.choosePool,
      `Lab · ${enHosts.sharing.owned}`,
      "Pool B · Ada",
    ]);
    // The trust copy is one line; the full notice and the grace sit under Learn more.
    expect(page().querySelector("[data-pool-trust-line]")?.textContent).toBe(
      enSandboxes.create.poolTrustLine,
    );
    expect(page().querySelector<HTMLDetailsElement>("[data-pool-trust-more]")?.open).toBe(false);
    await user.click(form().getByRole("button", { name: enSandboxes.create.placementHost }));
    const hosts = await openSelect(
      user,
      await form().findByRole("combobox", { name: enSandboxes.create.host }),
    );
    expect(hosts.getAllByRole("option").map((option) => option.textContent)).toEqual([
      enSandboxes.create.chooseHost,
      "Alpha · Available",
      `Beta · ${enHosts.status.reconnecting}`,
      "Draining rack · Unavailable: draining",
      "Bare · Unavailable: no storage",
    ]);
    expect(
      hosts
        .getByRole("option", { name: "Draining rack · Unavailable: draining" })
        .getAttribute("aria-disabled"),
    ).toBe("true");
    expect(
      hosts
        .getByRole("option", { name: "Bare · Unavailable: no storage" })
        .getAttribute("aria-disabled"),
    ).toBe("true");
    expect(
      hosts.getByRole("option", { name: "Alpha · Available" }).getAttribute("aria-disabled"),
    ).not.toBe("true");
    expect(page().querySelector("[data-draining-hosts]")?.textContent).toBe(
      enSandboxes.create.drainingHosts,
    );
    expect(document.body.textContent).not.toContain("pool-raw-id");
  });

  it("advanced sections start collapsed and summarise their current values", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const summary = (name: string) =>
      page().querySelector(`details[data-section="${name}"] [data-slot="advanced-section-summary"]`)
        ?.textContent;
    for (const details of page().querySelectorAll("details[data-section]"))
      expect((details as HTMLDetailsElement).open).toBe(false);
    expect(summary("version")).toBe(enSandboxes.create.summary.latest);
    expect(summary("size")).toBe(enSandboxes.create.summary.templateDefault);
    expect(summary("envs")).toBe(enSandboxes.create.summary.none);
    expect(summary("network")).toBe(enSandboxes.create.summary.internet);
    expect(summary("access")).toBe(enSandboxes.create.summary.sudoOn);
    await typeEnv(user, "APP", "x");
    expect(summary("envs")).toBe("1 variable");
    // Capacity wait is a pool-only choice.
    expect(page().querySelector('details[data-section="wait"]')).toBeNull();
  });

  it("the back link and Cancel return to the Sandboxes list; buttons are touch-sized", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    expect(form().getByRole("link", { name: enSandboxes.create.back }).getAttribute("href")).toBe(
      "/en-US/dashboard/sandboxes",
    );
    expect(form().getByRole("link", { name: enCommon.actions.cancel }).getAttribute("href")).toBe(
      "/en-US/dashboard/sandboxes",
    );
    for (const button of form().getAllByRole("button"))
      expect(button.className).toMatch(/h-11|min-h-\[44px\]|min-h-11/);
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(enSandboxes.create.title);
  });
});

describe("creating a sandbox", () => {
  it("refuses an incomplete draft in the browser without a request and focuses the first invalid field", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await submit(user);
    const problems = [...page().querySelectorAll("[data-draft-problem]")].map(
      (item) => (item as HTMLElement).dataset.draftProblem,
    );
    expect(problems).toEqual(["noTemplate", "noHost"]);
    const template = form().getByRole("combobox", { name: enSandboxes.create.template });
    expect(template.getAttribute("aria-invalid")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(template));
    expect(form().getByText(enCommon.form.fixErrors)).toBeTruthy();
    // A label value without a key is a labels problem, shown in its (opened) section.
    const labels = await openSection(user, "labels");
    await user.click(labels.getByRole("button", { name: enSandboxes.create.labelsAdd }));
    await user.type(labels.getByLabelText("Value, row 1"), "oops");
    await submit(user);
    expect(page().querySelector('[data-draft-problem="labelsSyntax"]')).not.toBeNull();
    expect(calls("createSandbox")).toEqual([]);
  });

  it("selects template and revision independently of placement; create → the sandbox's page", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    expect(
      (
        await selectChoices(
          user,
          form().getByRole("combobox", { name: enSandboxes.create.template }),
        )
      ).some((option) => option.textContent?.includes("Debian")),
    ).toBe(true);
    await pickHost(user, /^Alpha · /);
    await chooseRevision(user, "tpl-1");
    await selectOption(user, form().getByLabelText(enSandboxes.lifetime.field), /^2 hours$/);
    await user.click(form().getByRole("radio", { name: enSandboxes.lifetime.destroyOption }));
    const labels = await openSection(user, "labels");
    await user.click(labels.getByRole("button", { name: enSandboxes.create.labelsAdd }));
    await user.type(labels.getByLabelText("Key, row 1"), "team");
    await user.type(labels.getByLabelText("Value for team"), "infra");
    await typeEnv(user, "APP", "synthetic-create-env");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created()).toMatchObject({
      template: "revision/tpl-1",
      sandboxHostId: "host-1",
      metadata: { team: "infra" },
      envs: { APP: "synthetic-create-env" },
      lifecycle: { onTimeout: "kill" },
      timeoutMs: 120 * 60_000,
    });
    expect(String(created().idempotencyKey)).toMatch(/^web\.create\.[0-9a-f-]{36}$/);
    expect(created()).not.toHaveProperty("leaseExpiresAt");
    expect(navigate).toHaveBeenCalledWith({
      to: "/$lang/dashboard/sandboxes/$sandboxId",
      params: { lang: "en-US", sandboxId: "sbx-new-1" },
    });
    expect(toast.success).toHaveBeenCalledWith(enSandboxes.create.done);
  });

  it("environment rows and .env text become the API's string map", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    const envs = await openSection(user, "envs");
    await user.click(envs.getByRole("button", { name: enCommon.forms.keyValue.textMode }));
    await user.click(envs.getByRole("textbox", { name: enSandboxes.create.envTitle }));
    await user.paste('# comment\nAPP=hello\nexport GREETING="hi there"\n');
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created().envs).toEqual({ APP: "hello", GREETING: "hi there" });
  });

  it(".env text with a line that is not KEY=value is refused, never sent without it", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    const envs = await openSection(user, "envs");
    await user.click(envs.getByRole("button", { name: enCommon.forms.keyValue.textMode }));
    const text = envs.getByRole("textbox", { name: enSandboxes.create.envTitle });
    await user.click(text);
    await user.paste("FOO=bar\nREQUIRED_SECRET");
    await submit(user);
    expect(calls("createSandbox")).toEqual([]);
    expect(page().querySelector('[data-draft-problem="envs"]')).not.toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(text));
    await user.type(text, "=s3");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created().envs).toEqual({ FOO: "bar", REQUIRED_SECRET: "s3" });
  });

  it("label .env text with an unreadable line is refused", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    const labels = await openSection(user, "labels");
    await user.click(labels.getByRole("button", { name: enCommon.forms.keyValue.textMode }));
    const text = labels.getByRole("textbox", { name: enSandboxes.create.labels });
    await user.click(text);
    await user.paste("team=a\nowner");
    await submit(user);
    expect(calls("createSandbox")).toEqual([]);
    expect(page().querySelector('[data-draft-problem="labelsSyntax"]')).not.toBeNull();
  });

  it("a label value with a newline stays one label", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    const labels = await openSection(user, "labels");
    await user.click(labels.getByRole("button", { name: enCommon.forms.keyValue.textMode }));
    await user.click(labels.getByRole("textbox", { name: enSandboxes.create.labels }));
    await user.paste('NOTE="first\\nTEAM=prod"');
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created().metadata).toEqual({ NOTE: "first\nTEAM=prod" });
  });

  it("a label key .env text can't carry (#team) keeps the editor in rows and is sent as typed", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    const labels = await openSection(user, "labels");
    const textMode = () => labels.queryByRole("button", { name: enCommon.forms.keyValue.textMode });
    expect(textMode()).not.toBeNull();
    const key = labels.getByRole("textbox", { name: /^Key, row 1$/ }) as HTMLInputElement;
    await user.type(key, "#team");
    await user.click(labels.getByLabelText(/^Value for #team$/));
    await user.paste("ops");
    // The text view would read `#team=ops` as a comment and drop it: refused,
    // with the reason, and the row stays as typed.
    expect(textMode()).toBeNull();
    expect(labels.getByText(enSandboxes.create.labelsTextUnavailable)).toBeTruthy();
    expect(key.value).toBe("#team");
    await user.type(labels.getByLabelText(/^Value for #team$/), "!");
    expect((labels.getByRole("textbox", { name: /^Key, row 1$/ }) as HTMLInputElement).value).toBe(
      "#team",
    );
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created().metadata).toEqual({ "#team": "ops!" });
    // A key text can carry offers the text view again.
    await user.clear(labels.getByRole("textbox", { name: /^Key, row 1$/ }));
    await user.type(labels.getByRole("textbox", { name: /^Key, row 1$/ }), "team");
    expect(textMode()).not.toBeNull();
    expect(labels.queryByText(enSandboxes.create.labelsTextUnavailable)).toBeNull();
  });

  it("reserved or invalid environment names are refused inline, never sent", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    await typeEnv(user, "HOME", "/tmp");
    expect(page().querySelector('[data-section="envs"]')?.textContent).toContain(
      enCommon.forms.keyValue.errors.reservedKey.replace("{{key}}", "HOME"),
    );
    await submit(user);
    expect(page().querySelector('[data-draft-problem="envs"]')).not.toBeNull();
    expect(calls("createSandbox")).toEqual([]);
  });

  it("a __proto__ environment or label key is refused inline, never dropped silently", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user);
    await typeEnv(user, "__proto__", "x");
    const reserved = enCommon.forms.keyValue.errors.reservedKey.replace("{{key}}", "__proto__");
    expect(page().querySelector('[data-section="envs"]')?.textContent).toContain(reserved);
    const labels = await openSection(user, "labels");
    await user.click(labels.getByRole("button", { name: enCommon.forms.keyValue.textMode }));
    await user.click(labels.getByRole("textbox", { name: enSandboxes.create.labels }));
    await user.paste("__proto__=y");
    expect(page().querySelector('[data-section="labels"]')?.textContent).toContain(reserved);
    await submit(user);
    expect(page().querySelector('[data-draft-problem="envs"]')).not.toBeNull();
    expect(page().querySelector('[data-draft-problem="labelsSyntax"]')).not.toBeNull();
    expect(calls("createSandbox")).toEqual([]);
  });

  it("a disconnected host explains fresh-launch admission; the server decides the request", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user, /^Beta · /);
    // Named with the Hosts page's own state for it.
    expect(page().querySelector("[data-host-waits]")?.textContent).toBe(
      enSandboxes.create.hostWaits.replace("{{state}}", enHosts.status.reconnecting),
    );
    await chooseRevision(user, "tpl-2");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
  });

  it("a double submit while pending sends one request", async () => {
    let release!: () => void;
    server.current.gates.createSandbox = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const button = form().getByRole("button", { name: enSandboxes.create.pending });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    await user.click(button);
    await act(async () => release());
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(calls("createSandbox")).toHaveLength(1);
    expect(server.current.sandboxes).toHaveLength(1);
  });

  it("a lost response is retried with the same key and input: one sandbox, not two", async () => {
    server.current.errors.createSandbox = [new Error("network")];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    expect((await form().findByRole("alert")).textContent).toBe(enSandboxes.problem.generic);
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const [first, second] = calls("createSandbox").map((call) => call.input);
    expect(second).toEqual(first);
    expect(server.current.sandboxes).toHaveLength(1);
  });

  it("a definite refusal is explained at its field and the next submit is a new request", async () => {
    server.current.errors.createSandbox = [coded("sandbox.host_capacity")];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const alert = await body().findByRole("alert");
    expect(alert.textContent).toBe(enSandboxes.problem.hostCapacity);
    // Shown in the placement section, next to the host it concerns, and
    // repeated in the action bar with a way back to it.
    expect(alert.closest("section")?.querySelector("[data-host-fields]")).not.toBeNull();
    expect(summary()?.getAttribute("role")).toBe("alert");
    expect(summary()?.textContent).toContain(enSandboxes.problem.hostCapacity);
    // Focus moved to the host picker it concerns.
    const host = form().getByRole("combobox", { name: enSandboxes.create.host });
    await waitFor(() => expect(document.activeElement).toBe(host));
    expect(server.current.sandboxes).toEqual([]);
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const keys = calls("createSandbox").map(
      (call) => (call.input as { idempotencyKey: string }).idempotencyKey,
    );
    expect(new Set(keys).size).toBe(2);
  });

  it("a host without egress enforcement gets actionable copy, not 'not valid' (E-07)", async () => {
    server.current.errors.createSandbox = [
      Object.assign(new Error("Unsupported capability: egress."), {
        code: "BAD_REQUEST",
        data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress" },
      }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const alert = await form().findByRole("alert");
    expect(alert.textContent).toBe(enSandboxes.problem.hostNoEgress);
    expect(alert.getAttribute("data-create-problem")).toBe("hostNoEgress");
    expect(server.current.sandboxes).toEqual([]);
  });

  it("internet access is on by default and sends open mode (default-open egress)", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const network = await openSection(user, "network");
    expect(
      network
        .getByRole("switch", { name: enSandboxes.create.internetAccess })
        .getAttribute("aria-checked"),
    ).toBe("true");
    expect(page().querySelector("[data-egress-hint]")?.textContent).toBe(
      enSandboxes.create.internetAccessOnHint,
    );
    // The collapsed fallback list says what it holds (never a bare "allow:").
    expect(page().querySelector("[data-egress-fallback] summary")?.textContent).toBe(
      `${enSandboxes.create.fallbackSummary}${enSandboxes.create.summary.none}`,
    );
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created().egress).toEqual({ mode: "open", domains: [], cidrs: [] });
    expect(server.current.sandboxes[0]?.egress).toEqual({ mode: "open", domains: [], cidrs: [] });
  });

  it("an optional name is checked inline and never changed silently; blank sends none", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const name = form().getByLabelText(enSandboxes.create.name) as HTMLInputElement;
    expect(name.getAttribute("autocomplete")).toBe("off");
    expect(name.hasAttribute("maxlength")).toBe(false);
    await user.type(name, "CI-Runner");
    // What was typed stays; the rule explains what to change.
    expect(name.value).toBe("CI-Runner");
    expect(name.getAttribute("aria-invalid")).toBe("true");
    expect(form().getByText(enSandboxes.draft.name)).toBeTruthy();
    await submit(user);
    expect(calls("createSandbox")).toEqual([]);
    await waitFor(() => expect(document.activeElement).toBe(name));
    await user.clear(name);
    await user.type(name, "ci-runner");
    expect(name.getAttribute("aria-invalid")).toBeNull();
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created().name).toBe("ci-runner");
  });

  it("a blank name sends none (the server generates one)", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).not.toHaveProperty("name");
  });

  it("an invalid name is a draft problem; a taken one is explained and the next submit is a new request", async () => {
    server.current.errors.createSandbox = [coded("sandbox.name_taken")];
    const user = userEvent.setup();
    await openCreate(user);
    await user.type(form().getByLabelText(enSandboxes.create.name), "wssp-x");
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    expect(form().getByText(enSandboxes.draft.name)).toBeTruthy();
    expect(calls("createSandbox")).toEqual([]);
    await user.clear(form().getByLabelText(enSandboxes.create.name));
    await user.type(form().getByLabelText(enSandboxes.create.name), "quiet-otter");
    await submit(user);
    await waitFor(() =>
      expect(page().querySelector("[data-create-problem]")?.textContent).toBe(
        enSandboxes.problem.nameTaken,
      ),
    );
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(2));
    const keys = calls("createSandbox").map(
      (call) => (call.input as { idempotencyKey: string }).idempotencyKey,
    );
    expect(new Set(keys).size).toBe(2);
  });

  it("guest root (sudo) is on by default and is always sent", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const access = await openSection(user, "access");
    const toggle = access.getByRole("switch", { name: enSandboxes.create.guestSudo });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    expect(page().querySelector("[data-guest-sudo-hint]")?.textContent).toBe(
      enSandboxes.create.guestSudoOnHint.replace(/<\/?code>/g, ""),
    );
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created().guestSudo).toBe(true);
  });

  it("guest root off on a tainted pinned revision warns that root may still be reachable", async () => {
    const user = userEvent.setup();
    const row = server.current.templates.find((candidate) => candidate.id === "tpl-1")!;
    Object.assign(row, { capturedWithGuestRoot: true });
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    expect(page().querySelector("[data-guest-root-tainted]")).toBeNull();
    const access = await openSection(user, "access");
    await user.click(access.getByRole("switch", { name: enSandboxes.create.guestSudo }));
    expect(page().querySelector("[data-guest-sudo-hint]")?.textContent).toBe(
      enSandboxes.create.guestSudoOffHint,
    );
    expect(page().querySelector("[data-guest-root-tainted]")?.textContent).toBe(
      enSandboxes.create.guestRootTainted,
    );
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created().guestSudo).toBe(false);
  });

  it("fallback grants ride along with open mode", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    await user.click(network.getByText(enSandboxes.create.fallbackSummary));
    await user.type(
      network.getByLabelText(enSandboxes.create.egressDomains),
      "registry.example.com",
    );
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created().egress).toEqual({
      mode: "open",
      domains: ["registry.example.com"],
      cidrs: [],
    });
  });

  it("internet access off sends the entries as the immutable allowlist (C37)", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    await user.click(network.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    expect(page().querySelector("[data-egress-fallback]")).toBeNull();
    expect(page().querySelector("[data-egress-hint]")?.textContent).toBe(
      enSandboxes.create.egressHint,
    );
    await user.type(
      network.getByLabelText(enSandboxes.create.egressDomains),
      "registry.example.com",
    );
    await user.type(network.getByLabelText(enSandboxes.create.egressCidrs), "128.66.0.0/24");
    expect(
      page().querySelector('details[data-section="network"] [data-slot="advanced-section-summary"]')
        ?.textContent,
    ).toBe("Allowlist: 2 entries");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const allowlist = {
      mode: "allowlist",
      domains: ["registry.example.com"],
      cidrs: ["128.66.0.0/24"],
    };
    expect(created().egress).toEqual(allowlist);
    expect(server.current.sandboxes[0]?.egress).toEqual(allowlist);
  });

  it("internet access off with no entries is an explicit deny-all", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    await user.click(network.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created().egress).toEqual({ mode: "allowlist", domains: [], cidrs: [] });
  });

  it.each([
    ["egress_guard_unavailable", "egressGuardUnavailable"],
    ["open_egress_not_permitted", "openEgressNotPermitted"],
  ] as const)("an egress refusal with reason %s is explained", async (reason, problem) => {
    server.current.errors.createSandbox = [
      Object.assign(new Error("egress refused"), {
        code: "BAD_REQUEST",
        data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress", reason },
      }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const alert = await form().findByRole("alert");
    expect(alert.getAttribute("data-create-problem")).toBe(problem);
    expect(alert.textContent).toBe(enSandboxes.problem[problem]);
    expect(server.current.sandboxes).toEqual([]);
  });

  it("an egress entry outside the schema bounds is a draft problem, never a request", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    await user.click(network.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    await user.click(network.getByLabelText(enSandboxes.create.egressDomains));
    // One entry over the catalog's 253-character domain bound.
    await user.paste(`${"a".repeat(254)}.example.com`);
    await submit(user);
    expect(page().querySelector('[data-draft-problem="egress"]')?.textContent).toBe(
      enSandboxes.draft.egress,
    );
    expect(calls("createSandbox")).toEqual([]);
  });

  it("a refused egress policy is explained in Network and the next submit is a new request", async () => {
    server.current.errors.createSandbox = [coded("sandbox.egress_policy_invalid")];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    await user.click(network.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    await user.type(network.getByLabelText(enSandboxes.create.egressCidrs), "10.0.0.0/8");
    await submit(user);
    const alert = await body().findByRole("alert");
    expect(alert.textContent).toBe(enSandboxes.problem.egress);
    expect(alert.closest('details[data-section="network"]')).not.toBeNull();
    expect(server.current.sandboxes).toEqual([]);
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const keys = calls("createSandbox").map(
      (call) => (call.input as { idempotencyKey: string }).idempotencyKey,
    );
    expect(new Set(keys).size).toBe(2);
  });
});

describe("size sliders", () => {
  it("untouched sliders inherit the template (nothing sent) and show its default", async () => {
    server.current.templates = [
      fakeTemplate({ cpuCount: 2, memoryMiB: 2048, defaultDiskGiB: 48, minDiskGiB: 8 }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    expect(sizeInput(size, "vCPUs").value).toBe("2 vCPU");
    expect(sizeInput(size, "Memory").value).toBe("2 GiB");
    expect(sizeInput(size, "Root disk").value).toBe("48 GiB");
    expect(size.getByText(/Default 48 GiB; at least 8 GiB/)).toBeTruthy();
    // The default is marked as coming from the pinned version.
    expect(
      size.getAllByText(
        enCommon.forms.range.defaultFrom.replace(
          "{{source}}",
          enSandboxes.create.sizeDefaultSource.replace("{{revision}}", "1"),
        ),
      ).length,
    ).toBe(3);
    expect(
      page().querySelector('details[data-section="size"] [data-slot="advanced-section-summary"]')
        ?.textContent,
    ).toBe(enSandboxes.create.summary.templateDefault);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    for (const field of ["cpuCount", "memoryMiB", "diskGiB"])
      expect(created()).not.toHaveProperty(field);
  });

  it.each(["en-US", "es-MX"])(
    "%s sends a typed partial override (memory in GiB, rounded to 256 MiB)",
    async (lang) => {
      server.current.templates = [fakeTemplate({ cpuCount: 2, memoryMiB: 2048 })];
      const copy = lang === "en-US" ? enSandboxes : esSandboxes;
      const user = userEvent.setup();
      await openCreate(user, lang);
      await selectOption(
        user,
        form().getByRole("combobox", { name: copy.create.template }),
        /^Ubuntu \(ubuntu\)/,
      );
      await user.click(form().getByRole("button", { name: copy.create.placementHost }));
      await selectOption(
        user,
        await form().findByRole("combobox", { name: copy.create.host }),
        /^Alpha · /,
      );
      const size = await openSection(user, "size");
      const inputLabel = (lang === "en-US" ? enCommon : esCommon).forms.range.inputLabel;
      const memory = sizeInput(size, copy.create.memory, inputLabel);
      await typeSize(user, memory, "3.1");
      // Shown in GiB, rounded to the 256 MiB step.
      expect(memory.value).toBe("3 GiB");
      await typeSize(user, sizeInput(size, copy.create.disk, inputLabel), "40");
      await user.click(form().getByRole("button", { name: copy.create.submit }));
      await waitFor(() => expect(navigate).toHaveBeenCalled());
      expect(created()).toMatchObject({ memoryMiB: 3072, diskGiB: 40 });
      expect(created()).not.toHaveProperty("cpuCount");
    },
  );

  it("a host caps the sliders at its free capacity and refuses more, with the reason", async () => {
    // Alpha: 4 vCPU per VM, 4096 MiB free (3584 after the VM overhead), 95 GiB disk free.
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    expect(size.getByText("This host has 4 vCPUs free.")).toBeTruthy();
    expect(size.getByText("This host has 3.5 GiB of memory free.")).toBeTruthy();
    expect(size.getByText("This host has 95 GiB of disk free.")).toBeTruthy();
    const cpu = sizeInput(size, "vCPUs");
    // More than the host has is kept as typed and refused, with the reason
    // and the cap one click away; it is never lowered silently.
    await typeSize(user, cpu, "8");
    expect(cpu.value).toBe("8 vCPU");
    expect(cpu.getAttribute("aria-invalid")).toBe("true");
    expect(size.getByRole("alert").textContent).toContain("This host has 4 vCPUs free");
    await submit(user);
    await waitFor(() => expect(document.activeElement).toBe(cpu));
    expect(calls("createSandbox")).toHaveLength(0);
    // A 44px target on phones (this app's small buttons are 28px otherwise).
    expect(size.getByRole("button", { name: "Use 4 vCPU" }).className).toMatch(/\bh-11\b/);
    await user.click(size.getByRole("button", { name: "Use 4 vCPU" }));
    expect(cpu.value).toBe("4 vCPU");
    expect(cpu.getAttribute("aria-invalid")).toBeNull();
    expect(size.queryByRole("button", { name: "Use 4 vCPU" })).toBeNull();
    await typeSize(user, cpu, "3");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ cpuCount: 3 });
  });

  it("a pinned version's size above the host's free capacity blocks the create, typed or untouched", async () => {
    // The pinned revision asks for 8 vCPUs; Alpha has 4 free.
    server.current.templates = [fakeTemplate({ cpuCount: 8 })];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    const cpu = sizeInput(size, "vCPUs");
    expect(cpu.value).toBe("8 vCPU");
    expect(size.getByRole("alert").textContent).toContain("This host has 4 vCPUs free");
    // Typing the default itself is "inherit": still the same 8, still blocked.
    await typeSize(user, cpu, "8");
    await submit(user);
    await waitFor(() => expect(document.activeElement).toBe(cpu));
    expect(calls("createSandbox")).toHaveLength(0);
    await user.click(size.getByRole("button", { name: "Use 4 vCPU" }));
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ cpuCount: 4 });
  });

  it("a pool caps the sliders at the largest size one host can take, read once per choice", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.poolLargest = { cpuCount: 6, memoryMiB: 8192, diskGiB: 100 };
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    await waitFor(() =>
      expect(
        size.getByText("The most any host in this pool can take now is 6 vCPUs."),
      ).toBeTruthy(),
    );
    const capacityReads = calls("poolCapacity");
    expect(capacityReads.at(-1)?.input).toEqual({ id: "pool-1", template: "revision/tpl-1" });
    const cpu = sizeInput(size, "vCPUs");
    await typeSize(user, cpu, "8");
    expect(cpu.value).toBe("8 vCPU");
    expect(size.getByRole("alert").textContent).toBe(
      "The most any host in this pool can take now is 6 vCPUs.",
    );
    await user.click(size.getByRole("button", { name: "Use 6 vCPU" }));
    expect(cpu.value).toBe("6 vCPU");
    await typeSize(user, sizeInput(size, "Memory"), "4");
    // Moving sizes never re-reads the budgeted capacity view.
    expect(calls("poolCapacity")).toHaveLength(capacityReads.length);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ poolId: "pool-1", cpuCount: 6, memoryMiB: 4096 });
  });

  it("Latest shows no template default: the latest tag may not be the newest revision", async () => {
    // Revision 2 is the newest listed, but `latest` may still name revision 1;
    // the list does not say which, so its size is no default and no host's
    // capacity refuses an untouched size.
    server.current.templates = [
      fakeTemplate({ cpuCount: 2, memoryMiB: 2048, defaultDiskGiB: 48, minDiskGiB: 8 }),
      fakeTemplate({
        id: "tpl-1b",
        revision: 2,
        cpuCount: 8,
        memoryMiB: 8192,
        defaultDiskGiB: 128,
        minDiskGiB: 8,
      }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickTemplate(user);
    // Alpha takes 4 vCPU per VM: revision 2's 8 would have ruled it out.
    await pickHost(user);
    const size = await openSection(user, "size");
    await waitFor(() => expect(size.getByText(enSandboxes.create.latestSizeHint)).toBeTruthy());
    // Untouched fields say they are not set; no default mark or Reset.
    expect(size.getAllByText(enSandboxes.create.sizeNotSet).length).toBe(3);
    expect(size.queryByText(/^Default/)).toBeNull();
    expect(size.queryByRole("button", { name: enCommon.forms.range.reset })).toBeNull();
    // A shown-only value never reads as over the host's cap.
    expect(sizeInput(size, "vCPUs").getAttribute("aria-invalid")).toBeNull();
    expect(
      page().querySelector('details[data-section="size"] [data-slot="advanced-section-summary"]')
        ?.textContent,
    ).toBe(enSandboxes.create.summary.templateDefault);
    expect(page().querySelector("[data-create-status]")?.textContent).toContain(
      enSandboxes.create.status.templateSize,
    );
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ template: "template/logical-1", sandboxHostId: "host-1" });
    for (const field of ["cpuCount", "memoryMiB", "diskGiB"])
      expect(created()).not.toHaveProperty(field);
  });

  it("with Latest, typing exactly the shown value is an override and is sent", async () => {
    server.current.templates = [fakeTemplate({ cpuCount: 8, memoryMiB: 2048 })];
    const user = userEvent.setup();
    await openCreate(user);
    await pickTemplate(user);
    await pickHost(user);
    const size = await openSection(user, "size");
    // Alpha has 4 vCPUs free: the untouched field shows 4 and sends nothing.
    const cpu = sizeInput(size, "vCPUs");
    await waitFor(() => expect(cpu.value).toBe("4 vCPU"));
    expect(size.getAllByText(enSandboxes.create.sizeNotSet).length).toBe(3);
    await typeSize(user, cpu, "4");
    expect(size.getAllByText(enSandboxes.create.sizeNotSet).length).toBe(2);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ cpuCount: 4 });
    expect(created()).not.toHaveProperty("memoryMiB");
  });

  it.each(["latest", "pinned"])(
    "Use template default puts %s overrides back to inherit (nothing sent)",
    async (mode) => {
      server.current.templates = [
        fakeTemplate({ cpuCount: 2, memoryMiB: 2048, defaultDiskGiB: 48, minDiskGiB: 8 }),
      ];
      const user = userEvent.setup();
      await openCreate(user);
      if (mode === "pinned") await chooseRevision(user, "tpl-1");
      else await pickTemplate(user);
      await pickHost(user);
      const size = await openSection(user, "size");
      const templateDefaultButton = () =>
        size.queryByRole("button", { name: enSandboxes.create.sizeUseTemplateDefault });
      // Nothing overridden: nothing to put back.
      expect(templateDefaultButton()).toBeNull();
      await typeSize(user, sizeInput(size, "vCPUs"), "3");
      await typeSize(user, sizeInput(size, "Memory"), "3");
      await user.click(templateDefaultButton()!);
      expect(templateDefaultButton()).toBeNull();
      expect(
        page().querySelector('details[data-section="size"] [data-slot="advanced-section-summary"]')
          ?.textContent,
      ).toBe(enSandboxes.create.summary.templateDefault);
      if (mode === "latest")
        expect(size.getAllByText(enSandboxes.create.sizeNotSet).length).toBe(3);
      else expect(sizeInput(size, "vCPUs").value).toBe("2 vCPU");
      await submit(user);
      await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
      for (const field of ["cpuCount", "memoryMiB", "diskGiB"])
        expect(created()).not.toHaveProperty(field);
    },
  );

  it("a pool cap that would refuse a submit is read again first, and a raised cap lets it through", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.poolLargest = { cpuCount: 6, memoryMiB: 8192, diskGiB: 100 };
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    await waitFor(() =>
      expect(
        size.getByText("The most any host in this pool can take now is 6 vCPUs."),
      ).toBeTruthy(),
    );
    const reads = calls("poolCapacity").length;
    await cpuAbovePoolCap(user, "8");
    expect(sizeInput(size, "vCPUs").getAttribute("aria-invalid")).toBe("true");
    // Still 6: one fresh read, then the refusal.
    await submit(user);
    await waitFor(() => expect(calls("poolCapacity")).toHaveLength(reads + 1));
    expect(calls("createSandbox")).toEqual([]);
    // A host freed up: the fresh read raises the cap and the create goes out.
    server.current.poolLargest = { cpuCount: 8, memoryMiB: 8192, diskGiB: 100 };
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(calls("poolCapacity")).toHaveLength(reads + 2);
    expect(created()).toMatchObject({ poolId: "pool-1", cpuCount: 8 });
  });

  it("leaving the page while the fresh pool capacity read is pending sends nothing", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.poolLargest = { cpuCount: 6, memoryMiB: 8192, diskGiB: 100 };
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    await waitFor(() =>
      expect(
        size.getByText("The most any host in this pool can take now is 6 vCPUs."),
      ).toBeTruthy(),
    );
    await cpuAbovePoolCap(user, "8");
    expect(sizeInput(size, "vCPUs").getAttribute("aria-invalid")).toBe("true");
    const reads = calls("poolCapacity").length;
    let release = () => {};
    server.current.gates.poolCapacity = new Promise<void>((resolve) => {
      release = resolve;
    });
    // The fresh read would raise the cap, but the person pressed Cancel first.
    server.current.poolLargest = { cpuCount: 8, memoryMiB: 8192, diskGiB: 100 };
    await submit(user);
    await waitFor(() => expect(calls("poolCapacity")).toHaveLength(reads + 1));
    cleanup();
    release();
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(calls("createSandbox")).toEqual([]);
  });

  it("when the fresh pool capacity read fails, the cached cap refuses nothing", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.poolLargest = { cpuCount: 6, memoryMiB: 8192, diskGiB: 100 };
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    await waitFor(() =>
      expect(
        size.getByText("The most any host in this pool can take now is 6 vCPUs."),
      ).toBeTruthy(),
    );
    await cpuAbovePoolCap(user, "8");
    expect(sizeInput(size, "vCPUs").getAttribute("aria-invalid")).toBe("true");
    server.current.errors.poolCapacity = [new Error("network")];
    await submit(user);
    // The server checks capacity under its locks; the browser does not refuse.
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ poolId: "pool-1", cpuCount: 8 });
  });

  it("pool capacity reads are reused for 30 seconds, then refreshed", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    await mount();
    await waitFor(() => expect(calls("poolCapacity").length).toBeGreaterThan(0));
    const query = client
      .getQueryCache()
      .findAll({ queryKey: ["sandboxPools", "capacity"] })
      .find((entry) => entry.getObserversCount() > 0);
    expect(query).toBeDefined();
    const observer = query!.observers[0]!;
    expect(observer.options.staleTime).toBe(30_000);
    expect(observer.options.refetchOnWindowFocus).not.toBe(false);
  });

  it("blank size remains omitted through lost-response retry after template defaults change", async () => {
    server.current.templates = [
      fakeTemplate({ cpuCount: 2, memoryMiB: 2048, defaultDiskGiB: 48, minDiskGiB: 8 }),
    ];
    server.current.lostResponses.createSandbox = 1;
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    await pickHost(user);
    const version = await openSection(user, "version");
    expect(
      version.getByRole("combobox", { name: enSandboxes.create.revision }).textContent,
    ).toContain("2 vCPU · 2048 MiB");
    await submit(user);
    await form().findByText(enSandboxes.problem.generic);
    const first = created();
    for (const field of ["cpuCount", "memoryMiB", "diskGiB"])
      expect(first).not.toHaveProperty(field);
    server.current.templates = [
      fakeTemplate({ cpuCount: 8, memoryMiB: 8192, defaultDiskGiB: 128, minDiskGiB: 8 }),
    ];
    await act(() => client.invalidateQueries({ queryKey: ["sandboxTemplates"] }));
    await waitFor(() =>
      expect(
        version.getByRole("combobox", { name: enSandboxes.create.revision }).textContent,
      ).toContain("8 vCPU · 8192 MiB"),
    );
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    expect(created(1)).toEqual(first);
    expect(server.current.sandboxes).toHaveLength(1);
    expect(server.current.sandboxes[0]).toMatchObject({
      cpuCount: 2,
      memoryMiB: 2048,
      diskGiB: 48,
    });
  });
});

describe("pools, paging and refusals", () => {
  it("pages logical templates, revisions, pools and hosts independently and retains exact choice on placement changes", async () => {
    server.current.pickerPageSize = 1;
    server.current.templates = [
      fakeTemplate({ id: "rev-a", templateId: "logical-a" }),
      fakeTemplate({ id: "rev-b", templateId: "logical-b", label: "Debian" }),
      fakeTemplate({ id: "rev-c", templateId: "logical-b", revision: 2, label: "Debian" }),
    ];
    server.current.pools = [
      { id: "pool-a", slug: "a", label: "Pool A" },
      { id: "pool-b", slug: "b", label: "Pool B" },
    ];
    const user = userEvent.setup();
    await openCreate(user);
    expect(
      (
        await selectChoices(
          user,
          form().getByRole("combobox", { name: enSandboxes.create.template }),
        )
      ).some((option) => option.textContent?.includes("Debian")),
    ).toBe(false);
    await user.click(form().getByRole("button", { name: enSandboxes.create.moreTemplates }));
    await selectOption(
      user,
      form().getByRole("combobox", { name: enSandboxes.create.template }),
      /^Debian \(ubuntu\)/,
    );
    const version = await openSection(user, "version");
    const revisions = await selectChoices(
      user,
      version.getByLabelText(enSandboxes.create.revision),
    );
    expect(revisions.some((option) => option.textContent?.startsWith("Revision 1 · "))).toBe(true);
    expect(revisions.some((option) => option.textContent?.startsWith("Revision 2 · "))).toBe(false);
    await user.click(version.getByRole("button", { name: enSandboxes.create.moreRevisions }));
    await selectOption(user, version.getByLabelText(enSandboxes.create.revision), /^Revision 2 · /);
    await user.click(form().getByRole("button", { name: enSandboxes.create.placementHost }));
    await user.click(await form().findByRole("button", { name: enSandboxes.create.moreHosts }));
    await selectOption(user, form().getByLabelText(enSandboxes.create.host), /^Beta · /);
    expect(version.getByLabelText(enSandboxes.create.revision).textContent).toMatch(
      /^Revision 2 · /,
    );
    await user.click(form().getByRole("button", { name: enSandboxes.create.placementPool }));
    expect(version.getByLabelText(enSandboxes.create.revision).textContent).toMatch(
      /^Revision 2 · /,
    );
    await user.click(form().getByRole("button", { name: enCommon.actions.loadMore }));
    await selectOption(user, form().getByLabelText(enSandboxes.create.pool), /^Pool B · /);
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ poolId: "pool-b", template: "revision/rev-c" });
    expect(created()).not.toHaveProperty("sandboxHostId");
    expect(
      calls("listTemplates").some((call) => (call.input as { cursor?: string }).cursor === "1"),
    ).toBe(true);
    expect(
      calls("listRevisions").some((call) => (call.input as { cursor?: string }).cursor === "1"),
    ).toBe(true);
    for (const call of [...calls("listTemplates"), ...calls("listRevisions")]) {
      expect(call.input).toMatchObject({ limit: 100 });
      expect(call.input).not.toHaveProperty("poolId");
      expect(call.input).not.toHaveProperty("hostIds");
    }
  });

  it("a pool's capacity wait choice is sent with the pooled create", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    const user = userEvent.setup();
    await openCreate(user);
    await pickTemplate(user);
    const wait = await openSection(user, "wait");
    await selectOption(
      user,
      wait.getByLabelText(enSandboxes.create.capacityWait),
      enSandboxes.create.wait["1h"],
    );
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ poolId: "pool-1", waitForCapacityMs: 3_600_000 });
  });

  it("waiting for capacity lets a size above what is free now through, with a note", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.poolLargest = { cpuCount: 6, memoryMiB: 8192, diskGiB: 100 };
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    const wait = await openSection(user, "wait");
    await selectOption(
      user,
      wait.getByLabelText(enSandboxes.create.capacityWait),
      enSandboxes.create.wait["1h"],
    );
    const size = await openSection(user, "size");
    await waitFor(() => expect(calls("poolCapacity").length).toBeGreaterThan(0));
    const reads = calls("poolCapacity").length;
    const cpu = sizeInput(size, "vCPUs");
    await typeSize(user, cpu, "8");
    expect(cpu.value).toBe("8 vCPU");
    expect(cpu.getAttribute("aria-invalid")).not.toBe("true");
    // The cap is said, not applied.
    expect(size.getByText("The most any host in this pool can take now is 6 vCPUs.")).toBeTruthy();
    expect(page().querySelector("[data-size-waits]")?.textContent).toBe(
      enSandboxes.create.capacity.poolWaits,
    );
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(calls("poolCapacity")).toHaveLength(reads);
    expect(created()).toMatchObject({
      poolId: "pool-1",
      cpuCount: 8,
      waitForCapacityMs: 3_600_000,
    });
  });

  it.each([
    ["sandbox.vm_size_unsupported", "sizeUnsupported"],
    ["sandbox.pool_full", "poolFull"],
    ["sandbox.pool_no_compatible_host", "poolIncompatible"],
    ["sandbox.pool_unavailable", "poolUnavailable"],
    ["sandbox.host_capacity", "hostCapacity"],
    ["sandbox.host_draining", "hostDraining"],
    ["sandbox.host_unavailable", "hostUnavailable"],
    ["sandbox.pool_not_found", "poolMissing"],
    ["FORBIDDEN", "forbidden"],
    ["NOT_FOUND", "notFound"],
  ] as const)(
    "%s has bilingual safe copy, keeps typed env values in the open form only, settles mutation state, and releases the intent",
    async (code, problem) => {
      server.current.pools = [{ id: "pool-a", slug: "a", label: "Pool A" }];
      const user = userEvent.setup();
      await openCreate(user);
      await chooseRevision(user, "tpl-1");
      if (!(code.startsWith("sandbox.pool_") || code === "FORBIDDEN")) await pickHost(user);
      const sentinel = "synthetic-private-env-s4";
      await typeEnv(user, "APP", sentinel);
      const storage = vi.spyOn(Storage.prototype, "setItem");
      server.current.errors.createSandbox = [
        Object.assign(new Error(sentinel), code.includes(".") ? { data: { code } } : { code }),
      ];
      const pickerReads = ["listHosts", "listPools", "listTemplates", "listRevisions"].map(
        (procedure) => [procedure, calls(procedure).length] as const,
      );
      await submit(user);
      await waitFor(() => {
        for (const [procedure, before] of pickerReads)
          expect(calls(procedure).length).toBeGreaterThan(before);
      });
      const text = (copy: typeof enSandboxes) =>
        problem === "notFound"
          ? copy.problem.createNotFound
          : problem === "forbidden"
            ? copy.problem.createForbidden
            : copy.problem[problem];
      // At its field (and echoed in the action bar), or in the action bar alone.
      expect((await form().findAllByText(text(enSandboxes))).length).toBeGreaterThan(0);
      // The typed value stays in the open form (React state only) so the cause
      // can be fixed and the create sent again.
      expect(envValues().filter(Boolean)).toEqual(["APP", sentinel]);
      // Never anywhere new: not in the settled mutation, toasts, page text or
      // browser storage.
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
      expect(document.body.textContent).not.toContain(sentinel);
      expect(JSON.stringify(toast.success.mock.calls)).not.toContain(sentinel);
      expect(JSON.stringify(storage.mock.calls)).not.toContain(sentinel);
      await act(() => i18n.changeLanguage("es-MX"));
      expect(form().getAllByText(text(esSandboxes)).length).toBeGreaterThan(0);
      await act(() => i18n.changeLanguage("en-US"));
      // Sending again is a new intent with the same values.
      await submit(user);
      await waitFor(() => expect(calls("createSandbox")).toHaveLength(2));
      const inputs = calls("createSandbox").map(
        (call) => call.input as { idempotencyKey: string; envs: Record<string, string> },
      );
      expect(inputs[1]?.idempotencyKey).not.toBe(inputs[0]?.idempotencyKey);
      expect(inputs[1]?.envs).toEqual({ APP: sentinel });
      expect(JSON.stringify(storage.mock.calls)).not.toContain(sentinel);
    },
  );

  it("a refused create keeps the env rows; one can still be removed before sending again", async () => {
    server.current.errors.createSandbox = [coded("sandbox.host_capacity")];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await typeEnv(user, "APP", "synthetic-private-drop");
    await submit(user);
    await body().findByText(enSandboxes.problem.hostCapacity);
    const envs = await openSection(user, "envs");
    await user.click(
      envs.getByRole("button", { name: enCommon.forms.keyValue.remove.replace("{{key}}", "APP") }),
    );
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(2));
    expect(created(1)).toMatchObject({ envs: {} });
  });

  it("the kept values show in .env text mode after a refusal and are sent as edited", async () => {
    server.current.errors.createSandbox = [coded("sandbox.host_capacity")];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await typeEnv(user, "TOKEN", "synthetic-private-text");
    await submit(user);
    await body().findByText(enSandboxes.problem.hostCapacity);
    const envs = await openSection(user, "envs");
    await user.click(envs.getByRole("button", { name: enCommon.forms.keyValue.textMode }));
    const text = envs.getByRole("textbox", { name: enSandboxes.create.envTitle });
    expect((text as HTMLTextAreaElement).value).toBe("TOKEN=synthetic-private-text");
    fireEvent.change(text, { target: { value: "TOKEN=typed-again" } });
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(2));
    expect(created(1)).toMatchObject({ envs: { TOKEN: "typed-again" } });
  });

  it("kept values are gone once the page is left after a refusal", async () => {
    server.current.errors.createSandbox = [coded("sandbox.host_capacity")];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await typeEnv(user, "APP", "synthetic-private-leave");
    await submit(user);
    await body().findByText(enSandboxes.problem.hostCapacity);
    expect(envValues().filter(Boolean)).toEqual(["APP", "synthetic-private-leave"]);
    cleanup();
    await openCreate(user);
    await openSection(user, "envs");
    expect(envValues()).not.toContain("synthetic-private-leave");
    expect(envValues()).not.toContain("APP");
  });

  it.each([
    ["sandbox.vm_size_invalid", "sizeInvalid"],
    ["sandbox.disk_below_image", "diskBelowImage"],
    ["sandbox.metadata_invalid", "labels"],
    ["sandbox.egress_policy_invalid", "egress"],
    ["BAD_REQUEST", "invalid"],
    ["PAYLOAD_TOO_LARGE", "invalid"],
    ["UNSUPPORTED_MEDIA_TYPE", "invalid"],
    ["UNSUPPORTED_CAPABILITY", "hostNoEgress"],
  ] as const)(
    "input mistake %s keeps env only on the open page, releases the intent, and clears on leaving",
    async (code, problem) => {
      const storage = vi.spyOn(Storage.prototype, "setItem");
      const user = userEvent.setup();
      await openCreate(user);
      await pickHost(user);
      await chooseRevision(user, "tpl-1");
      const sentinel = "synthetic-input-mistake-private";
      await typeEnv(user, "APP", sentinel);
      // BAD_REQUEST also covers a deployment maximum lowered since discovery.
      const error = Object.assign(
        new Error("safe refusal"),
        code.includes(".") || code === "UNSUPPORTED_CAPABILITY"
          ? { code: "BAD_REQUEST", data: { code, capability: "egress" } }
          : { code },
      );
      server.current.errors.createSandbox = [error, error];
      const pickerReads = ["listHosts", "listPools", "listTemplates", "listRevisions"].map(
        (procedure) => [procedure, calls(procedure).length] as const,
      );
      await submit(user);
      await waitFor(() => {
        for (const [procedure, before] of pickerReads)
          expect(calls(procedure).length).toBeGreaterThan(before);
      });
      expect((await form().findAllByText(enSandboxes.problem[problem])).length).toBeGreaterThan(0);
      expect(envValues()).toContain(sentinel);
      expect(page().querySelector("[data-env-cleared]")).toBeNull();
      await waitFor(() =>
        expect(
          JSON.stringify(
            client
              .getMutationCache()
              .getAll()
              .map((m) => m.state),
          ),
        ).not.toContain(sentinel),
      );
      expect(
        JSON.stringify(
          client
            .getQueryCache()
            .getAll()
            .map((q) => q.state),
        ),
      ).not.toContain(sentinel);
      await submit(user);
      await waitFor(() => expect(calls("createSandbox")).toHaveLength(2));
      const inputs = calls("createSandbox").map(
        (call) => call.input as { idempotencyKey: string; envs: Record<string, string> },
      );
      expect(inputs[1]?.idempotencyKey).not.toBe(inputs[0]?.idempotencyKey);
      expect(inputs[1]?.envs).toEqual({ APP: sentinel });
      await waitFor(() =>
        expect(
          JSON.stringify(
            client
              .getMutationCache()
              .getAll()
              .map((m) => m.state),
          ),
        ).not.toContain(sentinel),
      );
      // Leaving the page and coming back starts a fresh, empty draft.
      cleanup();
      await openCreate(user);
      expect(envValues()).toEqual(["", ""]);
      expect(JSON.stringify(storage.mock.calls)).not.toContain(sentinel);
      expect(JSON.stringify(localStorage)).not.toContain(sentinel);
      expect(JSON.stringify(sessionStorage)).not.toContain(sentinel);
    },
  );

  it.each(["host_runtime_unsupported", "future_refusal"])(
    "a host or unfamiliar domain refusal %s is definite even with BAD_REQUEST status and keeps env values",
    async (code) => {
      const user = userEvent.setup();
      await openCreate(user);
      await pickHost(user);
      await chooseRevision(user, "tpl-1");
      await typeEnv(user, "APP", "synthetic-settled-private");
      server.current.errors.createSandbox = [
        Object.assign(new Error("safe refusal"), {
          code: "BAD_REQUEST",
          status: 400,
          data: { code },
        }),
      ];
      await submit(user);
      // Not placed at a field: the action bar says it.
      expect(await form().findByText(enSandboxes.problem.invalid)).toBeTruthy();
      expect(envValues().filter(Boolean)).toEqual(["APP", "synthetic-settled-private"]);
    },
  );

  it("a template that isn't on the chosen host is named at the template, with the hosts that have it", async () => {
    // Debian is only on Beta; Alpha is chosen. The page warns before submit.
    server.current.hosts = [fakeHost(), fakeHost({ id: "host-2", slug: "beta", label: "Beta" })];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await pickTemplate(user, /^Debian \(debian\)$/);
    await waitFor(() =>
      expect(page().querySelector("[data-template-off-host]")?.textContent).toBe(
        enSandboxes.create.templateOffHost.warnElsewhere
          .replace("{{template}}", "Debian")
          .replace("{{host}}", "Alpha")
          .replace("{{hosts}}", "Beta"),
      ),
    );
    await typeEnv(user, "APP", "synthetic-off-host");
    server.current.errors.createSandbox = [
      Object.assign(new Error("Exact revision is not verified on this host connection."), {
        code: "BAD_REQUEST",
        status: 400,
        data: { code: "sandbox.template_image_rejected" },
      }),
    ];
    await submit(user);
    const expected = enSandboxes.create.templateOffHost.elsewhere
      .replace("{{template}}", "Debian")
      .replace("{{host}}", "Alpha")
      .replace("{{hosts}}", "Beta");
    const inline = await body().findByText(expected);
    expect(inline.getAttribute("data-create-problem")).toBe("templateNotOnHost");
    expect(inline.closest("section")?.querySelector('[aria-invalid="true"]')).toBe(
      form().getByRole("combobox", { name: enSandboxes.create.template }),
    );
    expect(summary()?.textContent).toContain(expected);
    // A definite refusal: the values stay in the open form, and the warning
    // gives way to the refusal itself.
    expect(envValues().filter(Boolean)).toEqual(["APP", "synthetic-off-host"]);
    expect(page().querySelector("[data-template-off-host]")).toBeNull();
    await waitFor(() =>
      expect(document.activeElement).toBe(
        form().getByRole("combobox", { name: enSandboxes.create.template }),
      ),
    );
    // Choosing the host that has it clears both.
    await pickHost(user, /^Beta · /);
    expect(summary()).toBeNull();
    await waitFor(() => expect(page().querySelector("[data-template-off-host]")).toBeNull());
  });

  it("templates without a version are listed but not offered; none usable links to New template", async () => {
    server.current.templates = [fakeTemplate()];
    server.current.templateVersions = { "logical-1": { count: 0, latest: null } };
    const user = userEvent.setup();
    await mount();
    const note = await waitFor(() => {
      const found = page().querySelector("[data-no-templates]");
      expect(found).not.toBeNull();
      return found!;
    });
    expect(note.textContent).toContain(enSandboxes.create.noTemplates);
    expect(
      within(note as HTMLElement)
        .getByRole("link")
        .getAttribute("href"),
    ).toBe("/en-US/dashboard/templates");
    const options = await selectChoices(
      user,
      form().getByRole("combobox", { name: enSandboxes.create.template }),
    );
    const ubuntu = options.find((option) => option.textContent?.startsWith("Ubuntu"));
    expect(ubuntu?.textContent).toBe(enSandboxes.create.noVersions.replace("{{label}}", "Ubuntu"));
    expect(ubuntu?.getAttribute("aria-disabled")).toBe("true");
  });

  it("uncertain pooled create retains exact env/body/key for replay even after discovery changes", async () => {
    server.current.pools = [
      { id: "pool-a", slug: "a", label: "Pool A", disconnectGraceSeconds: 259200 },
    ];
    server.current.lostResponses.createSandbox = 1;
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    await waitFor(() =>
      expect(
        form().getByText(enHosts.sharing.grace.replace("{{duration}}", "3 days")),
      ).toBeTruthy(),
    );
    const sentinel = "synthetic-uncertain-env-s4";
    await typeEnv(user, "APP", sentinel);
    const storage = vi.spyOn(Storage.prototype, "setItem");
    await submit(user);
    await form().findByText(enSandboxes.problem.generic);
    expect(envValues()).toContain(sentinel);
    server.current.pools = [];
    server.current.templates = [];
    await act(() => client.invalidateQueries({ queryKey: ["sandboxTemplates"] }));
    await act(() => client.invalidateQueries({ queryKey: ["sandboxPools"] }));
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const inputs = calls("createSandbox").map((call) => call.input);
    expect(inputs[1]).toEqual(inputs[0]);
    expect(inputs[0]).toHaveProperty("expectedDisconnectGraceSeconds", 259200);
    expect(inputs[0]).toHaveProperty("poolId", "pool-a");
    expect(server.current.sandboxes).toHaveLength(1);
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
  });

  it.each(["pool", "host", "template", "revision"])(
    "refuses a selected %s ID removed by refetch without issuing create",
    async (kind) => {
      server.current.pools = [{ id: "pool-a", slug: "a", label: "Pool A" }];
      const user = userEvent.setup();
      await openCreate(user);
      await chooseRevision(user, "tpl-1");
      if (kind !== "pool") await pickHost(user);
      if (kind === "pool") server.current.pools = [];
      else if (kind === "host") server.current.hosts = [];
      else server.current.templates = [];
      await act(() => client.invalidateQueries());
      await submit(user);
      expect((await form().findAllByRole("alert")).length).toBeGreaterThan(0);
      expect(calls("createSandbox")).toHaveLength(0);
    },
  );

  it("lifetime choices respect a lowered server maximum, and the default clamps to it", async () => {
    server.current.maxTimeoutMs = 17 * 60_000;
    const user = userEvent.setup();
    await openCreate(user);
    const field = form().getByLabelText(enSandboxes.lifetime.field);
    await waitFor(() => expect(field.textContent).toContain("15 minutes"));
    expect((await selectChoices(user, field)).map((option) => option.textContent)).toEqual([
      "5 minutes",
      "15 minutes",
    ]);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ timeoutMs: 15 * 60_000 });
  });

  it("offers a retry when lifetime discovery fails and restores the choices", async () => {
    server.current.maxTimeoutMs = 17 * 60_000;
    server.current.errors.getLimits = [new Error("network")];
    const user = userEvent.setup();
    await openCreate(user);
    await form().findByText(enSandboxes.lifetime.limitsFailed);
    await user.click(form().getByRole("button", { name: enCommon.actions.tryAgain }));
    await waitFor(() => expect(form().queryByText(enSandboxes.lifetime.limitsFailed)).toBeNull());
    const field = form().getByLabelText(enSandboxes.lifetime.field);
    expect((await selectChoices(user, field)).map((option) => option.textContent)).toEqual([
      "5 minutes",
      "15 minutes",
    ]);
    expect(calls("getLimits")).toHaveLength(2);
  });

  it("a failed picker load resolves to an inline retry, never an endless skeleton", async () => {
    server.current.errors.listHosts = [new Error("network")];
    const user = userEvent.setup();
    await openCreate(user);
    await form().findByText(enSandboxes.create.hostsFailed);
    expect(page().querySelector('[data-host-fields] [data-slot="skeleton"]')).toBeNull();
    await user.click(form().getByRole("button", { name: enCommon.actions.tryAgain }));
    await waitFor(() =>
      expect(form().getByRole("combobox", { name: enSandboxes.create.host })).toBeTruthy(),
    );
  });
});

describe("first-time walk fixes", () => {
  it("a chosen host shows its free capacity at once, and the host list refreshes like the Hosts page", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    // Before any submit: what fits on Alpha (3584 MiB after the VM overhead).
    expect(page().querySelector("[data-host-free]")?.textContent).toBe(
      enSandboxes.create.capacity.hostFree
        .replace("{{cpu}}", "4")
        .replace("{{memory}}", "3.5")
        .replace("{{disk}}", "95"),
    );
    // A connected host keeps reading as connected while the page is open: the
    // list is refetched well inside the 30 s heartbeat window.
    const hostsQuery = client
      .getQueryCache()
      .findAll({ queryKey: ["sandboxHosts", "listHosts"] })
      .find((entry) => entry.getObserversCount() > 0);
    expect(hostsQuery?.observers[0]?.options.refetchInterval).toBe(15_000);
  });

  it("a storage report that was current when the list was read still counts (no 0 GiB disk, no 'no storage')", async () => {
    // Read 14 s after the storage report: current then, stale a second later
    // by the wall clock. The page judges it as of the read.
    server.current.hosts = [
      fakeHost({
        storagePools: [
          {
            ...(fakeHost().storagePools as Record<string, unknown>[])[0],
            reportedAt: new Date(Date.now() - 14_000).toISOString(),
          },
        ],
      }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await new Promise((resolve) => setTimeout(resolve, 1_500));
    await chooseRevision(user, "tpl-1");
    expect(form().getByRole("combobox", { name: enSandboxes.create.host }).textContent).toContain(
      "Alpha · Available",
    );
    expect(page().querySelector("[data-host-free]")?.textContent).toContain("95 GiB disk");
  });

  it("a connected host without a current capacity report says so, not 'not connected'", async () => {
    const report = fakeHost().capacity as Record<string, unknown>;
    server.current.hosts = [fakeHost({ capacity: { ...report, current: false } })];
    const user = userEvent.setup();
    await openCreate(user);
    await waitFor(() =>
      expect(form().getByRole("combobox", { name: enSandboxes.create.host }).textContent).toContain(
        enSandboxes.create.hostUnmeasured.replace("{{label}}", "Alpha"),
      ),
    );
    expect(page().querySelector("[data-host-waits]")).toBeNull();
    expect(page().querySelector("[data-host-free]")?.textContent).toBe(
      enSandboxes.create.capacity.hostUnknown,
    );
  });

  it("a full host is unavailable for the constraint that is full (RAM, not storage)", async () => {
    const report = fakeHost().capacity as Record<string, unknown>;
    server.current.hosts = [
      fakeHost(),
      fakeHost({
        id: "host-2",
        slug: "beta",
        label: "Beta",
        capacity: { ...report, memoryAvailableMiB: 300 },
        storagePools: [],
      }),
    ];
    server.current.templates = [fakeTemplate({ memoryMiB: 1024 })];
    const user = userEvent.setup();
    await openCreate(user);
    await chooseRevision(user, "tpl-1");
    const options = await selectChoices(
      user,
      await form().findByRole("combobox", { name: enSandboxes.create.host }),
    );
    expect(options.map((option) => option.textContent)).toContain(
      enSandboxes.create.hostUnavailable
        .replace("{{label}}", "Beta")
        .replace("{{reason}}", enSandboxes.create.unavailable.ram),
    );
  });

  it("typing above the host's free memory keeps the value, blocks the create and offers the cap", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const size = await openSection(user, "size");
    const memory = sizeInput(size, "Memory");
    await typeSize(user, memory, "3.75");
    expect(memory.value).toBe("3.75 GiB");
    expect(memory.getAttribute("aria-invalid")).toBe("true");
    // Said once, as the field's error.
    expect(size.getAllByText("This host has 3.5 GiB of memory free.")).toHaveLength(1);
    expect(size.getByRole("alert").textContent).toBe("This host has 3.5 GiB of memory free.");
    await submit(user);
    await waitFor(() => expect(document.activeElement).toBe(memory));
    expect(calls("createSandbox")).toHaveLength(0);
    await user.click(size.getByRole("button", { name: "Use 3.5 GiB" }));
    expect(memory.value).toBe("3.5 GiB");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ memoryMiB: 3584 });
  });

  it("a pooled RAM refusal is shown at Memory, echoed in the action bar, and focus moves there", async () => {
    server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
    server.current.errors.createSandbox = [
      Object.assign(new Error("full"), {
        code: "CONFLICT",
        data: { code: "sandbox.pool_full", reason: "ram", retryable: true },
      }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickTemplate(user);
    await submit(user);
    await waitFor(() => expect(summary()?.textContent).toContain(enSandboxes.problem.capacityRam));
    const size = page().querySelector<HTMLDetailsElement>('details[data-section="size"]')!;
    expect(size.open).toBe(true);
    const memory = sizeInput(within(size), "Memory");
    expect(memory.getAttribute("aria-invalid")).toBe("true");
    expect(within(size).getByText(enSandboxes.problem.capacityRam)).toBeTruthy();
    await waitFor(() => expect(document.activeElement).toBe(memory));
    // "Show" goes back there after focus moved away and the section closed.
    memory.blur();
    await user.click(size.querySelector("summary")!);
    expect(size.open).toBe(false);
    await user.click(
      within(summary()!).getByRole("button", { name: enSandboxes.create.showProblem }),
    );
    await waitFor(() => expect(document.activeElement).toBe(memory));
    expect(size.open).toBe(true);
  });

  it("preview ports are offered with a tunnel server, checked inline and sent as tunnelPorts", async () => {
    server.current.previewTunnels = true;
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    const ports = await network.findByLabelText(enSandboxes.create.previewPorts);
    await user.type(ports, "3000, 3000");
    expect(ports.getAttribute("aria-invalid")).toBe("true");
    expect(network.getByText(enSandboxes.draft.previewPorts)).toBeTruthy();
    await submit(user);
    expect(calls("createSandbox")).toEqual([]);
    await user.clear(ports);
    await user.type(ports, "8080 3000");
    expect(ports.getAttribute("aria-invalid")).toBeNull();
    expect(
      page().querySelector('details[data-section="network"] [data-slot="advanced-section-summary"]')
        ?.textContent,
    ).toContain(enSandboxes.create.summary.ports_other.replace("{{count}}", "2"));
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).toMatchObject({ network: { tunnelPorts: [8080, 3000] } });
  });

  it("without a tunnel server there is no preview ports field and nothing is sent", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    expect(network.queryByLabelText(enSandboxes.create.previewPorts)).toBeNull();
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect(created()).not.toHaveProperty("network");
  });

  it("a refused preview tunnel is explained in Network, and focus moves to it", async () => {
    server.current.previewTunnels = true;
    server.current.errors.createSandbox = [
      Object.assign(new Error("tunnels off"), {
        code: "BAD_REQUEST",
        data: { code: "UNSUPPORTED_CAPABILITY", capability: "tunnel", reason: "tunnel_no_host" },
      }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    await pickHost(user);
    await chooseRevision(user, "tpl-1");
    const network = await openSection(user, "network");
    await user.type(network.getByLabelText(enSandboxes.create.previewPorts), "8080");
    await submit(user);
    const inline = await body().findByText(enSandboxes.problem.tunnelUnavailable);
    expect(inline.closest('details[data-section="network"]')).not.toBeNull();
    await waitFor(() => expect(document.activeElement).toBe(inline));
  });
});
