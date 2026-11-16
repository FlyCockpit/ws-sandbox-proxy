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
  coded,
  type FakeSandboxServer,
  fakeHost,
  fakeTemplate,
  newFakeSandboxServer,
  sandboxRow,
} from "@/test/sandbox-fake";

/**
 * Sandboxes list and create dialog against a scripted fake server (real
 * TanStack Query, i18n and dialogs): rows show exactly what the server
 * reported — queued, unknown and offline included — and create is pinned to a
 * host and one of its templates, sends one request per intent (a retry
 * replays the first key and input), and opens the new sandbox's page.
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
const dialog = () => screen.getByRole("dialog");

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
    // Each step check is one bounded read.
    for (const procedure of ["listHosts:first", "listPools:first", "listTemplates:first"])
      expect(calls(procedure)[0]?.input, procedure).toMatchObject({ limit: 1 });
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

async function chooseRevision(user: ReturnType<typeof userEvent.setup>, revisionId: string) {
  const template = server.current.templates.find((row) => row.id === revisionId)!;
  const form = within(dialog());
  await selectOption(
    user,
    form.getByLabelText(enSandboxes.create.template),
    new RegExp(`^${template.label} \\(${template.slug}\\)$`),
  );
  await form.findByRole("combobox", { name: enSandboxes.create.revision });
  await selectOption(
    user,
    form.getByLabelText(enSandboxes.create.revision),
    new RegExp(`^Revision ${template.revision} · `),
  );
}

async function openCreate(user: ReturnType<typeof userEvent.setup>, lang = "en-US") {
  await mount(lang);
  const copy = lang === "en-US" ? enSandboxes : esSandboxes;
  await screen.findByText(copy.onboarding.title);
  await user.click(screen.getByRole("button", { name: copy.create.action }));
  await within(dialog()).findByRole("combobox", { name: copy.create.host });
}

const submit = (user: ReturnType<typeof userEvent.setup>) =>
  user.click(within(dialog()).getByRole("button", { name: enSandboxes.create.submit }));

describe("creating a sandbox", () => {
  it("refuses an incomplete draft in the browser without a request", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await submit(user);
    const problems = [...dialog().querySelectorAll("[data-draft-problem]")].map(
      (item) => (item as HTMLElement).dataset.draftProblem,
    );
    expect(problems).toEqual(["noHost", "noTemplate"]);
    await user.type(within(dialog()).getByLabelText(enSandboxes.create.labels), "oops");
    await submit(user);
    expect(dialog().querySelector('[data-draft-problem="labelsSyntax"]')).not.toBeNull();
    expect(calls("createSandbox")).toEqual([]);
  });

  it("selects template and revision independently of placement; create → server state → the sandbox's page", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    expect(
      (await selectChoices(user, form.getByLabelText(enSandboxes.create.template))).some((option) =>
        option.textContent?.includes("Ubuntu"),
      ),
    ).toBe(true);
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    expect(
      (await selectChoices(user, form.getByLabelText(enSandboxes.create.template))).some((option) =>
        option.textContent?.includes("Debian"),
      ),
    ).toBe(true);
    await chooseRevision(user, "tpl-1");
    await selectOption(
      user,
      form.getByLabelText(enSandboxes.lifetime.field),
      /^(2 hours|2 horas)$/,
    );
    await user.click(form.getByRole("radio", { name: enSandboxes.lifetime.destroyOption }));
    await user.type(form.getByLabelText(enSandboxes.create.labels), "team=infra");
    await user.click(form.getByLabelText(enSandboxes.create.envs));
    await user.paste('{"APP":"synthetic-create-env"}');
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const [created] = calls("createSandbox");
    const input = created?.input as Record<string, unknown>;
    expect(input).toMatchObject({
      template: "revision/" + "tpl-1",
      sandboxHostId: "host-1",
      metadata: { team: "infra" },
      envs: { APP: "synthetic-create-env" },
      lifecycle: { onTimeout: "kill" },
    });
    expect(String(input.idempotencyKey)).toMatch(/^web\.create\.[0-9a-f-]{36}$/);
    const lease = input.timeoutMs as number;
    expect(lease).toBe(120 * 60_000);
    expect(input).not.toHaveProperty("leaseExpiresAt");
    expect(navigate).toHaveBeenCalledWith({
      to: "/$lang/dashboard/sandboxes/$sandboxId",
      params: { lang: "en-US", sandboxId: "sbx-new-1" },
    });
    // The list refreshes from the server: the new sandbox is Requested, not Ready.
    expect(await screen.findByText("sbx-new-1")).toBeTruthy();
    expect(row("sbx-new-1").dataset.sandboxState).toBe("REQUESTED");
  });

  it("a disconnected host explains fresh-launch admission; the server decides the request", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    await selectOption(
      user,
      within(dialog()).getByLabelText(enSandboxes.create.host),
      /^Beta \(beta\)/,
    );
    expect(dialog().querySelector("[data-host-waits]")?.textContent).toBe(
      enSandboxes.create.hostWaits,
    );
    await chooseRevision(user, "tpl-2");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
  });

  it("labels a draining host and does not let it be chosen (M7-S5)", async () => {
    server.current.hosts = [
      fakeHost(),
      fakeHost({ id: "host-3", slug: "rack", label: "Draining rack", draining: true }),
    ];
    const user = userEvent.setup();
    await openCreate(user);
    const choices = await openSelect(
      user,
      within(dialog()).getByLabelText(enSandboxes.create.host),
    );
    const option = choices.getByRole("option", {
      name: "Draining rack (rack) — Connected · draining",
    });
    expect(option.getAttribute("aria-disabled")).toBe("true");
    expect(dialog().querySelector("[data-draining-hosts]")?.textContent).toBe(
      enSandboxes.create.drainingHosts,
    );
    const alpha = choices.getByRole("option", {
      name: /Alpha \(alpha\) · Connected · 0 live/,
    });
    expect(alpha.getAttribute("aria-disabled")).not.toBe("true");
  });

  it("a double submit while pending sends one request", async () => {
    let release!: () => void;
    server.current.gates.createSandbox = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup();
    await openCreate(user);
    await selectOption(
      user,
      within(dialog()).getByLabelText(enSandboxes.create.host),
      /^Alpha \(alpha\)/,
    );
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const button = within(dialog()).getByRole("button", { name: enSandboxes.create.pending });
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
    await selectOption(
      user,
      within(dialog()).getByLabelText(enSandboxes.create.host),
      /^Alpha \(alpha\)/,
    );
    await chooseRevision(user, "tpl-1");
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toBe(
      enSandboxes.problem.generic,
    );
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const [first, second] = calls("createSandbox").map((call) => call.input);
    expect(second).toEqual(first);
    expect(server.current.sandboxes).toHaveLength(1);
  });

  it("a definite refusal is explained and the next submit is a new request", async () => {
    server.current.errors.createSandbox = [coded("sandbox.host_capacity")];
    const user = userEvent.setup();
    await openCreate(user);
    await selectOption(
      user,
      within(dialog()).getByLabelText(enSandboxes.create.host),
      /^Alpha \(alpha\)/,
    );
    await chooseRevision(user, "tpl-1");
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toBe(
      enSandboxes.problem.hostCapacity,
    );
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
    await selectOption(
      user,
      within(dialog()).getByLabelText(enSandboxes.create.host),
      /^Alpha \(alpha\)/,
    );
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const alert = await within(dialog()).findByRole("alert");
    expect(alert.textContent).toBe(enSandboxes.problem.hostNoEgress);
    expect(alert.getAttribute("data-create-problem")).toBe("hostNoEgress");
    expect(alert.textContent).not.toBe(enSandboxes.problem.invalid);
    expect(server.current.sandboxes).toEqual([]);
  });

  it("internet access is on by default and sends open mode (default-open egress)", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    expect(
      form
        .getByRole("switch", { name: enSandboxes.create.internetAccess })
        .getAttribute("aria-checked"),
    ).toBe("true");
    expect(dialog().querySelector("[data-egress-hint]")?.textContent).toBe(
      enSandboxes.create.internetAccessOnHint,
    );
    // The grant fields are the collapsed fallback list while internet access is on.
    expect(dialog().querySelector("[data-egress-fallback] summary")?.textContent).toBe(
      enSandboxes.create.fallbackSummary,
    );
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const [created] = calls("createSandbox");
    const input = created?.input as Record<string, unknown>;
    expect(input.egress).toEqual({ mode: "open", domains: [], cidrs: [] });
    expect(server.current.sandboxes[0]?.egress).toEqual({ mode: "open", domains: [], cidrs: [] });
  });

  it("an optional name is sent lowercased; blank sends none (the server generates one)", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    const name = form.getByLabelText(enSandboxes.create.name);
    expect(name.getAttribute("autocomplete")).toBe("off");
    await user.type(name, "CI-Runner");
    expect((name as HTMLInputElement).value).toBe("ci-runner");
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
    expect((calls("createSandbox")[0]!.input as Record<string, unknown>).name).toBe("ci-runner");
  });

  it("an invalid name is a draft problem; a taken one is explained and the next submit is a new request", async () => {
    server.current.errors.createSandbox = [coded("sandbox.name_taken")];
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await user.type(form.getByLabelText(enSandboxes.create.name), "wssp-x");
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    expect(dialog().querySelector('[data-draft-problem="name"]')?.textContent).toBe(
      enSandboxes.draft.name,
    );
    expect(calls("createSandbox")).toEqual([]);
    await user.clear(form.getByLabelText(enSandboxes.create.name));
    await user.type(form.getByLabelText(enSandboxes.create.name), "quiet-otter");
    await submit(user);
    await waitFor(() =>
      expect(dialog().querySelector("[data-create-problem]")?.textContent).toBe(
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
    const form = within(dialog());
    const toggle = form.getByRole("switch", { name: enSandboxes.create.guestSudo });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    expect(dialog().querySelector("[data-guest-sudo-hint]")?.textContent).toBe(
      enSandboxes.create.guestSudoOnHint,
    );
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const input = calls("createSandbox")[0]?.input as Record<string, unknown> | undefined;
    expect(input?.guestSudo).toBe(true);
  });

  it("guest root off on a tainted pinned revision warns that root may still be reachable", async () => {
    const user = userEvent.setup();
    const row = server.current.templates.find((candidate) => candidate.id === "tpl-1")!;
    Object.assign(row, { capturedWithGuestRoot: true });
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    expect(dialog().querySelector("[data-guest-root-tainted]")).toBeNull();
    await user.click(form.getByRole("switch", { name: enSandboxes.create.guestSudo }));
    expect(dialog().querySelector("[data-guest-sudo-hint]")?.textContent).toBe(
      enSandboxes.create.guestSudoOffHint,
    );
    expect(dialog().querySelector("[data-guest-root-tainted]")?.textContent).toBe(
      enSandboxes.create.guestRootTainted,
    );
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const input = calls("createSandbox")[0]?.input as Record<string, unknown> | undefined;
    expect(input?.guestSudo).toBe(false);
  });

  it("fallback grants ride along with open mode", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await user.click(form.getByText(enSandboxes.create.fallbackSummary));
    await user.type(form.getByLabelText(enSandboxes.create.egressDomains), "registry.example.com");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const input = calls("createSandbox")[0]?.input as Record<string, unknown>;
    expect(input.egress).toEqual({ mode: "open", domains: ["registry.example.com"], cidrs: [] });
  });

  it("internet access off sends the entries as the immutable allowlist (C37)", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await user.click(form.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    expect(dialog().querySelector("[data-egress-fallback]")).toBeNull();
    expect(dialog().querySelector("[data-egress-hint]")?.textContent).toBe(
      enSandboxes.create.egressHint,
    );
    await user.type(form.getByLabelText(enSandboxes.create.egressDomains), "registry.example.com");
    await user.type(form.getByLabelText(enSandboxes.create.egressCidrs), "128.66.0.0/24");
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const input = calls("createSandbox")[0]?.input as Record<string, unknown>;
    expect(input.egress).toEqual({
      mode: "allowlist",
      domains: ["registry.example.com"],
      cidrs: ["128.66.0.0/24"],
    });
    expect(server.current.sandboxes[0]?.egress).toEqual({
      mode: "allowlist",
      domains: ["registry.example.com"],
      cidrs: ["128.66.0.0/24"],
    });
  });

  it("internet access off with no entries is an explicit deny-all", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await user.click(form.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const input = calls("createSandbox")[0]?.input as Record<string, unknown>;
    expect(input.egress).toEqual({ mode: "allowlist", domains: [], cidrs: [] });
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
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await submit(user);
    const alert = await within(dialog()).findByRole("alert");
    expect(alert.getAttribute("data-create-problem")).toBe(problem);
    expect(alert.textContent).toBe(enSandboxes.problem[problem]);
    expect(server.current.sandboxes).toEqual([]);
  });

  it("an egress entry outside the schema bounds is a draft problem, never a request", async () => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await user.click(form.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    const domains = form.getByLabelText(enSandboxes.create.egressDomains);
    await user.click(domains);
    // One entry over the catalog's 253-character domain bound.
    await user.paste(`${"a".repeat(254)}.example.com`);
    await submit(user);
    expect(dialog().querySelector('[data-draft-problem="egress"]')?.textContent).toBe(
      enSandboxes.draft.egress,
    );
    expect(calls("createSandbox")).toEqual([]);
  });

  it("a refused egress policy is explained and the next submit is a new request", async () => {
    server.current.errors.createSandbox = [coded("sandbox.egress_policy_invalid")];
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await user.click(form.getByRole("switch", { name: enSandboxes.create.internetAccess }));
    await user.type(form.getByLabelText(enSandboxes.create.egressCidrs), "10.0.0.0/8");
    await submit(user);
    expect((await within(dialog()).findByRole("alert")).textContent).toBe(
      enSandboxes.problem.egress,
    );
    expect(server.current.sandboxes).toEqual([]);
    // Definite refusal: the retry is a new request with a fresh intent key.
    await submit(user);
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const keys = calls("createSandbox").map(
      (call) => (call.input as { idempotencyKey: string }).idempotencyKey,
    );
    expect(new Set(keys).size).toBe(2);
  });
});

it("create offers a pool independently of host selection and submits XOR placement", async () => {
  const user = userEvent.setup();
  server.current.pools = [{ id: "pool-1", slug: "lab", label: "Lab" }];
  await openCreate(user);
  const form = within(dialog());
  await selectOption(user, form.getByLabelText(enSandboxes.create.placement), /^(Pool|Grupo)$/);
  await selectOption(user, await form.findByLabelText(enSandboxes.create.pool), /^Lab \(lab\)/);
  await chooseRevision(user, "tpl-1");
  await submit(user);
  await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
  const input = calls("createSandbox")[0]!.input as Record<string, unknown>;
  expect(input).toMatchObject({ poolId: "pool-1" });
  expect(input).not.toHaveProperty("sandboxHostId");
});

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
  const form = within(dialog());
  expect(
    (await selectChoices(user, form.getByLabelText(enSandboxes.create.template))).some((option) =>
      option.textContent?.includes("Debian"),
    ),
  ).toBe(false);
  await user.click(form.getByRole("button", { name: enSandboxes.create.moreTemplates }));
  await selectOption(user, form.getByLabelText(enSandboxes.create.template), /^Debian \(ubuntu\)/);
  const revisions = await selectChoices(user, form.getByLabelText(enSandboxes.create.revision));
  expect(revisions.some((option) => option.textContent?.startsWith("Revision 1 · "))).toBe(true);
  expect(revisions.some((option) => option.textContent?.startsWith("Revision 2 · "))).toBe(false);
  await user.click(form.getByRole("button", { name: enSandboxes.create.moreRevisions }));
  await selectOption(user, form.getByLabelText(enSandboxes.create.revision), /^Revision 2 · /);
  await user.click(form.getByRole("button", { name: enSandboxes.create.moreHosts }));
  await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Beta \(beta\)/);
  expect(form.getByLabelText(enSandboxes.create.revision).textContent).toMatch(/^Revision 2 · /);
  await selectOption(user, form.getByLabelText(enSandboxes.create.placement), /^(Pool|Grupo)$/);
  expect(form.getByLabelText(enSandboxes.create.revision).textContent).toMatch(/^Revision 2 · /);
  await user.click(form.getByRole("button", { name: enCommon.actions.loadMore }));
  await selectOption(user, form.getByLabelText(enSandboxes.create.pool), /^Pool B \(b\)/);
  await submit(user);
  await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
  expect(calls("createSandbox")[0]?.input).toMatchObject({
    poolId: "pool-b",
    template: "revision/rev-c",
  });
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

it("submits logical latest once with relative stop lifetime", async () => {
  const user = userEvent.setup();
  await openCreate(user);
  const form = within(dialog());
  await selectOption(user, form.getByLabelText(enSandboxes.create.template), /^Ubuntu \(ubuntu\)/);
  await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
  await user.click(form.getByRole("radio", { name: enSandboxes.lifetime.stopOption }));
  await submit(user);
  await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
  expect(calls("createSandbox")[0]?.input).toMatchObject({
    template: "template/logical-1",
    timeoutMs: 300000,
    lifecycle: { onTimeout: "stop" },
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
  "%s has bilingual safe copy, clears env and settled mutation state, and releases the intent",
  async (code, problem) => {
    server.current.pools = [{ id: "pool-a", slug: "a", label: "Pool A" }];
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    if (code.startsWith("sandbox.pool_") || code === "FORBIDDEN") {
      await selectOption(user, form.getByLabelText(enSandboxes.create.placement), /^(Pool|Grupo)$/);
      await selectOption(user, form.getByLabelText(enSandboxes.create.pool), /^Pool A \(a\)/);
    }
    const sentinel = "synthetic-private-env-s4";
    await user.click(form.getByLabelText(enSandboxes.create.envs));
    await user.paste(JSON.stringify({ APP: sentinel }));
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
    expect(
      await form.findByText(
        problem === "notFound"
          ? enSandboxes.problem.createNotFound
          : problem === "forbidden"
            ? enSandboxes.problem.createForbidden
            : enSandboxes.problem[problem],
      ),
    ).toBeTruthy();
    expect((form.getByLabelText(enSandboxes.create.envs) as HTMLTextAreaElement).value).toBe("");
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
    expect(
      form.getByText(
        problem === "notFound"
          ? esSandboxes.problem.createNotFound
          : problem === "forbidden"
            ? esSandboxes.problem.createForbidden
            : esSandboxes.problem[problem],
      ),
    ).toBeTruthy();
    await act(() => i18n.changeLanguage("en-US"));
    await submit(user);
    await waitFor(() => expect(calls("createSandbox")).toHaveLength(2));
    const inputs = calls("createSandbox").map(
      (call) => call.input as { idempotencyKey: string; envs: Record<string, string> },
    );
    expect(inputs[1]?.idempotencyKey).not.toBe(inputs[0]?.idempotencyKey);
    expect(inputs[1]?.envs).toEqual({});
  },
);

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
  "input mistake %s keeps env only in the open form, releases the intent, and clears on close",
  async (code, problem) => {
    const storage = vi.spyOn(Storage.prototype, "setItem");
    const user = userEvent.setup();
    await openCreate(user);
    let form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    const sentinel = "synthetic-input-mistake-private";
    const env = JSON.stringify({ APP: sentinel });
    await user.click(form.getByLabelText(enSandboxes.create.envs));
    await user.paste(env);
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
    expect(await form.findByText(enSandboxes.problem[problem])).toBeTruthy();
    expect((form.getByLabelText(enSandboxes.create.envs) as HTMLTextAreaElement).value).toBe(env);
    // Reset mutation variables/errors despite keeping the local form editable.
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
    await user.click(form.getByRole("button", { name: enCommon.actions.cancel }));
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    await user.click(screen.getByRole("button", { name: enSandboxes.create.action }));
    form = within(dialog());
    expect((form.getByLabelText(enSandboxes.create.envs) as HTMLTextAreaElement).value).toBe("");
    expect(JSON.stringify(storage.mock.calls)).not.toContain(sentinel);
    expect(JSON.stringify(localStorage)).not.toContain(sentinel);
    expect(JSON.stringify(sessionStorage)).not.toContain(sentinel);
  },
);

it.each(["sandbox.template_image_rejected", "host_runtime_unsupported", "future_refusal"])(
  "a host or unfamiliar domain refusal %s still clears env even with BAD_REQUEST status",
  async (code) => {
    const user = userEvent.setup();
    await openCreate(user);
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    await chooseRevision(user, "tpl-1");
    await user.click(form.getByLabelText(enSandboxes.create.envs));
    await user.paste('{"APP":"synthetic-settled-private"}');
    server.current.errors.createSandbox = [
      Object.assign(new Error("safe refusal"), {
        code: "BAD_REQUEST",
        status: 400,
        data: { code },
      }),
    ];
    await submit(user);
    expect(await form.findByText(enSandboxes.problem.invalid)).toBeTruthy();
    expect((form.getByLabelText(enSandboxes.create.envs) as HTMLTextAreaElement).value).toBe("");
  },
);

it("uncertain pooled create retains exact env/body/key for replay even after discovery changes", async () => {
  server.current.pools = [
    { id: "pool-a", slug: "a", label: "Pool A", disconnectGraceSeconds: 259200 },
  ];
  server.current.lostResponses.createSandbox = 1;
  const user = userEvent.setup();
  await openCreate(user);
  const form = within(dialog());
  await chooseRevision(user, "tpl-1");
  await selectOption(user, form.getByLabelText(enSandboxes.create.placement), /^(Pool|Grupo)$/);
  await selectOption(user, form.getByLabelText(enSandboxes.create.pool), /^Pool A \(a\)/);
  expect(form.getByText(enHosts.sharing.grace.replace("{{duration}}", "3 days"))).toBeTruthy();
  const sentinel = "synthetic-uncertain-env-s4";
  await user.click(form.getByLabelText(enSandboxes.create.envs));
  await user.paste(JSON.stringify({ APP: sentinel }));
  const storage = vi.spyOn(Storage.prototype, "setItem");
  await submit(user);
  await form.findByText(enSandboxes.problem.generic);
  expect((form.getByLabelText(enSandboxes.create.envs) as HTMLTextAreaElement).value).toContain(
    sentinel,
  );
  server.current.pools = [];
  server.current.templates = [];
  await act(() => client.invalidateQueries({ queryKey: ["sandboxTemplates"] }));
  await act(() => client.invalidateQueries({ queryKey: ["sandboxPools"] }));
  await submit(user);
  await waitFor(() => expect(navigate).toHaveBeenCalled());
  const inputs = calls("createSandbox").map((call) => call.input);
  expect(inputs[1]).toEqual(inputs[0]);
  expect(inputs[0]).toHaveProperty("expectedDisconnectGraceSeconds", 259200);
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
    const form = within(dialog());
    await chooseRevision(user, "tpl-1");
    await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
    if (kind === "pool")
      await selectOption(user, form.getByLabelText(enSandboxes.create.placement), /^(Pool|Grupo)$/);
    const labels = {
      pool: enSandboxes.create.pool,
      host: enSandboxes.create.host,
      template: enSandboxes.create.template,
      revision: enSandboxes.create.revision,
    };
    const select = form.getByLabelText(labels[kind as keyof typeof labels]);
    if (kind === "pool") await selectOption(user, select, /^Pool A \(a\)/);
    if (kind === "pool") server.current.pools = [];
    else if (kind === "host") server.current.hosts = [];
    else server.current.templates = [];
    await act(() => client.invalidateQueries());

    await submit(user);
    expect(await form.findByRole("alert")).toBeTruthy();
    expect(calls("createSandbox")).toHaveLength(0);
  },
);

it("closing a private draft clears it on reopen; focus and touch controls are accessible", async () => {
  const user = userEvent.setup();
  await openCreate(user);
  let form = within(dialog());
  await waitFor(() => expect(dialog().contains(document.activeElement)).toBe(true));
  for (const button of form.getAllByRole("button"))
    expect(button.className).toMatch(/h-11|min-h-\[44px\]/);
  expect(form.getAllByRole("combobox").length).toBeGreaterThan(0);
  await user.click(form.getByLabelText(enSandboxes.create.envs));
  await user.paste('{"APP":"synthetic-close-env"}');
  await user.click(form.getByRole("button", { name: enCommon.actions.cancel }));
  const opener = screen.getByRole("button", { name: enSandboxes.create.action });
  await waitFor(() => expect(document.activeElement).toBe(opener));
  await user.click(opener);
  form = within(await screen.findByRole("dialog"));
  expect((form.getByLabelText(enSandboxes.create.envs) as HTMLTextAreaElement).value).toBe("");
  expect(calls("createSandbox")).toHaveLength(0);
});

it("create host choices show live count without a count ceiling", async () => {
  server.current.hosts = [
    fakeHost({ liveSandboxCount: 1 }),
    fakeHost({
      id: "full",
      slug: "full",
      label: "Full host",
      liveSandboxCount: 2,
    }),
  ];
  const user = userEvent.setup();
  await openCreate(user);
  expect(
    (await openSelect(user, within(dialog()).getByLabelText(enSandboxes.create.host))).getByRole(
      "option",
      { name: /Alpha \(alpha\) · Connected · 1 live/ },
    ),
  ).toBeTruthy();
  expect(
    screen.getByRole("option", { name: /Full host \(full\) · Connected · 2 live/ }),
  ).toBeTruthy();
});

it("create lifetime choices respect a lowered server maximum", async () => {
  server.current.maxTimeoutMs = 17 * 60_000;
  const user = userEvent.setup();
  await openCreate(user);
  const field = within(dialog()).getByLabelText(enSandboxes.lifetime.field);
  expect((await selectChoices(user, field)).map((option) => option.textContent)).toEqual([
    "5 minutes",
    "15 minutes",
  ]);
  await selectOption(user, field, /^(15 minutes|15 minutos)$/);
  await selectOption(
    user,
    within(dialog()).getByLabelText(enSandboxes.create.host),
    /^Alpha \(alpha\)/,
  );
  await chooseRevision(user, "tpl-1");
  await submit(user);
  await waitFor(() => expect(calls("createSandbox")).toHaveLength(1));
  expect(calls("createSandbox")[0]?.input).toMatchObject({ timeoutMs: 15 * 60_000 });
});

it("create offers a retry when lifetime discovery fails and restores the choices", async () => {
  server.current.maxTimeoutMs = 17 * 60_000;
  server.current.errors.getLimits = [new Error("network")];
  const user = userEvent.setup();
  await openCreate(user);
  const popup = within(dialog());
  await popup.findByText(enSandboxes.lifetime.limitsFailed);
  await user.click(popup.getByRole("button", { name: enCommon.actions.tryAgain }));
  await waitFor(() => expect(popup.queryByText(enSandboxes.lifetime.limitsFailed)).toBeNull());
  const field = popup.getByLabelText(enSandboxes.lifetime.field);
  expect((await selectChoices(user, field)).map((option) => option.textContent)).toEqual([
    "5 minutes",
    "15 minutes",
  ]);
  expect(calls("getLimits")).toHaveLength(2);
});

it("blank size remains omitted through lost-response retry after template defaults change", async () => {
  server.current.templates = [
    fakeTemplate({ cpuCount: 2, memoryMiB: 2048, defaultDiskGiB: 48, minDiskGiB: 8 }),
  ];
  server.current.lostResponses.createSandbox = 1;
  const user = userEvent.setup();
  await openCreate(user);
  const form = within(dialog());
  await chooseRevision(user, "tpl-1");
  await selectOption(user, form.getByLabelText(enSandboxes.create.host), /^Alpha \(alpha\)/);
  const cpu = form.getByLabelText(enSandboxes.create.cpuCount) as HTMLInputElement;
  const memory = form.getByLabelText(enSandboxes.create.memoryMiB) as HTMLInputElement;
  expect(cpu.value).toBe("");
  expect(memory.value).toBe("");
  const disk = form.getByLabelText(enSandboxes.create.diskGiB) as HTMLInputElement;
  // The chosen revision's floor and default are shown and bound the field.
  expect(disk.getAttribute("min")).toBe("8");
  expect(form.getByText(/Root disk: 48 GiB if left blank; at least 8 GiB/)).toBeTruthy();
  await user.type(disk, "64");
  await user.clear(disk);
  expect(disk.value).toBe("");
  expect(cpu.getAttribute("inputmode")).toBe("numeric");
  expect(memory.getAttribute("inputmode")).toBe("numeric");
  expect(cpu.getAttribute("min")).toBe("1");
  expect(cpu.getAttribute("max")).toBe("32");
  expect(memory.getAttribute("step")).toBe("256");
  expect(form.getByLabelText(enSandboxes.create.revision).textContent).toContain(
    "2 vCPU · 2048 MiB",
  );
  await submit(user);
  await form.findByText(enSandboxes.problem.generic);
  const first = calls("createSandbox")[0]?.input;
  expect(first).not.toHaveProperty("cpuCount");
  expect(first).not.toHaveProperty("memoryMiB");
  expect(first).not.toHaveProperty("diskGiB");
  server.current.templates = [
    fakeTemplate({ cpuCount: 8, memoryMiB: 8192, defaultDiskGiB: 128, minDiskGiB: 8 }),
  ];
  await act(() => client.invalidateQueries({ queryKey: ["sandboxTemplates"] }));
  await waitFor(() =>
    expect(form.getByLabelText(enSandboxes.create.revision).textContent).toContain(
      "8 vCPU · 8192 MiB",
    ),
  );
  await submit(user);
  await waitFor(() => expect(navigate).toHaveBeenCalled());
  expect(calls("createSandbox")[1]?.input).toEqual(first);
  expect(server.current.sandboxes).toHaveLength(1);
  expect(server.current.sandboxes[0]).toMatchObject({ cpuCount: 2, memoryMiB: 2048, diskGiB: 48 });
});

it.each(["en-US", "es-MX"])(
  "%s creates a partial override and displays the actual allocation",
  async (lang) => {
    server.current.templates = [fakeTemplate({ cpuCount: 2, memoryMiB: 2048 })];
    const user = userEvent.setup();
    await mount(lang);
    const copy = lang === "en-US" ? enSandboxes : esSandboxes;
    await user.click(await screen.findByRole("button", { name: copy.create.action }));
    const form = within(dialog());
    await selectOption(user, form.getByLabelText(copy.create.template), /^Ubuntu \(ubuntu\)/);
    await selectOption(user, form.getByLabelText(copy.create.host), /^Alpha \(alpha\)/);
    await user.type(form.getByLabelText(copy.create.memoryMiB), "3072");
    await user.type(form.getByLabelText(copy.create.diskGiB), "40");
    await user.click(form.getByRole("button", { name: copy.create.submit }));
    await waitFor(() => expect(navigate).toHaveBeenCalled());
    const input = calls("createSandbox")[0]?.input;
    expect(input).toMatchObject({ memoryMiB: 3072, diskGiB: 40 });
    expect(input).not.toHaveProperty("cpuCount");
    await waitFor(() =>
      expect(document.querySelector("[data-sandbox-allocation]")?.textContent).toBe(
        "2 vCPU · 3072 MiB · 40 GiB",
      ),
    );
  },
);
