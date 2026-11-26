// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import enTerminal from "@wssp/locales/src/en-US/terminal.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esHosts from "@wssp/locales/src/es-MX/hosts.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import esTerminal from "@wssp/locales/src/es-MX/terminal.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/** The Terminals page against a scripted fake server, real Query and i18n. */

type Terminal = {
  id: string;
  status: "attached" | "connecting";
  openedAt: Date;
  lastActivityAt: Date;
  thisBrowser: boolean;
  device: { browser: string | null; os: string | null };
  target:
    | { kind: "sandbox"; id: string; name: string | null; state: string | null }
    | { kind: "host"; id: string; name: string | null; status: string | null };
};

const server = vi.hoisted(() => ({
  terminals: [] as unknown[],
  sandboxes: [] as { id: string; name: string; state: string }[],
  hosts: [] as Record<string, unknown>[],
  calls: [] as { procedure: string; input: unknown }[],
  endError: null as unknown,
  sandboxesError: null as unknown,
}));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://api.example.test" } }));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirectOnError: () => {} }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
    hash,
    ...rest
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: Record<string, string>;
    hash?: string;
    "aria-label"?: string;
  }) => {
    let href = to;
    for (const [key, value] of Object.entries(params ?? {})) href = href.replace(`$${key}`, value);
    return (
      <a
        className={className}
        href={hash ? `${href}#${hash}` : href}
        aria-label={rest["aria-label"]}
      >
        {children}
      </a>
    );
  },
}));
vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  return {
    orpc: {
      terminals: {
        list: {
          key: () => ["terminals", "list"],
          queryOptions: () => ({
            queryKey: ["terminals", "list"],
            queryFn: async () => {
              record("terminals.list", undefined);
              return { terminals: structuredClone(server.terminals), truncated: false };
            },
          }),
        },
        hostTargets: {
          queryOptions: () => ({
            queryKey: ["terminals", "hostTargets"],
            queryFn: async () => {
              record("terminals.hostTargets", undefined);
              return { hosts: structuredClone(server.hosts), more: false };
            },
          }),
        },
        end: {
          mutationOptions: () => ({
            mutationFn: async (input: { id: string }) => {
              record("terminals.end", input);
              if (server.endError) throw server.endError;
              server.terminals = server.terminals.filter((t) => (t as Terminal).id !== input.id);
              return { ended: true };
            },
          }),
        },
      },
      sandboxes: {
        list: {
          queryOptions: ({ input }: { input: unknown }) => ({
            queryKey: ["sandboxes", "list", input],
            queryFn: async () => {
              record("sandboxes.list", input);
              if (server.sandboxesError) throw server.sandboxesError;
              return { items: structuredClone(server.sandboxes), nextCursor: null };
            },
          }),
        },
      },
    },
  };
});

const { TerminalsPage } = await import("./terminals-page");

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "hosts", "sandboxes", "terminal"],
    defaultNS: "common",
    resources: {
      "en-US": {
        common: enCommon,
        dashboard: enDashboard,
        hosts: enHosts,
        sandboxes: enSandboxes,
        terminal: enTerminal,
      },
      "es-MX": {
        common: esCommon,
        dashboard: esDashboard,
        hosts: esHosts,
        sandboxes: esSandboxes,
        terminal: esTerminal,
      },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

const minutesAgo = (n: number) => new Date(Date.now() - n * 60_000);
const sandboxTerminal = (overrides: Partial<Terminal> = {}): Terminal => ({
  id: `bt_${"a".repeat(32)}`,
  status: "attached",
  openedAt: minutesAgo(30),
  lastActivityAt: minutesAgo(2),
  thisBrowser: false,
  device: { browser: "Firefox", os: "Linux" },
  target: { kind: "sandbox", id: "sbx-1", name: "dev-box", state: "READY" },
  ...overrides,
});
const hostTerminal = (): Terminal => ({
  id: `bt_${"b".repeat(32)}`,
  status: "connecting",
  openedAt: minutesAgo(1),
  lastActivityAt: minutesAgo(1),
  thisBrowser: true,
  device: { browser: "Chrome", os: "macOS" },
  target: { kind: "host", id: "host-1", name: "halo", status: "CONNECTED" },
});
const host = (overrides: Record<string, unknown> = {}) => ({
  id: "host-1",
  label: "halo",
  status: "CONNECTED",
  lastConnectedAt: minutesAgo(5),
  lastHeartbeatAt: new Date(),
  deletionRequestedAt: null,
  quarantinedAt: null,
  hostTerminal: true,
  ...overrides,
});

function mount(kind: "all" | "sandbox" | "host" = "all", onKindChange = vi.fn()) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <TerminalsPage lang="en-US" kind={kind} onKindChange={onKindChange} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return onKindChange;
}

const page = enTerminal.page;
const row = (id: string) => document.querySelector<HTMLElement>(`li[data-terminal-id="${id}"]`);

beforeEach(async () => {
  await i18n.changeLanguage("en-US");
  server.terminals = [];
  server.sandboxes = [];
  server.hosts = [];
  server.calls = [];
  server.endError = null;
  server.sandboxesError = null;
  toast.success.mockReset();
  toast.error.mockReset();
});
afterEach(() => cleanup());

describe("Terminals page", () => {
  it("empty: says how to open the first terminal and links to the picker", async () => {
    server.sandboxes = [{ id: "sbx-1", name: "dev-box", state: "READY" }];
    mount();
    expect(await screen.findByText(page.empty.title)).toBeTruthy();
    expect(screen.getByText(page.empty.description.all)).toBeTruthy();
    // One New terminal button (the header); the picker is right below the empty state.
    const newLinks = screen
      .getAllByRole("link", { name: page.new })
      .map((a) => a.getAttribute("href"));
    expect(newLinks).toEqual(["/en-US/dashboard/terminals#new-terminal"]);
    // The picker offers the running sandbox, opening at its terminal.
    const open = await screen.findByRole("link", { name: "Open a terminal on dev-box" });
    expect(open.getAttribute("href")).toBe("/en-US/dashboard/sandboxes/sbx-1#terminal");
    expect(server.calls).toContainEqual({
      procedure: "sandboxes.list",
      input: { limit: 20, states: ["READY"] },
    });
  });

  it("lists each terminal with target, state, device, times and status", async () => {
    server.terminals = [sandboxTerminal(), hostTerminal()];
    mount();
    await waitFor(() => expect(row(`bt_${"a".repeat(32)}`)).toBeTruthy());
    const sandboxRow = within(row(`bt_${"a".repeat(32)}`)!);
    expect(sandboxRow.getByRole("link", { name: "dev-box" }).getAttribute("href")).toBe(
      "/en-US/dashboard/sandboxes/sbx-1#terminal",
    );
    expect(sandboxRow.getByText("Sandbox · Ready")).toBeTruthy();
    expect(sandboxRow.getByText("Firefox on Linux")).toBeTruthy();
    expect(sandboxRow.getByText("Attached")).toBeTruthy();
    expect(sandboxRow.getByText("30 minutes ago")).toBeTruthy();
    expect(sandboxRow.getByText("2 minutes ago")).toBeTruthy();
    const hostRow = within(row(`bt_${"b".repeat(32)}`)!);
    expect(hostRow.getByText("Host · Connected")).toBeTruthy();
    expect(hostRow.getByText(page.thisBrowser)).toBeTruthy();
    expect(hostRow.getByText("Connecting")).toBeTruthy();
    expect(
      hostRow.getByRole("link", { name: "Open the terminal on halo here" }).getAttribute("href"),
    ).toBe("/en-US/settings/hosts/host-1#terminal");
  });

  it("filters by kind and reports the change for the URL", async () => {
    server.terminals = [sandboxTerminal(), hostTerminal()];
    const user = userEvent.setup();
    const onKindChange = mount("host");
    await waitFor(() => expect(row(`bt_${"b".repeat(32)}`)).toBeTruthy());
    expect(row(`bt_${"a".repeat(32)}`)).toBeNull();
    // The host filter never asks for sandboxes.
    expect(server.calls.some((c) => c.procedure === "sandboxes.list")).toBe(false);
    await user.click(screen.getByRole("button", { name: page.filter.sandbox }));
    expect(onKindChange).toHaveBeenCalledWith("sandbox");
  });

  it("a filter with nothing open says so, distinct from no terminals at all", async () => {
    server.terminals = [hostTerminal()];
    mount("sandbox");
    expect(await screen.findByText(page.emptyFiltered)).toBeTruthy();
  });

  it("End asks first, then ends exactly that terminal and refreshes", async () => {
    server.terminals = [sandboxTerminal()];
    const user = userEvent.setup();
    mount();
    const id = `bt_${"a".repeat(32)}`;
    await waitFor(() => expect(row(id)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: "End the terminal on dev-box" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText("End the terminal on dev-box?")).toBeTruthy();
    expect(within(dialog).getByText(/opened from Firefox on Linux closes/)).toBeTruthy();
    expect(server.calls.some((c) => c.procedure === "terminals.end")).toBe(false);
    await user.click(within(dialog).getByRole("button", { name: page.end.confirm }));
    await waitFor(() =>
      expect(server.calls).toContainEqual({ procedure: "terminals.end", input: { id } }),
    );
    await waitFor(() => expect(row(id)).toBeNull());
    expect(toast.success).toHaveBeenCalledWith(page.end.done);
  });

  it("Cancel ends nothing", async () => {
    server.terminals = [sandboxTerminal()];
    const user = userEvent.setup();
    mount();
    await waitFor(() => expect(row(`bt_${"a".repeat(32)}`)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: "End the terminal on dev-box" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: enCommon.actions.cancel,
      }),
    );
    expect(server.calls.some((c) => c.procedure === "terminals.end")).toBe(false);
  });

  it("a terminal that closed meanwhile is reported as already gone, not as a failure", async () => {
    server.terminals = [sandboxTerminal()];
    server.endError = Object.assign(new Error("gone"), { code: "NOT_FOUND" });
    const user = userEvent.setup();
    mount();
    await waitFor(() => expect(row(`bt_${"a".repeat(32)}`)).toBeTruthy());
    await user.click(screen.getByRole("button", { name: "End the terminal on dev-box" }));
    await user.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", {
        name: page.end.confirm,
      }),
    );
    await waitFor(() => expect(toast.success).toHaveBeenCalledWith(page.end.alreadyGone));
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("the picker says which host is offline and how to start it, and marks open targets", async () => {
    server.terminals = [hostTerminal()];
    server.hosts = [
      host(),
      host({
        id: "host-2",
        label: "desk",
        status: "DISCONNECTED",
        lastConnectedAt: minutesAgo(600),
        lastHeartbeatAt: null,
      }),
    ];
    mount("host");
    const desk = await waitFor(() => {
      const el = document.querySelector<HTMLElement>('[data-new-terminal-target="host-2"]');
      expect(el).toBeTruthy();
      return el!;
    });
    expect(
      within(desk).getByText(/Offline · Not connected; start it with wssp host run/),
    ).toBeTruthy();
    expect(within(desk).queryByRole("link")).toBeNull();
    const halo = document.querySelector<HTMLElement>('[data-new-terminal-target="host-1"]')!;
    expect(within(halo).getByText(/A terminal is open here/)).toBeTruthy();
    // Already open there: the button says it starts a new one (ending the other).
    const replace = within(halo).getByRole("link", {
      name: "Open a new terminal on halo (ends the one open there)",
    });
    expect(replace.textContent).toBe(page.replaceOn);
    expect(replace.getAttribute("href")).toBe("/en-US/settings/hosts/host-1#terminal");
  });

  it("a connected host whose live policy is not known yet is never called 'off'", async () => {
    server.hosts = [host({ hostTerminal: null })];
    mount("host");
    const halo = await waitFor(() => {
      const el = document.querySelector<HTMLElement>('[data-new-terminal-target="host-1"]');
      expect(el).toBeTruthy();
      return el!;
    });
    expect(within(halo).getByText(new RegExp(page.hostTerminalUnknown))).toBeTruthy();
    expect(within(halo).queryByText(/is off/)).toBeNull();
    expect(within(halo).queryByRole("link")).toBeNull();
  });

  it("a connected host with host terminals off says so and links to how to turn it on", async () => {
    server.hosts = [
      host({ hostTerminal: false }),
      host({
        id: "host-3",
        label: "away",
        hostTerminal: null,
        status: "DISCONNECTED",
        lastConnectedAt: minutesAgo(600),
        lastHeartbeatAt: null,
      }),
    ];
    mount("host");
    const halo = await waitFor(() => {
      const el = document.querySelector<HTMLElement>('[data-new-terminal-target="host-1"]');
      expect(el).toBeTruthy();
      return el!;
    });
    expect(within(halo).getByText(/Connected · Host terminal is off at this host/)).toBeTruthy();
    const help = within(halo).getByRole("link");
    expect(help.textContent).toBe(page.howToTurnOn);
    expect(help.getAttribute("href")).toBe("/en-US/settings/hosts/host-1#terminal");
    expect(within(halo).queryByRole("link", { name: /Open a terminal/ })).toBeNull();
    // Offline wins: the person must start the daemon first.
    const away = document.querySelector<HTMLElement>('[data-new-terminal-target="host-3"]')!;
    expect(within(away).getByText(/start it with wssp host run/)).toBeTruthy();
    expect(within(away).queryByRole("link")).toBeNull();
    // The filtered empty state names only hosts.
    expect(screen.queryByText(/Can't tell yet/)).toBeNull();
    expect(screen.getByText(page.empty.description.host)).toBeTruthy();
  });

  it("a failed first load of the picker offers retry, never 'no sandbox is running'", async () => {
    server.sandboxesError = new Error("network");
    mount("sandbox");
    await waitFor(() =>
      expect(server.calls.some((c) => c.procedure === "sandboxes.list")).toBe(true),
    );
    expect(await screen.findAllByText(enDashboard.list.loadFailed)).toHaveLength(1);
    expect(screen.queryByText(page.noSandboxes)).toBeNull();
  });

  it("es-MX has every page string", () => {
    const keys = (value: unknown, prefix = ""): string[] =>
      value && typeof value === "object"
        ? Object.entries(value).flatMap(([k, v]) => keys(v, `${prefix}${k}.`))
        : [prefix];
    expect(keys(esTerminal.page)).toEqual(keys(enTerminal.page));
  });
});
