import { selectOption } from "@/test/select-option";

vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esDashboard from "@wssp/locales/src/es-MX/dashboard.json";
import esOperations from "@wssp/locales/src/es-MX/operations.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { OperationsSearch } from "@/lib/operation-rules";
import { type FakeSandboxServer, newFakeSandboxServer, operationRow } from "@/test/sandbox-fake";

/**
 * The operations list against a scripted fake server (real TanStack Query
 * and i18n): rows carry status metadata only, filters come from (and go
 * back to) the URL search, the empty state tells an empty account from an
 * over-narrow filter, and the rendered row count stops at a fixed cap.
 */

const server = vi.hoisted(() => ({ current: null as unknown as FakeSandboxServer }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({
    children,
    className,
    to,
    params,
    "aria-label": ariaLabel,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: Record<string, string>;
    "aria-label"?: string;
  }) => (
    <a
      className={className}
      aria-label={ariaLabel}
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

import { OPERATIONS_MAX_ROWS, OperationsPage } from "./operations-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

const instances: Record<string, I18n> = {};
beforeAll(async () => {
  for (const [lang, resources] of [
    ["en-US", { common: enCommon, dashboard: enDashboard, operations: enOperations }],
    ["es-MX", { common: esCommon, dashboard: esDashboard, operations: esOperations }],
  ] as const) {
    const i18n = createInstance();
    await i18n.init({
      lng: lang,
      fallbackLng: false,
      ns: ["common", "dashboard", "operations"],
      defaultNS: "common",
      resources: { [lang]: resources },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
    });
    instances[lang] = i18n;
  }
});

const onSearchChange = vi.fn<(next: OperationsSearch) => void>();
function mount(search: OperationsSearch = {}, lang = "en-US") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={instances[lang]!}>
        <OperationsPage lang={lang} search={search} onSearchChange={onSearchChange} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const calls = (procedure: string) =>
  server.current.calls.filter((call) => call.procedure === procedure);
const rows = () => document.querySelectorAll("tr[data-operation-id]");

beforeEach(() => {
  server.current = newFakeSandboxServer();
  onSearchChange.mockReset();
});
afterEach(() => {
  cleanup();
});

describe("operations list", () => {
  it("an account with no operations is told where operations come from", async () => {
    mount();
    expect(await screen.findByText(enOperations.empty.title)).toBeTruthy();
    expect(screen.getByRole("link", { name: enOperations.empty.action }).getAttribute("href")).toBe(
      "/en-US/dashboard/sandboxes",
    );
    expect(calls("listOperations")).toEqual([
      { procedure: "listOperations", input: { limit: 50 } },
    ]);
  });

  it("es-MX: the empty state is localized", async () => {
    mount({}, "es-MX");
    expect(await screen.findByText(esOperations.empty.title)).toBeTruthy();
  });

  it("rows show type, status, sandbox, exit code or typed error, and link to the operation", async () => {
    server.current.operations = [
      operationRow({ id: "op-a", state: "SUCCEEDED", exitCode: 7, completedAt: new Date() }),
      operationRow({
        id: "op-b",
        kind: "GET_FILE",
        state: "FAILED",
        errorCode: "not_found",
        sandboxId: "sbx-gone",
        sandboxName: "gone-otter",
        sandboxState: "DELETED",
        completedAt: new Date(),
      }),
      operationRow({ id: "op-c", kind: "CREATE_SANDBOX", state: "UNKNOWN_OUTCOME" }),
    ];
    mount();
    await waitFor(() => expect(rows()).toHaveLength(3));
    const [a, b, c] = [...rows()] as HTMLElement[];
    expect(a!.textContent).toContain(enOperations.kind.RUN_COMMAND);
    expect(a!.textContent).toContain("Exit 7");
    expect(a!.querySelector("[data-operation-state]")?.textContent).toBe(
      enOperations.state.SUCCEEDED,
    );
    expect(b!.textContent).toContain(enOperations.error.not_found);
    expect(b!.querySelector("[data-sandbox-deleted]")).not.toBeNull();
    expect(c!.textContent).toContain(enOperations.state.UNKNOWN_OUTCOME);
    expect(screen.getByRole("link", { name: "Open operation op-a" }).getAttribute("href")).toBe(
      "/en-US/dashboard/operations/op-a",
    );
    // The sandbox is linked by its name; the link still targets its id.
    expect(screen.getByRole("link", { name: "gone-otter" }).getAttribute("href")).toBe(
      "/en-US/dashboard/sandboxes/sbx-gone",
    );
    // M7-S7: text cells and the 44 px link cells share one vertical alignment.
    for (const cell of a!.querySelectorAll("td")) {
      expect(cell.className).toContain("align-middle");
      expect(cell.className).not.toContain("align-top");
    }
  });

  it("reads with the URL's filters and writes filter changes back to the URL", async () => {
    server.current.operations = [
      operationRow({ id: "op-a", sandboxId: "sbx-2", state: "RUNNING" }),
      operationRow({ id: "op-b", sandboxId: "sbx-3", state: "RUNNING" }),
    ];
    const user = userEvent.setup();
    mount({ sandboxId: "sbx-2", state: "active" });
    await waitFor(() => expect(rows()).toHaveLength(1));
    expect(calls("listOperations")[0]?.input).toEqual({
      limit: 50,
      sandboxId: "sbx-2",
      state: "active",
    });
    expect(document.querySelector("[data-sandbox-filter]")?.textContent).toBe("Sandbox sbx-2");

    await selectOption(
      user,
      screen.getByLabelText(enOperations.filter.kind),
      enOperations.kind.RUN_COMMAND,
    );
    expect(onSearchChange).toHaveBeenLastCalledWith({
      sandboxId: "sbx-2",
      state: "active",
      kind: "RUN_COMMAND",
    });
    await selectOption(
      user,
      screen.getByLabelText(enOperations.filter.state),
      enOperations.filter.allStates,
    );
    expect(onSearchChange).toHaveBeenLastCalledWith({ sandboxId: "sbx-2", state: undefined });
    await user.click(screen.getByRole("button", { name: enOperations.filter.clearSandbox }));
    expect(onSearchChange).toHaveBeenLastCalledWith({ sandboxId: undefined, state: "active" });
  });

  it("an over-narrow filter says nothing matches, without the first-run link", async () => {
    server.current.operations = [operationRow({ state: "SUCCEEDED" })];
    mount({ state: "FAILED" });
    expect(await screen.findByText(enOperations.empty.filteredTitle)).toBeTruthy();
    expect(screen.queryByRole("link", { name: enOperations.empty.action })).toBeNull();
  });

  it("a failed load shows a retry that recovers", async () => {
    server.current.operations = [operationRow()];
    server.current.errors.listOperations = [new Error("network")];
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: enCommon.actions.tryAgain }));
    await waitFor(() => expect(rows()).toHaveLength(1));
  });

  it("renders at most the row cap and then asks for a narrower filter", async () => {
    server.current.operations = Array.from({ length: OPERATIONS_MAX_ROWS + 60 }, (_, index) =>
      operationRow({ id: `op-${index}`, state: "SUCCEEDED", completedAt: new Date() }),
    );
    const user = userEvent.setup();
    mount();
    await waitFor(() => expect(rows()).toHaveLength(50));
    while (screen.queryByRole("button", { name: enCommon.actions.loadMore })) {
      const before = rows().length;
      await user.click(screen.getByRole("button", { name: enCommon.actions.loadMore }));
      await waitFor(() => expect(rows().length).toBeGreaterThan(before));
    }
    expect(rows()).toHaveLength(OPERATIONS_MAX_ROWS);
    expect(document.querySelector("[data-row-cap]")?.textContent).toBe(
      enOperations.rowCap_other.replace("{{count}}", String(OPERATIONS_MAX_ROWS)),
    );
  });
});

it.each(["en-US", "es-MX"])("%s explains canonical missing-image operations", async (lang) => {
  server.current.operations = [
    operationRow({
      kind: "CREATE_SANDBOX",
      state: "FAILED",
      errorCode: "sandbox.template_image_missing",
      completedAt: new Date(),
    }),
  ];
  mount({}, lang);
  const copy = lang === "en-US" ? enOperations : esOperations;
  expect(await screen.findByText(copy.error["sandbox.template_image_missing"])).toBeTruthy();
});
