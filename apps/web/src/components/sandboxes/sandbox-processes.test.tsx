// @vitest-environment jsdom
import { readFileSync } from "node:fs";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import {
  type EntryInfo,
  FS_PROCESS_LIMITS,
  type OperationErrorCode,
} from "@wssp/api/sandbox/contracts";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esOperations from "@wssp/locales/src/es-MX/operations.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { observationProblem } from "@/hooks/use-sandbox-observation";
import {
  coded,
  completeFakeCommand,
  type FakeSandboxServer,
  newFakeSandboxServer,
  operationRow,
} from "@/test/sandbox-fake";

const authority = vi.hoisted(() => ({ impersonatedBy: null as string | null }));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: {
      status: "authenticated",
      session: { session: { impersonatedBy: authority.impersonatedBy } },
    },
  }),
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
const fake = vi.hoisted(() => ({ current: null as unknown as FakeSandboxServer }));
vi.mock("@/utils/orpc", async () => {
  const { fakeSandboxOrpc } = await import("@/test/sandbox-fake");
  return {
    orpc: new Proxy(
      {},
      {
        get: (_, key) => (fakeSandboxOrpc(fake.current) as Record<string, unknown>)[key as string],
      },
    ),
  };
});
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => vi.fn() }));

import { SandboxFiles } from "./sandbox-files";
import { SandboxProcesses } from "./sandbox-processes";

const REF = { sandboxId: "sbx", generation: 1, processId: "tracked-process", attempt: 1, pid: 42 };
const argvText = (cmd: string, args: string[]) =>
  [cmd, ...args].map((arg) => JSON.stringify(arg)).join(" ");
const hostile = "<img src=x onerror=alert(1)> ñ 雪 é";
const info = {
  process: REF,
  operationId: "command",
  cmd: hostile,
  args: ["<script>bad()</script>", "🧪"],
  argsTruncated: true,
  cwd: "/",
  kind: "command",
  startedAt: new Date().toISOString(),
  observedAt: new Date().toISOString(),
};
const entry: EntryInfo = {
  name: hostile,
  path: `/${hostile}`,
  type: "symlink",
  size: 7,
  mode: 511,
  permissions: "rwxrwxrwx",
  uid: 1000,
  gid: 1000,
  owner: null,
  group: null,
  modifiedTime: null,
  symlinkTarget: "<svg onload=bad()>",
};
const processPage = (items = [info], nextCursor: string | null = null) => ({
  outcome: "succeeded",
  result: {
    type: "process.list",
    items: [...items].sort((a, b) =>
      a.process.processId < b.process.processId
        ? -1
        : a.process.processId > b.process.processId
          ? 1
          : 0,
    ),
    consistency: "live",
    nextCursor,
  },
});
const filePage = (items = [entry], nextCursor: string | null = null) => ({
  outcome: "succeeded",
  result: { type: "file.list", path: "/", depth: 1, consistency: "live", items, nextCursor },
});
const calls = (name: string) => fake.current.calls.filter((c) => c.procedure === name);
let client: QueryClient;
let instance: ReturnType<typeof createInstance>;
async function mount(panel: "files" | "processes" = "processes", lang = "en-US") {
  instance = createInstance();
  await instance.init({
    lng: lang,
    fallbackLng: false,
    resources: {
      "en-US": { common: enCommon, sandboxes: enSandboxes, operations: enOperations },
      "es-MX": { common: esCommon, sandboxes: esSandboxes, operations: esOperations },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={instance}>
        {panel === "files" ? (
          <SandboxFiles sandboxId="sbx" lang={lang} />
        ) : (
          <SandboxProcesses sandboxId="sbx" available />
        )}
      </I18nextProvider>
    </QueryClientProvider>,
  );
}
beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: true,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  fake.current = newFakeSandboxServer();
  authority.impersonatedBy = null;
});
afterEach(() => {
  cleanup();
  client?.clear();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});
async function refresh(panel: "files" | "processes" = "processes") {
  await userEvent.click(
    await screen.findByRole("button", {
      name: panel === "files" ? "Refresh files" : "Refresh processes",
    }),
  );
}

it("uses skipToken before an explicit max-limit refresh, replaces pages and renders hostile argv literally", async () => {
  fake.current.observationResults = [
    processPage(
      Array.from({ length: 25 }, (_, i) => ({
        ...info,
        process: { ...REF, processId: `process-${i}`, pid: i + 2 },
      })),
      "next",
    ),
    processPage([{ ...info, cmd: "second-page" }]),
  ];
  await mount();
  await screen.findByRole("button", { name: "Refresh processes" });
  expect(calls("getOperationResult")).toHaveLength(0);
  expect(calls("listProcesses")).toHaveLength(0);
  await refresh();
  await screen.findByRole("button", { name: "Next page" });
  expect(screen.getAllByRole("button", { name: "View output" })).toHaveLength(25);
  expect(calls("listProcesses")).toHaveLength(1);
  expect(calls("listProcesses")[0]?.input).toMatchObject({ limit: FS_PROCESS_LIMITS.listMaxLimit });
  expect(document.querySelector("script, img, svg[onload]")).toBeNull();
  expect(screen.getAllByText(argvText(hostile, info.args))).toHaveLength(25);
  for (const signal of ["Send TERM", "Send INT", "Send HUP"])
    expect(screen.queryByRole("button", { name: signal })).toBeNull();
  expect(screen.getAllByRole("button", { name: "Kill command" })).toHaveLength(25);
  await userEvent.click(screen.getByRole("button", { name: "Next page" }));
  await screen.findByText(argvText("second-page", info.args));
  expect(screen.getAllByRole("button", { name: "View output" })).toHaveLength(1);
  expect(calls("listProcesses")[1]?.input).toMatchObject({ cursor: "next", limit: 100 });
});

it.each([true, false])(
  "files preserve keyboard details and focus return (desktop: %s)",
  async (desktop) => {
    vi.stubGlobal("matchMedia", () => ({
      matches: desktop,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }));
    fake.current.observationResults = [
      filePage([entry], "files-next"),
      filePage([{ ...entry, name: "last", path: "/last" }]),
    ];
    await mount("files");
    expect(calls("getOperationResult")).toHaveLength(0);
    await refresh("files");
    const row = await screen.findByRole("button", { name: hostile });
    row.focus();
    await userEvent.keyboard("{Enter}");
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText(entry.symlinkTarget!)).toBeTruthy();
    expect(within(dialog).getByText("Symbolic link")).toBeTruthy();
    expect(dialog.getAttribute("data-slot")).toBe(desktop ? "dialog-content" : "drawer-content");
    expect(within(dialog).getAllByRole("button", { name: "Close" })).toHaveLength(desktop ? 2 : 1);
    expect(document.querySelector("img, svg[onload]")).toBeNull();
    await userEvent.keyboard("{Escape}");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(row);
    expect(calls("listDir")[0]?.input).toMatchObject({ path: "/", depth: 1, limit: 100 });
    await userEvent.click(screen.getByRole("button", { name: "Next page" }));
    await screen.findByRole("button", { name: "last" });
    expect(screen.queryByRole("button", { name: hostile })).toBeNull();
    expect(calls("listDir")[1]?.input).toMatchObject({ cursor: "files-next", limit: 100 });
  },
);

it("derives enabled controls from supportedSignals and preserves stale-client typed refusal without cancel", async () => {
  fake.current.supportedSignals = ["SIGTERM", "SIGINT", "SIGHUP", "SIGKILL"];
  fake.current.observationResults = [processPage()];
  fake.current.errors.signalProcess = [coded("signal_unsupported_on_guest")];
  await mount();
  await refresh();
  for (const name of ["Send TERM", "Send INT", "Send HUP", "Kill command"])
    expect(await screen.findByRole("button", { name })).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: "Send TERM" }));
  await screen.findByText(enSandboxes.observations.signalUnsupported);
  expect(calls("signalProcess")).toHaveLength(1);
  expect(calls("killProcess")).toHaveLength(0);
  expect(calls("cancelOperation")).toHaveLength(0);
});

it("requires typing before kill and shows ACCEPTED and UNKNOWN without inferring killed or retry", async () => {
  fake.current.operations.push(
    operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId }),
  );
  fake.current.observationResults = [processPage()];
  await mount();
  await refresh();
  await userEvent.click(await screen.findByRole("button", { name: "Kill command" }));
  const dialog = await screen.findByRole("alertdialog");
  const confirm = within(dialog).getByRole("button", { name: "Confirm kill" }) as HTMLButtonElement;
  expect(confirm.disabled).toBe(true);
  await userEvent.type(within(dialog).getByRole("textbox"), "wrong");
  expect(confirm.disabled).toBe(true);
  await userEvent.clear(within(dialog).getByRole("textbox"));
  await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
  expect(confirm.disabled).toBe(false);
  await userEvent.click(confirm);
  await waitFor(() => expect(calls("killProcess")).toHaveLength(1));
  const control = fake.current.operations[0]!;
  control.state = "ACCEPTED";
  await act(async () => {
    await client.refetchQueries();
  });
  await waitFor(() =>
    expect(
      document
        .querySelector("[data-process-control-state]")
        ?.getAttribute("data-process-control-state"),
    ).toBe("CANCEL_REQUESTED"),
  );
  expect(screen.getByText(/Acceptance is not proof of termination/)).toBeTruthy();
  expect(screen.queryByText(/^Killed$/)).toBeNull();
  control.state = "UNKNOWN_OUTCOME";
  await act(async () => {
    await client.refetchQueries();
  });
  await screen.findByText(enSandboxes.observations.unknown);
  expect(screen.queryByRole("button", { name: /retry/i })).toBeNull();
  expect(calls("killProcess")).toHaveLength(1);
});

it.each(["files", "processes"] as const)(
  "%s pending Skeleton and unknown never render an empty success",
  async (panel) => {
    fake.current.observationResults = [{ outcome: "unknown", result: null }];
    const view = await mount(panel);
    await refresh(panel);
    await screen.findByText(enSandboxes.observations.unknown);
    expect(screen.queryByText(enSandboxes.observations.emptyProcesses)).toBeNull();
    expect(screen.queryByText(enSandboxes.observations.emptyFiles)).toBeNull();
    expect(screen.queryByRole("button", { name: /retry/i })).toBeNull();
    fake.current.observationResults = [{ outcome: "pending", result: null }];
    await refresh(panel);
    await waitFor(() =>
      expect(view.container.querySelector('[data-slot="skeleton"]')).toBeTruthy(),
    );
  },
);

it.each([
  ["OPERATION_RESULT_EXPIRED", "expired"],
  ["RESULT_CURSOR_STALE", "stale"],
  ["sandbox.process_unknown_outcome", "unknown"],
  ["TOO_MANY_REQUESTS", "rateLimited"],
  ["FORBIDDEN", "unavailable"],
  ["UNSUPPORTED_CAPABILITY", "unsupported"],
] as const)("%s stays distinct from an empty process page", async (code, state) => {
  fake.current.errors.getOperationResult = [coded(code, code)];
  await mount();
  await refresh();
  await screen.findByText(enSandboxes.observations[state]);
  expect(screen.queryByText(enSandboxes.observations.emptyProcesses)).toBeNull();
  expect(screen.queryByRole("alert")).toBeNull();
});

it.each(["files", "processes"] as const)(
  "%s impersonation and live revocation show translated non-error unavailability and hide payload",
  async (panel) => {
    authority.impersonatedBy = "admin";
    const view = await mount(panel, "es-MX");
    expect(await screen.findByText(esSandboxes.sensitiveAccessUnavailable)).toBeTruthy();
    expect(calls("getSandboxCapabilities")).toHaveLength(0);
    expect(calls("getOperationResult")).toHaveLength(0);
    view.unmount();
    authority.impersonatedBy = null;
    fake.current.observationResults = [panel === "files" ? filePage() : processPage()];
    await mount(panel, "es-MX");
    await userEvent.click(
      await screen.findByRole("button", {
        name: panel === "files" ? "Actualizar archivos" : "Actualizar procesos",
      }),
    );
    await screen.findByText(panel === "files" ? hostile : argvText(hostile, info.args));
    fake.current.errors.getOperationResult = [coded("FORBIDDEN", "FORBIDDEN")];
    await act(async () => {
      await client.refetchQueries();
    });
    await screen.findByText(esSandboxes.observations.unavailable);
    expect(screen.queryByText(hostile)).toBeNull();
    expect(screen.queryByText(argvText(hostile, info.args))).toBeNull();
    expect(screen.queryByRole("alert")).toBeNull();
  },
);

it.each([true, false])(
  "output details preserve reads, literal output and focus (desktop: %s)",
  async (desktop) => {
    vi.stubGlobal("matchMedia", () => ({
      matches: desktop,
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }));
    fake.current.observationResults = [processPage()];
    fake.current.connections = [
      {
        info,
        state: "SUCCEEDED",
        exitCode: 7,
        outputOperationId: "command",
        attempt: 1,
        attachmentCursor: "1_0",
      },
    ];
    fake.current.outputs.set("command", {
      attempt: 1,
      chunks: [{ stream: "stdout", offset: 0, bytes: new TextEncoder().encode(hostile) }],
      gaps: [],
      complete: true,
    });
    await mount();
    await refresh();
    await screen.findByRole("button", { name: "View output" });
    fake.current.operations.push({ id: "command", kind: "RUN_COMMAND", state: "SUCCEEDED" });
    const trigger = screen.getByRole("button", { name: "View output" });
    await userEvent.click(trigger);
    await screen.findByText("Exit 7");
    const log = await screen.findByRole("log");
    expect(log.textContent).toBe(hostile);
    expect(log.querySelector("img")).toBeNull();
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("data-slot")).toBe(desktop ? "dialog-content" : "drawer-content");
    // The footer action stays available in the drawer without a corner X.
    await userEvent.click(within(dialog).getAllByRole("button", { name: "Close" }).at(-1)!);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.activeElement).toBe(trigger);
    expect(calls("connectProcess")[0]?.input).toEqual({ process: REF });
    expect(calls("killProcess")).toHaveLength(0);
    expect(calls("signalProcess")).toHaveLength(0);
  },
);

it("observation classifications and bilingual keys stay closed and in parity", () => {
  expect(observationProblem({ status: 410 })).toBe("expired");
  expect(observationProblem({ code: "OUTPUT_EXPIRED" })).toBe("expired");
  expect(observationProblem({ code: "OPERATION_RESULT_NOT_READY" })).toBe("pending");
  expect(observationProblem(new Error(hostile))).toBe("failed");
  for (const key of ["observations", "entry", "entryType", "signals"] as const)
    expect(Object.keys(enSandboxes[key])).toEqual(Object.keys(esSandboxes[key]));
});

it("panels retain web conventions: no component effects, markup injection, session bypass, or route exports", async () => {
  for (const name of [
    "sandbox-processes.tsx",
    "sandbox-file-list.tsx",
    "sandbox-observation.tsx",
  ]) {
    const source = readFileSync(new URL(name, import.meta.url), "utf8");
    expect(source).not.toMatch(
      /useEffect|dangerouslySetInnerHTML|transition[-]all|\.useSession\(|getSession\(/,
    );
    for (const match of source.matchAll(/className="([^"]*overflow-y-auto[^"]*)"/g))
      expect(match[1]).toContain("overflow-x-");
  }
  fake.current.observationResults = [processPage()];
  await mount();
  await refresh();
  await screen.findByRole("button", { name: "Kill command" });
  expect(screen.getByText("Process tracked-process · generation 1 · attempt 1")).toBeTruthy();
  expect(
    screen.getByText(enSandboxes.observations.startedAtLabel, { selector: "dt" }),
  ).toBeTruthy();
  for (const button of screen.getAllByRole("button"))
    expect(button.className).toMatch(/min-h-11|h-11|min-h-\[44px\]/);
});

it("UNKNOWN command recovery is translated in Spanish with no command retry", async () => {
  fake.current.observationResults = [{ outcome: "unknown", result: null }];
  await mount("processes", "es-MX");
  await userEvent.click(await screen.findByRole("button", { name: "Actualizar procesos" }));
  expect(await screen.findByText(esSandboxes.observations.unknown)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /reintentar|retry/i })).toBeNull();
});

it("navigates only actual directory entries, never symlink targets", async () => {
  fake.current.observationResults = [
    filePage([
      entry,
      { ...entry, type: "dir", name: "child", path: "/child", symlinkTarget: null },
    ]),
    filePage([]),
  ];
  await mount("files");
  await refresh("files");
  const open = await screen.findByRole("button", { name: "Open directory" });
  expect(screen.getAllByRole("button", { name: "Open directory" })).toHaveLength(1);
  await userEvent.click(open);
  await waitFor(() => expect(calls("listDir")).toHaveLength(2));
  expect(calls("listDir")[1]?.input).toMatchObject({ path: "/child", limit: 100 });
  expect((screen.getByLabelText("Directory path") as HTMLInputElement).value).toBe("/child");
});

it.each([
  ["signal_unsupported_on_guest", "signalUnsupported"],
  ["unsupported_capability", "unsupported"],
  ["process_exited", "processExited"],
  ["process_stale", "stale"],
  ["process_not_started", "processNotStarted"],
  ["process_not_found", "processMissing"],
  ["process_cancel_pending", "cancelPending"],
] as const satisfies ReadonlyArray<
  readonly [OperationErrorCode, keyof typeof enSandboxes.observations]
>)("shows a retained %s control refusal with no automatic kill", async (errorCode, state) => {
  fake.current.supportedSignals = ["SIGTERM", "SIGKILL"];
  fake.current.observationResults = [processPage()];
  await mount();
  await refresh();
  await userEvent.click(await screen.findByRole("button", { name: "Send TERM" }));
  await waitFor(() => expect(calls("signalProcess")).toHaveLength(1));
  Object.assign(fake.current.operations[1]!, { state: "FAILED", errorCode });
  await act(async () => {
    await client.refetchQueries();
  });
  expect(await screen.findByText(enSandboxes.observations[state])).toBeTruthy();
  expect(calls("killProcess")).toHaveLength(0);
  expect(calls("cancelOperation")).toHaveLength(0);
});

it.each(["en-US", "es-MX"])(
  "directory path validation is translated and sends no observation (%s)",
  async (lang) => {
    await mount("files", lang);
    const copy = lang === "es-MX" ? esSandboxes : enSandboxes;
    const path = await screen.findByLabelText(copy.observations.directoryPath);
    expect(path.getAttribute("autocomplete")).toBe("off");
    await userEvent.clear(path);
    await userEvent.type(path, "/../bad");
    await userEvent.click(screen.getByRole("button", { name: copy.observations.refreshFiles }));
    expect((await screen.findByRole("alert")).textContent).toBe(copy.files.badPath);
    expect(calls("listDir")).toHaveLength(0);
  },
);

// Adapted from the consumer review's B7-U-1 UI probe: receipt IDs cannot be
// resolved by browser getOperation. Assert the corrected target observation.
it.each(["CANCELLED", "SUCCEEDED", "UNKNOWN_OUTCOME"])(
  "B7-U-1: real kill receipt follows target to %s",
  async (state) => {
    const target = operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId });
    fake.current.operations.push(target);
    fake.current.observationResults = [processPage()];
    await mount();
    await refresh();
    await userEvent.click(await screen.findByRole("button", { name: "Kill command" }));
    const dialog = await screen.findByRole("alertdialog");
    await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
    await userEvent.click(within(dialog).getByRole("button", { name: "Confirm kill" }));
    await waitFor(() => expect(calls("getOperation").length).toBeGreaterThan(0));
    expect(
      calls("getOperation").every(
        (call) => (call.input as { operationId: string }).operationId === "command",
      ),
    ).toBe(true);
    expect(screen.queryByText(enSandboxes.observations.failed)).toBeNull();
    expect(
      document
        .querySelector("[data-process-control-state]")
        ?.getAttribute("data-process-control-state"),
    ).toBe("CANCEL_REQUESTED");
    completeFakeCommand(
      target,
      state === "CANCELLED" ? "cancelled" : state === "SUCCEEDED" ? "succeeded" : "unknown",
    );
    await act(async () => {
      await client.refetchQueries();
    });
    await waitFor(() =>
      expect(
        document
          .querySelector("[data-process-control-state]")
          ?.getAttribute("data-process-control-state"),
      ).toBe(state),
    );
    if (state === "UNKNOWN_OUTCOME")
      expect(await screen.findByText(enSandboxes.observations.unknown)).toBeTruthy();
  },
);

it("guest bidi and multiline names, paths, links, owner/group and argv stay visibly escaped", async () => {
  const name = "invoice\u202Efdp.exe\nPID 1";
  const safeName = "invoice⟨U+202E⟩fdp.exe\\nPID 1";
  fake.current.observationResults = [
    filePage([{ ...entry, name, path: `/${name}`, owner: name, group: name, symlinkTarget: name }]),
  ];
  const files = await mount("files");
  await refresh("files");
  await userEvent.click(await screen.findByRole("button", { name: safeName }));
  const dialog = await screen.findByRole("dialog");
  expect(within(dialog).getAllByText(safeName).length).toBeGreaterThan(1);
  expect(within(dialog).getByText(`/${safeName}`)).toBeTruthy();
  expect(dialog.textContent).not.toContain("\u202E");
  files.unmount();
  client.clear();
  fake.current = newFakeSandboxServer();
  fake.current.observationResults = [
    processPage([{ ...info, cmd: "sh\u202E", args: ["x\nPID 1", "a b", "", "a", "b"] }]),
  ];
  await mount();
  await refresh();
  const argv = await screen.findByText('"sh⟨U+202E⟩" "x\\nPID 1" "a b" "" "a" "b"');
  expect(argv.textContent).not.toContain("\u202E");
  expect(argv.textContent).not.toContain("\n");
});

it.each(["en-US", "es-MX"])(
  "known process refusals use specific translated copy (%s)",
  async (lang) => {
    const copy = lang === "es-MX" ? esSandboxes : enSandboxes;
    for (const [code, state] of [
      ["sandbox.process_exited", "processExited"],
      ["sandbox.process_cancel_pending", "cancelPending"],
      ["sandbox.process_not_started", "processNotStarted"],
      ["sandbox.process_unavailable", "processUnavailable"],
      ["sandbox.process_not_found", "processMissing"],
      ["sandbox.process_stale", "stale"],
    ] as const) {
      fake.current.observationResults = [processPage()];
      fake.current.supportedSignals = ["SIGTERM", "SIGKILL"];
      fake.current.errors.signalProcess = [coded(code)];
      const view = await mount("processes", lang);
      await userEvent.click(
        await screen.findByRole("button", { name: copy.observations.refreshProcesses }),
      );
      await userEvent.click(await screen.findByRole("button", { name: copy.signals.SIGTERM }));
      expect(await screen.findByText(copy.observations[state])).toBeTruthy();
      expect(screen.queryByText(copy.observations.failed)).toBeNull();
      expect(calls("killProcess")).toHaveLength(0);
      view.unmount();
      client.clear();
      fake.current = newFakeSandboxServer();
    }
  },
);

it.each(["files", "processes"] as const)(
  "%s capabilities recover explicitly after disconnect and failed query",
  async (panel) => {
    fake.current.capabilitiesUnavailable = true;
    const view = await mount(panel);
    await screen.findByText(enSandboxes.observations.unavailable);
    fake.current.capabilitiesUnavailable = false;
    fake.current.errors.getSandboxCapabilities = [new Error("network")];
    await userEvent.click(screen.getByRole("button", { name: "Refresh capabilities" }));
    await screen.findByText(enSandboxes.observations.failed);
    await userEvent.click(screen.getByRole("button", { name: "Refresh capabilities" }));
    await screen.findByRole("button", {
      name: panel === "files" ? "Refresh files" : "Refresh processes",
    });
    expect(view.container.querySelector('[data-observation-state="unavailable"]')).toBeNull();
    expect(calls("getSandboxCapabilities")).toHaveLength(3);
  },
);

it("an earlier signal refusal cannot hide a later explicitly confirmed kill", async () => {
  fake.current.supportedSignals = ["SIGTERM", "SIGKILL"];
  fake.current.operations.push(
    operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId }),
  );
  fake.current.observationResults = [processPage()];
  fake.current.errors.signalProcess = [coded("signal_unsupported_on_guest")];
  await mount();
  await refresh();
  await userEvent.click(await screen.findByRole("button", { name: "Send TERM" }));
  await screen.findByText(enSandboxes.observations.signalUnsupported);
  expect(calls("killProcess")).toHaveLength(0);
  await userEvent.click(screen.getByRole("button", { name: "Kill command" }));
  const dialog = await screen.findByRole("alertdialog");
  await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
  await userEvent.click(within(dialog).getByRole("button", { name: "Confirm kill" }));
  await waitFor(() =>
    expect(
      document
        .querySelector("[data-process-control-state]")
        ?.getAttribute("data-process-control-state"),
    ).toBe("CANCEL_REQUESTED"),
  );
  expect(screen.queryByText(enSandboxes.observations.signalUnsupported)).toBeNull();
  expect(calls("killProcess")).toHaveLength(1);
});

// Regression from the correctness r2 review.

it("B7-C r2 probe: a killed target that the server stores as CANCELLED/cancelled is not reported as a failed observation", async () => {
  const target = operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId });
  fake.current.operations.push(target);
  fake.current.observationResults = [processPage()];
  await mount();
  await refresh();
  await userEvent.click(await screen.findByRole("button", { name: "Kill command" }));
  const dialog = await screen.findByRole("alertdialog");
  await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
  await userEvent.click(within(dialog).getByRole("button", { name: "Confirm kill" }));
  await waitFor(() => expect(calls("killProcess")).toHaveLength(1));
  Object.assign(target, { state: "CANCELLED", errorCode: "cancelled" });
  await act(async () => {
    await client.refetchQueries();
  });
  await waitFor(() =>
    expect(
      document
        .querySelector("[data-process-control-state]")
        ?.getAttribute("data-process-control-state"),
    ).toBe("CANCELLED"),
  );
  expect(screen.queryByText(enSandboxes.observations.failed)).toBeNull();
});

// Regression from the consumer r2 review.

it.each([
  ["CANCELLED", "cancelled"],
  ["FAILED", "timeout"],
  ["SUCCEEDED", null],
] as const)("B7-U-9: confirmed kill target %s with real errorCode %s", async (state, errorCode) => {
  const target = operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId });
  fake.current.operations.push(target);
  fake.current.observationResults = [processPage()];
  await mount();
  await refresh();
  await userEvent.click(await screen.findByRole("button", { name: "Kill command" }));
  const dialog = await screen.findByRole("alertdialog");
  await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
  await userEvent.click(within(dialog).getByRole("button", { name: "Confirm kill" }));
  await waitFor(() => expect(calls("getOperation").length).toBeGreaterThan(0));
  completeFakeCommand(
    target,
    state === "CANCELLED" ? "cancelled" : state === "FAILED" ? "timeout" : "succeeded",
    { failure: state === "FAILED" ? { resource: "command", effect: "partial" } : null },
  );
  expect(target.errorCode).toBe(errorCode);
  await act(async () => {
    await client.refetchQueries();
  });
  await waitFor(() =>
    expect(
      document
        .querySelector("[data-process-control-state]")
        ?.getAttribute("data-process-control-state"),
    ).toBe(state),
  );
  expect(screen.queryByText(enSandboxes.observations.failed)).toBeNull();
  expect(screen.queryByText(enSandboxes.observations.unknown)).toBeNull();
  expect(
    await screen.findByText(
      enSandboxes.observations[state === "CANCELLED" ? "killed" : "alreadyExited"],
    ),
  ).toBeTruthy();
});

it("renders all 100 short process rows within the real response cap", async () => {
  const page = processPage(
    Array.from({ length: 100 }, (_, i) => ({
      ...info,
      cmd: "sh",
      args: [],
      argsTruncated: false,
      operationId: `c${i}`,
      process: { ...REF, processId: `p${i.toString().padStart(2, "0")}`, pid: i + 2 },
    })),
  );
  expect(new TextEncoder().encode(JSON.stringify(page)).length).toBeLessThanOrEqual(32 * 1024);
  fake.current.observationResults = [page];
  await mount();
  await refresh();
  await waitFor(() =>
    expect(screen.getAllByRole("button", { name: "View output" })).toHaveLength(100),
  );
  expect(screen.getAllByRole("button", { name: "Kill command" })).toHaveLength(100);
  expect(calls("listProcesses")[0]?.input).toMatchObject({ limit: 100 });
});

it("distinguishes literal backslash-n and newline file names side by side", async () => {
  fake.current.observationResults = [
    filePage([
      { ...entry, name: "a\nb", path: "/a\nb" },
      { ...entry, name: "a\\nb", path: "/a\\nb" },
    ]),
  ];
  await mount("files");
  await refresh("files");
  expect(await screen.findByRole("button", { name: "a\\\\nb" })).toBeTruthy();
  expect(screen.getByRole("button", { name: "a\\nb" })).toBeTruthy();
});

it.each(["en-US", "es-MX"])("open directory labels the true path safely (%s)", async (lang) => {
  const name = "dir\u202E\u2028\u2029\u200B\u200C\u200D\u2060\uFEFF";
  const path = `/${name}`;
  const safe = "/dir⟨U+202E⟩⟨U+2028⟩⟨U+2029⟩⟨U+200B⟩⟨U+200C⟩⟨U+200D⟩⟨U+2060⟩⟨U+FEFF⟩";
  fake.current.observationResults = [
    filePage([{ ...entry, name, path, type: "dir", symlinkTarget: null }]),
    { ...filePage([]), result: { ...filePage([]).result, path } },
  ];
  const copy = lang === "es-MX" ? esSandboxes : enSandboxes;
  await mount("files", lang);
  await userEvent.click(
    await screen.findByRole("button", { name: copy.observations.refreshFiles }),
  );
  await userEvent.click(
    await screen.findByRole("button", { name: copy.observations.openDirectory }),
  );
  await waitFor(() =>
    expect(document.querySelector("[data-current-directory]")?.textContent).toBe(
      copy.observations.currentDirectory.replace("{{path}}", safe),
    ),
  );
  expect(calls("listDir")[1]?.input).toMatchObject({ path });
  expect((screen.getByLabelText(copy.observations.directoryPath) as HTMLInputElement).value).toBe(
    path,
  );
});

it("argv neutralizes separators and invisible Unicode formatting", async () => {
  fake.current.observationResults = [
    processPage([
      { ...info, cmd: "sh\u2028", args: ["a\u2029\u200B\u200C\u200D\u2060\uFEFF\u{E0001}"] },
    ]),
  ];
  await mount();
  await refresh();
  const argv = await screen.findByText(
    '"sh⟨U+2028⟩" "a⟨U+2029⟩⟨U+200B⟩⟨U+200C⟩⟨U+200D⟩⟨U+2060⟩⟨U+FEFF⟩⟨U+E0001⟩"',
  );
  expect(argv.textContent).not.toMatch(/[\p{Cf}\u2028\u2029]/u);
});

it.each(["en-US", "es-MX"])("confirmed kill outcome is translated (%s)", async (lang) => {
  fake.current.operations.push(
    operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId, state: "QUEUED" }),
  );
  fake.current.observationResults = [processPage()];
  const copy = lang === "es-MX" ? esSandboxes : enSandboxes;
  await mount("processes", lang);
  await userEvent.click(
    await screen.findByRole("button", { name: copy.observations.refreshProcesses }),
  );
  await userEvent.click(await screen.findByRole("button", { name: copy.observations.kill }));
  const dialog = await screen.findByRole("alertdialog");
  await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
  await userEvent.click(
    within(dialog).getByRole("button", { name: copy.observations.killConfirm }),
  );
  expect(await screen.findByText(copy.observations.killed)).toBeTruthy();
  expect(screen.queryByText(copy.observations.failed)).toBeNull();
});

it.each([null, "unknown"] as const)(
  "FAILED with %s effect keeps kill termination unknown",
  async (effect) => {
    const target = operationRow({ id: "command", sandboxId: "sbx", processId: REF.processId });
    fake.current.operations.push(target);
    fake.current.observationResults = [processPage()];
    await mount();
    await refresh();
    await userEvent.click(await screen.findByRole("button", { name: "Kill command" }));
    const dialog = await screen.findByRole("alertdialog");
    await userEvent.type(within(dialog).getByRole("textbox"), REF.processId);
    await userEvent.click(within(dialog).getByRole("button", { name: "Confirm kill" }));
    await waitFor(() => expect(calls("getOperation").length).toBeGreaterThan(0));
    completeFakeCommand(target, "timeout", {
      failure: effect ? { resource: "command", effect } : null,
    });
    await act(async () => {
      await client.refetchQueries();
    });
    expect(await screen.findByText(enSandboxes.observations.unknown)).toBeTruthy();
    expect(screen.queryByText(enSandboxes.observations.killed)).toBeNull();
    expect(screen.queryByText(enSandboxes.observations.alreadyExited)).toBeNull();
  },
);
