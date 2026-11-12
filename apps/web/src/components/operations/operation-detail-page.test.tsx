const browserAuthority = vi.hoisted(() => ({ impersonatedBy: null as string | null }));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: {
      status: "authenticated",
      session: { session: { impersonatedBy: browserAuthority.impersonatedBy } },
    },
  }),
}));
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
import enOperations from "@wssp/locales/src/en-US/operations.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import type { OutputTiming } from "@/hooks/use-command-output";
import { PIECE_MAX_COUNT, PIECE_SOFT_CAP } from "@/lib/command-output-buffer";
import {
  appendOutput,
  type FakeOutput,
  type FakeSandboxServer,
  fakeHost,
  newFakeSandboxServer,
  operationRow,
} from "@/test/sandbox-fake";

/**
 * One operation's page against a scripted fake server (real TanStack Query,
 * i18n, dialogs and the real output poller with short timings). The host's
 * progress is simulated by changing the fake's rows and stored output: the
 * page must show output before the command exits, follow the byte cursor
 * without repeating text, mark gaps/truncation/expiry, render output as
 * inert text, keep a cancel pending until the host acknowledges it, keep a
 * deleted sandbox deleted, report a stalled or offline server, and stop all
 * reads when the view is left.
 */

const server = vi.hoisted(() => ({ current: null as unknown as FakeSandboxServer }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
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

import {
  OPERATION_PENDING_REFETCH_MS,
  OPERATION_REFETCH_TIMING,
  OperationDetailPage,
  type OperationRefetchTiming,
} from "./operation-detail-page";

configure({ asyncUtilTimeout: 4_000 });
vi.setConfig({ testTimeout: 20_000 });

const TIMING: OutputTiming = {
  liveMs: 25,
  settledMs: 25,
  requestTimeoutMs: 150,
  maxBackoffMs: 60,
  pagesPerTick: 20,
  settledPolls: 3,
};

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "dashboard", "operations", "sandboxes", "hosts"],
    defaultNS: "common",
    resources: {
      "en-US": {
        common: enCommon,
        dashboard: enDashboard,
        operations: enOperations,
        sandboxes: enSandboxes,
        hosts: enHosts,
      },
    },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

let client: QueryClient;
function tree(operationId: string, refetchTiming?: OperationRefetchTiming) {
  return (
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <OperationDetailPage
          lang="en-US"
          operationId={operationId}
          outputTiming={TIMING}
          refetchTiming={refetchTiming}
        />
      </I18nextProvider>
    </QueryClientProvider>
  );
}
function mount(operationId = "op-1", refetchTiming?: OperationRefetchTiming) {
  client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(tree(operationId, refetchTiming));
}

const calls = (procedure: string) =>
  server.current.calls.filter((call) => call.procedure === procedure);
const op = () => server.current.operations[0]!;
const output = (): FakeOutput => server.current.outputs.get("op-1")!;
const pre = () => document.querySelector<HTMLElement>("[data-output]");
const outputText = () => pre()?.textContent ?? "";
const pill = () =>
  document.querySelector<HTMLElement>("[data-operation-state]")?.dataset.operationState;
const refetch = () =>
  act(async () => {
    await client.refetchQueries();
    await new Promise((resolve) => setTimeout(resolve, 0));
  });
/** Lets `ms` of (fake) time pass: every poll, backoff and stall timer due in it fires. */
const sleep = (ms: number) =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
const MUTATIONS = ["cancelOperation", "runCommand", "killSandbox", "stopSandbox", "createSandbox"];
const mutationCalls = () =>
  server.current.calls.filter((call) => MUTATIONS.includes(call.procedure));

beforeEach(() => {
  // Fake time that still moves on its own, so `sleep` skips its wait instead of sleeping.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  browserAuthority.impersonatedBy = null;
  server.current = newFakeSandboxServer();
  server.current.operations = [operationRow()];
  server.current.outputs.set("op-1", { attempt: 1, chunks: [], gaps: [], complete: false });
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe("reading an operation", () => {
  it.each([401, 403, 404])("hides a previously loaded operation after HTTP %s", async (status) => {
    mount();
    await screen.findByRole("heading", { level: 1 });
    server.current.errors.getOperationView = Array.from({ length: 2 }, () =>
      Object.assign(new Error("denied"), { status }),
    );
    await refetch();
    await waitFor(() => expect(screen.queryByRole("heading", { level: 1 })).toBeNull());
    expect(screen.queryByRole("button", { name: enOperations.cancel.action })).toBeNull();
  });

  it("another owner's (or a missing) operation is a plain not-found, with no cancel or output read", async () => {
    server.current.operations = [];
    mount("op-foreign");
    expect(await screen.findByText(enOperations.detail.notFoundTitle)).toBeTruthy();
    expect(document.querySelector("[data-operation-missing]")).not.toBeNull();
    expect(calls("getOperationView")).toEqual([
      { procedure: "getOperationView", input: { operationId: "op-foreign" } },
    ]);
    expect(screen.queryByRole("button", { name: enOperations.cancel.action })).toBeNull();
    await sleep(60);
    expect(calls("getCommandOutput")).toEqual([]);
  });

  it("shows status, timestamps, the typed error and the host's message as text; no output for a file read", async () => {
    server.current.operations = [
      operationRow({
        kind: "GET_FILE",
        state: "FAILED",
        errorCode: "path_refused",
        errorMessage: "<b>refused</b> /etc/shadow",
        completedAt: new Date(),
      }),
    ];
    mount();
    expect(await screen.findByText(enOperations.error.path_refused)).toBeTruthy();
    expect(pill()).toBe("FAILED");
    const message = document.querySelector("[data-error-message]")!;
    expect(message.textContent).toBe("<b>refused</b> /etc/shadow");
    expect(message.querySelector("b")).toBeNull();
    expect(document.querySelector("[data-output-status]")).toBeNull();
    await sleep(60);
    expect(calls("getCommandOutput")).toEqual([]);
  });
});

describe("operation identity", () => {
  it("keeps the operation ID in a copyable ID row, not the subtitle, and says commands are not stored", async () => {
    server.current.operations = [operationRow({ kind: "RUN_COMMAND", state: "SUCCEEDED" })];
    mount();
    const idRow = await waitFor(() => {
      const field = document.querySelector("[data-copyable-id]");
      expect(field).not.toBeNull();
      return field as HTMLElement;
    });
    const id = server.current.operations[0]!.id as string;
    expect(idRow.textContent).toContain(id.length > 12 ? `${id.slice(0, 8)}…` : id);
    expect(
      within(idRow).getByRole("button", { name: `Copy ${enOperations.detail.fields.id}` }),
    ).toBeTruthy();
    expect(document.querySelector("[data-command-not-stored]")?.textContent).toBe(
      enOperations.detail.commandNotStored,
    );
  });
});

it("names a captured revision slug vN and keeps its exact ID copyable under Advanced", async () => {
  server.current.operations = [
    operationRow({
      kind: "CAPTURE_TEMPLATE",
      state: "SUCCEEDED",
      completedAt: new Date(),
      capturedRevisionId: "rev-captured-123456",
      capturedRevision: { slug: "web", revision: 4 },
    }),
  ];
  mount();
  const field = await waitFor(() => {
    const node = document.querySelector("[data-detail-captured-revision]");
    expect(node).not.toBeNull();
    return node as HTMLElement;
  });
  expect(field.textContent).toBe("web v4");
  const advanced = field.parentElement!.querySelector("details[data-advanced-details]")!;
  expect(advanced.hasAttribute("open")).toBe(false);
  expect(advanced.textContent).toContain("rev-capt…");
  expect(
    within(advanced as HTMLElement).getByRole("button", {
      name: `Copy ${enOperations.detail.fields.capturedRevisionId}`,
    }),
  ).toBeTruthy();
});

describe("incremental output", () => {
  it("output appears while the command still runs, then follows the cursor without repeating", async () => {
    appendOutput(output(), "stdout", "step 1\n");
    mount();
    await waitFor(() => expect(outputText()).toBe("step 1\n"));
    // Still running: no exit code, status straight from the operation read.
    expect(pill()).toBe("RUNNING");
    expect(document.querySelector("[data-detail-exit-code]")?.textContent).toBe("—");
    expect(screen.getByText(enOperations.output.live)).toBeTruthy();

    appendOutput(output(), "stderr", "warn\n");
    appendOutput(output(), "stdout", "step 2\n");
    await waitFor(() => expect(outputText()).toBe("step 1\nwarn\nstep 2\n"));
    const cursors = calls("getCommandOutput").map(
      (call) => (call.input as { cursor?: string }).cursor,
    );
    expect(cursors[0]).toBeUndefined();
    expect(cursors).toContain("1_7");
    expect(document.querySelector('[data-output-stream="stderr"]')?.textContent).toBe("warn\n");

    // The host finishes: the status read (not the output) says so.
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0, completedAt: new Date() });
    output().complete = true;
    await refetch();
    await waitFor(() =>
      expect(
        document.querySelector("[data-output-status]")?.getAttribute("data-output-status"),
      ).toBe("complete"),
    );
    expect(pill()).toBe("SUCCEEDED");
    expect(document.querySelector("[data-detail-exit-code]")?.textContent).toBe("0");
    expect(outputText()).toBe("step 1\nwarn\nstep 2\n");
  });

  it("gaps and truncation are explicit, and the page follows hasMore across pages", async () => {
    const out = output();
    out.pageLimit = 1;
    out.chunks.push({ stream: "stdout", offset: 0, bytes: new TextEncoder().encode("HEAD") });
    out.gaps.push({ start: 4, end: 5_000_004 });
    out.chunks.push({
      stream: "stdout",
      offset: 5_000_004,
      bytes: new TextEncoder().encode("TAIL"),
    });
    out.complete = true;
    out.truncated = true;
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0, completedAt: new Date() });
    mount();
    await waitFor(() => expect(outputText()).toContain("TAIL"));
    const gap = document.querySelector("[data-output-gap]")!;
    expect(gap.getAttribute("data-output-gap")).toBe("4-5000004");
    expect(gap.textContent).toContain("bytes 4–5000004");
    expect(outputText().indexOf("HEAD")).toBeLessThan(outputText().indexOf("TAIL"));
    expect(document.querySelector("[data-output-truncated]")).not.toBeNull();
    // Three one-item pages were read in one tick, each from the previous cursor.
    expect(
      calls("getCommandOutput")
        .slice(0, 3)
        .map((call) => (call.input as { cursor?: string }).cursor),
    ).toEqual([undefined, "1_4", "1_5000004"]);
  });

  it("large interleaved output keeps the rendered node count bounded", async () => {
    const out = output();
    for (let i = 0; i < 4_000; i++) appendOutput(out, i % 2 === 0 ? "stdout" : "stderr", "z");
    out.complete = true;
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0, completedAt: new Date() });
    mount();
    await waitFor(() => expect(outputText()).toBe("z".repeat(4_000)));
    expect(pre()!.children.length).toBeLessThanOrEqual(PIECE_SOFT_CAP + 2);
  });

  it("sparse output between dropped ranges keeps the rendered node count bounded across pages", async () => {
    const out = output();
    out.pageLimit = 500;
    const encoder = new TextEncoder();
    for (let i = 0; i < 4_000; i++) {
      out.gaps.push({ start: i * 2, end: i * 2 + 1 });
      out.chunks.push({ stream: "stdout", offset: i * 2 + 1, bytes: encoder.encode("q") });
    }
    out.complete = true;
    out.truncated = true;
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0, completedAt: new Date() });
    mount();
    await waitFor(() =>
      expect(
        document.querySelector("[data-output-status]")?.getAttribute("data-output-status"),
      ).toBe("complete"),
    );
    expect(calls("getCommandOutput").length).toBeGreaterThan(1);
    expect(pre()!.children.length).toBeLessThanOrEqual(PIECE_MAX_COUNT + 2);
    expect(outputText().endsWith("q")).toBe(true);
  });

  it("markup, terminal escapes and bidi controls render as inert, visible text", async () => {
    const hostile =
      '<img src=x onerror="window.__pwned=1"><script>window.__pwned=2</script>' +
      "\u001b[31mRED\u001b[0m \u001b]8;;javascript:alert(1)\u0007click\u001b]8;;\u0007 " +
      "abc\u202Eevil\u2028\u2029\u200B\u200C\u200D\u2060\uFEFF\u{E0001}";
    appendOutput(output(), "stdout", hostile);
    mount();
    await waitFor(() => expect(outputText()).toContain("RED"));
    const node = pre()!;
    expect(node.querySelector("img, script, a, iframe, style")).toBeNull();
    expect(node.textContent).toContain('<img src=x onerror="window.__pwned=1">');
    expect(node.textContent).toContain("<script>window.__pwned=2</script>");
    expect(node.textContent).toContain("␛[31mRED␛[0m");
    expect(node.textContent).toContain("␛]8;;javascript:alert(1)␇click");
    expect(node.textContent).toContain(
      "abc⟨U+202E⟩evil⟨U+2028⟩⟨U+2029⟩⟨U+200B⟩⟨U+200C⟩⟨U+200D⟩⟨U+2060⟩⟨U+FEFF⟩⟨U+E0001⟩",
    );
    expect(node.textContent).not.toMatch(/[\p{Cf}\u2028\u2029]/u);
    expect(node.textContent?.includes("\u001b")).toBe(false);
    expect(node.textContent?.includes("\u202e")).toBe(false);
    expect((window as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("expired output is explained while the status and exit code stay", async () => {
    Object.assign(op(), {
      state: "SUCCEEDED",
      exitCode: 3,
      completedAt: new Date(Date.now() - 25 * 3_600_000),
    });
    output().expired = true;
    mount();
    expect(await screen.findByText(enOperations.output.expired)).toBeTruthy();
    expect(pill()).toBe("SUCCEEDED");
    expect(document.querySelector("[data-detail-exit-code]")?.textContent).toBe("3");
    expect(pre()).toBeNull();
    // The typed expiry ends the reads; nothing polls a gone output.
    const reads = calls("getCommandOutput").length;
    await sleep(120);
    expect(calls("getCommandOutput")).toHaveLength(reads);
  });

  it("a settled command's status is not polled at the in-flight rate; its output is read until the watermark", async () => {
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0, completedAt: new Date() });
    appendOutput(output(), "stdout", "almost");
    mount();
    await waitFor(() => expect(outputText()).toBe("almost"));
    expect(screen.getByText(enOperations.output.waitingFinal)).toBeTruthy();
    // The last chunk and the watermark arrive after the terminal status.
    appendOutput(output(), "stdout", " done");
    output().complete = true;
    await waitFor(() => expect(outputText()).toBe("almost done"));
    await waitFor(() =>
      expect(
        document.querySelector("[data-output-status]")?.getAttribute("data-output-status"),
      ).toBe("complete"),
    );
    const reads = calls("getCommandOutput").length;
    // Longer than the in-flight status poll interval: a settled receipt is not re-read.
    await sleep(OPERATION_PENDING_REFETCH_MS + 200);
    expect(calls("getCommandOutput")).toHaveLength(reads);
    expect(calls("getOperationView")).toHaveLength(1);
  });

  it("an output the host never seals stops being polled and says it may be incomplete", async () => {
    Object.assign(op(), { state: "UNKNOWN_OUTCOME", completedAt: new Date() });
    appendOutput(output(), "stdout", "partial");
    mount();
    expect(await screen.findByText(enOperations.output.unsealed)).toBeTruthy();
    const reads = calls("getCommandOutput").length;
    expect(reads).toBe(TIMING.settledPolls);
    await sleep(120);
    expect(calls("getCommandOutput")).toHaveLength(reads);
    expect(outputText()).toBe("partial");
    expect(screen.getByText(enOperations.stateHint.commandUnknown)).toBeTruthy();
    expect(screen.queryByRole("button", { name: /retry command/i })).toBeNull();
  });

  it("an uncertain outcome keeps being read, and a later host reconciliation resumes the output", async () => {
    expect(OPERATION_REFETCH_TIMING.uncertainMs).toBeLessThan(OPERATION_REFETCH_TIMING.settledMs);
    Object.assign(op(), { state: "UNKNOWN_OUTCOME", completedAt: new Date() });
    appendOutput(output(), "stdout", "partial");
    mount("op-1", { uncertainMs: 150, settledMs: 60_000 });
    expect(await screen.findByText(enOperations.output.unsealed)).toBeTruthy();
    // An exact host receipt reconciles the outcome, with the rest of the output.
    appendOutput(output(), "stdout", " rest");
    output().complete = true;
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0 });
    await waitFor(() => expect(pill()).toBe("SUCCEEDED"));
    expect(document.querySelector("[data-detail-exit-code]")?.textContent).toBe("0");
    await waitFor(() => expect(outputText()).toBe("partial rest"));
    await waitFor(() =>
      expect(
        document.querySelector("[data-output-status]")?.getAttribute("data-output-status"),
      ).toBe("complete"),
    );
  });

  it("a finished operation keeps its host's heartbeat fresh instead of aging it into offline", async () => {
    const host = fakeHost({ lastHeartbeatAt: new Date(Date.now() - 29_700) });
    Object.assign(op(), {
      state: "SUCCEEDED",
      exitCode: 0,
      completedAt: new Date(),
      sandbox: { id: "sbx-1", state: "READY", generation: 1, host },
    });
    output().complete = true;
    mount("op-1", { uncertainMs: 60_000, settledMs: 100 });
    await waitFor(() => expect(pill()).toBe("SUCCEEDED"));
    expect(document.querySelector("[data-host-offline]")).toBeNull();
    // The host keeps heartbeating after the command completed.
    host.lastHeartbeatAt = new Date();
    await sleep(700);
    expect(calls("getOperationView").length).toBeGreaterThan(1);
    expect(document.querySelector("[data-host-offline]")).toBeNull();
  });

  it("a deleted sandbox stays deleted on screen when late output arrives", async () => {
    Object.assign(op(), {
      state: "CANCELLED",
      completedAt: new Date(),
      sandboxState: "DELETED",
      sandbox: { id: "sbx-1", state: "DELETED", generation: 2, host: null },
    });
    appendOutput(output(), "stdout", "before kill\n");
    mount();
    await waitFor(() => expect(outputText()).toBe("before kill\n"));
    expect(document.querySelector("[data-sandbox-deleted]")).not.toBeNull();
    // A late chunk (its page even claims RUNNING) is output, not status.
    appendOutput(output(), "stdout", "late chunk\n");
    await waitFor(() => expect(outputText()).toBe("before kill\nlate chunk\n"));
    expect(pill()).toBe("CANCELLED");
    expect(
      document
        .querySelector("[data-operation-sandbox-state] [data-sandbox-state]")
        ?.getAttribute("data-sandbox-state"),
    ).toBe("DELETED");
    expect(document.querySelector("[data-sandbox-deleted]")).not.toBeNull();
    expect(screen.queryByRole("button", { name: enOperations.cancel.action })).toBeNull();
  });
});

describe("cancel", () => {
  it("stays pending until the host acknowledges, and never shows Cancelled early", async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.action }));
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.confirm }));
    expect(await screen.findByText(enOperations.cancel.waiting)).toBeTruthy();
    expect(calls("cancelOperation")).toEqual([
      { procedure: "cancelOperation", input: { operationId: "op-1" } },
    ]);
    await waitFor(() => expect(pill()).toBe("CANCEL_REQUESTED"));
    expect(screen.queryByRole("button", { name: enOperations.cancel.action })).toBeNull();
    // Many reads later, still no acknowledgement: still pending.
    await refetch();
    await refetch();
    expect(pill()).toBe("CANCEL_REQUESTED");
    expect(screen.getByText(enOperations.cancel.waiting)).toBeTruthy();
    expect(screen.queryByText(enOperations.state.CANCELLED)).toBeNull();
    // M7-S8: the waiting sentence appears once, with no near-duplicate hint.
    expect(screen.getAllByText(/Cancellation (was )?requested/)).toHaveLength(1);

    // The host confirms the process group is gone.
    op().state = "CANCELLED";
    op().completedAt = new Date();
    await refetch();
    await waitFor(() => expect(pill()).toBe("CANCELLED"));
    expect(screen.getByText(enOperations.cancel.answer.cancelled)).toBeTruthy();
    expect(screen.queryByText(enOperations.cancel.waiting)).toBeNull();
    expect(calls("cancelOperation")).toHaveLength(1);
  });

  it("with the host offline it says the cancellation waits for the host", async () => {
    Object.assign(op(), {
      sandbox: {
        id: "sbx-1",
        state: "READY",
        generation: 1,
        host: fakeHost({ status: "DISCONNECTED" }),
      },
    });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.action }));
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.confirm }));
    expect(await screen.findByText(enOperations.cancel.waitingOffline)).toBeTruthy();
    expect(document.querySelector("[data-host-offline]")).not.toBeNull();
  });

  it("race: the command finishes before the cancel arrives, and its result stands", async () => {
    let release!: () => void;
    server.current.gates.cancelOperation = new Promise<void>((resolve) => {
      release = resolve;
    });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.action }));
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.confirm }));
    await waitFor(() => expect(calls("cancelOperation")).toHaveLength(1));
    // The host reports completion while the cancel request is in flight.
    Object.assign(op(), { state: "SUCCEEDED", exitCode: 0, completedAt: new Date() });
    output().complete = true;
    release();
    expect(await screen.findByText(enOperations.cancel.answer.finishedFirst)).toBeTruthy();
    await waitFor(() => expect(pill()).toBe("SUCCEEDED"));
    expect(screen.queryByText(enOperations.cancel.waiting)).toBeNull();
    expect(document.querySelector('[data-operation-state="CANCELLED"]')).toBeNull();
    expect(document.querySelector("[data-detail-exit-code]")?.textContent).toBe("0");
  });

  it("a queued command is cancelled by the server at once", async () => {
    Object.assign(op(), { state: "QUEUED", dispatchedAt: null });
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.action }));
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.confirm }));
    await waitFor(() => expect(pill()).toBe("CANCELLED"));
    // M7-S9: no host was involved, so the copy does not claim one confirmed it.
    expect(screen.getByText(enOperations.cancel.answer.cancelledQueued)).toBeTruthy();
    expect(screen.queryByText(enOperations.cancel.answer.cancelled)).toBeNull();
  });

  it("a refused cancel is explained and nothing is shown as cancelled", async () => {
    server.current.errors.cancelOperation = [
      Object.assign(new Error("conflict"), { code: "CONFLICT", status: 409 }),
    ];
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.action }));
    await user.click(await screen.findByRole("button", { name: enOperations.cancel.confirm }));
    expect(await screen.findByText(enOperations.cancel.problem.notCancellable)).toBeTruthy();
    expect(pill()).toBe("RUNNING");
  });

  it("lifecycle operations offer no cancel", async () => {
    Object.assign(op(), { kind: "CREATE_SANDBOX", state: "RUNNING" });
    mount();
    await screen.findByText(enOperations.kind.CREATE_SANDBOX);
    expect(screen.queryByRole("button", { name: enOperations.cancel.action })).toBeNull();
  });
});

describe("leaving and returning", () => {
  it("navigating away aborts the read in flight and stops polling; nothing is re-run", async () => {
    server.current.gates.getCommandOutput = new Promise<void>(() => {});
    const view = mount();
    await waitFor(() => expect(calls("getCommandOutput")).toHaveLength(1));
    view.unmount();
    // Nothing more is read once the view is gone, however long we wait.
    await sleep(TIMING.requestTimeoutMs + 100);
    expect(calls("getCommandOutput")).toHaveLength(1);
    expect(mutationCalls()).toEqual([]);
    // The hanging request was aborted by the unmount, not by its stall timer.
    expect(server.current.aborted).toBe(1);
  });

  it("returning re-reads from the start, shows each byte once and re-runs nothing", async () => {
    appendOutput(output(), "stdout", "only once\n");
    const first = mount();
    await waitFor(() => expect(outputText()).toBe("only once\n"));
    first.unmount();
    const before = calls("getCommandOutput").length;
    render(tree("op-1"));
    await waitFor(() => expect(outputText()).toBe("only once\n"));
    const after = calls("getCommandOutput").slice(before);
    expect(after[0]?.input).toEqual({ operationId: "op-1" });
    expect(mutationCalls()).toEqual([]);
  });
});

describe("a slow or unreachable server", () => {
  it("a stalled output request is reported and retried, keeping what was shown", async () => {
    appendOutput(output(), "stdout", "before\n");
    mount();
    await waitFor(() => expect(outputText()).toBe("before\n"));
    let release!: () => void;
    server.current.gates.getCommandOutput = new Promise<void>((resolve) => {
      release = resolve;
    });
    await waitFor(() =>
      expect(
        document.querySelector("[data-output-connection]")?.getAttribute("data-output-connection"),
      ).toBe("stalled"),
    );
    expect(outputText()).toBe("before\n");
    appendOutput(output(), "stdout", "after\n");
    server.current.gates.getCommandOutput = undefined;
    release();
    await waitFor(() => expect(outputText()).toBe("before\nafter\n"));
    await waitFor(() => expect(document.querySelector("[data-output-connection]")).toBeNull());
  });

  it("an offline server is reported and retried", async () => {
    appendOutput(output(), "stdout", "hello");
    server.current.errors.getCommandOutput = [new Error("network"), new Error("network")];
    mount();
    await waitFor(() =>
      expect(
        document.querySelector("[data-output-connection]")?.getAttribute("data-output-connection"),
      ).toBe("offline"),
    );
    await waitFor(() => expect(outputText()).toBe("hello"));
    expect(document.querySelector("[data-output-connection]")).toBeNull();
  });
});

describe("S0 sensitive session unavailable", () => {
  it("an impersonated snapshot retains status but reads no output and cannot cancel", async () => {
    browserAuthority.impersonatedBy = "administrator";
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime });
    mount();
    await screen.findByText(enOperations.sensitiveAccessUnavailable);
    const cancel = screen.getByRole("button", { name: enOperations.cancel.action });
    expect((cancel as HTMLButtonElement).disabled).toBe(true);
    await user.click(cancel);
    expect(calls("getCommandOutput")).toEqual([]);
    expect(calls("cancelOperation")).toEqual([]);
    expect(calls("getOperationView").length).toBeGreaterThan(0);
    expect(document.querySelector("[data-output-connection]")).toBeNull();
  });
  it("a server401 clears output and ends polling with the signed-out state", async () => {
    server.current.errors.getCommandOutput = [{ code: "UNAUTHORIZED", status: 401 }];
    mount();
    await screen.findByText(enOperations.output.signedOut);
    expect(screen.queryByText(enOperations.sensitiveAccessUnavailable)).toBeNull();
    expect(pre()).toBeNull();
    const before = calls("getCommandOutput").length;
    await sleep(100);
    expect(calls("getCommandOutput")).toHaveLength(before);
  });
});

it("S0 an impersonation snapshot change clears mounted output and aborts its reader", async () => {
  server.current.gates.getCommandOutput = new Promise<void>(() => {});
  const rendered = mount();
  await waitFor(() => expect(calls("getCommandOutput")).toHaveLength(1));
  browserAuthority.impersonatedBy = "administrator";
  rendered.rerender(tree("op-1"));
  await screen.findByText(enOperations.sensitiveAccessUnavailable);
  await waitFor(() => expect(server.current.aborted).toBe(1));
  await sleep(75);
  expect(calls("getCommandOutput")).toHaveLength(1);
  expect(pre()).toBeNull();
});
