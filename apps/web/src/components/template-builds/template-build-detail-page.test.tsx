// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, configure, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { TEMPLATE_BUILD_CAPTURE_DETAIL_ERROR_CODES } from "@wssp/api/sandbox/contracts";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { FetchOutputPage } from "@/hooks/use-command-output";

/**
 * Build detail page: live steps with output read through the
 * build's own logs route, the typed failure and owner-only failure tail,
 * cancel behind type-to-confirm, and a not-found build.
 */

const server = vi.hoisted(() => ({
  build: null as Record<string, unknown> | null,
  tail: null as string | null,
  calls: [] as { procedure: string; input: unknown }[],
  pool: { id: "pool_1", label: "Pool A", slug: "pool-a", memberCount: 1 },
  members: [] as Record<string, unknown>[],
  host: null as Record<string, unknown> | null,
}));

vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className} href="#link">
      {children}
    </a>
  ),
}));
vi.mock("@/components/operations/command-output-view", () => ({
  CommandOutputView: ({
    operationId,
    fetchPage,
  }: {
    operationId: string;
    fetchPage: FetchOutputPage;
  }) => (
    <button
      type="button"
      data-output-for={operationId}
      onClick={() =>
        void fetchPage({ operationId, cursor: "c1" }, { signal: new AbortController().signal })
      }
    >
      output {operationId}
    </button>
  ),
}));
vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  const notFound = Object.assign(new Error("not found"), { code: "NOT_FOUND", status: 404 });
  const query = (key: string, data: () => unknown) => ({
    queryOptions: ({ input }: { input: unknown }) => ({
      queryKey: [key, input],
      queryFn: async () => {
        record(key, input);
        return structuredClone(data());
      },
    }),
  });
  return {
    orpc: {
      sandboxPools: {
        getUsable: query("getUsable", () => server.pool),
        listUsableMembers: query("listUsableMembers", () => ({
          items: server.members,
          nextCursor: null,
        })),
      },
      sandboxHosts: { getHost: query("getHost", () => server.host) },
      templateBuilds: {
        key: () => ["templateBuilds"],
        get: {
          queryKey: ({ input }: { input: unknown }) => ["templateBuilds", "get", input],
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["templateBuilds", "get", input],
            queryFn: async () => {
              record("get", input);
              if (!server.build) throw notFound;
              return structuredClone(server.build);
            },
          }),
        },
        failureTail: {
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["templateBuilds", "failureTail", input],
            queryFn: async () => {
              record("failureTail", input);
              return { tail: server.tail };
            },
          }),
        },
        cancel: {
          mutationOptions: () => ({
            mutationFn: async (input: { id: string }) => {
              record("cancel", input);
              const next = { ...server.build, state: "CANCELLING" };
              server.build = next;
              return structuredClone(next);
            },
          }),
        },
        logs: {
          call: async (input: unknown) => {
            record("logs", input);
            return { buildId: "b1", step: {}, output: { chunks: [] } };
          },
        },
      },
    },
  };
});

import { TemplateBuildDetailPage } from "./template-build-detail-page";

configure({ asyncUtilTimeout: 4_000 });

function build(overrides: Record<string, unknown> = {}) {
  return {
    id: "build_1",
    templateId: "tpl_1",
    tag: "latest",
    acceptedBy: "session",
    state: "RUNNING",
    phase: "step",
    stepIndex: 1,
    steps: [
      {
        n: 0,
        stepIndex: 0,
        kind: "run",
        state: "succeeded",
        operationId: "op_0",
        exitCode: 0,
      },
      { n: 1, stepIndex: 1, kind: "run", state: "running", operationId: "op_1", exitCode: null },
      { n: 2, stepIndex: 2, kind: "copy", state: "pending", operationId: null, exitCode: null },
    ],
    recipeDigest: "a".repeat(64),
    buildDigest: "b".repeat(64),
    contextSha256: null,
    contextBytes: null,
    timeoutMinutes: 30,
    reservedMinutes: 30,
    chargedMinutes: null,
    revisionId: null,
    cacheHitRevisionId: null,
    errorCode: null,
    errorDetail: null,
    failureStepIndex: null,
    failureExitCode: null,
    cancelRequestedAt: null,
    cleanupState: "PENDING",
    createdAt: "2026-11-03T10:00:00.000Z",
    updatedAt: "2026-11-03T10:01:00.000Z",
    completedAt: null,
    egressModeReason: null,
    target: { poolId: null, hostId: null },
    ...overrides,
  };
}

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
  server.build = build();
  server.tail = null;
  server.calls = [];
  server.pool = { id: "pool_1", label: "Pool A", slug: "pool-a", memberCount: 1 };
  server.members = [];
  server.host = null;
});
afterEach(() => cleanup());

let client: QueryClient;
function renderPage() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <TemplateBuildDetailPage lang="en-US" buildId="build_1" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

describe("TemplateBuildDetailPage", () => {
  it("shows the running step's output through the build logs route", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText("Running step 2 of 3")).toBeTruthy();
    // The running step's output is open by default; finished ones on demand.
    const running = await screen.findByText("output op_1");
    expect(screen.queryByText("output op_0")).toBeNull();
    await user.click(running);
    await waitFor(() =>
      expect(server.calls.filter((call) => call.procedure === "logs")).toEqual([
        { procedure: "logs", input: { id: "build_1", step: 1, cursor: "c1" } },
      ]),
    );
    const showButtons = screen.getAllByRole("button", { name: "Show output" });
    await user.click(showButtons[0] as HTMLElement);
    expect(await screen.findByText("output op_0")).toBeTruthy();
    // A step without a command yet has no output control.
    expect(screen.getByText("No output yet.")).toBeTruthy();
    expect(server.calls.some((call) => call.procedure === "failureTail")).toBe(false);
  });

  it("keeps the build ID and digests short, behind Advanced, with plain labels and full copies", async () => {
    server.build = build({ recipeDigest: "a".repeat(64), buildDigest: "b".repeat(64) });
    renderPage();
    const buildLabel = await screen.findByText("Build digest");
    const advanced = buildLabel.closest("details")!;
    expect(advanced.hasAttribute("open")).toBe(false);
    expect(advanced.textContent).toContain(`${"b".repeat(12)}…`);
    expect(advanced.textContent).toContain(`${"a".repeat(12)}…`);
    expect(screen.getByText("Recipe digest")).toBeTruthy();
    expect(document.body.textContent).not.toContain("b".repeat(64));
    expect(document.body.textContent).not.toMatch(/\((buildDigest|recipeDigest)\)/);
    expect(screen.getByRole("button", { name: "Copy Build digest" })).toBeTruthy();
  });

  it("titles the build by template slug and tag, and names the result revision slug vN", async () => {
    server.build = build({
      templateName: "My app",
      templateSlug: "my-app",
      state: "SUCCEEDED",
      revisionId: "rev_9",
      revisionNumber: 3,
    });
    renderPage();
    const heading = await screen.findByRole("heading", { level: 1 });
    expect(heading.textContent).toBe("Build of my-app:latest");
    expect(await screen.findByText("Revision my-app v3")).toBeTruthy();
    expect(document.querySelector("[data-build-result]")?.textContent).not.toContain("rev_9");
    // The exact revision ID stays copyable, only under the closed Advanced.
    expect(screen.getByText("rev_9").closest("details")?.hasAttribute("open")).toBe(false);
    expect(screen.getByRole("button", { name: "Copy Revision ID" })).toBeTruthy();
  });

  it("names the template instead of showing its id", async () => {
    server.build = build({ templateName: "My app" });
    renderPage();
    expect(await screen.findByText("My app")).toBeTruthy();
    expect(screen.queryByText("tpl_1")).toBeNull();
  });

  it("cancels only after the build ID is typed", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Cancel build" }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = Array.from(dialog.querySelectorAll("button")).find(
      (button) => button.textContent === "Cancel build",
    ) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    await user.type(screen.getByLabelText("Type the build ID to confirm"), "build_1");
    expect(confirm.disabled).toBe(false);
    await user.click(confirm);
    await waitFor(() =>
      expect(server.calls.filter((call) => call.procedure === "cancel")).toEqual([
        { procedure: "cancel", input: { id: "build_1" } },
      ]),
    );
    expect(await screen.findByText("Cancelling")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Cancel build" })).toBeNull();
  });

  it("explains a failed build with the owner-only output tail as plain text", async () => {
    server.build = build({
      state: "FAILED",
      phase: null,
      errorCode: "build_step_failed",
      failureStepIndex: 1,
      failureExitCode: 100,
      cleanupState: "DONE",
      completedAt: "2026-11-03T10:02:00.000Z",
      steps: [
        { n: 0, stepIndex: 0, kind: "run", state: "succeeded", operationId: "op_0", exitCode: 0 },
        { n: 1, stepIndex: 1, kind: "run", state: "failed", operationId: "op_1", exitCode: 100 },
      ],
    });
    server.tail = "\u001b[31mE: Unable to locate package nope\u001b[0m\n";
    renderPage();
    expect(await screen.findByText("A build step failed.")).toBeTruthy();
    expect(screen.getByText("Recipe step 2 exited with 100.")).toBeTruthy();
    const tail = await waitFor(() => {
      const node = document.querySelector("[data-build-failure-tail]");
      if (!node) throw new Error("no tail");
      return node;
    });
    expect(tail.textContent).toBe("[31mE: Unable to locate package nope[0m\n");
    expect(screen.queryByRole("button", { name: "Cancel build" })).toBeNull();
  });

  it.each([
    ["upload_stalled", "The image upload stalled: no data reached the image store for too long."],
    ["upload_http_503", "The image store refused the upload (HTTP 503)."],
    ["upload_refused.image_quota_exceeded", "The account's stored-image quota is full."],
    ["upload_refused.rate_limited", "The server refused the upload (rate_limited)."],
    ["store_complete_failed", "The image store could not complete the upload."],
    ["store_list_failed", "The image store could not list the uploaded parts."],
  ])("explains a known storage detail %s as a sentence", async (detail, sentence) => {
    server.build = build({
      state: "FAILED",
      phase: null,
      errorCode: "build_store_failed",
      errorDetail: detail,
      cleanupState: "DONE",
      completedAt: "2026-11-03T10:02:00.000Z",
    });
    renderPage();
    expect(await screen.findByText("Storing the image failed.")).toBeTruthy();
    expect(screen.getByText(sentence)).toBeTruthy();
    expect(screen.queryByText(`Detail: ${detail}`)).toBeNull();
  });

  it.each(TEMPLATE_BUILD_CAPTURE_DETAIL_ERROR_CODES)(
    "explains a host-reported export failure on %s",
    async (errorCode) => {
      server.build = build({
        state: "FAILED",
        phase: null,
        errorCode,
        errorDetail: "upload_export",
        cleanupState: "DONE",
        completedAt: "2026-11-03T10:02:00.000Z",
      });
      renderPage();
      expect(
        await screen.findByText("The builder host could not export the captured image."),
      ).toBeTruthy();
      expect(screen.queryByText("Detail: upload_export")).toBeNull();
    },
  );

  it("shows an unknown storage detail raw", async () => {
    server.build = build({
      state: "FAILED",
      phase: null,
      errorCode: "build_store_failed",
      errorDetail: "upload_something_new",
      cleanupState: "DONE",
      completedAt: "2026-11-03T10:02:00.000Z",
    });
    renderPage();
    expect(await screen.findByText("Detail: upload_something_new")).toBeTruthy();
  });

  it("explains 'no builder' in words with a next step, and marks unrun steps Not run", async () => {
    server.build = build({
      state: "FAILED",
      phase: null,
      stepIndex: -1,
      errorCode: "build_placement_failed",
      errorDetail: "template.build_no_builder",
      steps: [
        { n: 0, stepIndex: 0, kind: "run", state: "pending", operationId: null, exitCode: null },
        { n: 1, stepIndex: 1, kind: "run", state: "pending", operationId: null, exitCode: null },
      ],
      cleanupState: "DONE",
      completedAt: "2026-11-03T10:02:00.000Z",
    });
    renderPage();
    expect(await screen.findByText(enTemplates.builds.nextStep.noBuilder)).toBeTruthy();
    expect(screen.getByText(enTemplates.builds.nextStep.openImageSettings)).toBeTruthy();
    // The raw code is never shown as text.
    expect(document.body.textContent).not.toContain("template.build_no_builder");
    const steps = document.querySelectorAll("[data-build-step]");
    expect(steps).toHaveLength(2);
    for (const step of steps) {
      expect(step.getAttribute("data-step-state")).toBe("notRun");
      expect(step.textContent).toContain(enTemplates.builds.stepState.notRun);
      expect(step.textContent).not.toContain(enTemplates.builds.stepState.pending);
    }
  });

  it("keeps a running build's later steps Pending", async () => {
    renderPage();
    await waitFor(() =>
      expect(document.querySelector("[data-build-step='2']")?.getAttribute("data-step-state")).toBe(
        "pending",
      ),
    );
  });

  it("says when the build VM ran with the allowlist under node policy (§6.3)", async () => {
    server.build = build({ egressModeReason: "node_policy" });
    renderPage();
    const line = await waitFor(() => {
      const node = document.querySelector('[data-build-egress-reason="node_policy"]');
      if (!node) throw new Error("no egress line");
      return node;
    });
    expect(line.textContent).toContain("host policy");
  });

  it("hides a previously loaded build after a not-found refetch", async () => {
    renderPage();
    await screen.findByText("Running step 2 of 3");
    server.build = null;
    await act(async () => {
      await client.refetchQueries({ queryKey: ["templateBuilds", "get"] });
    });
    expect(await screen.findByText("Build not found")).toBeTruthy();
    expect(screen.queryByText("Running step 2 of 3")).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel build" })).toBeNull();
  });

  it("reads another owner's build as not found", async () => {
    server.build = null;
    renderPage();
    expect(await screen.findByText("Build not found")).toBeTruthy();
  });

  it("explains a build stuck in Placing on a pool with no hosts, with the next step", async () => {
    server.pool = { ...server.pool, memberCount: 0 };
    server.build = build({
      state: "PLACING",
      phase: "placing",
      stepIndex: -1,
      createdAt: new Date(Date.now() - 120_000).toISOString(),
      target: { poolId: "pool_1", hostId: null },
    });
    renderPage();
    expect(
      await screen.findByText(/^Nothing can run this build: Pool A has no hosts\./),
    ).toBeTruthy();
    expect(screen.getByText("Open Pools")).toBeTruthy();
  });

  it("says a placing build waits for room on a pool that has a connected host", async () => {
    server.members = [{ id: "m1", enabled: true, Host: { status: "CONNECTED" } }];
    server.build = build({
      state: "QUEUED",
      phase: "queued",
      stepIndex: -1,
      createdAt: new Date(Date.now() - 60_000).toISOString(),
      target: { poolId: "pool_1", hostId: null },
    });
    renderPage();
    expect(
      await screen.findByText(/^Still waiting for a host in Pool A with room for the build VM/),
    ).toBeTruthy();
  });

  it("names an offline host a placing build waits for", async () => {
    server.host = {
      id: "host_1",
      label: "Host A",
      status: "DISCONNECTED",
      lastConnectedAt: null,
      lastHeartbeatAt: null,
      deletionRequestedAt: null,
      draining: false,
    };
    server.build = build({
      state: "PLACING",
      phase: "placing",
      stepIndex: -1,
      createdAt: new Date(Date.now() - 60_000).toISOString(),
      target: { poolId: null, hostId: "host_1" },
    });
    renderPage();
    expect(await screen.findByText(/^Still waiting: Host A isn't connected/)).toBeTruthy();
    expect(screen.getByText("Open Hosts")).toBeTruthy();
  });

  it("says nothing extra in the first 30 seconds of placing", async () => {
    server.build = build({
      state: "PLACING",
      phase: "placing",
      stepIndex: -1,
      createdAt: new Date(Date.now() - 5_000).toISOString(),
      target: { poolId: "pool_1", hostId: null },
    });
    const view = renderPage();
    await screen.findByText("Build of tpl_1:latest");
    expect(view.container.querySelector("[data-build-placing]")).toBeNull();
    expect(server.calls.some((call) => call.procedure === "getUsable")).toBe(false);
  });
});
