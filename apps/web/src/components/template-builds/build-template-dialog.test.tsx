// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { selectOption } from "@/test/select-option";

/**
 * Build template Dialog: inline Dockerfile errors from the recipe
 * package before anything is sent, the create body (target, tag, args,
 * egress lines), the COPY context flow (hash before acceptance, upload after),
 * secret-name warnings, and a disabled deployment.
 */

const server = vi.hoisted(() => ({
  calls: [] as { procedure: string; input: unknown }[],
  usage: null as Record<string, unknown> | null,
  needsContext: false,
}));
const navigate = vi.hoisted(() => vi.fn());
const transfers = vi.hoisted(() => ({
  hashBuildContext: vi.fn(async (file: Blob) => ({ sha256: "c".repeat(64), bytes: file.size })),
  uploadBuildContext: vi.fn(async () => {}),
}));

vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://app.example.test" } }));
vi.mock("@tanstack/react-router", () => ({ useNavigate: () => navigate }));
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
            return {
              build: { id: "build_new" },
              joined: false,
              cacheHit: false,
              needsContext: server.needsContext,
            };
          },
        },
      },
      sandboxHosts: {
        listHosts: query("hosts", () => ({
          items: [{ id: "host_a", label: "Host A", slug: "host-a", deletionRequestedAt: null }],
          nextCursor: null,
        })),
      },
      sandboxPools: {
        listUsable: query("pools", () => ({ items: [], nextCursor: null })),
      },
    },
  };
});

import { BuildTemplateDialog } from "./build-template-dialog";

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

function renderDialog() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const onClose = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <BuildTemplateDialog
          lang="en-US"
          template={{ id: "tpl_1", label: "Base" }}
          onClose={onClose}
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return { onClose };
}

const source = () => screen.getByLabelText("Dockerfile") as HTMLTextAreaElement;
const creates = () => server.calls.filter((call) => call.procedure === "create");

async function chooseHost(user: ReturnType<typeof userEvent.setup>) {
  await waitFor(() => expect(screen.getByRole("combobox", { name: "Build on" })).toBeTruthy());
  await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Host A/);
}

describe("BuildTemplateDialog", () => {
  it("shows a refused instruction inline with its line and sends nothing", async () => {
    const user = userEvent.setup();
    renderDialog();
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
    const { onClose } = renderDialog();
    fireEvent.change(source(), { target: { value: "FROM base\nARG V\nRUN echo $V\n" } });
    fireEvent.change(screen.getByLabelText("Build args"), { target: { value: "V=1" } });
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
    expect(onClose).toHaveBeenCalled();
    expect(transfers.uploadBuildContext).not.toHaveBeenCalled();
  });

  it("needs a .tar for COPY, hashes it before acceptance and uploads it after", async () => {
    const user = userEvent.setup();
    server.needsContext = true;
    renderDialog();
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
    renderDialog();
    fireEvent.change(source(), { target: { value: "FROM base\nENV API_KEY=x\n" } });
    fireEvent.change(screen.getByLabelText("Build args"), { target: { value: "GITHUB_TOKEN=y" } });
    expect(
      await screen.findByText(/These names look like secrets: API_KEY, GITHUB_TOKEN/),
    ).toBeTruthy();
  });

  it("explains a disabled deployment and cannot submit", async () => {
    server.usage = { ...server.usage, enabled: false, reason: "lease_ceiling" };
    renderDialog();
    expect(
      await screen.findByText("This server's lease limit is too short for builds."),
    ).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Start build" }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });
});
