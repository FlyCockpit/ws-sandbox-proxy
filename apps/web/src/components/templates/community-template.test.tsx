// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, configure, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { selectChoices, selectOption } from "@/test/select-option";

/**
 * Community bases (community-base S12): the create Dialog offers only the
 * tested catalog and a builder target, explains a disabled deployment and a
 * typed refusal; the header controls drive the refresh switch, Refresh now
 * and Try again, show the last outcome and warn on peer image storage.
 */

type Call = { procedure: string; input: unknown };
const server = vi.hoisted(() => ({
  calls: [] as Call[],
  images: { images: [] as unknown[], disabledReason: null as string | null },
  latest: [] as unknown[],
  mode: "s3",
  createError: null as unknown,
  refreshOutcome: { kind: "skipped", reason: "unchanged" } as Record<string, unknown>,
  pool: { id: "pool_a", label: "Pool A", slug: "pool-a", memberCount: 1 },
  hosts: [] as unknown[],
}));
const navigate = vi.hoisted(() => vi.fn());
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn(), message: vi.fn() }));

vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => navigate,
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className} href="#link">
      {children}
    </a>
  ),
}));
vi.mock("@/utils/orpc", () => {
  const query = (key: string, data: () => unknown) => ({
    queryOptions: (options?: { input?: unknown }) => ({
      queryKey: [key, options?.input],
      queryFn: async () => data(),
    }),
  });
  const mutation = (procedure: string, answer: () => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: unknown) => {
        server.calls.push({ procedure, input });
        return answer();
      },
    }),
  });
  return {
    orpc: {
      communityTemplates: {
        images: query("images", () => server.images),
        create: mutation("create", () => {
          if (server.createError) throw server.createError;
          return { template: { id: "tpl_c" }, build: { id: "build_c" }, existing: false };
        }),
        refresh: mutation("refresh", () => server.refreshOutcome),
        retry: mutation("retry", () => ({
          template: { id: "tpl_c" },
          build: { id: "build_r" },
          existing: false,
        })),
        setRefresh: mutation("setRefresh", () => ({ ok: true })),
      },
      templateBuilds: {
        key: () => ["templateBuilds"],
        list: query("builds", () => ({ items: server.latest, nextCursor: null })),
      },
      sandboxTemplates: {
        listTemplates: { key: () => ["templates"] },
        listRevisions: { key: () => ["revisions"] },
      },
      settings: { imagePolicy: query("imagePolicy", () => ({ mode: server.mode })) },
      sandboxHosts: {
        listHosts: query("hosts", () => ({
          items: server.hosts,
          nextCursor: null,
        })),
      },
      sandboxPools: {
        listUsable: query("pools", () => ({ items: [server.pool], nextCursor: null })),
        getUsable: query("pool", () => server.pool),
        listUsableMembers: query("members", () => ({ items: [], nextCursor: null })),
      },
    },
  };
});

import { CommunityTemplateControls, CreateCommunityTemplateDialog } from "./community-template";

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

const tested = {
  id: "ubuntu-26.04",
  label: "Ubuntu 26.04 LTS",
  architecture: "x86_64",
  resources: { cpuCount: 2, memoryMiB: 2048, diskGiB: 8, defaultDiskGiB: 32 },
};

beforeEach(() => {
  server.calls = [];
  server.images = { images: [tested], disabledReason: null };
  server.latest = [];
  server.mode = "s3";
  server.createError = null;
  server.refreshOutcome = { kind: "skipped", reason: "unchanged" };
  server.pool = { id: "pool_a", label: "Pool A", slug: "pool-a", memberCount: 1 };
  server.hosts = [{ id: "host_a", label: "Host A", slug: "host-a", deletionRequestedAt: null }];
  navigate.mockReset();
  for (const fn of Object.values(toast)) fn.mockReset();
});
afterEach(() => cleanup());

function wrap(node: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>{node}</I18nextProvider>
    </QueryClientProvider>,
  );
}
const calls = (procedure: string) => server.calls.filter((call) => call.procedure === procedure);

describe("CreateCommunityTemplateDialog", () => {
  it("offers the tested images, creates on the chosen host and opens the build", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    wrap(<CreateCommunityTemplateDialog lang="en-US" onClose={onClose} />);
    const image = await screen.findByRole("combobox", { name: "Image" });
    await waitFor(async () =>
      expect((await selectChoices(user, image)).map((option) => option.textContent)).toEqual([
        "Choose an image",
        "Ubuntu 26.04 LTS · x86_64",
      ]),
    );
    await selectOption(user, image, "Ubuntu 26.04 LTS · x86_64");
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Host A/);
    await user.type(screen.getByLabelText("Label"), "Base");
    await user.click(screen.getByRole("button", { name: "Create template" }));
    await waitFor(() => expect(calls("create")).toHaveLength(1));
    expect(calls("create")[0]?.input).toMatchObject({
      source: "ubuntu-26.04",
      target: { sandboxHostId: "host_a" },
      label: "Base",
      idempotencyKey: expect.stringMatching(/^web\.community-template\./),
    });
    await waitFor(() =>
      expect(navigate).toHaveBeenCalledWith({
        to: "/$lang/dashboard/templates/builds/$buildId",
        params: { lang: "en-US", buildId: "build_c" },
      }),
    );
    expect(onClose).toHaveBeenCalled();
  });

  it("needs an image and a target before sending anything", async () => {
    const user = userEvent.setup();
    wrap(<CreateCommunityTemplateDialog lang="en-US" onClose={vi.fn()} />);
    await screen.findByRole("combobox", { name: "Image" });
    await user.click(screen.getByRole("button", { name: "Create template" }));
    expect((await screen.findAllByText("Choose an image.")).length).toBeGreaterThan(0);
    expect(screen.getByText("Choose where the build runs.")).toBeTruthy();
    expect(calls("create")).toEqual([]);
  });

  it("refuses a pool with no hosts before sending anything", async () => {
    const user = userEvent.setup();
    server.pool = { ...server.pool, memberCount: 0 };
    wrap(<CreateCommunityTemplateDialog lang="en-US" onClose={vi.fn()} />);
    await selectOption(
      user,
      await screen.findByRole("combobox", { name: "Image" }),
      "Ubuntu 26.04 LTS · x86_64",
    );
    await user.click(screen.getByRole("button", { name: "A pool" }));
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Pool A/);
    expect(await screen.findByText(/Pool A has no hosts/)).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Create template" }) as HTMLButtonElement).disabled,
    ).toBe(true);
    expect(calls("create")).toEqual([]);
  });

  it("starts at A pool for someone with no hosts, and builds there", async () => {
    const user = userEvent.setup();
    server.hosts = [];
    wrap(<CreateCommunityTemplateDialog lang="en-US" onClose={vi.fn()} />);
    await selectOption(
      user,
      await screen.findByRole("combobox", { name: "Image" }),
      "Ubuntu 26.04 LTS · x86_64",
    );
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "A pool" }).getAttribute("aria-pressed")).toBe(
        "true",
      ),
    );
    expect(screen.queryByText(enTemplates.builds.dialog.noHosts)).toBeNull();
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Pool A/);
    await user.click(screen.getByRole("button", { name: "Create template" }));
    await waitFor(() => expect(calls("create")).toHaveLength(1));
    expect(calls("create")[0]?.input).toMatchObject({ target: { poolId: "pool_a" } });
  });

  it("explains a disabled deployment and cannot submit", async () => {
    server.images = { images: [tested], disabledReason: "image_distribution_off" };
    wrap(<CreateCommunityTemplateDialog lang="en-US" onClose={vi.fn()} />);
    expect(
      await screen.findByText(
        "Template builds need image distribution, which is off on this server.",
      ),
    ).toBeTruthy();
    expect(
      (screen.getByRole("button", { name: "Create template" }) as HTMLButtonElement).disabled,
    ).toBe(true);
  });

  it("shows the typed allowlist refusal and the peer-storage warning", async () => {
    const user = userEvent.setup();
    server.mode = "peer";
    server.createError = { code: "FORBIDDEN", data: { code: "template.community_key_scope" } };
    wrap(<CreateCommunityTemplateDialog lang="en-US" onClose={vi.fn()} />);
    // Said as something a user can act on, not an operator's S3 advice.
    expect(await screen.findByText(enTemplates.community.dialog.peerWarning)).toBeTruthy();
    expect(document.body.textContent).not.toContain("S3");
    await selectOption(
      user,
      await screen.findByRole("combobox", { name: "Image" }),
      "Ubuntu 26.04 LTS · x86_64",
    );
    await selectOption(user, screen.getByRole("combobox", { name: "Build on" }), /Host A/);
    await user.click(screen.getByRole("button", { name: "Create template" }));
    expect(
      await screen.findByText("Community templates need access to every template and revision."),
    ).toBeTruthy();
  });
});

describe("CommunityTemplateControls", () => {
  const template = { id: "tpl_c", archivedAt: null, community: { refresh: true } };

  it("toggles the refresh switch and reports a skipped Refresh now", async () => {
    const user = userEvent.setup();
    wrap(<CommunityTemplateControls template={template} lang="en-US" />);
    await user.click(screen.getByRole("switch", { name: /Refresh automatically/ }));
    await waitFor(() =>
      expect(calls("setRefresh")[0]?.input).toEqual({ templateId: "tpl_c", refresh: false }),
    );
    await user.click(screen.getByRole("button", { name: "Refresh now" }));
    await waitFor(() =>
      expect(toast.message).toHaveBeenCalledWith(
        "Already up to date: the upstream image has not changed.",
      ),
    );
    expect(calls("refresh")[0]?.input).toMatchObject({ templateId: "tpl_c" });
    expect(screen.queryByRole("button", { name: "Try again" })).toBeNull();
  });

  it("offers Try again after a failed preparation and shows its outcome", async () => {
    const user = userEvent.setup();
    server.latest = [{ id: "build_f", state: "FAILED", errorCode: "build_verify_failed" }];
    wrap(<CommunityTemplateControls template={template} lang="en-US" />);
    expect(await screen.findByText(/The new image failed verification/)).toBeTruthy();
    await user.click(await screen.findByRole("button", { name: "Try again" }));
    await waitFor(() => expect(calls("retry")).toHaveLength(1));
    expect(calls("retry")[0]?.input).toMatchObject({ templateId: "tpl_c" });
    expect(toast.success).toHaveBeenCalledWith("Preparation started.");
  });

  it("renders nothing for an archived template", () => {
    const { container } = wrap(
      <CommunityTemplateControls
        template={{ ...template, archivedAt: "2026-11-06T00:00:00Z" }}
        lang="en-US"
      />,
    );
    expect(container.querySelector("[data-community-controls]")).toBeNull();
  });
});
