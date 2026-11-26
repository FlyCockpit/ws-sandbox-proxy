// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import common from "@wssp/locales/src/en-US/common.json";
import en from "@wssp/locales/src/en-US/hosts.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import es from "@wssp/locales/src/es-MX/hosts.json";
import { createInstance } from "i18next";
import { type ReactNode, useState } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { selectChoices, selectOption } from "@/test/select-option";

const state = vi.hoisted(() => ({
  pools: [] as Record<string, unknown>[],
  hosts: [] as Record<string, unknown>[],
  pageSize: 20,
  errors: {} as Record<string, unknown[]>,
  reads: [] as { kind: string; input: Record<string, unknown> }[],
  members: [] as Record<string, unknown>[],
  calls: [] as { kind: string; input: Record<string, unknown> }[],
  previewAffected: 0,
  shared: [] as Record<string, unknown>[],
  sharedGate: null as Promise<void> | null,
}));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children, className }: { children: ReactNode; className?: string }) => (
    <a className={className}>{children}</a>
  ),
}));
vi.mock("@/utils/orpc", () => {
  const now = new Date();
  const mutate = (kind: string, work: (input: Record<string, unknown>) => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: Record<string, unknown>) => {
        state.calls.push({ kind, input });
        const error = state.errors[kind]?.shift();
        if (error) throw error;
        return work(input);
      },
    }),
  });
  const page = (name: string, rows: (input: Record<string, unknown>) => unknown[]) => ({
    key: () => [name],
    infiniteOptions: (options: {
      input: (cursor: string | undefined) => Record<string, unknown>;
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: string | null }) => unknown;
    }) => ({
      queryKey: name === "pools-members" ? ["pools", "members"] : [name],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
        const input = options.input(pageParam);
        state.reads.push({ kind: name, input });
        if (name === "shared" && state.sharedGate) await state.sharedGate;
        const error = state.errors[name]?.shift();
        if (error) throw error;
        const start = Number(pageParam ?? 0);
        const size = Math.min(Number(input.limit), state.pageSize);
        const all = rows(input);
        return {
          items: structuredClone(all.slice(start, start + size)),
          nextCursor: start + size < all.length ? String(start + size) : null,
        };
      },
    }),
  });
  return {
    orpc: {
      settings: { getAll: { key: () => ["settings"] } },
      sandboxes: {
        getLimits: {
          queryOptions: () => ({
            queryKey: ["limits"],
            queryFn: async () => ({
              sandboxTimeoutMaxMs: 86_400_000,
              sandboxTimeoutZero: false,
              capacityWaitMaxMs: 3_600_000,
              capacityQueuePerKey: 16,
              capacityQueuePerOwner: 64,
            }),
          }),
        },
      },
      sandboxHosts: {
        listHosts: page("hosts", (input) =>
          state.hosts.filter(
            (host) =>
              !state.members.some(
                (member) =>
                  member.poolId === input.excludePoolId && member.sandboxHostId === host.id,
              ),
          ),
        ),
      },
      sandboxPools: {
        key: () => ["pools"],
        hostPolicy: {
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["hostPolicy", input.id],
            queryFn: async () => ({
              viewer: "member",
              hosts: 1,
              ownHosts: 0,
              images: "all",
              builds: "all",
              openEgress: "all",
              guestSudo: "all",
              allowForeignBuilds: true,
            }),
          }),
        },
        list: page("pools", () => state.pools),
        listShared: page("shared", () => state.shared),
        listContributions: page("contributions", () => []),
        leave: mutate("leave", () => ({})),
        withdrawHost: mutate("withdrawHost", () => ({})),
        listMembers: page("pools-members", () => state.members),
        create: mutate("create", (input) => {
          const row = { ...input, id: "pool-1", createdAt: now, updatedAt: now, deletedAt: null };
          state.pools.push(row);
          return row;
        }),
        update: mutate("update", (input) => Object.assign(state.pools[0]!, input)),
        delete: mutate("delete", () => {
          state.pools = [];
          return {};
        }),
        addMember: mutate("add", (input) => {
          const row = {
            ...input,
            id: "member-1",
            Host: { id: "host-1", label: "Host", slug: "lab", draining: false },
            createdAt: now,
            updatedAt: now,
          };
          state.members.push(row);
          return row;
        }),
        updateMember: mutate("updateMember", (input) =>
          Object.assign(
            state.members[0]!,
            input.enabled === undefined ? {} : { enabled: input.enabled },
            input.maxLeaseMs === undefined ? {} : { maxLeaseMs: input.maxLeaseMs },
          ),
        ),
        previewLeaseLowering: mutate("preview", () => ({
          affected: state.previewAffected,
          more: false,
          earliestEnd: null,
        })),
        removeMember: mutate("removeMember", () => {
          state.members = [];
          return { ok: true };
        }),
      },
    },
  };
});

import { PoolsPage, poolSlugFromLabel } from "./pools-page";

/** Open the (only or named) pool's "More actions" menu and choose an item. */
async function choosePoolAction(
  user: ReturnType<typeof userEvent.setup>,
  label: string,
  item: string,
  copy: typeof en = en,
) {
  await user.click(
    await screen.findByRole("button", {
      name: copy.pools.actions.more.replace("{{label}}", label),
    }),
  );
  await user.click(await screen.findByRole("menuitem", { name: item }));
}

afterEach(cleanup);
beforeEach(() => {
  vi.stubGlobal("matchMedia", () => ({
    matches: true,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
  state.hosts = [{ id: "host-1", slug: "lab", label: "Host", deletionRequestedAt: null }];
  state.pageSize = 20;
  state.errors = {};
  state.reads = [];
  state.pools = [];
  state.members = [];
  state.calls = [];
  state.previewAffected = 0;
  state.shared = [];
  state.sharedGate = null;
});
function Harness({
  lang,
  initialTab,
}: {
  lang: string;
  initialTab: "owned" | "shared" | undefined;
}) {
  const [tab, setTab] = useState<"owned" | "shared" | undefined>(initialTab);
  return <PoolsPage lang={lang} tab={tab} onTabChange={setTab} />;
}
/** `"auto"`: no tab chosen in the URL, so the page picks one. */
async function mount(lang = "en-US", initialTab: "owned" | "shared" | "auto" = "owned") {
  const i18n = createInstance();
  await i18n.init({
    lng: lang,
    fallbackLng: "en-US",
    resources: {
      "en-US": { hosts: en, common },
      "es-MX": { hosts: es, common: esCommon },
    },
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <Harness lang={lang} initialTab={initialTab === "auto" ? undefined : initialTab} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
it.each(["en-US", "es-MX"])(
  "%s pool page has translated loading/empty/create controls",
  async (lang) => {
    await mount(lang);
    const text = lang === "en-US" ? en : es;
    expect(await screen.findByText(text.pools.empty)).toBeTruthy();
    expect(screen.getByText(text.pools.emptyDescription)).toBeTruthy();
    expect(screen.getByRole("button", { name: text.pools.create })).toBeTruthy();
  },
);
it("creates a pool, edits in a sheet, and adds/enables/removes a host with confirmation", async () => {
  const user = userEvent.setup();
  await mount();
  await user.click(screen.getByRole("button", { name: en.pools.create }));
  let dialog = within(await screen.findByRole("dialog"));
  // The label comes first and fills in the slug.
  await user.type(dialog.getByLabelText(en.pools.label), "Test pool");
  expect((dialog.getByLabelText(en.pools.slug) as HTMLInputElement).value).toBe("test-pool");
  await user.click(dialog.getByRole("button", { name: en.pools.create }));
  await screen.findByRole("heading", { name: "Test pool" });
  expect(state.calls[0]?.input).toEqual({ slug: "test-pool", label: "Test pool" });
  await choosePoolAction(user, "Test pool", en.pools.edit.action);
  expect((await screen.findByRole("dialog")).getAttribute("data-slot")).toBe("sheet-content");
  dialog = within(screen.getByRole("dialog"));
  await user.clear(dialog.getByLabelText(en.pools.label));
  await user.type(dialog.getByLabelText(en.pools.label), "Updated");
  await user.click(dialog.getByRole("button", { name: common.actions.save }));
  await screen.findByRole("heading", { name: "Updated" });
  await user.click(screen.getByRole("button", { name: en.pools.actions.hosts }));
  await user.click(screen.getByRole("button", { name: en.pools.add }));
  const dialogs = await screen.findAllByRole("dialog");
  dialog = within(dialogs.at(-1)!);
  await selectOption(user, dialog.getByLabelText(en.pools.host), "Host (lab)");
  await user.click(dialog.getByRole("button", { name: en.pools.addSubmit }));
  const disable = await screen.findByRole("button", { name: en.pools.disable });
  await user.click(disable);
  await screen.findByRole("button", { name: en.pools.enable });
  await user.click(screen.getByRole("button", { name: en.pools.remove }));
  const confirm = within(await screen.findByRole("alertdialog"));
  // The confirmation names the host and the pool.
  expect(
    confirm.getByText(
      en.pools.removeTitle.replace("{{host}}", "Host").replace("{{pool}}", "Updated"),
    ),
  ).toBeTruthy();
  const action = confirm.getByRole("button", { name: common.actions.delete });
  expect(action.hasAttribute("disabled")).toBe(true);
  await user.type(confirm.getByLabelText(en.pools.confirm), "lab");
  await user.click(action);
  expect(state.calls.map((call) => call.kind)).toEqual([
    "create",
    "update",
    "add",
    "updateMember",
    "removeMember",
  ]);
});

it.each(["en-US", "es-MX"])(
  "%s localizes invalid pool form values through the shared validation rules",
  async (lang) => {
    const user = userEvent.setup();
    const text = lang === "en-US" ? en : es;
    const actions = lang === "en-US" ? common : esCommon;
    await mount(lang);
    await user.click(screen.getByRole("button", { name: text.pools.create }));
    const form = within(await screen.findByRole("dialog"));
    await user.type(form.getByLabelText(text.pools.slug), "UPPER");
    await user.click(form.getByRole("button", { name: text.pools.create }));
    expect(await form.findByText(text.pools.invalidSlug)).toBeTruthy();
    // An empty label just asks for one; the 1–120 rule is for a label that breaks it.
    expect(await form.findByText(text.pools.labelRequired)).toBeTruthy();
    expect(form.queryByText(text.pools.invalidLabel)).toBeNull();
    expect(text.pools.labelRequired).toMatch(lang === "en-US" ? /label/ : /etiqueta/);
    // Focus moves to the first invalid field (the label).
    await waitFor(() => expect(document.activeElement).toBe(form.getByLabelText(text.pools.label)));
    expect(state.calls).toHaveLength(0);
    void actions;
  },
);

it("an empty create asks for a label and shows no slug error the person didn't cause", async () => {
  const user = userEvent.setup();
  await mount();
  await user.click(screen.getByRole("button", { name: en.pools.create }));
  const form = within(await screen.findByRole("dialog"));
  await user.click(form.getByRole("button", { name: en.pools.create }));
  expect(await form.findByText(en.pools.labelRequired)).toBeTruthy();
  expect(form.queryByText(en.pools.invalidSlug)).toBeNull();
  expect(form.queryByText(en.pools.invalidLabel)).toBeNull();
  await waitFor(() => expect(document.activeElement).toBe(form.getByLabelText(en.pools.label)));
  // Typing a label fills the slug, and the pool is created.
  await user.type(form.getByLabelText(en.pools.label), "Team pool");
  await user.click(form.getByRole("button", { name: en.pools.create }));
  await waitFor(() =>
    expect(state.calls).toEqual([
      { kind: "create", input: { slug: "team-pool", label: "Team pool" } },
    ]),
  );
});

it("with no tab chosen, a teammate who owns no pool starts on Shared with me", async () => {
  state.shared = [
    {
      id: "pool-s",
      slug: "team",
      label: "Team pool",
      disconnectGraceSeconds: 0,
      owner: { name: "Ada" },
      share: {
        canUse: true,
        canContribute: false,
        maxMemoryMiB: null,
        maxVcpu: null,
        maxDiskGiB: null,
        usage: { memoryMiB: "0", vcpu: "0", diskGiB: "0" },
      },
    },
  ];
  await mount("en-US", "auto");
  expect(await screen.findByRole("heading", { name: "Team pool" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: en.sharing.shared }).getAttribute("aria-selected")).toBe(
    "true",
  );
  expect(screen.queryByText(en.pools.empty)).toBeNull();
  // Templates are not shared with the pool: said once, with a way to make one.
  expect(screen.getByText(en.sharing.templatesNotShared)).toBeTruthy();
  expect(screen.getByText(en.sharing.openTemplates).tagName).toBe("A");
});

it("with no tab chosen, nothing says 'No pools yet' or picks a tab before both lists answer", async () => {
  let answerShared: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    answerShared = resolve;
  });
  state.shared = [{ id: "pool-s", slug: "team", label: "Team pool", disconnectGraceSeconds: 0 }];
  state.sharedGate = gate;
  await mount("en-US", "auto");
  await waitFor(() => expect(state.reads.map((read) => read.kind)).toContain("pools"));
  await new Promise((resolve) => setTimeout(resolve, 50));
  expect(screen.queryByText(en.pools.empty)).toBeNull();
  for (const tab of screen.getAllByRole("tab"))
    expect(tab.getAttribute("aria-selected")).toBe("false");
  answerShared();
  expect(await screen.findByRole("heading", { name: "Team pool" })).toBeTruthy();
  expect(screen.getByRole("tab", { name: en.sharing.shared }).getAttribute("aria-selected")).toBe(
    "true",
  );
  expect(screen.queryByText(en.pools.empty)).toBeNull();
});

it("with no tab chosen and no pools owned, a failed Shared list opens with its retry", async () => {
  // Every read fails until the person retries.
  state.errors.shared = Array.from({ length: 20 }, () => new Error("offline"));
  state.shared = [{ id: "pool-s", slug: "team", label: "Team pool", disconnectGraceSeconds: 0 }];
  const user = userEvent.setup();
  await mount("en-US", "auto");
  const retry = await screen.findByRole("button", { name: common.actions.tryAgain });
  expect(screen.getByRole("tab", { name: en.sharing.shared }).getAttribute("aria-selected")).toBe(
    "true",
  );
  expect(screen.getByText(en.pools.failed)).toBeTruthy();
  expect(screen.queryByText(en.pools.empty)).toBeNull();
  // A failing list is read a bounded number of times, not in a loop.
  const reads = state.reads.filter((read) => read.kind === "shared").length;
  expect(reads).toBeLessThanOrEqual(3);
  await new Promise((resolve) => setTimeout(resolve, 300));
  expect(state.reads.filter((read) => read.kind === "shared")).toHaveLength(reads);
  state.errors.shared = [];
  await user.click(retry);
  expect(await screen.findByRole("heading", { name: "Team pool" })).toBeTruthy();
});

it("with no tab chosen, an owner starts on Owned; a chosen Owned tab stays even when empty", async () => {
  state.pools = [{ id: "pool-1", slug: "a", label: "Pool A" }];
  state.shared = [{ id: "pool-s", slug: "team", label: "Team pool", disconnectGraceSeconds: 0 }];
  const owner = await mount("en-US", "auto");
  await screen.findByRole("heading", { name: "Pool A" });
  expect(screen.getByRole("tab", { name: en.sharing.owned }).getAttribute("aria-selected")).toBe(
    "true",
  );
  owner.unmount();
  state.pools = [];
  await mount("en-US", "owned");
  expect(await screen.findByText(en.pools.empty)).toBeTruthy();
  expect(screen.getByRole("tab", { name: en.sharing.owned }).getAttribute("aria-selected")).toBe(
    "true",
  );
});

it("pages pools, members and host choices with bounded cursor requests", async () => {
  state.pageSize = 1;
  state.pools = [
    { id: "pool-1", slug: "a", label: "Pool A" },
    { id: "pool-2", slug: "b", label: "Pool B" },
  ];
  state.members = [1, 2].map((n) => ({
    id: `member-${n}`,
    poolId: "pool-2",
    sandboxHostId: `host-${n}`,
    enabled: true,
    Host: { id: `host-${n}`, label: `Member ${n}`, slug: `member-${n}`, draining: n === 2 },
  }));
  state.hosts[0]!.id = "host-3";
  state.hosts.push({ id: "host-4", slug: "rack", label: "Rack", deletionRequestedAt: null });
  const user = userEvent.setup();
  const view = await mount();
  expect(view.container.querySelector('[data-slot="skeleton"]')).toBeTruthy();
  await screen.findByRole("heading", { name: "Pool A" });
  expect(screen.queryByRole("heading", { name: "Pool B" })).toBeNull();
  await user.click(screen.getByRole("button", { name: common.actions.loadMore }));
  const poolB = (await screen.findByRole("heading", { name: "Pool B" })).closest("li")!;
  await user.click(within(poolB).getByRole("button", { name: en.pools.actions.hosts }));
  let popup = within(await screen.findByRole("dialog"));
  await popup.findByText("Member 1");
  expect(popup.queryByText("Member 2")).toBeNull();
  await user.click(popup.getByRole("button", { name: common.actions.loadMore }));
  await popup.findByText("Member 2");
  expect(popup.getByText(en.pools.draining)).toBeTruthy();
  await user.click(popup.getByRole("button", { name: en.pools.add }));
  popup = within((await screen.findAllByRole("dialog")).at(-1)!);
  const firstChoices = await selectChoices(user, popup.getByLabelText(en.pools.host));
  expect(firstChoices.some((option) => option.textContent?.includes("Host (lab)"))).toBe(true);
  expect(firstChoices.some((option) => option.textContent?.includes("Rack (rack)"))).toBe(false);
  await user.click(popup.getByRole("button", { name: common.actions.loadMore }));
  await selectOption(user, popup.getByLabelText(en.pools.host), "Rack (rack)");
  await user.click(popup.getByRole("button", { name: en.pools.addSubmit }));
  await waitFor(() =>
    expect(state.calls.at(-1)).toEqual({
      kind: "add",
      input: { poolId: "pool-2", sandboxHostId: "host-4", enabled: true },
    }),
  );
  expect(state.reads).toEqual(
    expect.arrayContaining([
      { kind: "pools", input: { cursor: "1", limit: 20 } },
      { kind: "pools-members", input: { cursor: "1", poolId: "pool-2", limit: 20 } },
      { kind: "hosts", input: { cursor: "1", limit: 100, excludePoolId: "pool-2" } },
    ]),
  );
});

it("an owner-local member says caps do not apply; a contributed member shows its caps", async () => {
  state.pools = [{ id: "pool-1", slug: "a", label: "Pool A" }];
  state.members = [
    {
      id: "member-own",
      poolId: "pool-1",
      sandboxHostId: "host-own",
      userId: "owner",
      hostOwnerId: "owner",
      memoryCapPercent: null,
      vcpuCapPercent: null,
      enabled: true,
      Host: { id: "host-own", label: "Own", slug: "own", draining: false },
    },
    {
      id: "member-shared",
      poolId: "pool-1",
      sandboxHostId: "host-shared",
      userId: "owner",
      hostOwnerId: "contributor",
      memoryCapPercent: 50,
      vcpuCapPercent: 25,
      enabled: true,
      Host: { id: "host-shared", label: "Shared", slug: "shared", draining: false },
    },
  ];
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByRole("button", { name: en.pools.actions.hosts }));
  const popup = within(await screen.findByRole("dialog"));
  const own = (await popup.findByText("Own")).closest("li")!;
  const shared = popup.getByText("Shared").closest("li")!;
  expect(own.querySelector("[data-member-caps]")!.textContent).toBe(en.sharing.ownerLocalCaps);
  expect(shared.querySelector("[data-member-caps]")!.textContent).toBe(
    en.sharing.percentages.replace("{{memory}}", "50").replace("{{vcpu}}", "25"),
  );
});

it("refuses a host choice removed by a refetch before issuing a member write", async () => {
  state.pools = [{ id: "pool-1", slug: "a", label: "Pool" }];
  const user = userEvent.setup();
  const { client } = await mount();
  await user.click(await screen.findByRole("button", { name: en.pools.actions.hosts }));
  await screen.findByText(en.pools.noMembers);
  await user.click(screen.getByRole("button", { name: en.pools.add }));
  const popup = within((await screen.findAllByRole("dialog")).at(-1)!);
  const select = popup.getByLabelText(en.pools.host);
  await selectOption(user, select, "Host (lab)");
  state.hosts = [{ id: "host-2", slug: "rack", label: "Rack", deletionRequestedAt: null }];
  await client.invalidateQueries({ queryKey: ["hosts"] });
  const choices = await selectChoices(user, select);
  expect(choices.some((option) => option.textContent?.includes("Rack (rack)"))).toBe(true);
  expect(choices.some((option) => option.textContent?.includes("Host (lab)"))).toBe(false);
  const add = popup.getByRole("button", { name: en.pools.addSubmit });
  expect(add.hasAttribute("disabled")).toBe(false);
  await user.click(add);
  expect(await popup.findByRole("alert")).toHaveProperty("textContent", en.pools.chooseHost);
  expect(state.calls).toHaveLength(0);
});

it.each(["en-US", "es-MX"])(
  "%s explains missing and forbidden pool writes without raw detail",
  async (lang) => {
    const copy = lang === "en-US" ? en : es;
    const actions = lang === "en-US" ? common : esCommon;
    state.pools = [{ id: "pool-1", slug: "a", label: "Pool" }];
    state.errors.update = [
      Object.assign(new Error("private-server-detail"), { code: "NOT_FOUND" }),
      Object.assign(new Error("private-server-detail"), { status: 403 }),
    ];
    const user = userEvent.setup();
    await mount(lang);
    await choosePoolAction(user, "Pool", copy.pools.edit.action, copy);
    const popup = within(await screen.findByRole("dialog"));
    await user.click(popup.getByRole("button", { name: actions.actions.save }));
    expect(await popup.findByRole("alert")).toHaveProperty(
      "textContent",
      copy.pools.problem.notFound,
    );
    await user.click(popup.getByRole("button", { name: actions.actions.save }));
    await popup.findByText(copy.pools.problem.forbidden);
    expect(document.body.textContent).not.toContain("private-server-detail");
  },
);

it("focus stays in a localized touch-sized create dialog and returns to its opener", async () => {
  const user = userEvent.setup();
  await mount("es-MX");
  const opener = screen.getByRole("button", { name: es.pools.create });
  await user.click(opener);
  const popup = await screen.findByRole("dialog");
  await waitFor(() => expect(popup.contains(document.activeElement)).toBe(true));
  for (const button of within(popup).getAllByRole("button"))
    expect(button.className).toMatch(/h-11|size-11|min-h-\[44px\]/);
  for (const input of popup.querySelectorAll("input")) {
    expect(input.getAttribute("autocomplete")).toBe("off");
    expect(input.className).toContain("min-h-11");
  }
  // Save and Cancel sit in one row on desktop (the dialog footer).
  expect(
    within(popup).getByRole("button", { name: esCommon.actions.cancel }).parentElement!.className,
  ).toMatch(/sm:flex-row/);
  await user.click(within(popup).getByRole("button", { name: esCommon.actions.cancel }));
  await waitFor(() => expect(document.activeElement).toBe(opener));
});

it("excludes every existing member, including unloaded and disabled members, and shows an empty picker", async () => {
  state.pageSize = 1;
  state.pools = [{ id: "pool-1", slug: "lab", label: "Pool" }];
  state.hosts.push({ id: "host-2", slug: "other", label: "Other", deletionRequestedAt: null });
  state.members = state.hosts.map((host, index) => ({
    id: `member-${index}`,
    poolId: "pool-1",
    sandboxHostId: host.id,
    enabled: index === 0,
    Host: { ...host, draining: false },
  }));
  const user = userEvent.setup();
  await mount();
  await user.click(await screen.findByRole("button", { name: en.pools.actions.hosts }));
  await user.click(screen.getByRole("button", { name: en.pools.add }));
  const popup = within((await screen.findAllByRole("dialog")).at(-1)!);
  await popup.findByText(en.pools.noHostsToAdd);
  expect(popup.getByRole("combobox", { name: en.pools.host }).hasAttribute("disabled")).toBe(true);
  expect(
    (popup.getByRole("button", { name: en.pools.addSubmit }) as HTMLButtonElement).disabled,
  ).toBe(true);
  expect(state.reads).toEqual(
    expect.arrayContaining([
      { kind: "hosts", input: { cursor: undefined, limit: 100, excludePoolId: "pool-1" } },
    ]),
  );
  expect(state.calls).toHaveLength(0);
});

it.each(["en-US", "es-MX"])(
  "%s refreshes excluded hosts after add and remove in the same open members dialog",
  async (lang) => {
    const text = lang === "en-US" ? en : es;
    const actions = lang === "en-US" ? common : esCommon;
    state.pools = [{ id: "pool-1", slug: "lab", label: "Pool" }];
    const user = userEvent.setup();
    const { client } = await mount(lang);
    // A fresh cached query must be explicitly invalidated. Remounting the
    // picker must not hide this regression by automatically refetching stale data.
    client.setQueryDefaults(["hosts"], { staleTime: Infinity });
    await user.click(await screen.findByRole("button", { name: text.pools.actions.hosts }));
    await user.click(screen.getByRole("button", { name: text.pools.add }));
    let popup = within((await screen.findAllByRole("dialog")).at(-1)!);
    await selectOption(user, popup.getByLabelText(text.pools.host), "Host (lab)");
    await user.click(popup.getByRole("button", { name: text.pools.addSubmit }));
    await screen.findByRole("button", { name: text.pools.disable });
    await user.click(screen.getByRole("button", { name: text.pools.add }));
    popup = within((await screen.findAllByRole("dialog")).at(-1)!);
    await popup.findByText(text.pools.noHostsToAdd);
    expect(popup.getByRole("combobox").hasAttribute("disabled")).toBe(true);
    await user.click(popup.getByRole("button", { name: actions.actions.cancel }));
    await user.click(screen.getByRole("button", { name: text.pools.remove }));
    const confirm = within(await screen.findByRole("alertdialog"));
    await user.type(confirm.getByLabelText(text.pools.confirm), "lab");
    await user.click(confirm.getByRole("button", { name: actions.actions.delete }));
    await screen.findByText(text.pools.noMembers);
    await user.click(screen.getByRole("button", { name: text.pools.add }));
    popup = within((await screen.findAllByRole("dialog")).at(-1)!);
    await selectOption(user, popup.getByLabelText(text.pools.host), "Host (lab)");
    expect(popup.queryByText(text.pools.noHostsToAdd)).toBeNull();
  },
);

it("pool lifetime: lowering shows the preview before saving; blank means no limit", async () => {
  const user = userEvent.setup();
  const now = new Date();
  state.pools = [
    {
      id: "pool-1",
      slug: "lab",
      label: "Lab",
      ownHostsOnly: false,
      disconnectGraceSeconds: 259200,
      maxLeaseMs: null,
      unlimitedLeaseForShares: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    },
  ];
  state.previewAffected = 3;
  await mount();
  await choosePoolAction(user, "Lab", en.pools.edit.action);
  const sheet = within(await screen.findByRole("dialog"));
  await user.type(sheet.getByLabelText(en.lease.poolField), "6h");
  await user.click(sheet.getByRole("button", { name: common.actions.save }));
  expect(await sheet.findByText(en.lease.preview_other.replace("{{count}}", "3"))).toBeTruthy();
  expect(state.calls.map((call) => call.kind)).toEqual(["preview"]);
  expect(state.calls[0]?.input).toEqual({
    scope: "pool",
    poolId: "pool-1",
    maxLeaseMs: 21_600_000,
  });
  await user.click(sheet.getByRole("button", { name: en.lease.saveAnyway }));
  await waitFor(() => expect(state.calls.map((call) => call.kind)).toEqual(["preview", "update"]));
  expect(state.calls[1]?.input).toMatchObject({
    maxLeaseMs: 21_600_000,
    unlimitedLeaseForShares: false,
  });
});

it("pool lifetime: an invalid value is refused locally", async () => {
  const user = userEvent.setup();
  const now = new Date();
  state.pools = [
    {
      id: "pool-1",
      slug: "lab",
      label: "Lab",
      ownHostsOnly: false,
      disconnectGraceSeconds: 259200,
      maxLeaseMs: 21_600_000,
      unlimitedLeaseForShares: false,
      createdAt: now,
      updatedAt: now,
      deletedAt: null,
    },
  ];
  await mount();
  await choosePoolAction(user, "Lab", en.pools.edit.action);
  const sheet = within(await screen.findByRole("dialog"));
  const field = sheet.getByLabelText(en.lease.poolField);
  expect((field as HTMLInputElement).value).toBe("6h");
  await user.clear(field);
  await user.type(field, "forever");
  await user.click(sheet.getByRole("button", { name: common.actions.save }));
  expect(await sheet.findByText(en.lease.invalid)).toBeTruthy();
  expect(state.calls).toEqual([]);
});

it("the pool card summarizes hosts, people, capacity and the longest lifetime, with Hosts and People as outline actions", async () => {
  state.pools = [
    {
      id: "pool-1",
      slug: "lab",
      label: "Lab",
      summary: {
        hosts: { total: 2, enabled: 2, connected: 1 },
        people: 3,
        capacity: { memoryMiB: 98_304, vcpu: 96 },
        lease: { maxTimeoutMs: 86_400_000, timeoutZero: false },
      },
    },
    {
      id: "pool-2",
      slug: "empty",
      label: "Empty",
      summary: {
        hosts: { total: 0, enabled: 0, connected: 0 },
        people: 0,
        capacity: { memoryMiB: 0, vcpu: 0 },
        lease: { maxTimeoutMs: 3_600_000, timeoutZero: true },
      },
    },
  ];
  const user = userEvent.setup();
  await mount();
  const lab = (await screen.findByRole("heading", { name: "Lab" })).closest("li")!;
  const text = (name: string) =>
    lab.querySelector(`[data-pool-summary-${name}]`)?.textContent ?? null;
  expect(text("hosts")).toBe("2 hosts · 1 connected");
  expect(text("people")).toBe("Shared with 3 people");
  expect(text("capacity")).toBe("96 GiB RAM · 96 vCPU");
  expect(text("lease")).toBe("24 hours");
  const empty = screen.getByRole("heading", { name: "Empty" }).closest("li")!;
  expect(empty.querySelector("[data-pool-summary-hosts]")?.textContent).toBe(
    en.pools.summary.hostsNone,
  );
  expect(empty.querySelector("[data-pool-summary-people]")?.textContent).toBe(
    en.pools.summary.peopleNone,
  );
  expect(empty.querySelector("[data-pool-summary-lease]")?.textContent).toBe(
    en.pools.summary.leaseUnlimited,
  );
  // Hosts and People are outline buttons (a filled Hosts read as a selected
  // tab beside Create pool); the rest in a menu, delete last.
  expect(within(lab).getByRole("button", { name: en.pools.actions.hosts }).className).not.toMatch(
    /\bbg-primary\b/,
  );
  const buttons = within(lab)
    .getAllByRole("button")
    .map((button) => button.textContent || button.getAttribute("aria-label"));
  expect(buttons).toEqual([
    en.pools.actions.hosts,
    en.pools.actions.people,
    en.pools.actions.more.replace("{{label}}", "Lab"),
  ]);
  await user.click(
    within(lab).getByRole("button", { name: en.pools.actions.more.replace("{{label}}", "Lab") }),
  );
  expect((await screen.findAllByRole("menuitem")).map((item) => item.textContent)).toEqual([
    en.poolCapacity.open,
    en.pools.edit.action,
    en.pools.delete,
  ]);
  await user.click(screen.getByRole("menuitem", { name: en.pools.delete }));
  // The delete confirmation names the pool.
  const confirm = within(await screen.findByRole("alertdialog"));
  expect(confirm.getByText(en.pools.deleteTitle.replace("{{label}}", "Lab"))).toBeTruthy();
  // The page says what a pool is, once.
  expect(screen.getByText(en.pools.description)).toBeTruthy();
});

it("edit shows the lifetime sandboxes actually get next to the pool's own limit, and keeps expert fields collapsed", async () => {
  state.pools = [
    {
      id: "pool-1",
      slug: "lab",
      label: "Lab",
      maxLeaseMs: null,
      summary: {
        hosts: { total: 1, enabled: 1, connected: 1 },
        people: 0,
        capacity: { memoryMiB: 4096, vcpu: 8 },
        lease: { maxTimeoutMs: 86_400_000, timeoutZero: false },
      },
    },
  ];
  const user = userEvent.setup();
  await mount();
  await choosePoolAction(user, "Lab", en.pools.edit.action);
  const sheet = await screen.findByRole("dialog");
  expect(sheet.querySelector("[data-pool-effective-lease]")?.textContent).toBe(
    en.pools.edit.effectiveLease.replace("{{value}}", "24 hours"),
  );
  const sections = [...sheet.querySelectorAll<HTMLDetailsElement>("details")];
  expect(sections.map((section) => section.open)).toEqual([false, false, false, false]);
  expect(sections.map((section) => section.querySelector("summary")?.textContent)).toEqual([
    `${en.pools.edit.lifetime}${en.lease.unlimitedOwner}`,
    `${en.pools.edit.placement}${en.pools.edit.preferOwn}`,
    `${en.pools.edit.images}${en.pools.edit.noPoolLimit}`,
    `${en.pools.edit.queue}${Array(3).fill(en.pools.edit.operatorLimit).join(" · ")}`,
  ]);
  expect(poolSlugFromLabel("Équipe Lab #2")).toBe("equipe-lab-2");
});
