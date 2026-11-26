// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import common from "@wssp/locales/src/en-US/common.json";
import en from "@wssp/locales/src/en-US/hosts.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import es from "@wssp/locales/src/es-MX/hosts.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const grant = vi.hoisted(() => vi.fn());
const contribute = vi.hoisted(() => vi.fn());
const resend = vi.hoisted(() => vi.fn());
const rows = vi.hoisted(() => ({
  contributions: [] as unknown[],
  invites: [] as unknown[],
  shared: null as unknown[] | null,
  shares: [] as unknown[],
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirect: () => () => false }));
vi.mock("@/utils/orpc", () => {
  const page = (name: string, items: unknown[]) => ({
    infiniteOptions: (options: Record<string, unknown>) => ({
      ...options,
      queryKey: [name],
      queryFn: async () => ({
        items:
          name === "contributions"
            ? rows.contributions
            : name === "invites"
              ? rows.invites
              : name === "shares"
                ? rows.shares
                : name === "shared" && rows.shared
                  ? rows.shared
                  : items,
        nextCursor: null,
      }),
    }),
  });
  return {
    orpc: {
      sandboxHosts: {
        listHosts: page("hosts", []),
        getHost: {
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["host", input.id],
            queryFn: async () => ({ id: input.id, label: "Own host", slug: "own-host" }),
          }),
        },
      },
      sandboxPools: {
        key: () => ["pools"],
        listShares: page("shares", []),
        listInvites: page("invites", []),
        revokeShare: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        revokeInvite: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        grantShare: { call: grant },
        resendInvite: { call: resend },
        contributeHost: { mutationOptions: () => ({ mutationFn: contribute }) },
        updateShare: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        leave: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        withdrawHost: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        listShared: page("shared", [
          {
            id: "pool-b",
            slug: "same",
            label: "Pool",
            disconnectGraceSeconds: 259200,
            owner: { name: "Pool owner" },
            share: {
              canUse: true,
              canContribute: false,
              maxMemoryMiB: null,
              maxVcpu: 2,
              maxDiskGiB: null,
              usage: { memoryMiB: "1024", vcpu: "1", diskGiB: "8" },
            },
          },
        ]),
        listContributions: page("contributions", []),
      },
    },
  };
});

import { PoolSharing, SharedPools, ShareForm } from "./pool-sharing";

afterEach(() => {
  cleanup();
  grant.mockReset();
  contribute.mockReset();
  rows.contributions = [];
  rows.invites = [];
  rows.shared = null;
  rows.shares = [];
});
async function mount(kind: "form" | "shared" | "manage", lang = "en-US") {
  const i18n = createInstance();
  await i18n.init({
    lng: lang,
    resources: { "en-US": { hosts: en, common }, "es-MX": { hosts: es, common: esCommon } },
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const view = render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        {kind === "form" ? (
          <ShareForm poolId="pool-1" lang={lang} onClose={() => {}} />
        ) : kind === "manage" ? (
          <PoolSharing poolLabel="Pool" poolId="pool-1" lang={lang} onClose={() => {}} />
        ) : (
          <SharedPools lang={lang} />
        )}
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return { ...view, client };
}
it.each(["en-US", "es-MX"])(
  "%s defaults BOTH and null caps, explains trust and forwarding, and keeps one-time invite secret out of caches",
  async (lang) => {
    const copy = lang === "en-US" ? en : es;
    const actions = lang === "en-US" ? common : esCommon;
    const user = userEvent.setup();
    const token = `wssp_inv_${"s".repeat(43)}`;
    grant.mockResolvedValue({ kind: "invite", token, sent: false });
    const { client } = await mount("form", lang);
    expect(
      (
        screen.getByRole("checkbox", { name: copy.sharing.canUse }) as HTMLInputElement
      ).getAttribute("aria-checked"),
    ).toBe("true");
    expect(
      screen
        .getByRole("checkbox", { name: copy.sharing.canContribute })
        .getAttribute("aria-checked"),
    ).toBe("true");
    expect(screen.getAllByText(copy.sharing.trust)).toHaveLength(1);
    // The inviter's link warning is stated once (the dialog description), and
    // the acceptor's wording is not shown to the inviter.
    expect(screen.getAllByText(copy.sharing.forwardingInviter)).toHaveLength(1);
    expect(screen.queryByText(copy.sharing.forwarding)).toBeNull();
    await user.type(screen.getByLabelText(copy.sharing.email), "invited@example.test");
    // Limits and sign-up are collapsed under Advanced, with their current values.
    const sections = [...document.querySelectorAll("details")];
    expect(sections.map((section) => section.open)).toEqual([false, false]);
    expect(sections[0]?.querySelector("summary")?.textContent).toContain(
      Array(3).fill(copy.sharing.unlimited).join(" · "),
    );
    await user.click(screen.getByRole("button", { name: copy.sharing.invite }));
    await waitFor(() => expect(grant).toHaveBeenCalledTimes(1));
    void actions;
    expect(grant.mock.calls[0]?.[0]).toMatchObject({
      canUse: true,
      canContribute: true,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
      signupAllowed: false,
    });
    await screen.findByText(copy.sharing.unsent);
    expect(JSON.stringify(client.getQueryCache().getAll())).not.toContain(token);
    expect(JSON.stringify(client.getMutationCache().getAll())).not.toContain(token);
    expect(window.location.href).not.toContain(token);
  },
);
it("shared views show only own permissions/caps/usage and canonical pool identity, with no foreign host navigation", async () => {
  const { container } = await mount("shared");
  await screen.findByText(/Pool owner/);
  expect(screen.getByText(/pool-b/)).toBeTruthy();
  expect(screen.getByText(/1024/)).toBeTruthy();
  expect(container.querySelector('a[href*="/hosts/"]')).toBeNull();
  expect(screen.queryByRole("button", { name: en.sharing.contribute })).toBeNull();
  expect(screen.getByRole("button", { name: en.sharing.leave })).toBeTruthy();
  expect(container.textContent).not.toMatch(/heartbeat|lastSeen|storage-marker|private-guest/);
});

it("a shared pool row puts names first, keeps the id in a copy chip and says things plainly", async () => {
  rows.shared = [
    {
      id: "rykluzikxme5bemtf9diicq5",
      slug: "team-pool",
      label: "Team pool",
      disconnectGraceSeconds: 259200,
      owner: { name: "Ada Admin" },
      share: {
        canUse: true,
        canContribute: true,
        maxMemoryMiB: null,
        maxVcpu: null,
        maxDiskGiB: null,
        usage: { memoryMiB: "0", vcpu: "0", diskGiB: "0" },
      },
    },
  ];
  const { container } = await mount("shared");
  await screen.findByText("Shared with you by Ada Admin");
  expect(screen.getByRole("heading", { name: "Team pool" })).toBeTruthy();
  // The id is a copy chip (short form), never a line of raw text.
  expect(container.querySelector("[data-copyable-id]")).toBeTruthy();
  expect(container.textContent).not.toContain("rykluzikxme5bemtf9diicq5");
  expect(screen.getByText(en.sharing.youCanBoth)).toBeTruthy();
  expect(screen.getByText(/^You're using: RAM 0 MiB/)).toBeTruthy();
  expect(
    screen.getByText(/^If you lose access, your sandboxes' disks are kept for 3 days/),
  ).toBeTruthy();
  expect(container.textContent).not.toMatch(/incus-admin|accepted promise|Guaranteed disk grace/);
});

it("the owner reads each person's usage under their name, not as 'Your usage'", async () => {
  rows.shares = [
    {
      id: "share-1",
      canUse: true,
      canContribute: true,
      maxMemoryMiB: null,
      maxVcpu: null,
      maxDiskGiB: null,
      usage: { memoryMiB: "512", vcpu: "1", diskGiB: "4" },
      Grantee: { name: "Devon Developer", email: "dev@example.test" },
    },
  ];
  await mount("manage");
  await screen.findByText(/^Devon Developer's usage: RAM 512 MiB · vCPU 1/);
  expect(screen.queryByText(/^Your usage/)).toBeNull();
  expect(screen.queryByText(/^You're using/)).toBeNull();
});

it("shared tab shows an empty state when no pools are shared", async () => {
  rows.shared = [];
  await mount("shared");
  await screen.findByText(en.sharing.emptyShared);
  expect(screen.getByText(en.sharing.emptySharedHint)).toBeTruthy();
  expect(screen.queryByText(en.sharing.loading)).toBeNull();
});
it("shared tab hides the empty state when a pool is shared", async () => {
  await mount("shared");
  await screen.findByText(/Pool owner/);
  expect(screen.queryByText(en.sharing.emptyShared)).toBeNull();
});
it("editing contribution percentages uses a sheet, preserves disabled state and warns about disk/host-delete retention", async () => {
  rows.contributions = [
    {
      id: "member-own",
      sandboxHostId: "host-own",
      poolId: "pool-b",
      enabled: false,
      memoryCapPercent: 50,
      vcpuCapPercent: null,
      removedAt: null,
    },
  ];
  contribute.mockResolvedValue({});
  const user = userEvent.setup();
  await mount("shared");
  await user.click(await screen.findByRole("button", { name: en.sharing.editPercentages }));
  expect(screen.getByRole("dialog").getAttribute("data-slot")).toBe("sheet-content");
  const memory = screen.getByLabelText(en.sharing.memoryCapPercent);
  await user.clear(memory);
  await user.type(memory, "25");
  // The contribution notice is stated once in the sheet, not twice.
  expect(
    within(screen.getByRole("dialog")).getAllByText(en.sharing.contributionNotice),
  ).toHaveLength(1);
  // The contributed host is named, not shown by id.
  expect(within(screen.getByRole("dialog")).getByText("Own host (own-host)")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: en.sharing.contribute }));
  await waitFor(() => expect(contribute).toHaveBeenCalledTimes(1));
  expect(contribute.mock.calls[0]?.[0]).toMatchObject({
    sandboxHostId: "host-own",
    enabled: false,
    memoryCapPercent: 25,
    vcpuCapPercent: null,
  });
});

it("accepted invitations show accepted state and no expiry, rotate or revoke action", async () => {
  rows.invites = [
    {
      id: "accepted",
      email: "accepted@example.test",
      acceptedAt: new Date(),
      expiresAt: new Date("2030-01-01"),
      sentAt: new Date(),
      revokedAt: null,
      expiredAt: null,
    },
  ];
  await mount("manage");
  await screen.findByText("accepted@example.test");
  expect(screen.getByText(en.sharing.inviteAccepted)).toBeTruthy();
  expect(screen.queryByRole("button", { name: en.sharing.resend })).toBeNull();
  expect(screen.queryByRole("button", { name: en.sharing.revoke })).toBeNull();
  expect(document.body.textContent).not.toContain("2030");
});
it.each(["en-US", "es-MX"])(
  "%s formats grace as days and unlimited caps without units",
  async (lang) => {
    await mount("shared", lang);
    await screen.findByText("Pool");
    const text = document.body.textContent ?? "";
    expect(text).toContain(lang === "es-MX" ? "3 días" : "3 days");
    expect(text).not.toMatch(/Unlimited MiB|Unlimited GiB|Ilimitado MiB|Ilimitado GiB|259200/);
  },
);

it("a resent invitation link is shown with the inviter's forwarding warning, once", async () => {
  rows.invites = [
    {
      id: "pending",
      email: "pending@example.test",
      acceptedAt: null,
      expiresAt: new Date("2030-01-01"),
      sentAt: new Date(),
      revokedAt: null,
      expiredAt: null,
    },
  ];
  resend.mockResolvedValue({ token: `wssp_inv_${"r".repeat(43)}`, sent: true });
  const user = userEvent.setup();
  await mount("manage");
  // Before any link is revealed, the dialog describes sharing, not the link.
  expect(screen.getByText(en.sharing.manageDescription)).toBeTruthy();
  expect(screen.queryByText(en.sharing.forwardingInviter)).toBeNull();
  await user.click(await screen.findByRole("button", { name: en.sharing.resend }));
  await waitFor(() => expect(resend).toHaveBeenCalledTimes(1));
  expect(await screen.findAllByText(en.sharing.forwardingInviter)).toHaveLength(1);
});
