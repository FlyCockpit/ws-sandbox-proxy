// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import common from "@wssp/locales/src/en-US/common.json";
import credentials from "@wssp/locales/src/en-US/credentials.json";
import en from "@wssp/locales/src/en-US/hosts.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import es from "@wssp/locales/src/es-MX/hosts.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const grant = vi.hoisted(() => vi.fn());
const contribute = vi.hoisted(() => vi.fn());
const resend = vi.hoisted(() => vi.fn());
const leaveFn = vi.hoisted(() => vi.fn(async () => ({})));
const updateShareFn = vi.hoisted(() => vi.fn(async () => ({})));
const rows = vi.hoisted(() => ({
  contributions: [] as unknown[],
  invites: [] as unknown[],
  shared: null as unknown[] | null,
  shares: [] as unknown[],
  hostPolicy: {} as Record<string, unknown>,
}));
const CLOSED_POLICY = {
  hosts: 2,
  ownHosts: 0,
  images: "none",
  builds: "none",
  openEgress: "none",
  guestSudo: "all",
};
const toastSuccess = vi.hoisted(() => vi.fn());
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: toastSuccess } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => (
    <a className={className} href={to}>
      {children}
    </a>
  ),
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
        hostPolicy: {
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["hostPolicy", input.id],
            queryFn: async () => rows.hostPolicy,
          }),
        },
        listShares: page("shares", []),
        listInvites: page("invites", []),
        revokeShare: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        revokeInvite: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        grantShare: { call: grant },
        resendInvite: { call: resend },
        contributeHost: { mutationOptions: () => ({ mutationFn: contribute }) },
        updateShare: { mutationOptions: () => ({ mutationFn: updateShareFn }) },
        leave: { mutationOptions: () => ({ mutationFn: leaveFn }) },
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
  resend.mockReset();
  rows.contributions = [];
  rows.invites = [];
  rows.shared = null;
  rows.shares = [];
  rows.hostPolicy = { ...CLOSED_POLICY, viewer: "owner", allowForeignBuilds: null };
});
async function mount(kind: "form" | "shared" | "manage", lang = "en-US") {
  const i18n = createInstance();
  await i18n.init({
    lng: lang,
    resources: {
      "en-US": { hosts: en, common, credentials },
      "es-MX": { hosts: es, common: esCommon },
    },
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
it("a revoked invitation shows its status without delivery or actions", async () => {
  rows.invites = [
    {
      id: "revoked",
      email: "revoked@example.test",
      acceptedAt: null,
      expiresAt: new Date("2030-01-01"),
      sentAt: new Date(),
      revokedAt: new Date(),
      expiredAt: null,
    },
  ];
  await mount("manage");
  await screen.findByText("revoked@example.test");
  expect(screen.getByText(en.sharing.inviteRevoked)).toBeTruthy();
  expect(screen.queryByText(en.sharing.sent)).toBeNull();
  expect(screen.queryByRole("button", { name: en.sharing.resend })).toBeNull();
  expect(screen.queryByRole("button", { name: en.sharing.revoke })).toBeNull();
  expect(document.body.textContent).not.toContain("2030");
});
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
    expect(toastSuccess).toHaveBeenCalledWith(copy.sharing.sharedToast);
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
  // Leave is in the card's menu, as Delete is on an owned pool's card.
  await userEvent
    .setup()
    .click(
      screen.getByRole("button", { name: en.pools.actions.more.replace("{{label}}", "Pool") }),
    );
  expect(await screen.findByRole("menuitem", { name: en.sharing.leave })).toBeTruthy();
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

it.each([
  [0, false],
  [2, true],
])(
  "revoking a person with %i contributed hosts warns about hosts only when they have some",
  async (hosts, warns) => {
    rows.shares = [
      {
        id: "share-1",
        granteeUserId: "user-2",
        canUse: true,
        canContribute: true,
        maxMemoryMiB: null,
        maxVcpu: null,
        maxDiskGiB: null,
        contributedHosts: hosts,
        usage: { memoryMiB: "0", vcpu: "0", diskGiB: "0" },
        Grantee: { name: "Devon", email: "dev@example.test" },
      },
    ];
    const user = userEvent.setup();
    await mount("manage");
    await user.click(await screen.findByRole("button", { name: en.sharing.revoke }));
    const dialog = await screen.findByRole("alertdialog");
    const text = dialog.textContent ?? "";
    expect(text.includes(en.sharing.contributionNotice)).toBe(warns);
    expect(within(dialog).queryByRole("button", { name: common.actions.delete })).toBeNull();
    if (warns) {
      expect(text).toContain(
        en.sharing.revokeContributedHosts_other
          .replace("{{name}}", "dev@example.test")
          .replace("{{count}}", "2"),
      );
      // Typed confirmation, and the action says what it does.
      expect(
        within(dialog).getByRole("button", { name: en.sharing.revoke }).hasAttribute("disabled"),
      ).toBe(true);
    } else {
      expect(text).toContain(
        en.sharing.revokePlain.replace("{{name}}", "dev@example.test").replace("{{pool}}", "Pool"),
      );
      expect(within(dialog).queryByRole("textbox")).toBeNull();
      expect(within(dialog).getByRole("button", { name: credentials.revoke.confirm })).toBeTruthy();
    }
  },
);

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

it("a rate-limited resend uses the invitation limit message", async () => {
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
  resend.mockRejectedValueOnce({ code: "TOO_MANY_REQUESTS", data: { retryAfterSeconds: 120 } });
  const user = userEvent.setup();
  await mount("manage");
  await user.click(await screen.findByRole("button", { name: en.sharing.resend }));
  expect(await screen.findByText(/Too many invitations for now/)).toBeTruthy();
  expect(screen.queryByText(/Too many sharing changes/)).toBeNull();
});

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

it.each(["", "not-an-email", `${"a".repeat(310)}@example.test`])(
  "sharing with %j is refused under the email field, focused, and nothing is sent",
  async (typed) => {
    const user = userEvent.setup();
    await mount("form");
    const email = screen.getByLabelText(en.sharing.email);
    if (typed) {
      await user.click(email);
      await user.paste(typed);
    }
    await user.click(screen.getByRole("button", { name: en.sharing.invite }));
    expect(await screen.findByText(en.sharing.invalidEmail)).toBeTruthy();
    expect(email.getAttribute("aria-invalid")).toBe("true");
    await waitFor(() => expect(document.activeElement).toBe(email));
    expect(grant).not.toHaveBeenCalled();
    expect(screen.queryByText(en.sharing.failed)).toBeNull();
    // Fixing the address clears the error and sends the invitation.
    grant.mockResolvedValue({ kind: "share" });
    await user.clear(email);
    await user.type(email, "devon@example.test");
    const share = screen.getByRole("button", { name: en.sharing.invite }) as HTMLButtonElement;
    await waitFor(() => expect(share.disabled).toBe(false));
    await user.click(share);
    await waitFor(() => expect(grant).toHaveBeenCalledTimes(1));
    expect(grant.mock.calls[0]?.[0]).toMatchObject({ email: "devon@example.test" });
  },
);

it.each([
  ["CONFLICT", undefined, en.sharing.shareConflict],
  // The daily invitation limit: the server's wait, rounded up, not "a few minutes".
  [
    "TOO_MANY_REQUESTS",
    { retryAfterSeconds: 80_000 },
    "Too many invitations for now. Try again in 23 hours.",
  ],
  [
    "TOO_MANY_REQUESTS",
    { retryAfterSeconds: 42 },
    "Too many invitations for now. Try again in 42 seconds.",
  ],
  ["TOO_MANY_REQUESTS", undefined, en.sharing.tooManyLater],
  ["INTERNAL_SERVER_ERROR", undefined, en.sharing.failed],
])("a %s refusal (%j) says what it means, next to the email field", async (code, data, message) => {
  const user = userEvent.setup();
  grant.mockRejectedValue(Object.assign(new Error("refused"), { code, data }));
  await mount("form");
  await user.type(screen.getByLabelText(en.sharing.email), "someone@example.test");
  await user.click(screen.getByRole("button", { name: en.sharing.invite }));
  const alert = await screen.findByText(message);
  expect(alert.getAttribute("role")).toBe("alert");
  // It sits in the first section with the field, above Limits and the notice.
  expect(
    alert.closest("section, fieldset, div")?.contains(screen.getByLabelText(en.sharing.email)),
  ).toBe(true);
});

it("a shared pool card shows its actions in one row, labels the id and states the trust warning once", async () => {
  rows.shared = [
    {
      id: "rykluzikxme5bemtf9diicq5",
      slug: "team-pool",
      label: "Team pool",
      disconnectGraceSeconds: 0,
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
  const card = (await screen.findByRole("heading", { name: "Team pool" })).closest("li")!;
  const actions = card.querySelector("[data-page-actions]")!;
  expect(
    within(actions as HTMLElement)
      .getAllByRole("button")
      .map((button) => button.textContent || button.getAttribute("aria-label")),
  ).toEqual([
    en.poolCapacity.open,
    en.sharing.contribute,
    en.pools.actions.more.replace("{{label}}", "Team pool"),
  ]);
  // No filled or destructive button on the card itself.
  for (const button of within(card).getAllByRole("button"))
    expect(button.className).not.toMatch(/\bbg-primary\b|\bbg-destructive\b/);
  expect(within(card).getByText(en.sharing.poolIdLabel)).toBeTruthy();
  expect(screen.getAllByText(en.sharing.trust)).toHaveLength(1);
  expect(container.querySelector("[data-node-owner-access]")).toBeNull();
});

it("a rate-limited Leave says to wait, without invitation wording", async () => {
  const user = userEvent.setup();
  leaveFn.mockRejectedValueOnce(
    Object.assign(new Error("slow down"), { code: "TOO_MANY_REQUESTS" }),
  );
  await mount("shared");
  await user.click(
    await screen.findByRole("button", { name: en.pools.actions.more.replace("{{label}}", "Pool") }),
  );
  const leaveItem = await screen.findByRole("menuitem", { name: en.sharing.leave });
  expect(leaveItem.getAttribute("data-variant")).toBe("destructive");
  await user.click(leaveItem);
  const confirm = within(await screen.findByRole("alertdialog"));
  expect(confirm.getByText(en.sharing.leaveDescription)).toBeTruthy();
  expect(confirm.queryByText(en.sharing.contributionNotice)).toBeNull();
  await user.type(confirm.getByRole("textbox"), "same");
  await user.click(confirm.getByRole("button", { name: en.sharing.leave }));
  expect(await screen.findByText(en.sharing.tooManyChangesLater)).toBeTruthy();
  expect(screen.queryByText(/invitations/)).toBeNull();
});

it("a rate-limited edit of an existing share says to wait, without invitation wording", async () => {
  updateShareFn.mockRejectedValueOnce(
    Object.assign(new Error("slow down"), { code: "TOO_MANY_REQUESTS" }),
  );
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { hosts: en, common } } });
  const user = userEvent.setup();
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { mutations: { retry: false } } })}
    >
      <I18nextProvider i18n={i18n}>
        <ShareForm
          poolId="pool-1"
          lang="en-US"
          onClose={() => {}}
          share={
            {
              granteeUserId: "user-2",
              canUse: true,
              canContribute: false,
              maxMemoryMiB: null,
              maxVcpu: null,
              maxDiskGiB: null,
            } as Parameters<typeof ShareForm>[0]["share"]
          }
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await user.click(screen.getByRole("button", { name: common.actions.save }));
  expect(await screen.findByText(en.sharing.tooManyChangesLater)).toBeTruthy();
  expect(screen.queryByText(/invitations/)).toBeNull();
});

it("the share sheet says other accounts can't run anything on these hosts and how the host owner allows it", async () => {
  rows.hostPolicy = { ...CLOSED_POLICY, viewer: "owner", allowForeignBuilds: null };
  const { container } = await mount("form");
  const notice = await screen.findByRole("region", { name: en.hostPolicy.titleOwner });
  expect(within(notice).getByText(en.hostPolicy.owner.images.none)).toBeTruthy();
  expect(within(notice).getByText(en.hostPolicy.owner.builds.none)).toBeTruthy();
  expect(within(notice).getByText(en.hostPolicy.imagesStep)).toBeTruthy();
  expect(notice.textContent).toContain("wssp host config set-accept-foreign-builds on");
  expect(notice.textContent).toContain("wssp host config set-open-egress-for-others on");
  expect(within(notice).getByText(en.hostPolicy.restartStep)).toBeTruthy();
  // Nothing can run yet, so no "they can start" step.
  expect(container.querySelector("[data-host-policy-state='ready']")).toBeNull();
});
it("the People sheet repeats it, and an open pool tells the owner the next step", async () => {
  rows.hostPolicy = {
    viewer: "owner",
    hosts: 1,
    ownHosts: 1,
    images: "all",
    builds: "all",
    openEgress: "all",
    guestSudo: "all",
    allowForeignBuilds: null,
  };
  const { container } = await mount("manage");
  await screen.findByText(en.hostPolicy.readyOwner);
  expect(container.querySelector("[data-host-policy-steps]")).toBeNull();
});
it("a shared pool's card tells its member what the hosts refuse and whom to ask", async () => {
  rows.hostPolicy = { ...CLOSED_POLICY, viewer: "member", allowForeignBuilds: false };
  await mount("shared");
  const notice = await screen.findByRole("region", { name: en.hostPolicy.titleMember });
  expect(within(notice).getByText(en.hostPolicy.member.images.none)).toBeTruthy();
  expect(
    within(notice).getByText(en.hostPolicy.nextMember.replace("{{owner}}", "Pool owner")),
  ).toBeTruthy();
  // A member is shown only the steps that block its own work.
  expect(notice.textContent).toContain("wssp host config set-accept-foreign-builds on");
  expect(notice.textContent).not.toContain("set-open-egress-for-others");
});
