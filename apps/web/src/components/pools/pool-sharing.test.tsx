// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
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
const rows = vi.hoisted(() => ({
  contributions: [] as unknown[],
  invites: [] as unknown[],
  shared: null as unknown[] | null,
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
              : name === "shared" && rows.shared
                ? rows.shared
                : items,
        nextCursor: null,
      }),
    }),
  });
  return {
    orpc: {
      sandboxHosts: { listHosts: page("hosts", []) },
      sandboxPools: {
        key: () => ["pools"],
        listShares: page("shares", []),
        listInvites: page("invites", []),
        revokeShare: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        revokeInvite: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
        grantShare: { call: grant },
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
          <PoolSharing poolId="pool-1" lang={lang} onClose={() => {}} />
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
    expect(screen.getByText(copy.sharing.trust)).toBeTruthy();
    await user.type(screen.getByLabelText(copy.sharing.email), "invited@example.test");
    await user.click(screen.getByRole("button", { name: actions.actions.save }));
    await waitFor(() => expect(grant).toHaveBeenCalledTimes(1));
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
  expect(screen.getAllByText(en.sharing.contributionNotice).length).toBeGreaterThan(0);
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
  expect(screen.getByText(en.sharing.accepted)).toBeTruthy();
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
