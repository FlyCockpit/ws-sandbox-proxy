// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import en from "@wssp/locales/src/en-US/hosts.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_DOCS_URL: undefined } }));
vi.mock("@/utils/orpc", () => ({ orpc: {} }));

import { type PoolHostPolicy, PoolHostPolicyView } from "./pool-host-policy";

afterEach(cleanup);

const base: PoolHostPolicy = {
  viewer: "member",
  hosts: 2,
  ownHosts: 0,
  images: "all",
  builds: "all",
  openEgress: "all",
  guestSudo: "all",
  allowForeignBuilds: true,
};

async function show(policy: Partial<PoolHostPolicy>) {
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { hosts: en } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <PoolHostPolicyView policy={{ ...base, ...policy }} lang="en-US" ownerName="Ana" />
    </I18nextProvider>,
  );
}

it("an empty pool names its next step for the owner and for a member", async () => {
  await show({ viewer: "owner", hosts: 0, allowForeignBuilds: null });
  expect(screen.getByText(en.hostPolicy.noHostsOwner)).toBeTruthy();
  cleanup();
  await show({ hosts: 0 });
  expect(screen.getByText(en.hostPolicy.noHostsMember.replace("{{owner}}", "Ana"))).toBeTruthy();
});

it("an open pool tells a member to add a template of their own, with no host steps", async () => {
  const { container } = await show({});
  expect(screen.getByText(en.hostPolicy.member.images.all)).toBeTruthy();
  expect(screen.getByText(en.hostPolicy.readyMember)).toBeTruthy();
  expect(container.querySelector("[data-host-policy-steps]")).toBeNull();
  // The guide link is always there.
  expect(screen.getByRole("link", { name: en.hostPolicy.guide }).getAttribute("href")).toContain(
    "guide/pools.md#what-a-pools-hosts-allow-other-accounts",
  );
});

it("some hosts: a member can start, and is told how to get the rest", async () => {
  const { container } = await show({ images: "some", builds: "none", openEgress: "some" });
  expect(screen.getByText(en.hostPolicy.member.images.some)).toBeTruthy();
  expect(screen.getByText(en.hostPolicy.member.builds.none)).toBeTruthy();
  expect(screen.getByText(en.hostPolicy.member.openEgress.some)).toBeTruthy();
  expect(screen.getByText(en.hostPolicy.readyMember)).toBeTruthy();
  const steps = container.querySelectorAll("[data-host-policy-step]");
  expect([...steps].map((step) => step.getAttribute("data-host-policy-step"))).toEqual([
    "images",
    "builds",
  ]);
});

it("a member whose own builds stay home is sent to Settings › Images & builds", async () => {
  await show({ allowForeignBuilds: false });
  expect(screen.getByText(en.hostPolicy.foreignBuildsOff)).toBeTruthy();
  expect(
    screen.getByRole("link", { name: en.hostPolicy.openImageSettings }).getAttribute("href"),
  ).toBe("/$lang/settings/images");
});

it("a member's own hosts still run its work when the others refuse", async () => {
  await show({ ownHosts: 1, images: "none", builds: "none" });
  expect(screen.getByText(en.hostPolicy.ownHosts_one)).toBeTruthy();
  expect(screen.getByText(en.hostPolicy.readyMember)).toBeTruthy();
});

it("the owner sees every refused setting with its host command", async () => {
  const { container } = await show({
    viewer: "owner",
    images: "all",
    builds: "all",
    openEgress: "none",
    guestSudo: "none",
    allowForeignBuilds: null,
  });
  expect(screen.getByText(en.hostPolicy.readyOwner)).toBeTruthy();
  expect(screen.getByText(en.hostPolicy.owner.guestSudo.none)).toBeTruthy();
  expect(container.textContent).toContain("wssp host config set-open-egress-for-others on");
  expect(container.textContent).toContain("wssp host config set-allow-guest-sudo-for-others on");
  // Neither image nor build settings changed, so no restart is asked for.
  expect(screen.queryByText(en.hostPolicy.restartStep)).toBeNull();
});
