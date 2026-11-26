// @vitest-environment jsdom
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({
  ownerId: "owner-1" as string | null,
  /** Overrides the derived state: a pending or failing session check. */
  status: undefined as "pending" | "error" | undefined,
}));
const config = vi.hoisted(() => ({
  data: undefined as { signupEnabled: boolean; adminBootstrapSignupEnabled: boolean } | undefined,
  inviteToken: undefined as string | undefined,
}));
vi.mock("@/lib/pool-invite", () => ({ poolInviteToken: () => config.inviteToken }));

vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: auth.status
      ? { status: auth.status }
      : auth.ownerId === null
        ? { status: "anonymous" }
        : { status: "authenticated", session: { user: { id: auth.ownerId, name: "Owner" } } },
  }),
}));
vi.mock("@tanstack/react-router", () => ({
  useLocation: () => ({ pathname: "/en-US/dashboard" }),
  useParams: () => ({ lang: "en-US" }),
  Link: ({
    children,
    to,
    className,
    "aria-label": ariaLabel,
  }: {
    children: ReactNode;
    to: string;
    className?: string;
    "aria-label"?: string;
  }) => (
    <a data-to={to} className={className} aria-label={ariaLabel}>
      {children}
    </a>
  ),
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: config.data, isPending: config.data === undefined }),
}));
vi.mock("@/utils/orpc", () => ({ orpc: { appConfig: { queryOptions: () => ({}) } } }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: { name?: string }) =>
      options?.name ? `${key}:${options.name}` : key,
  }),
}));

import { useOrphanCredentials } from "@/stores/orphan-credentials";

import UserMenu from "./user-menu";

const store = () => useOrphanCredentials.getState();

beforeEach(() => {
  auth.ownerId = "owner-1";
  auth.status = undefined;
  config.data = undefined;
  config.inviteToken = undefined;
  useOrphanCredentials.setState({ entries: [], ownerId: undefined, epoch: 0 });
});

describe("user menu", () => {
  it("reports sign-out and owner changes to the orphan queue with no credential page open", () => {
    const view = render(<UserMenu />);
    expect(store().ownerId).toBe("owner-1");
    const started = store().epoch;

    auth.ownerId = "owner-2";
    view.rerender(<UserMenu />);
    expect(store().ownerId).toBe("owner-2");
    expect(store().epoch).not.toBe(started);

    const beforeSignOut = store().epoch;
    auth.ownerId = null;
    view.rerender(<UserMenu />);
    expect(store().ownerId).toBeNull();
    expect(store().epoch).not.toBe(beforeSignOut);
  });

  it("shows a 44px icon below md and the name from md, the box of the lazy menu's trigger", () => {
    const view = render(<UserMenu />);
    const trigger = view.container.querySelector("button");
    expect(trigger?.getAttribute("aria-haspopup")).toBe("menu");
    expect(trigger?.getAttribute("title")).toBe("Owner");
    expect(trigger?.className.split(" ")).toEqual(
      expect.arrayContaining(["w-11", "px-0!", "md:w-auto", "md:max-w-48", "md:shrink"]),
    );
    expect(trigger?.querySelector("svg")?.getAttribute("class")).toContain("md:hidden");
    expect(trigger?.querySelector("span")?.className).toBe("hidden truncate md:block");
    expect(trigger?.textContent).toBe("Owner");
  });

  it("names the trigger for the account it opens", () => {
    const trigger = render(<UserMenu />).container.querySelector("button");
    expect(trigger?.getAttribute("aria-label")).toBe("userMenu.open:Owner");
  });

  it("is a skeleton while the session is pending or failing before any identity", () => {
    for (const status of ["pending", "error"] as const) {
      auth.status = status;
      const view = render(<UserMenu />);
      expect(view.container.querySelector('[data-slot="skeleton"]')).not.toBeNull();
      expect(view.container.querySelector("button")).toBeNull();
      view.unmount();
    }
  });

  it("keeps a known account's control, disabled, when its session check fails", () => {
    const view = render(<UserMenu />);
    auth.status = "error";
    view.rerender(<UserMenu />);
    const control = view.container.querySelector<HTMLButtonElement>("[data-account-unavailable]");
    expect(control?.disabled).toBe(true);
    expect(control?.getAttribute("aria-label")).toBe("userMenu.open:Owner");
    expect(control?.className.split(" ")).toContain("size-11");
    expect(view.container.querySelector('[data-slot="skeleton"]')).toBeNull();
    // Back online: the live trigger again.
    auth.status = undefined;
    view.rerender(<UserMenu />);
    expect(view.container.querySelector("[data-account-unavailable]")).toBeNull();
    expect(view.container.querySelector("button")?.getAttribute("aria-haspopup")).toBe("menu");
  });

  describe("signed out", () => {
    beforeEach(() => {
      auth.ownerId = null;
    });
    const links = (container: HTMLElement) =>
      [...container.querySelectorAll("a")].map((link) => link.dataset.to);

    it("shows only Sign In until the sign-up flags are known, and while sign-up is closed", () => {
      expect(links(render(<UserMenu />).container)).toEqual(["/$lang/login"]);
      config.data = { signupEnabled: false, adminBootstrapSignupEnabled: false };
      expect(links(render(<UserMenu />).container)).toEqual(["/$lang/login"]);
    });

    it("adds Sign Up while sign-up is open or the admin bootstrap is", () => {
      for (const data of [
        { signupEnabled: true, adminBootstrapSignupEnabled: false },
        { signupEnabled: false, adminBootstrapSignupEnabled: true },
      ]) {
        config.data = data;
        const view = render(<UserMenu />);
        expect(links(view.container)).toEqual(["/$lang/signup", "/$lang/login"]);
        view.unmount();
      }
    });

    it("names the bootstrap way in Set Up, as the landing page does", () => {
      config.data = { signupEnabled: false, adminBootstrapSignupEnabled: true };
      const link = render(<UserMenu />).container.querySelector<HTMLElement>(
        'a[data-to="/$lang/signup"]',
      );
      expect(link?.getAttribute("aria-label")).toBe("userMenu.setUpLabel");
      expect(link?.querySelector("span")?.textContent).toBe("userMenu.setUp");
    });

    it("offers Sign Up on a closed server to a visitor holding a pool invitation", () => {
      config.data = { signupEnabled: false, adminBootstrapSignupEnabled: false };
      config.inviteToken = "wssp_inv_x";
      const link = render(<UserMenu />).container.querySelector<HTMLElement>(
        'a[data-to="/$lang/signup"]',
      );
      expect(link?.getAttribute("aria-label")).toBe("userMenu.signUp");
    });

    it("is two 44px named icon buttons below sm, the text from sm, on every page", () => {
      config.data = { signupEnabled: true, adminBootstrapSignupEnabled: false };
      const view = render(<UserMenu />);
      for (const [to, label] of [
        ["/$lang/signup", "userMenu.signUp"],
        ["/$lang/login", "userMenu.signIn"],
      ]) {
        const link = view.container.querySelector<HTMLElement>(`a[data-to="${to}"]`);
        expect(link?.getAttribute("aria-label")).toBe(label);
        const classes = link?.className.split(" ") ?? [];
        expect(classes).toEqual(expect.arrayContaining(["w-11", "px-0", "sm:w-auto", "h-11"]));
        expect(classes).not.toContain("hidden");
        expect(link?.querySelector("svg")?.getAttribute("class")).toContain("sm:hidden");
        expect(link?.querySelector("span")?.className).toBe("hidden sm:inline");
        expect(link?.querySelector("span")?.textContent).toBe(label);
      }
    });
  });
});
