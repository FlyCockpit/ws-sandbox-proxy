import { cloneElement, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  signOut: vi.fn(),
  clear: vi.fn(),
  mark: vi.fn(),
  cancel: vi.fn(),
  assign: vi.fn(),
  toast: vi.fn(),
  signOutClick: undefined as (() => Promise<void>) | undefined,
  env: { VITE_DOCS_URL: undefined as string | undefined },
}));
vi.mock("@wssp/env/web", () => ({ env: fixture.env }));
vi.mock("@tanstack/react-query", () => ({ useQueryClient: () => ({ clear: fixture.clear }) }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  useParams: () => ({ lang: "es-MX" }),
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state: {
      status: "authenticated",
      session: { user: { id: "owner-1", name: "Owner", email: "owner@example.test" } },
    },
  }),
}));
vi.mock("@/hooks/use-admin-navigation", () => ({ useShowsAdminNavigation: () => false }));
vi.mock("@/hooks/use-reload-on-identity-change", () => ({ markExplicitSignOut: fixture.mark }));
vi.mock("@/lib/auth-client", () => ({ authClient: { signOut: fixture.signOut } }));
vi.mock("@/utils/friendly-error", () => ({ friendly: () => "Please try again" }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { error: fixture.toast } }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string, options?: { name?: string }) =>
      options?.name ? `${key}:${options.name}` : key,
  }),
}));
vi.mock("@wssp/ui/components/dropdown-menu", () => {
  const Container = ({ children }: { children: ReactNode }) => children;
  return {
    DropdownMenu: Container,
    DropdownMenuContent: ({
      children,
      align,
      className,
    }: {
      children: ReactNode;
      align?: string;
      className?: string;
    }) => (
      <div data-menu-content="" data-align={align} className={className}>
        {children}
      </div>
    ),
    DropdownMenuGroup: Container,
    DropdownMenuLabel: ({ children }: { children: ReactNode }) => (
      <div data-menu-label="">{children}</div>
    ),
    DropdownMenuSeparator: () => null,
    DropdownMenuTrigger: ({ children, render }: { children: ReactNode; render: ReactElement }) =>
      cloneElement(render, {}, children),
    DropdownMenuItem: ({
      children,
      variant,
      onClick,
      render,
    }: {
      children: ReactNode;
      variant?: string;
      onClick?: () => Promise<void>;
      render?: ReactElement;
    }) => {
      if (variant === "destructive") fixture.signOutClick = onClick;
      if (render) return cloneElement(render, {}, children);
      return <div data-menu-item="">{children}</div>;
    },
  };
});

import { useOrphanCredentials } from "@/stores/orphan-credentials";
import UserMenuContent from "./user-menu-content";

beforeEach(() => {
  vi.clearAllMocks();
  fixture.env.VITE_DOCS_URL = undefined;
  fixture.mark.mockReturnValue(fixture.cancel);
  useOrphanCredentials.setState({ entries: [], ownerId: "owner-1", epoch: 10 });
  vi.stubGlobal("window", { location: { assign: fixture.assign } });
});
afterEach(() => vi.unstubAllGlobals());
it("waits for successful signout, clears client state, then full-loads localized login once", async () => {
  let finish: ((result: { error: null }) => void) | undefined;
  fixture.signOut.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  renderToStaticMarkup(<UserMenuContent />);
  const pending = fixture.signOutClick?.();
  await vi.waitFor(() => expect(fixture.signOut).toHaveBeenCalledOnce());
  expect(fixture.clear).not.toHaveBeenCalled();
  expect(useOrphanCredentials.getState().epoch).toBe(10);
  finish?.({ error: null });
  await pending;
  expect(fixture.mark).toHaveBeenCalledOnce();
  expect(fixture.cancel).not.toHaveBeenCalled();
  expect(fixture.clear).toHaveBeenCalledOnce();
  expect(useOrphanCredentials.getState().epoch).not.toBe(10);
  expect(fixture.assign).toHaveBeenCalledExactlyOnceWith("/es-MX/login");
});
it.each(["response", "throw"])(
  "unmarks failed signout (%s) and retains cached state with friendly retry",
  async (kind) => {
    if (kind === "response") fixture.signOut.mockResolvedValue({ error: { status: 503 } });
    else fixture.signOut.mockRejectedValue(new Error("offline"));
    renderToStaticMarkup(<UserMenuContent />);
    await fixture.signOutClick?.();
    expect(fixture.cancel).toHaveBeenCalledOnce();
    expect(fixture.clear).not.toHaveBeenCalled();
    expect(useOrphanCredentials.getState().epoch).toBe(10);
    expect(fixture.assign).not.toHaveBeenCalled();
    expect(fixture.toast).toHaveBeenCalledWith("Please try again");
  },
);

it("heads the menu with the name and the email on one truncated line each, at least 224px wide", () => {
  const html = renderToStaticMarkup(<UserMenuContent />);
  const content = /<div data-menu-content="" data-align="([^"]*)" class="([^"]*)"/.exec(html);
  expect(content?.[1]).toBe("end");
  expect(content?.[2]?.split(" ")).toContain("min-w-56");
  const label = /<div data-menu-label="">(.*?)<\/div>/.exec(html)?.[1] ?? "";
  expect(label).toContain(">userMenu.myAccount</span>");
  expect(label).toMatch(/<span class="[^"]*truncate[^"]*" title="Owner">Owner<\/span>/);
  expect(label).toMatch(
    /<span class="[^"]*truncate[^"]*" title="owner@example.test">owner@example.test<\/span>/,
  );
  // The email is a label, not a clickable menu item.
  expect(html).not.toMatch(/data-menu-item="">owner@example.test/);
});

it("uses a 44px icon trigger below md and the name from md, named for the account", () => {
  const html = renderToStaticMarkup(<UserMenuContent />);
  const trigger = /<button[^>]*>.*?<\/button>/.exec(html)?.[0] ?? "";
  expect(trigger).toContain('aria-label="userMenu.open:Owner"');
  expect(trigger).toContain('title="Owner"');
  expect(trigger).toMatch(/class="[^"]*\bw-11\b[^"]*md:w-auto[^"]*md:max-w-48/);
  expect(trigger).toMatch(/<svg[^>]*class="[^"]*md:hidden/);
  expect(trigger).toMatch(/<span class="hidden truncate md:block">Owner<\/span>/);
});

it("links Help & docs to the configured guide in a new tab, else to the repository's guide", () => {
  expect(renderToStaticMarkup(<UserMenuContent />)).toContain(
    'href="https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/guide/README.md"',
  );
  fixture.env.VITE_DOCS_URL = "https://docs.example.test/wssp/";
  const html = renderToStaticMarkup(<UserMenuContent />);
  const link = /<a [^>]*>.*?userMenu\.helpDocs<\/a>/.exec(html)?.[0] ?? "";
  expect(link).toContain('href="https://docs.example.test/wssp/guide/README.md"');
  expect(link).toContain('target="_blank"');
  expect(link).toContain('rel="noopener noreferrer"');
});
