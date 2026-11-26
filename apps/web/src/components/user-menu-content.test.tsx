import { cloneElement, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  signOut: vi.fn(),
  mark: vi.fn(),
  cancel: vi.fn(),
  leave: vi.fn(),
  toast: vi.fn(),
  signOutClick: undefined as (() => Promise<void>) | undefined,
  env: { VITE_DOCS_URL: undefined as string | undefined },
}));
vi.mock("@wssp/env/web", () => ({ env: fixture.env }));
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
vi.mock("@/lib/document-identity", () => ({
  markExplicitSignOut: fixture.mark,
  leaveDocument: fixture.leave,
}));
vi.mock("@/lib/auth-client", () => ({ authClient: { signOut: fixture.signOut } }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (_error: unknown, fallback?: string) => fallback ?? "Please try again",
}));
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
      inset,
      onClick,
      render,
    }: {
      children: ReactNode;
      variant?: string;
      inset?: boolean;
      onClick?: () => Promise<void>;
      render?: ReactElement;
    }) => {
      if (variant === "destructive") fixture.signOutClick = onClick;
      if (render) return cloneElement(render, {}, children);
      return (
        <div data-menu-item="" data-variant={variant} data-inset={inset ? "" : undefined}>
          {children}
        </div>
      );
    },
  };
});

import UserMenuContent from "./user-menu-content";

beforeEach(() => {
  vi.clearAllMocks();
  fixture.env.VITE_DOCS_URL = undefined;
  fixture.mark.mockReturnValue(fixture.cancel);
});
it("waits for successful signout, then leaves for localized login once (quarantined full load)", async () => {
  let finish: ((result: { error: null }) => void) | undefined;
  fixture.signOut.mockReturnValue(
    new Promise((resolve) => {
      finish = resolve;
    }),
  );
  renderToStaticMarkup(<UserMenuContent />);
  const pending = fixture.signOutClick?.();
  await vi.waitFor(() => expect(fixture.signOut).toHaveBeenCalledOnce());
  // Nothing is dropped before the server confirmed the sign-out.
  expect(fixture.leave).not.toHaveBeenCalled();
  finish?.({ error: null });
  await pending;
  expect(fixture.mark).toHaveBeenCalledOnce();
  expect(fixture.cancel).not.toHaveBeenCalled();
  // lib/document-identity.ts hides the page and drops the query cache and the
  // orphan-credential store (router.tsx) before the load.
  expect(fixture.leave).toHaveBeenCalledExactlyOnceWith("/es-MX/login");
});
it.each(["response", "throw"])(
  "unmarks failed signout (%s) and retains cached state with friendly retry",
  async (kind) => {
    if (kind === "response") fixture.signOut.mockResolvedValue({ error: { status: 503 } });
    else fixture.signOut.mockRejectedValue(new Error("offline"));
    renderToStaticMarkup(<UserMenuContent />);
    await fixture.signOutClick?.();
    expect(fixture.cancel).toHaveBeenCalledOnce();
    expect(fixture.leave).not.toHaveBeenCalled();
    // An unrecognised failure says what failed, not just "try again".
    expect(fixture.toast).toHaveBeenCalledWith("userMenu.signOutFailed");
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

it("ends with Sign out, with its icon aligned like the other items (no inset)", () => {
  fixture.env.VITE_DOCS_URL = "https://docs.example.test/wssp/";
  const html = renderToStaticMarkup(<UserMenuContent />);
  const items = [...html.matchAll(/<(?:div data-menu-item=""[^>]*|a [^>]*)>(.*?)<\/(?:div|a)>/g)];
  const last = items.at(-1)?.[0] ?? "";
  expect(last).toContain('data-variant="destructive"');
  expect(last).not.toContain("data-inset");
  expect(last).toMatch(/<svg[^>]*class="[^"]*lucide-log-out/);
  expect(last).toContain("userMenu.signOut");
  // Help & docs comes before it.
  expect(html.indexOf("userMenu.helpDocs")).toBeLessThan(html.indexOf("userMenu.signOut"));
});
