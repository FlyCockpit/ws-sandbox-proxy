import type { ReactNode } from "react";
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
}));
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
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@wssp/ui/components/dropdown-menu", () => {
  const Container = ({ children }: { children: ReactNode }) => children;
  return {
    DropdownMenu: Container,
    DropdownMenuContent: Container,
    DropdownMenuGroup: Container,
    DropdownMenuLabel: Container,
    DropdownMenuSeparator: () => null,
    DropdownMenuTrigger: Container,
    DropdownMenuItem: ({
      children,
      variant,
      onClick,
    }: {
      children: ReactNode;
      variant?: string;
      onClick?: () => Promise<void>;
    }) => {
      if (variant === "destructive") fixture.signOutClick = onClick;
      return children;
    },
  };
});

import { useOrphanCredentials } from "@/stores/orphan-credentials";
import UserMenuContent from "./user-menu-content";

beforeEach(() => {
  vi.clearAllMocks();
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
