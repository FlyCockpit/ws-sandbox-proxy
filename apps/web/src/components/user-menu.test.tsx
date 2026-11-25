// @vitest-environment jsdom
import { render } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const auth = vi.hoisted(() => ({ ownerId: "owner-1" as string | null }));

vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({
    state:
      auth.ownerId === null
        ? { status: "anonymous" }
        : { status: "authenticated", session: { user: { id: auth.ownerId, name: "Owner" } } },
  }),
}));
vi.mock("@tanstack/react-router", () => ({
  useLocation: () => ({ pathname: "/en-US/dashboard" }),
  useParams: () => ({ lang: "en-US" }),
  Link: ({ children }: { children: ReactNode }) => children,
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ data: undefined, isPending: true }),
}));
vi.mock("@/utils/orpc", () => ({ orpc: { appConfig: { queryOptions: () => ({}) } } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));

import { useOrphanCredentials } from "@/stores/orphan-credentials";

import UserMenu from "./user-menu";

const store = () => useOrphanCredentials.getState();

beforeEach(() => {
  auth.ownerId = "owner-1";
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
});
