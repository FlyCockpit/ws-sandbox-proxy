// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { TWO_FACTOR_ENROLLMENT_GRACE_MS } from "@wssp/auth/two-factor-policy";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const session = vi.hoisted(() => ({ user: {} as Record<string, unknown> }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({ t: (key: string) => key, i18n: { language: "en-US" } }),
}));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => (
    <a href="/en-US/settings/security">{children}</a>
  ),
  useParams: () => ({ lang: "en-US" }),
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({ state: { status: "authenticated", session: { user: session.user } } }),
}));
vi.mock("@/utils/orpc", () => ({
  orpc: { settings: { getAll: { queryOptions: () => ({ queryKey: ["settings", "getAll"] }) } } },
}));

vi.mock("@/utils/relative-time", () => ({ formatRelativeTime: () => "in 24 hours" }));
vi.mock("@/lib/format-date-time", () => ({ dateTimeTitle: () => "deadline" }));

import { TwoFactorNudge } from "./two-factor-nudge";

const now = Date.now();
let client: QueryClient;

function renderNudge(settings: Record<string, string>, variant?: "admin" | "shell") {
  client.setQueryData(["settings", "getAll"], settings);
  return render(
    <QueryClientProvider client={client}>
      <TwoFactorNudge variant={variant} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  client = new QueryClient({
    defaultOptions: { queries: { staleTime: Number.POSITIVE_INFINITY } },
  });
});
afterEach(cleanup);

describe("TwoFactorNudge", () => {
  it("shows the running deadline in the app shell for an admin inside the grace window", () => {
    session.user = { role: "admin", twoFactorEnabled: false, createdAt: now - 60_000 };
    renderNudge({ force2faInternalUsers: "true" }, "shell");
    expect(screen.getByRole("alert").getAttribute("data-two-factor-nudge")).toBe("shell");
    expect(screen.getByText("twoFactorNudge.requiredTitle")).toBeTruthy();
    // The shell copy drops the policy pointer the admin area keeps.
    expect(screen.queryByText("twoFactorNudge.configurable")).toBeNull();
  });

  it("stays silent in the shell when the policy is off or the window has passed", () => {
    session.user = { role: "admin", twoFactorEnabled: false, createdAt: now - 60_000 };
    renderNudge({ force2faInternalUsers: "false" }, "shell");
    expect(screen.queryByRole("alert")).toBeNull();
    cleanup();
    session.user = {
      role: "admin",
      twoFactorEnabled: false,
      createdAt: now - 2 * TWO_FACTOR_ENROLLMENT_GRACE_MS,
    };
    renderNudge({ force2faInternalUsers: "true" }, "shell");
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("keeps every voice and the policy pointer inside the admin area", () => {
    session.user = { role: "admin", twoFactorEnabled: false, createdAt: now - 60_000 };
    renderNudge({ force2faInternalUsers: "false" });
    expect(screen.getByText("twoFactorNudge.title")).toBeTruthy();
    expect(screen.getByText("twoFactorNudge.configurable")).toBeTruthy();
  });

  it("renders nothing for an enrolled admin", () => {
    session.user = { role: "admin", twoFactorEnabled: true, createdAt: now - 60_000 };
    renderNudge({ force2faInternalUsers: "true" }, "shell");
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
