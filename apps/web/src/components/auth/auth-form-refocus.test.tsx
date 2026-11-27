// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { type ReactNode, useSyncExternalStore } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * A signed-out visitor's typed email and password survive the tab regaining
 * focus. Better Auth refetches the session on focus and marks every request
 * of an empty session `isPending` again (`dist/client/query.mjs`,
 * `onRequest`: `isPending: currentValue.data === null`), the same snapshot as
 * the first load; a refetch that fails reports an error. These tests drive
 * the real `useAuthSession` through that snapshot sequence with the real
 * sign-in, sign-up and forgot-password pages: the inputs stay the same DOM
 * nodes with the typed values, so the form was never unmounted. Only the first
 * load shows the skeleton. patterns: lib/auth-session-state.ts.
 */
type Snapshot = {
  data: { user: { id: string; name: string } } | null;
  isPending: boolean;
  isRefetching: boolean;
  error: unknown | null;
};

const fx = vi.hoisted(() => ({
  snapshot: { data: null, isPending: true, isRefetching: false, error: null } as Snapshot,
  listeners: new Set<() => void>(),
  config: { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: true },
  configFailed: false,
  signup: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock("@tanstack/react-router", async (importOriginal) => ({
  lazyRouteComponent: (await importOriginal<typeof import("@tanstack/react-router")>())
    .lazyRouteComponent,
  Link: ({ children, to, className }: { children: ReactNode; to: string; className?: string }) => (
    <a data-to={to} className={className}>
      {children}
    </a>
  ),
  redirect: vi.fn(),
  useNavigate: () => vi.fn(),
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ lang: "en-US" }),
    useSearch: () => ({ redirectTo: undefined }),
  }),
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({
    data: fx.config,
    isPending: false,
    isError: fx.configFailed,
    isLoadingError: false,
    refetch: vi.fn(),
  }),
}));
// Better Auth's session atom: a store the test moves through its snapshots.
vi.mock("@/lib/auth-client", () => ({
  authClient: {
    useSession: () => ({
      ...useSyncExternalStore(
        (onChange) => {
          fx.listeners.add(onChange);
          return () => fx.listeners.delete(onChange);
        },
        () => fx.snapshot,
      ),
      refetch: vi.fn(),
    }),
    signIn: { email: vi.fn() },
    signUp: { email: fx.signup },
    requestPasswordReset: vi.fn(),
  },
}));
vi.mock("@/hooks/use-network-status", () => ({ useNetworkStatus: () => true }));
vi.mock("@/server/auth-session", () => ({ getRouteSession: vi.fn() }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    appConfig: { queryOptions: () => ({}), queryKey: () => ["appConfig"], call: async () => ({}) },
  },
}));
vi.mock("@/lib/pool-invite", () => ({
  poolInviteToken: () => undefined,
  postAuthHref: (href: string) => href,
  clearPoolInviteToken: vi.fn(),
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: fx.toastError } }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (_error: unknown, fallback?: string) => fallback ?? "failed",
  isCredentialRejection: (error: { code?: string }) => error?.code === "INVALID_EMAIL_OR_PASSWORD",
  isCodeRejection: (error: { code?: string }) =>
    ["INVALID_CODE", "INVALID_BACKUP_CODE", "OTP_HAS_EXPIRED"].includes(error?.code ?? ""),
  isRateLimit: () => false,
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("@/components/auth/resend-verification", () => ({ ResendVerification: () => null }));

const { resetAuthSessionMemoryForTests } = await import("@/hooks/use-auth-session");
const identity = await import("@/lib/document-identity");

type Page = (() => ReactNode) & { preload?: () => Promise<void> };
async function page(path: string): Promise<Page> {
  const mod = (await import(path)) as { Route: { options: { component: Page } } };
  await mod.Route.options.component.preload?.();
  return mod.Route.options.component;
}
const LoginPage = await page("@/routes/$lang/_app/login");
const SignupPage = await page("@/routes/$lang/_app/signup");
const ForgotPasswordPage = await page("@/routes/$lang/_app/forgot-password");

const FIRST_LOAD: Snapshot = { data: null, isPending: true, isRefetching: true, error: null };
const ANONYMOUS: Snapshot = { data: null, isPending: false, isRefetching: false, error: null };
const REFETCH: Snapshot = { data: null, isPending: true, isRefetching: true, error: null };
const FAILED_REFETCH: Snapshot = {
  data: null,
  isPending: false,
  isRefetching: false,
  error: { status: 503 },
};

function setSnapshot(snapshot: Snapshot) {
  act(() => {
    fx.snapshot = snapshot;
    for (const listener of fx.listeners) listener();
  });
}

beforeEach(() => {
  resetAuthSessionMemoryForTests();
  identity.resetDocumentIdentityForTests(() => undefined);
  fx.snapshot = FIRST_LOAD;
  fx.configFailed = false;
  fx.signup.mockReset();
  fx.toastError.mockReset();
});
afterEach(() => cleanup());

const input = (label: string) => screen.queryByLabelText(label) as HTMLInputElement | null;

describe.each([
  ["sign-in", LoginPage, ["auth:fields.email", "auth:fields.password"]],
  ["sign-up", SignupPage, ["auth:fields.name", "auth:fields.email", "auth:fields.password"]],
  ["forgot-password", ForgotPasswordPage, ["auth:fields.email"]],
] as const)("%s page across a refocus refetch", (_name, Page, labels) => {
  it("shows the skeleton only on the first load, then keeps the form and its values", () => {
    render(<Page />);
    expect(input("auth:fields.email")).toBeNull();
    expect(document.querySelector('[data-slot="skeleton"]')).not.toBeNull();

    setSnapshot(ANONYMOUS);
    const nodes = labels.map((label) => {
      const node = input(label);
      expect(node, label).not.toBeNull();
      fireEvent.change(node as HTMLInputElement, { target: { value: `typed ${label}` } });
      return node;
    });

    for (const snapshot of [REFETCH, FAILED_REFETCH, ANONYMOUS, REFETCH]) {
      setSnapshot(snapshot);
      expect(document.querySelector('[data-slot="skeleton"]')).toBeNull();
      expect(screen.queryByText("auth:login.unableToConnect")).toBeNull();
      labels.forEach((label, index) => {
        // The same node: React kept the form mounted, so the value survived.
        expect(input(label)).toBe(nodes[index]);
        expect(input(label)?.value).toBe(`typed ${label}`);
      });
    }
  });

  it("keeps the typed form while another tab's identity change is checked (masked pending)", () => {
    render(<Page />);
    setSnapshot(ANONYMOUS);
    const nodes = labels.map((label) => {
      const node = input(label) as HTMLInputElement;
      fireEvent.change(node, { target: { value: `typed ${label}` } });
      return node;
    });
    // A 401 with no watcher connected: every reader but the watcher sees
    // `pending` until a check settles it.
    act(() => identity.reportSessionRejected());
    expect(identity.isDocumentIdentityUnverified()).toBe(true);
    expect(document.querySelector('[data-slot="skeleton"]')).toBeNull();
    labels.forEach((label, index) => {
      expect(input(label)).toBe(nodes[index]);
      expect(input(label)?.value).toBe(`typed ${label}`);
    });
  });
});

describe("a page mounted during a refetch", () => {
  it("shows the form, not the skeleton, once this document settled anonymous", () => {
    // Settled on one page (the atom is app-wide), then navigated while the
    // tab's focus refetch is in flight.
    const first = render(<LoginPage />);
    setSnapshot(ANONYMOUS);
    first.unmount();
    setSnapshot(REFETCH);
    render(<SignupPage />);
    expect(input("auth:fields.email")).not.toBeNull();
  });

  it("still waits on a first load that fails", () => {
    fx.snapshot = { ...FAILED_REFETCH };
    render(<LoginPage />);
    expect(input("auth:fields.email")).toBeNull();
  });
});

describe("retained auth configuration", () => {
  it.each([
    ["login", LoginPage],
    ["signup", SignupPage],
    ["forgot password", ForgotPasswordPage],
  ] as const)("keeps the %s form mounted on a background config error", (_name, Page) => {
    fx.snapshot = ANONYMOUS;
    const view = render(<Page />);
    const email = input("auth:fields.email") as HTMLInputElement;
    fireEvent.change(email, { target: { value: "person@example.test" } });
    fx.configFailed = true;
    view.rerender(<Page />);
    expect(input("auth:fields.email")).toBe(email);
    expect(email.value).toBe("person@example.test");
  });

  it("reports a thrown signup failure without discarding values", async () => {
    fx.snapshot = ANONYMOUS;
    fx.signup.mockRejectedValue(new TypeError("Failed to fetch"));
    render(<SignupPage />);
    for (const [label, value] of [
      ["auth:fields.name", "Person"],
      ["auth:fields.email", "person@example.test"],
      ["auth:fields.password", "CorrectHorseBattery1!"],
    ] as const) {
      fireEvent.change(input(label) as HTMLInputElement, { target: { value } });
    }
    const email = input("auth:fields.email") as HTMLInputElement;
    fireEvent.submit(email.closest("form") as HTMLFormElement);
    await vi.waitFor(() =>
      expect(fx.toastError).toHaveBeenCalledWith("auth:errors.couldNotCreateAccount"),
    );
    expect(email.value).toBe("person@example.test");
    expect(input("auth:fields.email")).toBe(email);
  });
});
