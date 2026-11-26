// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Sign-in and sign-up failures sit inside the form, next to the field they are
 * about (`role="alert"`, `aria-invalid`, `aria-describedby`, focus), and closed
 * sign-up says how people get in instead of offering a form that can only fail.
 */
const fx = vi.hoisted(() => ({
  config: {
    signupEnabled: true,
    adminBootstrapSignupEnabled: false,
    emailEnabled: false,
  },
  signIn: vi.fn(),
  signUp: vi.fn(),
  toast: { success: vi.fn(), error: vi.fn() },
}));

// Route files are code-split in the test build too: the page component
// arrives through the real `lazyRouteComponent`, preloaded before rendering.
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
  useQuery: () => ({ data: fx.config, isPending: false, isError: false, refetch: vi.fn() }),
}));
vi.mock("@/hooks/use-auth-session", () => ({
  useAuthSession: () => ({ state: { status: "anonymous" } }),
}));
vi.mock("@/lib/auth-client", () => ({
  authClient: { signIn: { email: fx.signIn }, signUp: { email: fx.signUp } },
}));
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
vi.mock("@wssp/ui/components/sileo", () => ({ toast: fx.toast }));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (_error: unknown, fallback?: string) => fallback ?? "Too many attempts.",
  isRateLimit: (error: { status?: number } | null) => error?.status === 429,
}));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (key: string) => key }) }));
vi.mock("./resend-verification", () => ({ ResendVerification: () => null }));
vi.mock("@/components/auth/resend-verification", () => ({ ResendVerification: () => null }));

type Page = (() => ReactNode) & { preload?: () => Promise<void> };
async function page(path: string): Promise<Page> {
  const mod = (await import(path)) as { Route: { options: { component: Page } } };
  await mod.Route.options.component.preload?.();
  return mod.Route.options.component;
}
const LoginPage = await page("@/routes/$lang/_app/login");
const SignupPage = await page("@/routes/$lang/_app/signup");

beforeEach(() => {
  fx.config = { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: false };
  fx.signIn.mockReset();
  fx.signUp.mockReset();
});
afterEach(() => cleanup());

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("sign in", () => {
  it("puts a wrong password under the password field, focuses it, and clears on edit", async () => {
    fx.signIn.mockResolvedValue({ error: { code: "INVALID_EMAIL_OR_PASSWORD", status: 401 } });
    render(<LoginPage />);
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "wrong-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("auth:errors.invalidCredentials");
    const password = screen.getByLabelText("auth:fields.password");
    expect(password.getAttribute("aria-invalid")).toBe("true");
    expect(password.getAttribute("aria-describedby")).toContain(alert.id);
    expect(document.activeElement).toBe(password);
    expect(fx.toast.error).not.toHaveBeenCalled();

    // Fixing the email (the server never says which one was wrong) clears it
    // and the button works again.
    fill("auth:fields.email", "other@example.test");
    await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
    expect(
      (screen.getByRole("button", { name: "auth:login.signIn" }) as HTMLButtonElement).disabled,
    ).toBe(false);
  });

  it("shows a rate limit inside the form without blocking the next try", async () => {
    fx.signIn.mockResolvedValue({ error: { status: 429 } });
    render(<LoginPage />);
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "some-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("Too many attempts.");
    expect(screen.getByLabelText("auth:fields.password").getAttribute("aria-invalid")).toBeNull();
  });

  it("offers Sign Up only while sign-up is open", () => {
    render(<LoginPage />);
    expect(screen.getByText("auth:login.signupHint")).toBeTruthy();
    expect(screen.queryByText("auth:login.byInvitation")).toBeNull();
  });

  it("says access is by invitation when sign-up is closed, with the admin bootstrap link", () => {
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: true, emailEnabled: false };
    render(<LoginPage />);
    expect(screen.queryByText("auth:login.signupHint")).toBeNull();
    expect(screen.getByText("auth:login.byInvitation")).toBeTruthy();
    expect(screen.getByText("auth:login.adminSignupHint").closest("a")?.dataset.to).toBe(
      "/$lang/signup",
    );
    cleanup();
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: false, emailEnabled: false };
    render(<LoginPage />);
    expect(screen.getByText("auth:login.byInvitation")).toBeTruthy();
    expect(screen.queryByText("auth:login.adminSignupHint")).toBeNull();
  });
});

describe("sign up", () => {
  it("leads with the invitation callout when sign-up is limited", () => {
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: true, emailEnabled: false };
    render(<SignupPage />);
    const note = screen.getByRole("note");
    expect(note.textContent).toContain("auth:login.byInvitation");
    expect(screen.getByText("auth:login.createDescriptionLimited")).toBeTruthy();
    expect(screen.queryByText("auth:login.createDescription")).toBeNull();
    // The callout comes before the first field.
    const first = screen.getByLabelText("auth:fields.name");
    expect(note.compareDocumentPosition(first) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
  });

  it("answers an uninvited address with how to get in, under the email field", async () => {
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: true, emailEnabled: false };
    fx.signUp.mockResolvedValue({ error: { code: "FAILED_TO_CREATE_USER", status: 422 } });
    render(<SignupPage />);
    fill("auth:fields.name", "Person");
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "a-long-enough-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signUp" }));

    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("auth:errors.signupByInvitation");
    const email = screen.getByLabelText("auth:fields.email");
    expect(email.getAttribute("aria-invalid")).toBe("true");
    expect(email.getAttribute("aria-describedby")).toContain(alert.id);
    expect(document.activeElement).toBe(email);
  });

  it("keeps the generic failure inside the form when sign-up is open", async () => {
    fx.signUp.mockResolvedValue({ error: { code: "FAILED_TO_CREATE_USER", status: 422 } });
    render(<SignupPage />);
    expect(screen.queryByRole("note")).toBeNull();
    fill("auth:fields.name", "Person");
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "a-long-enough-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signUp" }));
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe("auth:errors.couldNotCreateAccount");
    expect(screen.getByLabelText("auth:fields.email").getAttribute("aria-invalid")).toBeNull();
  });
});
