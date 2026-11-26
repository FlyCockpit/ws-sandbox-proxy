// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { act, type ReactNode, useSyncExternalStore } from "react";
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
  // A pool invitation held in this tab's memory (lib/pool-invite.ts).
  inviteToken: undefined as string | undefined,
  twoFactor: {
    sendOtp: vi.fn(),
    verifyOtp: vi.fn(),
    verifyTotp: vi.fn(),
    verifyBackupCode: vi.fn(),
  },
  // Better Auth's session atom as the page sees it; `setSession` re-renders.
  session: { status: "anonymous" as "pending" | "anonymous" | "error" },
  listeners: new Set<() => void>(),
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
  useAuthSession: () => ({
    state: useSyncExternalStore(
      (onChange) => {
        fx.listeners.add(onChange);
        return () => fx.listeners.delete(onChange);
      },
      () => fx.session,
    ),
  }),
}));
vi.mock("@/lib/auth-client", () => ({
  authClient: {
    signIn: { email: fx.signIn },
    signUp: { email: fx.signUp },
    twoFactor: fx.twoFactor,
  },
}));
vi.mock("@/server/auth-session", () => ({ getRouteSession: vi.fn() }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    auth: { verifyEmailTransport: { call: async () => ({ ok: true }) } },
    appConfig: { queryOptions: () => ({}), queryKey: () => ["appConfig"], call: async () => ({}) },
  },
}));
vi.mock("@/lib/pool-invite", () => ({
  poolInviteToken: () => fx.inviteToken,
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
  fx.inviteToken = undefined;
  for (const fn of Object.values(fx.twoFactor)) fn.mockReset();
  fx.session = { status: "anonymous" };
});
afterEach(() => cleanup());

function setSession(status: typeof fx.session.status) {
  fx.session = { status };
  for (const listener of fx.listeners) listener();
}

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

  it("offers Sign Up on a closed server to a visitor holding a pool invitation", () => {
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: false, emailEnabled: false };
    fx.inviteToken = "wssp_inv_x";
    render(<LoginPage />);
    expect(screen.getByText("auth:login.signupHint").closest("a")?.dataset.to).toBe(
      "/$lang/signup",
    );
    expect(screen.queryByText("auth:login.byInvitation")).toBeNull();
    expect(screen.getByText("auth:poolInviteReopen")).toBeTruthy();
  });

  it("sends a short password to the server: sign-in never applies the new-password minimum", async () => {
    fx.signIn.mockResolvedValue({ error: { code: "INVALID_EMAIL_OR_PASSWORD", status: 401 } });
    render(<LoginPage />);
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "short");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
    await waitFor(() =>
      expect(fx.signIn).toHaveBeenCalledWith({ email: "person@example.test", password: "short" }),
    );
  });

  it("asks for a password, and never shows the new-password rule", async () => {
    render(<LoginPage />);
    expect(screen.queryByText("auth:fields.passwordRule")).toBeNull();
    fill("auth:fields.email", "person@example.test");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
    expect((await screen.findByRole("alert")).textContent).toBe("validation:required");
    expect(fx.signIn).not.toHaveBeenCalled();
  });
});

describe("sign-in 2FA challenge", () => {
  const mode = () =>
    document.querySelector("[data-challenge-mode]")?.getAttribute("data-challenge-mode");

  async function reachChallenge() {
    fx.config = { ...fx.config, emailEnabled: true };
    fx.signIn.mockResolvedValue({ data: { twoFactorRedirect: true }, error: null });
    render(<LoginPage />);
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "right-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
    await waitFor(() => expect(mode()).toBe("totp"));
  }

  it("keeps the emailed-code mode through the session refetch the send causes", async () => {
    // Better Auth refetches the still-empty session after `/two-factor/send-otp`:
    // the atom reports pending while it runs, then anonymous again.
    fx.twoFactor.sendOtp.mockImplementation(async () => {
      setSession("pending");
      return { data: { status: true }, error: null };
    });
    fx.twoFactor.verifyOtp.mockResolvedValue({ error: { code: "INVALID_CODE", status: 401 } });
    await reachChallenge();
    const challenge = document.querySelector("[data-challenge-mode]");

    fireEvent.click(screen.getByRole("button", { name: "auth:twoFactor.emailMeCode" }));
    await waitFor(() => expect(mode()).toBe("email"));
    act(() => setSession("anonymous"));
    act(() => setSession("error"));
    expect(mode()).toBe("email");
    // The same element: the challenge was never unmounted.
    expect(document.querySelector("[data-challenge-mode]")).toBe(challenge);
    expect(screen.getByRole("button", { name: "auth:twoFactor.useAuthenticator" })).toBeTruthy();
    expect(screen.getByText("auth:twoFactor.emailCodeDescription")).toBeTruthy();

    fireEvent.change(screen.getByLabelText("auth:fields.verificationCode"), {
      target: { value: "654321" },
    });
    fireEvent.click(screen.getByRole("button", { name: "auth:twoFactor.verify" }));
    // Refused by the email check, so the email-code error, not the authenticator's.
    expect((await screen.findByRole("alert")).textContent).toBe("auth:errors.invalidEmailCode");
    expect(fx.twoFactor.verifyOtp).toHaveBeenCalledWith({ code: "654321" });
    expect(fx.twoFactor.verifyTotp).not.toHaveBeenCalled();
  });

  it("keeps the sign-in form and its error through a session refetch", async () => {
    fx.signIn.mockImplementation(async () => {
      setSession("pending");
      return { error: { code: "INVALID_EMAIL_OR_PASSWORD", status: 401 } };
    });
    render(<LoginPage />);
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "wrong-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
    expect((await screen.findByRole("alert")).textContent).toBe("auth:errors.invalidCredentials");
    expect(screen.getByLabelText("auth:fields.password")).toBeTruthy();
  });

  it("Cancel goes back to the sign-in form", async () => {
    await reachChallenge();
    fireEvent.click(screen.getByRole("button", { name: "common:actions.cancel" }));
    expect(mode()).toBeUndefined();
    expect(screen.getByLabelText("auth:fields.password")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "auth:twoFactor.verify" })).toBeNull();
  });

  it("waits for the first session answer before showing the form", () => {
    fx.session = { status: "pending" };
    render(<LoginPage />);
    expect(screen.queryByLabelText("auth:fields.password")).toBeNull();
    act(() => setSession("anonymous"));
    expect(screen.getByLabelText("auth:fields.password")).toBeTruthy();
  });
});

describe("sign up", () => {
  it("shows the invite-only card instead of a form when sign-up is closed", () => {
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: false, emailEnabled: false };
    render(<SignupPage />);
    expect(screen.getByText("auth:login.closedTitle")).toBeTruthy();
    expect(screen.getByText("auth:login.closedDescription")).toBeTruthy();
    expect(screen.getByText("auth:login.signIn").closest("a")?.dataset.to).toBe("/$lang/login");
    expect(screen.queryByLabelText("auth:fields.password")).toBeNull();
    expect(screen.queryByText("auth:login.createAccount")).toBeNull();
  });

  it("opens the form on a closed server for a visitor holding a pool invitation", () => {
    fx.config = { signupEnabled: false, adminBootstrapSignupEnabled: false, emailEnabled: false };
    fx.inviteToken = "wssp_inv_x";
    render(<SignupPage />);
    expect(screen.queryByText("auth:login.closedTitle")).toBeNull();
    expect(screen.getByText("auth:poolInviteReopen")).toBeTruthy();
    expect(screen.getByLabelText("auth:fields.password")).toBeTruthy();
  });

  it("states the password rule up front, tied to the field", () => {
    render(<SignupPage />);
    const rule = screen.getByText("auth:fields.passwordRule");
    const password = screen.getByLabelText("auth:fields.password");
    expect(password.getAttribute("aria-describedby")).toContain(rule.id);
  });

  it("refuses a password under the policy minimum before asking the server", async () => {
    render(<SignupPage />);
    fill("auth:fields.name", "Person");
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "a".repeat(11));
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signUp" }));
    await screen.findByRole("alert");
    expect(screen.getByLabelText("auth:fields.password").getAttribute("aria-invalid")).toBe("true");
    expect(fx.signUp).not.toHaveBeenCalled();
  });

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
