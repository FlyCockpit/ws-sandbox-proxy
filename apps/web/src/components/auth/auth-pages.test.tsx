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
  configPending: false,
  configError: false,
  search: {
    redirectTo: undefined as string | undefined,
    error: undefined as string | undefined,
    ok: undefined as boolean | undefined,
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
  session: { status: "anonymous" as "pending" | "anonymous" | "authenticated" | "error" },
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
    useSearch: () => fx.search,
  }),
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({
    data: fx.config,
    isPending: fx.configPending,
    isError: fx.configError,
    isLoadingError: fx.configError,
    refetch: vi.fn(),
  }),
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
vi.mock("react-i18next", async (importOriginal) => ({
  ...(await importOriginal<typeof import("react-i18next")>()),
  useTranslation: () => ({ t: (key: string) => key }),
}));

import enAuth from "@wssp/locales/src/en-US/auth.json";
import enErrors from "@wssp/locales/src/en-US/errors.json";
import esAuth from "@wssp/locales/src/es-MX/auth.json";
import esErrors from "@wssp/locales/src/es-MX/errors.json";
import i18n, { loadLocale } from "@/i18n";

vi.mock("./resend-verification", () => ({
  ResendVerification: ({ email }: { email?: string }) => (
    <div data-resend-verification="" data-email={email ?? ""} />
  ),
}));
vi.mock("@/components/auth/resend-verification", () => ({
  ResendVerification: ({ email }: { email?: string }) => (
    <div data-resend-verification="" data-email={email ?? ""} />
  ),
}));

type Page = (() => ReactNode) & { preload?: () => Promise<void> };
async function page(path: string): Promise<Page> {
  const mod = (await import(path)) as { Route: { options: { component: Page } } };
  await mod.Route.options.component.preload?.();
  return mod.Route.options.component;
}
const LoginPage = await page("@/routes/$lang/_app/login");
const SignupPage = await page("@/routes/$lang/_app/signup");
const VerifyEmailPage = await page("@/routes/$lang/_app/verify-email");

beforeEach(() => {
  fx.config = { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: false };
  fx.configPending = false;
  fx.configError = false;
  fx.search = { redirectTo: undefined, error: undefined, ok: undefined };
  fx.signIn.mockReset();
  fx.toast.error.mockReset();
  fx.toast.success.mockReset();
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
    expect(alert.textContent).toBe(enErrors.rateLimited);
    expect(screen.getByLabelText("auth:fields.password").getAttribute("aria-invalid")).toBeNull();
  });

  it.each([
    ["en-US", enErrors],
    ["es-MX", esErrors],
  ] as const)("classifies sign-in failures in %s", async (lang, errors) => {
    await loadLocale(lang);
    await i18n.changeLanguage(lang);
    for (const kind of ["server", "offline", "unreachable"] as const) {
      Object.defineProperty(navigator, "onLine", { configurable: true, value: kind !== "offline" });
      if (kind === "server") fx.signIn.mockResolvedValueOnce({ error: { status: 503 } });
      else fx.signIn.mockRejectedValueOnce(new TypeError("Failed to fetch"));
      render(<LoginPage />);
      fill("auth:fields.email", "person@example.test");
      fill("auth:fields.password", "some-password");
      fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
      await waitFor(() =>
        expect(fx.toast.error).toHaveBeenLastCalledWith(
          kind === "server" ? errors.serverError : errors[kind],
        ),
      );
      expect(screen.getByLabelText("auth:fields.password").getAttribute("aria-invalid")).toBeNull();
      expect(screen.getByLabelText("auth:fields.email")).toHaveProperty(
        "value",
        "person@example.test",
      );
      expect(screen.getByLabelText("auth:fields.password")).toHaveProperty(
        "value",
        "some-password",
      );
      cleanup();
    }
    Object.defineProperty(navigator, "onLine", { configurable: true, value: true });
    await i18n.changeLanguage("en-US");
  });

  it("shows verification guidance and a resend link inside the form", async () => {
    fx.signIn.mockResolvedValue({ error: { code: "EMAIL_NOT_VERIFIED", status: 403 } });
    render(<LoginPage />);
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "some-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signIn" }));
    expect((await screen.findByRole("alert")).textContent).toBe("auth:verifyEmail.notVerified");
    expect(screen.getByText("auth:verifyEmail.resend").closest("a")?.dataset.to).toBe(
      "/$lang/verify-email",
    );
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

  it("shows accountCreatedNoEmail without repeating emailUnavailable when mail is disabled", async () => {
    fx.config = { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: false };
    fx.signUp.mockResolvedValue({ data: { user: { id: "u1" } }, error: null });
    render(<SignupPage />);
    fill("auth:fields.name", "Person");
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "a-long-enough-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signUp" }));

    expect(await screen.findByText("auth:verifyEmail.pendingTitle")).toBeTruthy();
    expect(screen.getByText("auth:verifyEmail.accountCreatedNoEmail")).toBeTruthy();
    expect(screen.queryByText("auth:verifyEmail.emailUnavailable")).toBeNull();
    expect(document.querySelector("[data-resend-verification]")).toBeNull();
  });

  it("shows sent copy and ResendVerification when mail is enabled after signup", async () => {
    fx.config = { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: true };
    fx.inviteToken = "wssp_inv_x";
    fx.signUp.mockResolvedValue({ data: { user: { id: "u1" } }, error: null });
    render(<SignupPage />);
    fill("auth:fields.name", "Person");
    fill("auth:fields.email", "person@example.test");
    fill("auth:fields.password", "a-long-enough-password");
    fireEvent.click(screen.getByRole("button", { name: "auth:login.signUp" }));

    expect(await screen.findByText("auth:verifyEmail.sentTitle")).toBeTruthy();
    expect(screen.getByText("auth:verifyEmail.sentDescription")).toBeTruthy();
    expect(screen.getByText("auth:poolInviteReopen")).toBeTruthy();
    expect(screen.queryByText("auth:verifyEmail.emailUnavailable")).toBeNull();
    expect(document.querySelector("[data-resend-verification]")?.getAttribute("data-email")).toBe(
      "person@example.test",
    );
  });
});

describe("verify email", () => {
  it.each([
    ["pending", undefined, "pendingDescriptionNoResend", "pendingDescription"],
    ["invalid", "INVALID_TOKEN", "invalidDescriptionNoResend", "invalidDescription"],
  ] as const)(
    "uses %s no-resend description without prompting for email when mail is off",
    (_label, error, expectedKey, suppressedKey) => {
      fx.config = { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: false };
      fx.search = { redirectTo: undefined, error, ok: undefined };
      render(<VerifyEmailPage />);
      expect(screen.getByText(`auth:verifyEmail.${expectedKey}`)).toBeTruthy();
      expect(screen.queryByText(`auth:verifyEmail.${suppressedKey}`)).toBeNull();
      expect(screen.getByText("auth:verifyEmail.emailUnavailable")).toBeTruthy();
      expect(document.querySelector("[data-resend-verification]")).toBeNull();
    },
  );

  it.each([
    ["pending", undefined, "pendingDescription", "pendingDescriptionNoResend"],
    ["invalid", "INVALID_TOKEN", "invalidDescription", "invalidDescriptionNoResend"],
  ] as const)(
    "shows %s resend prompt and form when mail is enabled",
    (_label, error, expectedKey, suppressedKey) => {
      fx.config = { signupEnabled: true, adminBootstrapSignupEnabled: false, emailEnabled: true };
      fx.search = { redirectTo: undefined, error, ok: undefined };
      render(<VerifyEmailPage />);
      expect(screen.getByText(`auth:verifyEmail.${expectedKey}`)).toBeTruthy();
      expect(screen.queryByText(`auth:verifyEmail.${suppressedKey}`)).toBeNull();
      expect(screen.queryByText("auth:verifyEmail.emailUnavailable")).toBeNull();
      expect(document.querySelector("[data-resend-verification]")).not.toBeNull();
    },
  );

  it("does not prompt for email while config is pending or failed to load", () => {
    fx.configPending = true;
    render(<VerifyEmailPage />);
    expect(screen.getByText("auth:verifyEmail.pendingDescriptionNoResend")).toBeTruthy();
    expect(screen.queryByText("auth:verifyEmail.pendingDescription")).toBeNull();
    cleanup();

    fx.configPending = false;
    fx.configError = true;
    fx.search = { redirectTo: undefined, error: "INVALID_TOKEN", ok: undefined };
    render(<VerifyEmailPage />);
    expect(screen.getByText("auth:verifyEmail.invalidDescriptionNoResend")).toBeTruthy();
    expect(screen.queryByText("auth:verifyEmail.invalidDescription")).toBeNull();
    expect(screen.getByRole("button", { name: "common:actions.retry" })).toBeTruthy();
  });

  it("does not prompt to enter email in en-US or es-MX no-resend copy", () => {
    for (const bundle of [enAuth, esAuth]) {
      expect(bundle.verifyEmail.pendingDescriptionNoResend).not.toMatch(
        /enter your email|ingresa tu correo/i,
      );
      expect(bundle.verifyEmail.invalidDescriptionNoResend).not.toMatch(
        /enter your email|ingresa tu correo/i,
      );
    }
  });
});
