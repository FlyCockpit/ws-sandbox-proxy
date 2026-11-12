// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enErrors from "@wssp/locales/src/en-US/errors.json";
import enLogins from "@wssp/locales/src/en-US/logins.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The login session page against a scripted fake server: state copy, the
 * login command (or "not supported"), the terminal only while the session
 * holds its sandbox, Save / Check / Cancel, and session polling.
 */
const server = vi.hoisted(() => ({
  calls: [] as { name: string; input: unknown }[],
  session: {} as Record<string, unknown>,
  finishError: null as unknown,
  terminalProps: [] as Record<string, unknown>[],
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="#link">{children}</a>,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (error: { data?: { code?: string } }) => `friendly:${error?.data?.code ?? "generic"}`,
}));
vi.mock("@/components/sandboxes/sandbox-terminal", () => ({
  SandboxTerminal: (props: Record<string, unknown>) => {
    server.terminalProps.push(props);
    return (
      <div data-testid="terminal" data-available={String(props.available)}>
        {String(props.typeCommand ?? "")}
      </div>
    );
  },
}));
vi.mock("@/utils/orpc", () => {
  const mutation = (name: string, result: () => unknown, fail?: () => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: unknown) => {
        server.calls.push({ name, input });
        const error = fail?.();
        if (error) throw error;
        return result();
      },
    }),
  });
  return {
    orpc: {
      logins: {
        key: () => ["logins"],
        getLoginSession: {
          key: () => ["logins", "session"],
          queryOptions: () => ({
            queryKey: ["logins", "session"],
            queryFn: async () => structuredClone(server.session),
          }),
        },
        getLogin: {
          queryOptions: () => ({
            queryKey: ["logins", "login"],
            queryFn: async () => ({ id: "cred_1", name: "work" }),
          }),
        },
        finishLogin: mutation(
          "finishLogin",
          () => ({ sessionId: "ses_1", operationId: "op_1", state: "SAVING" }),
          () => server.finishError,
        ),
        verifyLogin: mutation("verifyLogin", () => ({ operationId: "op_v", state: "QUEUED" })),
        cancelLogin: mutation("cancelLogin", () => ({ ...server.session, state: "CANCELLED" })),
      },
      sandboxes: {
        getOperationView: {
          queryOptions: () => ({
            queryKey: ["op"],
            queryFn: async () => ({ state: "SUCCEEDED", exitCode: 3 }),
          }),
        },
      },
    },
  };
});

const { LoginSessionPage, sessionPollMs } = await import("./login-session-page");

function renderPage() {
  const i18n = createInstance();
  void i18n.init({
    lng: "en-US",
    resources: {
      "en-US": { logins: enLogins, common: enCommon, dashboard: enDashboard, errors: enErrors },
    },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <LoginSessionPage lang="en-US" sessionId="ses_1" />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

function session(overrides: Record<string, unknown> = {}) {
  return {
    id: "ses_1",
    credentialId: "cred_1",
    accountId: "acc_1",
    instanceId: "ins_1",
    sandboxId: "sbx_1",
    state: "READY",
    foreignConsent: false,
    expiresAt: new Date(Date.now() + 20 * 60_000).toISOString(),
    createdAt: "2026-11-03T00:00:00.000Z",
    updatedAt: "2026-11-03T00:00:00.000Z",
    login: {
      command: "tool auth login",
      method: "paste",
      supported: true,
      doneWhenCommandExits: false,
      hasVerifyCommand: true,
    },
    ...overrides,
  };
}

beforeEach(() => {
  server.calls = [];
  server.finishError = null;
  server.terminalProps = [];
  server.session = session();
});
afterEach(cleanup);

describe("login session page", () => {
  it("polls while the server moves the session and stops once it settles", () => {
    expect(sessionPollMs(undefined)).toBe(2_000);
    expect(sessionPollMs("PROVISIONING")).toBe(2_000);
    expect(sessionPollMs("SAVING")).toBe(2_000);
    expect(sessionPollMs("READY")).toBe(5_000);
    expect(sessionPollMs("FAILED")).toBe(5_000);
    expect(sessionPollMs("SAVED")).toBe(false);
    expect(sessionPollMs("CANCELLED")).toBe(false);
    expect(sessionPollMs("EXPIRED")).toBe(false);
  });

  it("shows the command, the terminal with Type it for me, and saves", async () => {
    const user = userEvent.setup();
    renderPage();
    expect(await screen.findByText(enLogins.session.stateHint.READY)).toBeTruthy();
    expect(screen.getByRole("button", { name: enLogins.session.command.copy })).toBeTruthy();
    expect(document.querySelector('[data-slot="copy-field-value"]')?.textContent).toBe(
      "tool auth login",
    );
    const terminal = screen.getByTestId("terminal");
    expect(terminal.dataset.available).toBe("true");
    expect(terminal.textContent).toBe("tool auth login");

    await user.click(screen.getByRole("button", { name: enLogins.session.actions.save }));
    await waitFor(() =>
      expect(server.calls).toContainEqual({ name: "finishLogin", input: { id: "ses_1" } }),
    );
  });

  it("explains a FAILED session and lets the user save again", async () => {
    const user = userEvent.setup();
    server.session = session({ state: "FAILED" });
    renderPage();
    expect(await screen.findByText(enLogins.session.stateHint.FAILED)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: enLogins.session.actions.save }));
    await waitFor(() => expect(server.calls.map((call) => call.name)).toContain("finishLogin"));
  });

  it("shows a refused save with the server's error copy", async () => {
    const user = userEvent.setup();
    server.finishError = { status: 409, data: { code: "credential.login_state" } };
    renderPage();
    await user.click(await screen.findByRole("button", { name: enLogins.session.actions.save }));
    expect(await screen.findByText("friendly:credential.login_state")).toBeTruthy();
  });

  it("runs the verify command and shows its exit code", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enLogins.session.actions.verify }));
    expect(
      await screen.findByText(enLogins.session.verify.failed.replace("{{code}}", "3")),
    ).toBeTruthy();
  });

  it("flags browser-callback logins as not supported and offers no Type it for me", async () => {
    server.session = session({
      login: {
        command: "tool login --web",
        method: "browser-callback",
        supported: false,
        doneWhenCommandExits: false,
        hasVerifyCommand: false,
      },
    });
    renderPage();
    expect(await screen.findByText(enLogins.session.command.unsupported)).toBeTruthy();
    expect(screen.getByTestId("terminal").textContent).toBe("");
    expect(screen.queryByRole("button", { name: enLogins.session.actions.verify })).toBeNull();
  });

  it("cancels through an AlertDialog", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enLogins.session.actions.cancel }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(enLogins.session.cancelDescription)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: enLogins.session.actions.cancel }));
    await waitFor(() =>
      expect(server.calls).toContainEqual({ name: "cancelLogin", input: { id: "ses_1" } }),
    );
  });

  it("keeps the terminal unavailable while provisioning and hides it once settled", async () => {
    server.session = session({ state: "PROVISIONING" });
    const view = renderPage();
    expect(await screen.findByText(enLogins.session.stateHint.PROVISIONING)).toBeTruthy();
    expect(screen.getByTestId("terminal").dataset.available).toBe("false");
    expect(
      (screen.getByRole("button", { name: enLogins.session.actions.save }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    view.unmount();

    server.session = session({ state: "SAVED" });
    renderPage();
    expect(await screen.findByText(enLogins.session.stateHint.SAVED)).toBeTruthy();
    expect(screen.queryByTestId("terminal")).toBeNull();
    expect(screen.queryByRole("button", { name: enLogins.session.actions.save })).toBeNull();
  });
});
