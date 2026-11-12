// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enLogins from "@wssp/locales/src/en-US/logins.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatRelativeTime } from "@/utils/relative-time";

/**
 * One login's page against a scripted fake server: settings, accounts with
 * pause, instances with automatic states and holders, write-only upload, and
 * the re-pin erase confirmation.
 */
const server = vi.hoisted(() => ({
  calls: [] as { name: string; input: unknown }[],
  repinErrors: [] as unknown[],
  login: {} as Record<string, unknown>,
  accounts: [] as Record<string, unknown>[],
  instances: [] as Record<string, unknown>[],
  definitions: [] as Record<string, unknown>[],
  document: {} as Record<string, unknown>,
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children }: { children: ReactNode }) => <a href="#back">{children}</a>,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/orpc", () => {
  const page = (key: string, items: () => Record<string, unknown>[]) => ({
    infiniteOptions: (options: {
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: string | null }) => unknown;
    }) => ({
      queryKey: ["logins", key],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async () => ({ items: structuredClone(items()), nextCursor: null }),
    }),
  });
  const mutation = (name: string, fail?: () => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: unknown) => {
        server.calls.push({ name, input });
        const error = fail?.();
        if (error) throw error;
        return {};
      },
    }),
  });
  return {
    orpc: {
      logins: {
        key: () => ["logins"],
        status: {
          queryOptions: () => ({
            queryKey: ["logins", "status"],
            queryFn: async () => ({ enabled: true, keyPresent: true, drain: false }),
          }),
        },
        getLogin: {
          queryOptions: () => ({
            queryKey: ["logins", "login"],
            queryFn: async () => structuredClone(server.login),
          }),
        },
        getDefinition: {
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["logins", "definition", input.id],
            queryFn: async () => ({ document: server.document, warnings: [] }),
          }),
        },
        listAccounts: page("accounts", () => server.accounts),
        listInstances: page("instances", () => server.instances),
        listDefinitions: page("definitions", () => server.definitions),
        listEvents: page("events", () => []),
        listLoginSessions: {
          queryOptions: () => ({
            queryKey: ["logins", "sessions"],
            queryFn: async () => ({ items: [], nextCursor: null }),
          }),
        },
        deleteLogin: mutation("deleteLogin"),
        updateLogin: mutation("updateLogin"),
        updateLoginPolicy: mutation("updateLoginPolicy"),
        repinLogin: mutation("repinLogin", () => server.repinErrors.shift()),
        createAccount: mutation("createAccount"),
        updateAccount: mutation("updateAccount"),
        deleteAccount: mutation("deleteAccount"),
        createInstance: mutation("createInstance"),
        updateInstance: mutation("updateInstance"),
        deleteInstance: mutation("deleteInstance"),
        writeValue: mutation("writeValue"),
      },
    },
  };
});

const { LoginDetailPage } = await import("./login-detail-page");

function renderPage() {
  const i18n = createInstance();
  void i18n.init({
    lng: "en-US",
    resources: { "en-US": { logins: enLogins, common: enCommon, dashboard: enDashboard } },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <LoginDetailPage lang="en-US" loginId="cred_1" />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  server.calls = [];
  server.repinErrors = [];
  server.login = {
    id: "cred_1",
    name: "work",
    definition: { id: "def_1", slug: "tool", version: 1, displayName: "Tool" },
    definitionDigest: "ab".repeat(32),
    mode: "EXCLUSIVE",
    delivery: "GUEST",
    copyBack: true,
    checkpointIntervalMin: null,
    foreignAllowed: false,
    createdAt: "2026-11-01T00:00:00.000Z",
    updatedAt: "2026-11-01T00:00:00.000Z",
  };
  server.document = {
    schemaVersion: 1,
    id: "tool",
    displayName: "Tool",
    login: { command: "true", method: "paste" },
    credentials: { env: [{ name: "TOOL_TOKEN", required: true }] },
  };
  server.accounts = [
    {
      id: "acc_1",
      credentialId: "cred_1",
      ordinal: 1,
      name: null,
      paused: true,
      pausedAt: "2026-11-01T00:00:00.000Z",
      createdAt: "2026-11-01T00:00:00.000Z",
    },
  ];
  server.instances = [
    {
      id: "ins_1",
      credentialId: "cred_1",
      accountId: "acc_1",
      ordinal: 1,
      name: "laptop",
      state: "NEEDS_LOGIN",
      needsLoginReason: "capture_failed",
      maxConcurrent: 1,
      activeLeases: 0,
      loginInProgress: false,
      lastCapturedAt: null,
      lastUploadedAt: null,
      createdAt: "2026-11-01T00:00:00.000Z",
    },
  ];
  server.definitions = [
    {
      id: "def_2",
      slug: "tool",
      version: 2,
      digest: "cd".repeat(32),
      displayName: "Tool",
      archivedAt: null,
      createdAt: "2026-11-02T00:00:00.000Z",
    },
  ];
});
afterEach(() => cleanup());

describe("LoginDetailPage", () => {
  it("shows settings, a paused account and an instance's automatic state", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { name: "work" })).toBeTruthy();
    expect(screen.getByText(enLogins.settings.checkpointsOff)).toBeTruthy();
    expect(await screen.findByText("Account 1")).toBeTruthy();
    expect(screen.getByText(enLogins.accounts.paused)).toBeTruthy();
    expect(await screen.findByText("laptop")).toBeTruthy();
    expect(screen.getByText(enLogins.instances.state.NEEDS_LOGIN)).toBeTruthy();
    expect(screen.getByText("In use by 0 of 1 · Last saved never")).toBeTruthy();
    // Instances have no pause control; only the account does.
    expect(screen.getAllByRole("switch", { name: /Pause/ })).toHaveLength(1);
  });

  it("shows the newest of the last upload and the last capture as last saved", async () => {
    const uploaded = Date.now() - 5 * 60_000;
    server.instances[0] = {
      ...server.instances[0],
      lastCapturedAt: new Date(uploaded - 3_600_000).toISOString(),
      lastUploadedAt: new Date(uploaded).toISOString(),
    };
    renderPage();
    await screen.findByText("laptop");
    const when = formatRelativeTime(uploaded, "en-US", Date.now());
    expect(screen.getByText(`In use by 0 of 1 · Last saved ${when}`)).toBeTruthy();
  });

  it("an upload alone counts as saved", async () => {
    const uploaded = Date.now() - 2 * 60_000;
    server.instances[0] = {
      ...server.instances[0],
      lastUploadedAt: new Date(uploaded).toISOString(),
    };
    renderPage();
    await screen.findByText("laptop");
    expect(screen.queryByText(/Last saved never/)).toBeNull();
    const when = formatRelativeTime(uploaded, "en-US", Date.now());
    expect(screen.getByText(`In use by 0 of 1 · Last saved ${when}`)).toBeTruthy();
  });

  it("labels the empty-instance dialog's submit with its action", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("laptop");
    await user.click(screen.getByRole("button", { name: enLogins.instances.addEmpty }));
    const dialog = await screen.findByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: enLogins.instances.addEmpty });
    expect(submit.getAttribute("type")).toBe("submit");
    expect(within(dialog).queryByRole("button", { name: /Add another instance/ })).toBeNull();
    await user.click(submit);
    await waitFor(() =>
      expect(server.calls).toContainEqual({
        name: "createInstance",
        input: { credentialId: "cred_1", accountId: "acc_1" },
      }),
    );
  });

  it("resumes a paused account", async () => {
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Account 1");
    await user.click(screen.getByRole("switch", { name: /Pause/ }));
    await waitFor(() =>
      expect(server.calls).toContainEqual({
        name: "updateAccount",
        input: { credentialId: "cred_1", accountId: "acc_1", paused: false },
      }),
    );
  });

  it("uploads a value write-only through a password field", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enLogins.upload.action }));
    const dialog = await screen.findByRole("dialog");
    const input = within(dialog).getByLabelText("TOOL_TOKEN");
    expect(input.getAttribute("type")).toBe("password");
    await user.type(input, "s3cr3t-value");
    await user.click(within(dialog).getByRole("button", { name: enLogins.upload.submit }));
    await waitFor(() =>
      expect(server.calls).toContainEqual({
        name: "writeValue",
        input: { credentialId: "cred_1", instanceId: "ins_1", env: { TOOL_TOKEN: "s3cr3t-value" } },
      }),
    );
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(document.body.innerHTML).not.toContain("s3cr3t-value");
  });

  it("asks for the login's name before a re-pin that erases proxied values", async () => {
    server.repinErrors = [{ data: { code: "credential.repin_confirm_erase" } }];
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enLogins.repin.action }));
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("combobox"));
    await user.click(await screen.findByRole("option", { name: "Tool v2" }));
    await user.click(within(dialog).getByRole("button", { name: enLogins.repin.submit }));
    const confirm = await within(dialog).findByLabelText(
      enLogins.repin.confirmErase.replace("{{name}}", "work"),
    );
    const erase = within(dialog).getByRole("button", { name: enLogins.repin.submitErase });
    expect(erase.hasAttribute("disabled")).toBe(true);
    await user.type(confirm, "work");
    await user.click(erase);
    await waitFor(() =>
      expect(server.calls.filter((call) => call.name === "repinLogin")).toEqual([
        { name: "repinLogin", input: { id: "cred_1", definitionId: "def_2" } },
        {
          name: "repinLogin",
          input: { id: "cred_1", definitionId: "def_2", confirmErase: "work" },
        },
      ]),
    );
  });
});
