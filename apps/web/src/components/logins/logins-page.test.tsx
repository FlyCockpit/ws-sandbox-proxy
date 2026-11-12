// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enLogins from "@wssp/locales/src/en-US/logins.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Logins overview against a scripted fake server: availability states, the
 * logins and definitions lists, and live definition validation before create.
 */
const server = vi.hoisted(() => ({
  status: { enabled: true, keyPresent: true, drain: false },
  logins: [] as Record<string, unknown>[],
  definitions: [] as Record<string, unknown>[],
  creates: [] as unknown[],
  documents: {} as Record<string, unknown>,
  loginCreates: [] as unknown[],
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  useNavigate: () => vi.fn(),
  Link: ({ children }: { children: ReactNode }) => <a href="#login">{children}</a>,
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
  return {
    orpc: {
      logins: {
        key: () => ["logins"],
        status: {
          queryOptions: () => ({
            queryKey: ["logins", "status"],
            queryFn: async () => server.status,
          }),
        },
        listLogins: page("list", () => server.logins),
        listDefinitions: page("definitions", () => server.definitions),
        getDefinition: {
          queryKey: ({ input }: { input: { id: string } }) => ["logins", "definition", input.id],
          queryOptions: ({ input }: { input: { id: string } }) => ({
            queryKey: ["logins", "definition", input.id],
            queryFn: async () => ({ document: server.documents[input.id] ?? {}, warnings: [] }),
          }),
        },
        createDefinition: {
          mutationOptions: () => ({
            mutationFn: async (input: unknown) => {
              server.creates.push(input);
              return {};
            },
          }),
        },
        createLogin: {
          mutationOptions: () => ({
            mutationFn: async (input: { name: string }) => {
              server.loginCreates.push(input);
              return { name: input.name };
            },
          }),
        },
        archiveDefinition: { mutationOptions: () => ({ mutationFn: async () => ({}) }) },
      },
    },
  };
});

const { LoginsPage } = await import("./logins-page");
const { selectOption } = await import("@/test/select-option");

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
        <LoginsPage lang="en-US" />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

const minimal = {
  schemaVersion: 1,
  id: "tool",
  displayName: "Tool",
  login: { command: "true", method: "paste" },
  credentials: { env: [{ name: "TOOL_TOKEN", required: true }] },
};

beforeEach(() => {
  server.status = { enabled: true, keyPresent: true, drain: false };
  server.logins = [];
  server.definitions = [];
  server.creates = [];
  server.documents = {};
  server.loginCreates = [];
});
afterEach(() => cleanup());

describe("LoginsPage", () => {
  it("explains a server without CLI logins and offers no create", async () => {
    server.status = { enabled: false, keyPresent: false, drain: false };
    renderPage();
    expect(await screen.findByText(enLogins.unavailable.title)).toBeTruthy();
    expect(screen.queryByRole("button", { name: enLogins.create.action })).toBeNull();
  });

  it("is read-only in drain mode", async () => {
    server.status = { enabled: false, keyPresent: true, drain: true };
    renderPage();
    expect(await screen.findByText(enLogins.readOnly)).toBeTruthy();
    expect(screen.queryByRole("button", { name: enLogins.create.action })).toBeNull();
    expect(screen.queryByRole("button", { name: enLogins.definitions.add })).toBeNull();
  });

  it("lists logins and definitions", async () => {
    server.logins = [
      {
        id: "cred_1",
        name: "work",
        mode: "EXCLUSIVE",
        delivery: "GUEST",
        definition: { id: "def_1", slug: "tool", version: 2, displayName: "Tool" },
      },
    ];
    server.definitions = [
      {
        id: "def_1",
        slug: "tool",
        version: 2,
        digest: "ab".repeat(32),
        displayName: "Tool",
        archivedAt: null,
        createdAt: "2026-11-01T00:00:00.000Z",
      },
    ];
    renderPage();
    expect(await screen.findByText("work")).toBeTruthy();
    expect(screen.getByText(enLogins.mode.EXCLUSIVE)).toBeTruthy();
    expect(screen.getByText("Tool (version 2)")).toBeTruthy();
    expect(await screen.findByText("Tool v2")).toBeTruthy();
  });

  it("validates a pasted definition live and only submits a valid one", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: enLogins.definitions.add }));
    const textarea = screen.getByLabelText(enLogins.definitions.json);
    fireEvent.change(textarea, { target: { value: "{" } });
    expect(await screen.findByText(enLogins.problem.definitionInvalid)).toBeTruthy();
    const submit = screen
      .getAllByRole("button", { name: enLogins.definitions.add })
      .find((button) => button.getAttribute("type") === "submit");
    expect(submit?.hasAttribute("disabled")).toBe(true);
    const text = JSON.stringify(minimal);
    fireEvent.change(textarea, { target: { value: text } });
    expect(await screen.findByText("Valid definition “Tool” (tool).")).toBeTruthy();
    expect(submit?.hasAttribute("disabled")).toBe(false);
    if (submit) await user.click(submit);
    await waitFor(() => expect(server.creates).toEqual([{ text }]));
  });

  describe("create login", () => {
    const definitionRow = (id: string, version: number, displayName: string) => ({
      id,
      slug: displayName.toLowerCase(),
      version,
      digest: "ab".repeat(32),
      displayName,
      archivedAt: null,
      createdAt: "2026-11-01T00:00:00.000Z",
    });
    const proxied = {
      schemaVersion: 1,
      id: "api",
      displayName: "API",
      login: { command: "true", method: "paste" },
      credentials: {
        env: [
          {
            name: "API_KEY",
            required: true,
            proxy: {
              upstream: "https://api.example.com/v1",
              header: "Authorization",
              format: "Bearer {value}",
              baseUrlEnv: "API_BASE_URL",
            },
          },
        ],
        sharing: "shareable",
      },
    };

    async function openCreate() {
      const user = userEvent.setup();
      renderPage();
      await user.click(await screen.findByRole("button", { name: enLogins.create.action }));
      const dialog = await screen.findByRole("dialog");
      const trigger = within(dialog).getByRole("combobox", { name: enLogins.form.definition });
      return { user, dialog, trigger };
    }

    it("shows a placeholder, not an unavailable option, before a definition is chosen", async () => {
      server.definitions = [definitionRow("def_api", 1, "API")];
      const { trigger } = await openCreate();
      await waitFor(() => expect(trigger.hasAttribute("disabled")).toBe(false));
      expect(trigger.textContent).toContain(enLogins.form.definitionPlaceholder);
      expect(trigger.textContent).not.toContain(enCommon.optionUnavailable);
    });

    it("defaults to proxied delivery when the definition supports it, per definition", async () => {
      server.definitions = [
        definitionRow("def_api", 1, "API"),
        definitionRow("def_tool", 1, "Tool"),
      ];
      server.documents = { def_api: proxied, def_tool: minimal };
      const { user, dialog, trigger } = await openCreate();
      await selectOption(user, trigger, "API v1");
      expect(trigger.textContent).toContain("API v1");
      const proxy = await within(dialog).findByRole("radio", { name: enLogins.delivery.PROXY });
      expect((proxy as HTMLInputElement).checked).toBe(true);
      expect(
        (within(dialog).getByRole("radio", { name: enLogins.delivery.GUEST }) as HTMLInputElement)
          .checked,
      ).toBe(false);
      expect(within(dialog).getByText(enLogins.form.deliveryHint)).toBeTruthy();
      // An explicit choice holds until the definition changes.
      await user.click(within(dialog).getByRole("radio", { name: enLogins.delivery.GUEST }));
      await selectOption(user, trigger, "Tool v1");
      await waitFor(() =>
        expect(within(dialog).queryByRole("radio", { name: enLogins.delivery.PROXY })).toBeNull(),
      );
      await selectOption(user, trigger, "API v1");
      const again = await within(dialog).findByRole("radio", { name: enLogins.delivery.PROXY });
      expect((again as HTMLInputElement).checked).toBe(true);
      fireEvent.change(within(dialog).getByLabelText(enLogins.form.name), {
        target: { value: "api" },
      });
      await user.click(within(dialog).getByRole("button", { name: enLogins.create.submit }));
      await waitFor(() =>
        expect(server.loginCreates).toEqual([
          { name: "api", definitionId: "def_api", delivery: "PROXY" },
        ]),
      );
    });

    it("sends guest delivery for a definition that cannot be proxied", async () => {
      server.definitions = [definitionRow("def_tool", 1, "Tool")];
      server.documents = { def_tool: minimal };
      const { user, dialog, trigger } = await openCreate();
      await selectOption(user, trigger, "Tool v1");
      fireEvent.change(within(dialog).getByLabelText(enLogins.form.name), {
        target: { value: "tool" },
      });
      await user.click(within(dialog).getByRole("button", { name: enLogins.create.submit }));
      await waitFor(() =>
        expect(server.loginCreates).toEqual([
          { name: "tool", definitionId: "def_tool", delivery: "GUEST", copyBack: true },
        ]),
      );
    });
  });
});
