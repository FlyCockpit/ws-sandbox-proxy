// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import { createInstance, type i18n as I18n } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Admin users page against a scripted fake server: real TanStack Query, real
 * en-US strings, real dialogs. Refusals carry the admin error codes the real
 * procedures attach (`@wssp/api/lib/admin-error-codes`).
 */

type FakeUser = {
  id: string;
  email: string;
  name: string;
  role: string;
  emailVerified: boolean;
  banned: boolean | null;
  banReason: string | null;
  createdAt: Date;
  cliLogins: { logins: number; instances: number };
};

const server = vi.hoisted(() => ({
  users: [] as FakeUser[],
  calls: [] as { procedure: string; input: unknown }[],
  nextError: null as unknown,
}));

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));

vi.mock("@/utils/orpc", () => {
  const record = (procedure: string, input: unknown) => server.calls.push({ procedure, input });
  const mutation = (procedure: string, apply: (input: { userId: string }) => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: { userId: string }) => {
        record(procedure, input);
        if (server.nextError) {
          const error = server.nextError;
          server.nextError = null;
          throw error;
        }
        return apply(input);
      },
    }),
  });
  const find = (id: string) => server.users.find((user) => user.id === id)!;
  return {
    orpc: {
      users: {
        key: () => ["users"],
        list: {
          infiniteOptions: (options: {
            input: (cursor: string | undefined) => unknown;
            initialPageParam: unknown;
            getNextPageParam: (page: { nextCursor: string | null }) => unknown;
          }) => ({
            queryKey: ["users", "list"],
            initialPageParam: options.initialPageParam,
            getNextPageParam: options.getNextPageParam,
            queryFn: async ({ pageParam }: { pageParam: string | undefined }) => {
              record("list", options.input(pageParam));
              return { users: structuredClone(server.users), nextCursor: null };
            },
          }),
        },
        setRole: mutation("setRole", (input) => {
          find(input.userId).role = (input as unknown as { role: string }).role;
          return { success: true };
        }),
        archive: mutation("archive", (input) => {
          find(input.userId).banned = true;
          return { success: true };
        }),
        unarchive: mutation("unarchive", (input) => {
          find(input.userId).banned = false;
          return { success: true };
        }),
        remove: mutation("remove", (input) => {
          server.users = server.users.filter((user) => user.id !== input.userId);
          return { success: true };
        }),
        invite: mutation("invite", () => ({
          userId: "new",
          tempPassword: "temp",
          emailSent: true,
        })),
      },
    },
  };
});

import { AdminUsersPage } from "./admin-users-page";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["admin", "common", "errors"],
    defaultNS: "admin",
    resources: { "en-US": { admin: enAdmin, common: enCommon } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

function user(overrides: Partial<FakeUser>): FakeUser {
  return {
    id: "u-1",
    email: "one@example.com",
    name: "One",
    role: "user",
    emailVerified: true,
    banned: false,
    banReason: null,
    createdAt: new Date("2026-01-01T00:00:00.000Z"),
    cliLogins: { logins: 0, instances: 0 },
    ...overrides,
  };
}

function refusal(code: string, extra: Record<string, unknown> = {}, orpcCode = "CONFLICT") {
  return Object.assign(new Error("refused"), { code: orpcCode, data: { code, ...extra } });
}

function mount() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <AdminUsersPage currentUserId="me" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const row = (id: string) => document.querySelector<HTMLElement>(`li[data-user-id="${id}"]`)!;
const calls = (procedure: string) => server.calls.filter((call) => call.procedure === procedure);

async function openAction(id: string, name: string, item: string) {
  const u = userEvent.setup();
  await u.click(
    within(row(id)).getByRole("button", {
      name: enAdmin.users.actionsAriaLabel.replace("{{name}}", name),
    }),
  );
  await u.click(await screen.findByRole("menuitem", { name: item }));
  return u;
}

beforeEach(() => {
  server.users = [
    user({ id: "me", email: "me@example.com", name: "Me", role: "admin" }),
    user({ id: "admin-2", email: "two@example.com", name: "Two", role: "admin" }),
    user({ id: "u-1" }),
  ];
  server.calls = [];
  server.nextError = null;
  toast.success.mockReset();
  toast.error.mockReset();
});
afterEach(() => cleanup());

describe("admin users mutations", () => {
  it("sends a role change only after confirmation and shows the last-admin refusal in the dialog", async () => {
    mount();
    await screen.findByText("Two");
    const u = await openAction("admin-2", "Two", enAdmin.users.demoteToUser);
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText("Remove Two's admin role?")).toBeTruthy();
    expect(calls("setRole")).toHaveLength(0);

    server.nextError = refusal("admin.last_admin");
    await u.click(within(dialog).getByRole("button", { name: enAdmin.users.confirm.demoteAction }));
    expect(await within(dialog).findByRole("alert")).toHaveProperty(
      "textContent",
      enAdmin.problems.lastAdmin,
    );
    expect(calls("setRole")).toEqual([
      { procedure: "setRole", input: { userId: "admin-2", role: "user" } },
    ]);
    // The refusal refetched the list; the role is unchanged.
    await waitFor(() => expect(calls("list").length).toBeGreaterThan(1));
    expect(server.users.find((entry) => entry.id === "admin-2")?.role).toBe("admin");
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("closes the confirmation after a successful archive", async () => {
    mount();
    await screen.findByText("One");
    const u = await openAction("u-1", "One", enAdmin.users.archiveUser);
    const dialog = await screen.findByRole("alertdialog");
    await u.click(
      within(dialog).getByRole("button", { name: enAdmin.users.confirm.archiveAction }),
    );
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(toast.success).toHaveBeenCalledWith(enAdmin.users.userArchived);
    expect(calls("archive")).toEqual([{ procedure: "archive", input: { userId: "u-1" } }]);
  });

  it("cancelling a confirmation sends nothing", async () => {
    mount();
    await screen.findByText("One");
    const u = await openAction("u-1", "One", enAdmin.users.promoteToAdmin);
    const dialog = await screen.findByRole("alertdialog");
    await u.click(within(dialog).getByRole("button", { name: enCommon.actions.cancel }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(calls("setRole")).toHaveLength(0);
  });

  it("offers no self-demotion, self-archive or self-delete", async () => {
    const u = userEvent.setup();
    mount();
    await screen.findByText("Me");
    await u.click(
      within(row("me")).getByRole("button", {
        name: enAdmin.users.actionsAriaLabel.replace("{{name}}", "Me"),
      }),
    );
    for (const label of [
      enAdmin.users.demoteToUser,
      enAdmin.users.archiveUser,
      enAdmin.users.deleteAction,
    ]) {
      const item = await screen.findByRole("menuitem", { name: label });
      expect(item.getAttribute("aria-disabled")).toBe("true");
    }
  });

  it("keeps the delete dialog open and names each cleanup blocker when deletion is refused", async () => {
    mount();
    await screen.findByText("One");
    const u = await openAction("u-1", "One", enAdmin.users.deleteAction);
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: enCommon.actions.delete });
    expect(confirm).toHaveProperty("disabled", true);
    await u.type(within(dialog).getByRole("textbox"), "one@example.com");

    server.nextError = refusal("admin.account_deletion_blocked", {
      blockers: ["hosts", "operations", "not-a-kind"],
    });
    await u.click(confirm);
    const alert = await within(dialog).findByRole("alert");
    expect(alert.getAttribute("data-deletion-blockers")).toBe("hosts,operations");
    expect(alert.textContent).toContain(enAdmin.problems.deletionBlocked);
    expect(alert.textContent).toContain(enAdmin.blockers.hosts);
    expect(alert.textContent).toContain(enAdmin.blockers.operations);
    expect(alert.textContent).not.toContain("not-a-kind");
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    expect(server.users.some((entry) => entry.id === "u-1")).toBe(true);

    // Once the owner has cleaned up, the same dialog deletes on retry.
    await u.click(confirm);
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(toast.success).toHaveBeenCalledWith(enAdmin.users.userDeleted);
    expect(calls("remove")).toHaveLength(2);
  });

  it("explains a deletion that raced with resource changes as retryable", async () => {
    mount();
    await screen.findByText("One");
    const u = await openAction("u-1", "One", enAdmin.users.deleteAction);
    const dialog = await screen.findByRole("alertdialog");
    await u.type(within(dialog).getByRole("textbox"), "one@example.com");
    server.nextError = refusal("admin.account_deletion_blocked", { blockers: [] });
    await u.click(within(dialog).getByRole("button", { name: enCommon.actions.delete }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe(
      enAdmin.problems.deletionChanged,
    );
  });

  it("explains a lost admin session on restore instead of a generic failure", async () => {
    server.users = [user({ id: "u-1", banned: true })];
    mount();
    await screen.findByText("One");
    server.nextError = Object.assign(new Error("Not found"), { code: "NOT_FOUND" });
    await openAction("u-1", "One", enAdmin.users.restoreUser);
    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(enAdmin.problems.accessLost));
  });

  it("shows an invite refusal inline and keeps the dialog open", async () => {
    const u = userEvent.setup();
    mount();
    await screen.findByText("One");
    await u.click(screen.getByRole("button", { name: enAdmin.users.invite }));
    const dialog = await screen.findByRole("dialog");
    await u.type(within(dialog).getByLabelText(enAdmin.users.nameLabel), "Dup");
    await u.type(within(dialog).getByLabelText(enAdmin.users.emailLabel), "dup@example.com");
    server.nextError = refusal("admin.email_taken");
    await u.click(within(dialog).getByRole("button", { name: enAdmin.users.sendInvite }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe(
      enAdmin.problems.emailTaken,
    );
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("labels the invite role select and formats join dates in the UI locale (M7-S15, M7-S16)", async () => {
    const u = userEvent.setup();
    mount();
    await screen.findByText("One");
    await u.click(screen.getByRole("button", { name: enAdmin.users.invite }));
    const dialog = await screen.findByRole("dialog");
    const role = within(dialog).getByLabelText(enAdmin.users.roleLabel);
    expect(role.textContent).toContain(enAdmin.users.roleUser);
    expect(role.textContent).not.toMatch(/\buser\b/);
    await u.keyboard("{Escape}");
    cleanup();

    await i18n.changeLanguage("es-MX");
    try {
      mount();
      await screen.findByText("One");
      const joined = row("u-1").querySelector("time");
      expect(joined?.textContent).toBe(
        new Intl.DateTimeFormat("es-MX", { dateStyle: "medium" }).format(
          new Date("2026-01-01T00:00:00.000Z"),
        ),
      );
      expect(joined?.textContent).not.toBe(
        new Date("2026-01-01T00:00:00.000Z").toLocaleDateString("en-US"),
      );
    } finally {
      await i18n.changeLanguage("en-US");
    }
  });
});
