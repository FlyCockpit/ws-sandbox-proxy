// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enDashboard from "@wssp/locales/src/en-US/dashboard.json";
import enErrors from "@wssp/locales/src/en-US/errors.json";
import enLogins from "@wssp/locales/src/en-US/logins.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The sandbox Credentials panel against a scripted fake server: attached
 * logins with their lease state, Attach (the error copy for every mapped
 * refusal), and Free / "Free anyway (discard)".
 */
const server = vi.hoisted(() => ({
  calls: [] as { name: string; input: Record<string, unknown> }[],
  attached: [] as Record<string, unknown>[],
  attachedReads: 0,
  attachError: null as unknown,
  freeError: null as unknown,
  status: { enabled: true, keyPresent: true, drain: false },
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="#link">{children}</a>,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("@/utils/friendly-error", async () => {
  const { credentialErrorKey } = await import("@/lib/credential-errors");
  return { friendly: (error: unknown) => credentialErrorKey(error) ?? "generic" };
});
vi.mock("@/utils/orpc", () => {
  const page = (key: string, items: () => Record<string, unknown>[]) => ({
    infiniteOptions: (options: {
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: string | null }) => unknown;
    }) => ({
      queryKey: ["logins", key],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async () => {
        if (key === "attached") server.attachedReads += 1;
        return { items: structuredClone(items()), nextCursor: null };
      },
    }),
  });
  const mutation = (name: string, fail: () => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: Record<string, unknown>) => {
        server.calls.push({ name, input });
        const error = fail();
        if (error) throw error;
        return { operationId: "op_1", state: "QUEUED" };
      },
    }),
  });
  return {
    orpc: {
      sandboxes: { key: () => ["sandboxes"] },
      logins: {
        key: () => ["logins"],
        status: {
          queryOptions: () => ({
            queryKey: ["logins", "status"],
            queryFn: async () => server.status,
          }),
        },
        listSandboxCredentials: page("attached", () => server.attached),
        listLogins: page("logins", () => [
          { id: "cred_1", name: "work" },
          { id: "cred_2", name: "personal" },
        ]),
        listAccounts: page("accounts", () => []),
        listInstances: page("instances", () => []),
        attachSandboxCredential: mutation("attach", () => server.attachError),
        freeSandboxCredential: mutation("free", () => server.freeError),
      },
    },
  };
});

const {
  CREDENTIALS_BUSY_REFETCH_MS,
  CREDENTIALS_IDLE_REFETCH_MS,
  SandboxCredentials,
  credentialsRefetchInterval,
} = await import("./sandbox-credentials");

function renderPanel(state = "READY") {
  const i18n = createInstance();
  void i18n.init({
    lng: "en-US",
    resources: {
      "en-US": {
        sandboxes: enSandboxes,
        logins: enLogins,
        common: enCommon,
        dashboard: enDashboard,
        errors: enErrors,
      },
    },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <I18nextProvider i18n={i18n}>
      <QueryClientProvider client={client}>
        <SandboxCredentials lang="en-US" sandboxId="sbx_1" sandboxState={state} />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  server.calls = [];
  server.attachedReads = 0;
  server.attachError = null;
  server.freeError = null;
  server.status = { enabled: true, keyPresent: true, drain: false };
  server.attached = [
    {
      credentialId: "cred_1",
      name: "work",
      mode: "EXCLUSIVE",
      attachedAt: "2026-11-03T00:00:00.000Z",
      account: { id: "acc_1", name: "Main", ordinal: 1, paused: false },
      instance: { id: "ins_1", name: null, ordinal: 2, state: "READY" },
      lease: { id: "lse_1", state: "ACTIVE" },
    },
  ];
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function chooseLogin(user: ReturnType<typeof userEvent.setup>, name: string) {
  const dialog = await screen.findByRole("dialog");
  await user.click(within(dialog).getAllByRole("combobox")[0] as HTMLElement);
  await user.click(await screen.findByRole("option", { name }));
  return dialog;
}

describe("sandbox Credentials panel", () => {
  it("lists attached logins with account, instance and lease state", async () => {
    renderPanel();
    expect(await screen.findByText("work")).toBeTruthy();
    expect(screen.getByText("Main · Instance 2")).toBeTruthy();
    expect(screen.getByText(enLogins.leases.state.ACTIVE)).toBeTruthy();
  });

  it("renders nothing when CLI logins are unavailable", async () => {
    server.status = { enabled: false, keyPresent: false, drain: false };
    const view = renderPanel();
    await waitFor(() => expect(view.container.innerHTML).toBe(""));
  });

  it("attaches a login with a fresh idempotency key", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: enSandboxes.credentials.attach }));
    const dialog = await chooseLogin(user, "personal");
    await user.click(within(dialog).getByRole("button", { name: enSandboxes.credentials.attach }));
    await waitFor(() => expect(server.calls).toHaveLength(1));
    const call = server.calls[0];
    expect(call?.name).toBe("attach");
    expect(call?.input).toMatchObject({ id: "sbx_1", credentialId: "cred_2" });
    expect(call?.input.idempotencyKey).toEqual(expect.stringMatching(/^web\.credentialAttach\./));
    expect(call?.input).not.toHaveProperty("accountId");
  });

  it.each([
    "env_conflict",
    "path_conflict",
    "proxy_not_enabled",
    "already_attached",
    "pending_drain",
    "recovery_required",
    "capture_in_progress",
  ])("maps the attach refusal credential.%s to its copy", async (code) => {
    const user = userEvent.setup();
    server.attachError = { status: 409, data: { code: `credential.${code}` } };
    renderPanel();
    await user.click(await screen.findByRole("button", { name: enSandboxes.credentials.attach }));
    const dialog = await chooseLogin(user, "personal");
    await user.click(within(dialog).getByRole("button", { name: enSandboxes.credentials.attach }));
    expect(await within(dialog).findByText(`errors:credential.${code}`)).toBeTruthy();
    if (code === "proxy_not_enabled")
      expect(within(dialog).getByText(enSandboxes.credentials.proxyHint)).toBeTruthy();
  });

  it("frees with copy-back, or discards with credentialCapture skip", async () => {
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: enSandboxes.credentials.free }));
    let dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(enSandboxes.credentials.freeTerminals)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: enSandboxes.credentials.free }));
    await waitFor(() => expect(server.calls).toHaveLength(1));
    expect(server.calls[0]?.input).toMatchObject({ id: "sbx_1", credentialId: "cred_1" });
    expect(server.calls[0]?.input).not.toHaveProperty("credentialCapture");

    await user.click(await screen.findByRole("button", { name: enSandboxes.credentials.free }));
    dialog = await screen.findByRole("alertdialog");
    await user.click(
      within(dialog).getByRole("button", { name: enSandboxes.credentials.freeDiscard }),
    );
    await waitFor(() => expect(server.calls).toHaveLength(2));
    expect(server.calls[1]?.input).toMatchObject({ credentialCapture: "skip" });
  });

  it.each(["not_attached", "pending_drain", "recovery_required"])(
    "maps the free refusal credential.%s to its copy",
    async (code) => {
      const user = userEvent.setup();
      server.freeError = { status: 409, data: { code: `credential.${code}` } };
      renderPanel();
      await user.click(await screen.findByRole("button", { name: enSandboxes.credentials.free }));
      const dialog = await screen.findByRole("alertdialog");
      await user.click(within(dialog).getByRole("button", { name: enSandboxes.credentials.free }));
      expect(await within(dialog).findByText(`errors:credential.${code}`)).toBeTruthy();
    },
  );

  it("offers no attach or free while the sandbox is neither READY nor STOPPED", async () => {
    renderPanel("PROVISIONING");
    expect(await screen.findByText("work")).toBeTruthy();
    expect(screen.queryByRole("button", { name: enSandboxes.credentials.attach })).toBeNull();
    expect(screen.queryByRole("button", { name: enSandboxes.credentials.free })).toBeNull();
  });

  it.each(["RESERVED", "INSTALLING", "RELEASING", "RECOVERING"])(
    "polls every 5s while a lease is %s",
    (state) => {
      expect(
        credentialsRefetchInterval([
          { items: [{ lease: { id: "lse_0", state: "ACTIVE" } }] },
          { items: [{ lease: null }, { lease: { id: "lse_1", state } }] },
        ] as Parameters<typeof credentialsRefetchInterval>[0]),
      ).toBe(CREDENTIALS_BUSY_REFETCH_MS);
    },
  );

  it.each(["ACTIVE", "RECOVERY_REQUIRED", "RELEASED", "FORCE_RELEASED", "ABANDONED"])(
    "polls every 15s when every lease is settled (%s)",
    (state) => {
      expect(
        credentialsRefetchInterval([
          { items: [{ lease: null }, { lease: { id: "lse_1", state } }] },
        ] as Parameters<typeof credentialsRefetchInterval>[0]),
      ).toBe(CREDENTIALS_IDLE_REFETCH_MS);
    },
  );

  it("polls every 15s before the first page and on an empty list", () => {
    expect(credentialsRefetchInterval(undefined)).toBe(CREDENTIALS_IDLE_REFETCH_MS);
    expect(credentialsRefetchInterval([{ items: [] }])).toBe(CREDENTIALS_IDLE_REFETCH_MS);
  });

  it("refetches on the busy cadence while installing, then the idle one once settled", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const lease = { id: "lse_1", state: "INSTALLING" };
    server.attached = [{ ...server.attached[0], lease }];
    renderPanel();
    expect(await screen.findByText(enLogins.leases.state.INSTALLING)).toBeTruthy();
    const first = server.attachedReads;
    await vi.advanceTimersByTimeAsync(CREDENTIALS_BUSY_REFETCH_MS);
    expect(server.attachedReads).toBe(first + 1);

    lease.state = "ACTIVE";
    await vi.advanceTimersByTimeAsync(CREDENTIALS_BUSY_REFETCH_MS);
    expect(await screen.findByText(enLogins.leases.state.ACTIVE)).toBeTruthy();
    const settled = server.attachedReads;
    await vi.advanceTimersByTimeAsync(CREDENTIALS_IDLE_REFETCH_MS - 1_000);
    expect(server.attachedReads).toBe(settled);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(server.attachedReads).toBe(settled + 1);
  });
});
