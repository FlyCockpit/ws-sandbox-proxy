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
import { CREDENTIAL_EVENT_TYPES, eventTypeKey } from "./login-activity";

/**
 * Instance recovery against a scripted fake server: holders with their
 * checkpoint, force release (lost-rotation copy, checkpoint promotion), and
 * "Discard rejected captures" behind type-to-confirm.
 */
const server = vi.hoisted(() => ({
  calls: [] as { name: string; input: Record<string, unknown> }[],
  leases: [] as Record<string, unknown>[],
  rejected: [] as Record<string, unknown>[],
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="#link">{children}</a>,
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
  const mutation = (name: string, result: (input: Record<string, unknown>) => unknown) => ({
    mutationOptions: () => ({
      mutationFn: async (input: Record<string, unknown>) => {
        server.calls.push({ name, input });
        return result(input);
      },
    }),
  });
  return {
    orpc: {
      logins: {
        key: () => ["logins"],
        listInstanceLeases: page("leases", () => server.leases),
        listRejectedCaptures: page("rejected", () => server.rejected),
        forceRelease: mutation("forceRelease", (input) => ({
          leaseId: input.leaseId,
          released: true,
          promoted: input.promoteCheckpoint ? { storageSeq: 7, fromSeq: 5 } : null,
        })),
        discardRejectedCaptures: mutation("discard", () => ({ discarded: 2 })),
      },
    },
  };
});

const { InstanceRecovery } = await import("./login-instance-admin");

const login = { id: "cred_1", name: "work" } as never;
const instance = { id: "ins_1", name: "laptop", ordinal: 1 } as never;

function renderRecovery() {
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
        <InstanceRecovery lang="en-US" login={login} instance={instance} writable />
      </QueryClientProvider>
    </I18nextProvider>,
  );
}

beforeEach(() => {
  server.calls = [];
  server.leases = [
    {
      id: "lse_1",
      kind: "WORKLOAD",
      state: "RECOVERY_REQUIRED",
      sandboxId: "sbx_1",
      createdAt: "2026-11-03T00:00:00.000Z",
      checkpoint: { storageSeq: 7, at: "2026-11-03T00:10:00.000Z" },
    },
  ];
  server.rejected = [
    { captureId: "cap_1", leaseId: "lse_1", reason: "digest_mismatch", at: "2026-11-03T00:05:00Z" },
  ];
});
afterEach(cleanup);

describe("instance recovery", () => {
  it("force-releases with the lost-rotation warning and promotes the checkpoint by default", async () => {
    const user = userEvent.setup();
    renderRecovery();
    expect(await screen.findByText(enLogins.leases.state.RECOVERY_REQUIRED)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: enLogins.leases.forceRelease }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(enLogins.leases.lostRotation)).toBeTruthy();
    const promote = within(dialog).getByRole("checkbox");
    expect(promote.getAttribute("aria-checked")).toBe("true");
    await user.click(within(dialog).getByRole("button", { name: enLogins.leases.forceRelease }));
    await waitFor(() => expect(server.calls).toHaveLength(1));
    expect(server.calls[0]).toEqual({
      name: "forceRelease",
      input: {
        credentialId: "cred_1",
        instanceId: "ins_1",
        leaseId: "lse_1",
        promoteCheckpoint: true,
      },
    });
  });

  it("force-releases without promotion when the box is cleared", async () => {
    const user = userEvent.setup();
    renderRecovery();
    await user.click(await screen.findByRole("button", { name: enLogins.leases.forceRelease }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("checkbox"));
    await user.click(within(dialog).getByRole("button", { name: enLogins.leases.forceRelease }));
    await waitFor(() => expect(server.calls).toHaveLength(1));
    expect(server.calls[0]?.input.promoteCheckpoint).toBe(false);
  });

  it("never asks to promote when the lease has no checkpoint", async () => {
    const user = userEvent.setup();
    server.leases = [{ ...server.leases[0], checkpoint: null }];
    renderRecovery();
    await user.click(await screen.findByRole("button", { name: enLogins.leases.forceRelease }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).queryByRole("checkbox")).toBeNull();
    await user.click(within(dialog).getByRole("button", { name: enLogins.leases.forceRelease }));
    await waitFor(() => expect(server.calls[0]?.input.promoteCheckpoint).toBe(false));
  });

  it("discards rejected captures only after typing the instance name", async () => {
    const user = userEvent.setup();
    renderRecovery();
    expect(await screen.findByText(/digest_mismatch/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: enLogins.rejected.discard }));
    const dialog = await screen.findByRole("alertdialog");
    const confirm = within(dialog).getByRole("button", { name: enLogins.rejected.discardConfirm });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    await user.type(within(dialog).getByRole("textbox"), "laptop");
    await user.click(confirm);
    await waitFor(() =>
      expect(server.calls).toContainEqual({
        name: "discard",
        input: { credentialId: "cred_1", instanceId: "ins_1" },
      }),
    );
  });

  it("labels every credential event type, including the new ones", () => {
    for (const type of [
      "force_released",
      "checkpoint_promoted",
      "rejected_discarded",
      "capture_failed",
      "needs_login",
      "login_started",
      "login_saved",
      "login_failed",
      "login_cancelled",
    ])
      expect(CREDENTIAL_EVENT_TYPES).toContain(type);
    const labels = enLogins.events.type as Record<string, string>;
    for (const type of CREDENTIAL_EVENT_TYPES) expect(labels[type]).toEqual(expect.any(String));
    expect(eventTypeKey("future_type")).toBeNull();
  });
});
