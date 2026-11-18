// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * Admin settings against a fake server that holds the effective policy.
 * The page must render only what the server reports, confirm every change,
 * and show typed refusals.
 */

const server = vi.hoisted(() => ({
  policy: {
    signupEnabled: false,
    force2faInternalUsers: true,
    force2faPublicUsers: false,
  } as Record<string, boolean>,
  calls: [] as { procedure: string; input: unknown }[],
  nextError: null as unknown,
  /** When set, a write is acknowledged but the server keeps its old value. */
  ignoreWrites: false,
  /** the consumed-copy grace the server reports. */
  graceSeconds: 3600,
  tunnel: {
    configured: false,
    turningOff: false,
    apiUrl: null as string | null,
    maxTunnelsPerOwner: 10,
    updatedAt: null,
    keyAvailable: true,
    tunnels: { total: 0, connected: 0 },
  },
  tunnelError: null as unknown,
}));

const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: { lang?: string };
  }) => (
    <a className={className} href={to.replace("$lang", params?.lang ?? "$lang")}>
      {children}
    </a>
  ),
}));

vi.mock("@/utils/orpc", () => ({
  orpc: {
    appConfig: { key: () => ["appConfig"] },
    adminTunnel: {
      key: () => ["adminTunnel"],
      get: {
        queryOptions: () => ({
          queryKey: ["adminTunnel", "get"],
          queryFn: async () => ({ ...server.tunnel }),
        }),
      },
      set: {
        mutationOptions: () => ({
          mutationFn: async (input: { apiUrl: string; credential?: string }) => {
            server.calls.push({ procedure: "tunnelSet", input });
            if (server.tunnelError) {
              const error = server.tunnelError;
              server.tunnelError = null;
              throw error;
            }
            server.tunnel = { ...server.tunnel, configured: true, apiUrl: input.apiUrl };
            return { configured: true, apiUrl: input.apiUrl, changed: true };
          },
        }),
      },
      clear: {
        mutationOptions: () => ({
          mutationFn: async () => {
            server.calls.push({ procedure: "tunnelClear", input: undefined });
            server.tunnel = { ...server.tunnel, configured: false, turningOff: true };
            return { turningOff: true, tunnelsLeft: 0 };
          },
        }),
      },
    },
    settings: {
      key: () => ["settings"],
      adminGet: {
        queryOptions: () => ({
          queryKey: ["settings", "adminGet"],
          queryFn: async () => {
            server.calls.push({ procedure: "adminGet", input: undefined });
            return {
              ...server.policy,
              offloadConsumedGraceSeconds: server.graceSeconds,
              limits: {
                commandPayloadMaxBytes: 32768,
                commandTimeoutDefaultMs: 120_000,
                commandTimeoutMaxMs: 1_800_000,
                outputMaxBytes: 1_048_576,
                outputRetentionMs: 86_400_000,
                transferMaxBytes: 1_073_741_824,
                transferDiskBytes: 10_737_418_240,
                transferOwnerActive: 4,
                transferGlobalActive: 16,
                transferIdleSeconds: 900,
                transferAbsoluteSeconds: 3600,
                sandboxLeaseMaxMs: null,
              },
            };
          },
        }),
      },
      update: {
        mutationOptions: () => ({
          mutationFn: async (input: { key: string; value: string }) => {
            server.calls.push({ procedure: "update", input });
            if (server.nextError) {
              const error = server.nextError;
              server.nextError = null;
              throw error;
            }
            if (server.ignoreWrites) return { success: true };
            if (input.key === "sandbox.offload.consumedGraceSeconds")
              server.graceSeconds = Number(input.value);
            else server.policy[input.key] = input.value === "true";
            return { success: true };
          },
        }),
      },
    },
  },
}));

import { AdminSettingsPage, isWeakeningChange } from "./admin-settings-page";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["admin", "common"],
    defaultNS: "admin",
    resources: { "en-US": { admin: enAdmin, common: enCommon } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

function mount(adminHas2FA = true) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <AdminSettingsPage lang="en-US" adminHas2FA={adminHas2FA} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

const policyRow = (key: string) =>
  document.querySelector<HTMLElement>(`[data-policy="${key}"]`) as HTMLElement;
const updates = () => server.calls.filter((call) => call.procedure === "update");

beforeEach(() => {
  server.policy = { signupEnabled: false, force2faInternalUsers: true, force2faPublicUsers: false };
  server.calls = [];
  server.nextError = null;
  server.tunnelError = null;
  server.tunnel = {
    configured: false,
    turningOff: false,
    apiUrl: null,
    maxTunnelsPerOwner: 10,
    updatedAt: null,
    keyAvailable: true,
    tunnels: { total: 0, connected: 0 },
  };
  server.ignoreWrites = false;
  server.graceSeconds = 3600;
  toast.success.mockReset();
});
afterEach(() => cleanup());

describe("admin settings", () => {
  it("renders the server's effective policy and read-only limits", async () => {
    mount();
    await screen.findByText(enAdmin.settings.policies.force2faInternalUsers.title);
    expect(policyRow("force2faInternalUsers").getAttribute("data-enabled")).toBe("true");
    expect(policyRow("force2faPublicUsers").getAttribute("data-enabled")).toBe("false");
    expect(policyRow("signupEnabled").getAttribute("data-enabled")).toBe("false");
    expect(
      within(policyRow("signupEnabled")).getByText(enAdmin.settings.policies.signupEnabled.off),
    ).toBeTruthy();
    const limit = (key: string) => document.querySelector(`[data-limit="${key}"] dd`)?.textContent;
    expect(limit("commandPayloadMaxBytes")).toBe("32 KiB");
    expect(limit("transferMaxBytes")).toBe("1 GiB");
    expect(limit("commandTimeoutMaxMs")).toBe("30 minutes");
    expect(limit("sandboxLeaseMaxMs")).toBe("No limit");
    expect(limit("transferOwnerActive")).toBe("4");
    // Limits have no controls: the three policy toggles and the offload
    // grace's save are the only buttons.
    expect(screen.getAllByRole("button")).toHaveLength(4);
  });

  it("confirms before turning off the administrator 2FA requirement, then shows the server value", async () => {
    const u = userEvent.setup();
    mount();
    await screen.findByText(enAdmin.settings.policies.force2faInternalUsers.title);
    await u.click(
      within(policyRow("force2faInternalUsers")).getByRole("button", {
        name: enAdmin.settings.disable,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    expect(
      within(dialog).getByText(enAdmin.settings.confirm.force2faInternalUsers.offTitle),
    ).toBeTruthy();
    expect(updates()).toHaveLength(0);

    await u.click(within(dialog).getByRole("button", { name: enCommon.actions.cancel }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(updates()).toHaveLength(0);
    expect(server.policy.force2faInternalUsers).toBe(true);

    await u.click(
      within(policyRow("force2faInternalUsers")).getByRole("button", {
        name: enAdmin.settings.disable,
      }),
    );
    const again = await screen.findByRole("alertdialog");
    await u.click(within(again).getByRole("button", { name: enAdmin.settings.disable }));
    await waitFor(() =>
      expect(policyRow("force2faInternalUsers").getAttribute("data-enabled")).toBe("false"),
    );
    expect(updates()).toEqual([
      { procedure: "update", input: { key: "force2faInternalUsers", value: "false" } },
    ]);
    expect(toast.success).toHaveBeenCalledWith(enAdmin.settings.toast.force2faInternalUsers.off);
  });

  it("shows what the server kept, not what was requested", async () => {
    const u = userEvent.setup();
    server.ignoreWrites = true;
    mount();
    await screen.findByText(enAdmin.settings.policies.signupEnabled.title);
    await u.click(
      within(policyRow("signupEnabled")).getByRole("button", { name: enAdmin.settings.enable }),
    );
    const dialog = await screen.findByRole("alertdialog");
    await u.click(within(dialog).getByRole("button", { name: enAdmin.settings.enable }));
    await waitFor(() =>
      expect(server.calls.filter((call) => call.procedure === "adminGet").length).toBe(2),
    );
    expect(policyRow("signupEnabled").getAttribute("data-enabled")).toBe("false");
  });

  it("blocks requiring 2FA of others until the admin has it, and explains a server refusal", async () => {
    const u = userEvent.setup();
    mount(false);
    await screen.findByText(enAdmin.settings.policies.force2faPublicUsers.title);
    expect(screen.getByText(enAdmin.settings.force2faAdminWarning, { exact: false })).toBeTruthy();
    expect(
      within(policyRow("force2faPublicUsers")).getByRole("button", {
        name: enAdmin.settings.enable,
      }),
    ).toHaveProperty("disabled", true);
    cleanup();

    // A stale session claimed 2FA; the server knows better and refuses.
    mount(true);
    await screen.findByText(enAdmin.settings.policies.force2faPublicUsers.title);
    await u.click(
      within(policyRow("force2faPublicUsers")).getByRole("button", {
        name: enAdmin.settings.enable,
      }),
    );
    const dialog = await screen.findByRole("alertdialog");
    server.nextError = Object.assign(new Error("forbidden"), {
      code: "FORBIDDEN",
      data: { code: "admin.own_two_factor_required" },
    });
    await u.click(within(dialog).getByRole("button", { name: enAdmin.settings.enable }));
    expect((await within(dialog).findByRole("alert")).textContent).toBe(
      enAdmin.problems.ownTwoFactorRequired,
    );
    expect(policyRow("force2faPublicUsers").getAttribute("data-enabled")).toBe("false");
  });

  it("links account security recovery outside the admin area", async () => {
    mount();
    await screen.findByText(enAdmin.settings.recoveryNote, { exact: false });
    const links = screen.getAllByRole("link", { name: enAdmin.settings.securityLink });
    for (const link of links) expect(link.getAttribute("href")).toBe("/en-US/settings/security");
  });

  it("classifies which changes weaken a safeguard", () => {
    expect(isWeakeningChange({ key: "force2faInternalUsers", next: false })).toBe(true);
    expect(isWeakeningChange({ key: "force2faPublicUsers", next: false })).toBe(true);
    expect(isWeakeningChange({ key: "signupEnabled", next: true })).toBe(true);
    expect(isWeakeningChange({ key: "force2faInternalUsers", next: true })).toBe(false);
    expect(isWeakeningChange({ key: "signupEnabled", next: false })).toBe(false);
  });

  it("preview tunnels: optional, write-only credential, typed refusals", async () => {
    const u = userEvent.setup();
    mount();
    expect(await screen.findByText(enAdmin.settings.tunnel.statusOff)).toBeTruthy();
    const url = screen.getByLabelText(enAdmin.settings.tunnel.urlLabel) as HTMLInputElement;
    const credential = screen.getByLabelText(
      enAdmin.settings.tunnel.credentialLabel,
    ) as HTMLInputElement;
    expect(credential.type).toBe("password");
    const save = screen.getByRole("button", { name: enAdmin.settings.tunnel.save });
    await u.type(url, "http://tunnel.example.com/path");
    await u.click(save);
    expect(await screen.findByText(enAdmin.settings.tunnel.urlInvalid)).toBeTruthy();
    await u.clear(url);
    await u.type(url, "https://tunnel.example.com");
    await u.type(credential, `tnsvc_${"a".repeat(43)}`);
    server.tunnelError = Object.assign(new Error("refused"), {
      code: "CONFLICT",
      data: { code: "admin.tunnel_config_refused", reason: "credential_rejected" },
    });
    await u.click(save);
    expect(
      await screen.findByText(enAdmin.settings.tunnel.refused.credential_rejected),
    ).toBeTruthy();
    await u.click(save);
    await waitFor(() =>
      expect(server.calls.filter((call) => call.procedure === "tunnelSet").at(-1)?.input).toEqual({
        apiUrl: "https://tunnel.example.com",
        credential: `tnsvc_${"a".repeat(43)}`,
        maxTunnelsPerOwner: 10,
      }),
    );
    expect(toast.success).toHaveBeenCalledWith(enAdmin.settings.tunnel.saved);
    // The credential is never echoed back into the form.
    await waitFor(() => expect(credential.value).toBe(""));
  });

  it("offload grace (§6a): shows the server's value, refuses out-of-range input, saves a valid one", async () => {
    const u = userEvent.setup();
    mount();
    const field = (await screen.findByLabelText(
      enAdmin.settings.offloadGrace.label,
    )) as HTMLInputElement;
    expect(field.value).toBe("3600");
    const save = screen.getByRole("button", { name: enAdmin.settings.offloadGrace.save });
    await u.clear(field);
    await u.type(field, "604801");
    await u.click(save);
    expect(await screen.findByText(enAdmin.settings.offloadGrace.invalid)).toBeTruthy();
    expect(updates()).toEqual([]);
    await u.clear(field);
    await u.type(field, "0");
    await u.click(save);
    await waitFor(() =>
      expect(updates()).toEqual([
        {
          procedure: "update",
          input: { key: "sandbox.offload.consumedGraceSeconds", value: "0" },
        },
      ]),
    );
    expect(toast.success).toHaveBeenCalledWith(enAdmin.settings.offloadGrace.saved);
    await waitFor(() => expect(server.graceSeconds).toBe(0));
  });
});
