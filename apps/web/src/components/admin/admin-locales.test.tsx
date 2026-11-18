vi.mock("@wssp/api/sandbox/budgets", () => ({
  consumeCreateConnectBudget: async () => {},
  consumeSandboxWriteBudget: async () => {},
}));

// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { ADMIN_ERROR_CODES } from "@wssp/api/lib/admin-error-codes";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enErrors from "@wssp/locales/src/en-US/errors.json";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esAdmin from "@wssp/locales/src/es-MX/admin.json";
import esCommon from "@wssp/locales/src/es-MX/common.json";
import esErrors from "@wssp/locales/src/es-MX/errors.json";
import esOperations from "@wssp/locales/src/es-MX/operations.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, describe, expect, it, vi } from "vitest";
import { adminProblem, adminProblemKey } from "@/lib/admin-errors";
import { DEFAULT_OBSERVABILITY_SEARCH } from "@/lib/admin-observability-search";

/**
 * Both locales carry every admin key, every admin page renders without a
 * missing translation in either locale, and every control on them is a
 * touch-sized target.
 */

vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, className, to }: { children: ReactNode; className?: string; to: string }) => (
    <a className={className} href={to}>
      {children}
    </a>
  ),
}));

const at = new Date("2026-03-01T00:00:00.000Z");
const data: Record<string, unknown> = {
  adminTunnel: {
    configured: true,
    turningOff: false,
    apiUrl: "https://tunnel.example.com",
    maxTunnelsPerOwner: 10,
    updatedAt: null,
    keyAvailable: true,
    tunnels: { total: 2, connected: 1 },
  },
  counters: {
    users: 2,
    hosts: 1,
    sandboxes: 1,
    operations: 1,
    leases: {
      expiredPending: 0,
      unacknowledgedRenewals: 0,
      hostEnforced: 0,
      quarantinedHosts: 1,
      relayOutbox: 0,
    },
    queues: [
      {
        queue: "check-backup-freshness",
        waiting: 0,
        active: 0,
        delayed: 1,
        failed: 0,
        completed: 3,
      },
    ],
    webhooks: {
      endpoints: 1,
      enabled: 1,
      disabledForFailures: 0,
      deliveries24h: { PENDING: 0, IN_FLIGHT: 0, SUCCEEDED: 1, FAILED: 0, CANCELLED: 0 },
      oldestPendingAgeSeconds: null,
      errorClasses24h: [],
    },
  },
  listHosts: {
    items: [
      {
        id: "h-1",
        userId: "u-1",
        createdAt: at,
        status: "STALE",
        lastHeartbeatAt: null,
        draining: true,
        quarantinedAt: at,
        liveCount: 1,
        rootCount: 2,
        daemonVcpuBudget: 8,
        vcpuReserved: 3,
        memoryReservedMiB: 3072,
        daemonMemoryBudgetMiB: 2048,
        daemonMaxCpuCount: 4,
      },
    ],
    nextCursor: "next",
  },
  listSandboxes: {
    items: [
      {
        id: "s-1",
        userId: "u-1",
        createdAt: at,
        sandboxHostId: "h-1",
        templateId: "t-1",
        templateRevisionId: "r-1",
        originPoolId: null,
        state: "STOPPED",
        generation: 2,
        cpuCount: 2,
        memoryMiB: 3072,
        diskGiB: 32,
      },
    ],
    nextCursor: null,
  },
  adminGet: {
    signupEnabled: true,
    force2faInternalUsers: true,
    force2faPublicUsers: false,
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
    },
  },
  users: {
    users: [
      {
        id: "u-1",
        email: "a@example.com",
        name: "A",
        role: "admin",
        emailVerified: false,
        banned: true,
        banReason: null,
        createdAt: at,
        cliLogins: { logins: 1, instances: 2 },
      },
    ],
    nextCursor: null,
  },
};

vi.mock("@/utils/orpc", () => {
  const query = (name: string) => ({
    queryOptions: () => ({ queryKey: [name], queryFn: async () => data[name] }),
    mutationOptions: () => ({ mutationFn: async () => ({}) }),
  });
  return {
    orpc: {
      appConfig: { key: () => ["appConfig"] },
      adminObservability: {
        counters: query("counters"),
        listHosts: query("listHosts"),
        listSandboxes: query("listSandboxes"),
        listOperations: query("listHosts"),
        listWebhookEndpoints: {
          infiniteOptions: () => ({
            queryKey: ["listWebhookEndpoints"],
            initialPageParam: undefined,
            getNextPageParam: () => undefined,
            queryFn: async () => ({
              items: [
                {
                  id: "whe-1",
                  ownerId: "owner-1",
                  createdAt: at,
                  host: "hooks.example.com",
                  state: "enabled",
                  consecutiveFailures: 0,
                  failingSince: null,
                  lastSuccessAt: null,
                },
              ],
              nextCursor: null,
            }),
          }),
        },
      },
      settings: { key: () => ["settings"], adminGet: query("adminGet"), update: query("update") },
      adminTunnel: {
        key: () => ["adminTunnel"],
        get: query("adminTunnel"),
        set: query("set"),
        clear: query("clear"),
      },
      users: {
        key: () => ["users"],
        list: {
          infiniteOptions: () => ({
            queryKey: ["users"],
            initialPageParam: undefined,
            getNextPageParam: () => undefined,
            queryFn: async () => data.users,
          }),
        },
        setRole: query("x"),
        archive: query("x"),
        unarchive: query("x"),
        remove: query("x"),
        invite: query("x"),
      },
    },
  };
});

import { AdminObservabilityPage } from "./admin-observability-page";
import { AdminSettingsPage } from "./admin-settings-page";
import { AdminUsersPage } from "./admin-users-page";

function keys(value: unknown, prefix = ""): string[] {
  if (value === null || typeof value !== "object") return [prefix];
  return Object.entries(value).flatMap(([key, child]) =>
    keys(child, prefix ? `${prefix}.${key}` : key),
  );
}

const bundles = {
  "en-US": {
    admin: enAdmin,
    common: enCommon,
    errors: enErrors,
    operations: enOperations,
    sandboxes: enSandboxes,
  },
  "es-MX": {
    admin: esAdmin,
    common: esCommon,
    errors: esErrors,
    operations: esOperations,
    sandboxes: esSandboxes,
  },
};

async function i18nFor(lng: keyof typeof bundles, missing: string[]): Promise<I18n> {
  const instance = createInstance();
  await instance.init({
    lng,
    fallbackLng: false,
    ns: Object.keys(bundles[lng]),
    defaultNS: "admin",
    resources: { [lng]: bundles[lng] },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
    saveMissing: true,
    missingKeyHandler: (_lngs, ns, key) => missing.push(`${ns}:${key}`),
  });
  return instance;
}

afterEach(() => cleanup());

describe("admin locales", () => {
  it("es-MX carries exactly the en-US admin keys", () => {
    expect(keys(esAdmin).sort()).toEqual(keys(enAdmin).sort());
  });

  it("explains every admin error code in the admin namespace", () => {
    for (const code of Object.values(ADMIN_ERROR_CODES)) {
      const key = adminProblemKey(
        adminProblem({ code: "CONFLICT", data: { code, blockers: ["hosts"] } }),
      );
      expect(keys(enAdmin)).toContain(key);
    }
  });

  for (const lng of ["en-US", "es-MX"] as const) {
    it(`renders every admin page in ${lng} with no missing key and touch-sized controls`, async () => {
      const missing: string[] = [];
      const i18n = await i18nFor(lng, missing);
      const pages = [
        <AdminObservabilityPage
          key="o"
          search={{ ...DEFAULT_OBSERVABILITY_SEARCH, owner: "bad id!" }}
          onSearch={() => undefined}
        />,
        <AdminObservabilityPage
          key="h"
          search={DEFAULT_OBSERVABILITY_SEARCH}
          onSearch={() => undefined}
        />,
        <AdminObservabilityPage
          key="v"
          search={{ ...DEFAULT_OBSERVABILITY_SEARCH, tab: "sandboxes" }}
          onSearch={() => undefined}
        />,
        <AdminSettingsPage key="s" lang={lng} adminHas2FA={false} />,
        <AdminUsersPage key="u" currentUserId="me" />,
      ];
      for (const page of pages) {
        const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
        render(
          <QueryClientProvider client={client}>
            <I18nextProvider i18n={i18n}>{page}</I18nextProvider>
          </QueryClientProvider>,
        );
      }
      // Wait for the data-backed parts of each page.
      await screen.findByText("h-1");
      await screen.findAllByText("a@example.com", { exact: false });
      await screen.findByText(bundles[lng].admin.settings.policies.signupEnabled.title);

      await screen.findByText("2 vCPU · 3072 MiB · 32 GiB");
      expect(document.querySelector("[data-admin-host-memory]")?.textContent).toBe(
        bundles[lng].admin.observability.memoryReserved.replace("{{value}}", "3072"),
      );
      expect(missing).toEqual([]);
      for (const button of screen.getAllByRole("button")) {
        expect(button.className, button.textContent ?? "").toMatch(/min-h-\[44px\]|min-h-11/);
      }
      for (const table of document.querySelectorAll("table")) {
        expect(table.parentElement?.className).toContain("overflow-x-auto");
      }
    });
  }
});
