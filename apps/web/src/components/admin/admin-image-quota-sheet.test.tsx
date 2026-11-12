// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

/** Admin per-account quota overrides, including the offloaded-disk cap. */

const server = vi.hoisted(() => ({
  quota: {
    storedGiBMax: null as number | null,
    downloadsPerHourMax: null as number | null,
    concurrentBuildsMax: null as number | null,
    buildMinutesPerMonthMax: null as number | null,
    offloadGiBMax: 40 as number | null,
    updatedAt: null,
  },
  writes: [] as unknown[],
}));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    users: {
      imageQuota: {
        key: () => ["imageQuota"],
        queryOptions: () => ({ queryKey: ["imageQuota"], queryFn: async () => server.quota }),
      },
      setImageQuota: {
        mutationOptions: () => ({
          mutationFn: async (input: unknown) => {
            server.writes.push(input);
            return { success: true };
          },
        }),
      },
    },
  },
}));

import { AdminImageQuotaSheet } from "./admin-image-quota-sheet";

beforeEach(() => {
  server.writes = [];
  server.quota.offloadGiBMax = 40;
});
afterEach(cleanup);

async function mount() {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["admin", "common"],
    defaultNS: "admin",
    resources: { "en-US": { admin: enAdmin, common: enCommon } },
    interpolation: { escapeValue: false },
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <I18nextProvider i18n={i18n}>
        <AdminImageQuotaSheet
          user={{ id: "user-1", name: "Ada", email: "ada@example.test" }}
          onClose={() => {}}
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

it("shows the offloaded-disk override and saves a cleared one as the deployment limit", async () => {
  const user = userEvent.setup();
  await mount();
  const field = (await screen.findByLabelText(enAdmin.imageQuota.offload)) as HTMLInputElement;
  expect(field.value).toBe("40");
  expect(field.getAttribute("autocomplete")).toBe("off");
  await user.clear(field);
  await user.click(screen.getByRole("button", { name: enCommon.actions.save }));
  await waitFor(() => expect(server.writes).toHaveLength(1));
  expect(server.writes[0]).toMatchObject({ userId: "user-1", offloadGiBMax: null });
  expect(toast.success).toHaveBeenCalledWith(enAdmin.imageQuota.saved);
});

it("refuses an out-of-range offload cap without a request", async () => {
  const user = userEvent.setup();
  await mount();
  const field = (await screen.findByLabelText(enAdmin.imageQuota.offload)) as HTMLInputElement;
  await user.clear(field);
  await user.type(field, "1048577");
  await user.click(screen.getByRole("button", { name: enCommon.actions.save }));
  // The browser's own range check (max) or the form schema stops it first.
  expect(field.validity.valid).toBe(false);
  await new Promise((resolve) => setTimeout(resolve, 50));
  expect(server.writes).toEqual([]);
});
