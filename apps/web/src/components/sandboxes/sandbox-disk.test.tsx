// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import { createInstance, type i18n as I18n } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { DiskView } from "@/lib/sandbox-rules";

/**
 * The Disk card and its restore-pin Sheet (disk offload, C8): what the
 * server's `disk` projection says, and one `setOffloadPin` request per save.
 */

const pin = vi.hoisted(() => ({
  calls: [] as unknown[],
  fail: false,
}));
const update = vi.hoisted(() => ({ calls: [] as unknown[] }));
const toast = vi.hoisted(() => ({ success: vi.fn(), error: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast }));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirect: () => () => false }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxes: {
      key: () => ["sandboxes"],
      setOffloadPin: {
        mutationOptions: () => ({
          mutationFn: async (input: unknown) => {
            pin.calls.push(input);
            if (pin.fail) throw new Error("network");
            return input;
          },
        }),
      },
      updateSandbox: {
        mutationOptions: () => ({
          mutationFn: async (input: unknown) => {
            update.calls.push(input);
            return input;
          },
        }),
      },
    },
  },
}));

import { DiskCard } from "./sandbox-disk";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["common", "sandboxes"],
    defaultNS: "common",
    resources: { "en-US": { common: enCommon, sandboxes: enSandboxes } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});

beforeEach(() => {
  update.calls = [];
  pin.calls = [];
  pin.fail = false;
  toast.success.mockReset();
});
afterEach(() => cleanup());

const DISK: DiskView = {
  location: "host",
  offloadState: "none",
  offloadFailure: null,
  offloadedAt: null,
  sizeBytes: null,
  eligibility: "any_host",
  offloadPin: "ANY",
  offloadPolicy: { mode: "on_stop" },
  offloadDueAt: null,
};

function mount(disk: DiskView | null, editable = true) {
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <DiskCard sandboxId="sbx-1" disk={disk} lang="en-US" locale="en-US" editable={editable} />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

describe("DiskCard", () => {
  it("renders nothing while the sandbox has no disk", () => {
    const view = mount(null);
    expect(view.container.querySelector("[data-sandbox-disk]")).toBeNull();
  });

  it("a host-only disk shows its location and no offload row", () => {
    mount(DISK);
    expect(screen.getByText(enSandboxes.disk.location.host)).toBeTruthy();
    expect(screen.getByText(enSandboxes.disk.locationHint.host)).toBeTruthy();
    expect(document.querySelector("[data-disk-offload-state]")).toBeNull();
    expect(document.querySelector("[data-disk-size]")).toBeNull();
  });

  it("an upload in progress shows its phase", () => {
    mount({ ...DISK, offloadState: "uploading" });
    expect(document.querySelector<HTMLElement>("[data-disk-offload-state]")?.textContent).toContain(
      enSandboxes.disk.offloadState.uploading,
    );
  });

  it("a stored copy shows its size; a quota failure says the disk stays", () => {
    mount({
      ...DISK,
      location: "host_and_store",
      offloadState: "stored",
      sizeBytes: 5 * 2 ** 30,
      offloadedAt: "2026-11-06T12:00:00.000Z",
    });
    expect(document.querySelector("[data-disk-size]")?.textContent).toBeTruthy();
    cleanup();
    mount({ ...DISK, offloadState: "failed", offloadFailure: "quota_exceeded" });
    expect(document.querySelector("[data-disk-offload-failure]")?.textContent).toBe(
      enSandboxes.disk.failure.quota_exceeded,
    );
  });

  it("a managed sandbox is never offloaded and offers no pin", () => {
    mount({ ...DISK, eligibility: "never" });
    expect(screen.getByText(enSandboxes.disk.eligibility.never)).toBeTruthy();
    expect(screen.queryByRole("button", { name: enSandboxes.disk.pin.change })).toBeNull();
  });

  it("the pin Sheet saves OWN_HOSTS once and explains a narrowed sandbox", async () => {
    const user = userEvent.setup();
    mount({ ...DISK, eligibility: "own_hosts" });
    await user.click(screen.getByRole("button", { name: enSandboxes.disk.pin.change }));
    const sheet = screen.getByRole("dialog");
    expect(within(sheet).getByText(enSandboxes.disk.pin.narrowed)).toBeTruthy();
    await user.click(
      within(sheet).getByRole("radio", { name: new RegExp(enSandboxes.disk.pin.OWN_HOSTS) }),
    );
    await user.click(within(sheet).getByRole("button", { name: enSandboxes.disk.pin.save }));
    await waitFor(() => expect(pin.calls).toEqual([{ id: "sbx-1", offloadPin: "OWN_HOSTS" }]));
    expect(toast.success).toHaveBeenCalledWith(enSandboxes.disk.pin.saved);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
  });

  it("a failed save stays open and says so", async () => {
    pin.fail = true;
    const user = userEvent.setup();
    mount(DISK);
    await user.click(screen.getByRole("button", { name: enSandboxes.disk.pin.change }));
    const sheet = screen.getByRole("dialog");
    await user.click(within(sheet).getByRole("button", { name: enSandboxes.disk.pin.save }));
    await waitFor(() =>
      expect(within(sheet).getByRole("alert").textContent).toBe(enSandboxes.disk.pin.failed),
    );
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("shows the offload policy and when it makes the stopped disk due", () => {
    mount({
      ...DISK,
      offloadPolicy: { mode: "after", afterMs: 2 * 3_600_000 },
      offloadDueAt: "2026-11-06T12:00:00.000Z",
    });
    expect(document.querySelector("[data-disk-offload-policy]")?.textContent).toBe(
      "After 2 hours stopped",
    );
    expect(document.querySelector("[data-disk-offload-due]")?.textContent).toMatch(/^Due /);
    cleanup();
    mount({ ...DISK, offloadPolicy: { mode: "after", afterMs: 90 * 60_000 } });
    expect(document.querySelector("[data-disk-offload-policy]")?.textContent).toBe(
      "After 90 minutes stopped",
    );
    cleanup();
    mount({ ...DISK, offloadPolicy: { mode: "on_pressure" } });
    expect(document.querySelector("[data-disk-offload-policy]")?.textContent).toBe(
      enSandboxes.disk.policy.on_pressure,
    );
    expect(document.querySelector("[data-disk-offload-due]")).toBeNull();
    cleanup();
    // Managed sandboxes have no policy row; a read-only viewer gets no Change.
    mount({ ...DISK, eligibility: "never" });
    expect(document.querySelector("[data-disk-offload-policy]")).toBeNull();
    cleanup();
    mount(DISK, false);
    expect(document.querySelector("[data-disk-policy-edit]")).toBeNull();
  });

  it("the policy Sheet saves an `after` delay in minutes, once, and refuses a bad delay", async () => {
    const user = userEvent.setup();
    mount(DISK);
    await user.click(screen.getByRole("button", { name: enSandboxes.disk.policy.changeLabel }));
    const sheet = screen.getByRole("dialog");
    await user.click(
      within(sheet).getByRole("radio", {
        name: new RegExp(`^${enSandboxes.disk.policy.option.after}`),
      }),
    );
    const minutes = within(sheet).getByLabelText(enSandboxes.disk.policy.minutes);
    await user.clear(minutes);
    await user.type(minutes, "0");
    await user.click(within(sheet).getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() =>
      expect(within(sheet).getByText(/Enter a whole number of minutes/)).toBeTruthy(),
    );
    expect(update.calls).toEqual([]);
    await user.clear(minutes);
    await user.type(minutes, "45");
    await user.click(within(sheet).getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() =>
      expect(update.calls).toEqual([
        { id: "sbx-1", offload: { mode: "after", afterMs: 45 * 60_000 } },
      ]),
    );
    expect(toast.success).toHaveBeenCalledWith(enSandboxes.disk.policy.saved);
  });

  it("the policy Sheet saves on_pressure without a delay", async () => {
    const user = userEvent.setup();
    mount(DISK);
    await user.click(screen.getByRole("button", { name: enSandboxes.disk.policy.changeLabel }));
    const sheet = screen.getByRole("dialog");
    expect(within(sheet).queryByLabelText(enSandboxes.disk.policy.minutes)).toBeNull();
    await user.click(
      within(sheet).getByRole("radio", {
        name: new RegExp(`^${enSandboxes.disk.policy.option.on_pressure}`),
      }),
    );
    await user.click(within(sheet).getByRole("button", { name: enCommon.actions.saveChanges }));
    await waitFor(() =>
      expect(update.calls).toEqual([{ id: "sbx-1", offload: { mode: "on_pressure" } }]),
    );
  });
});
