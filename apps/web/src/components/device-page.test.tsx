// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import en from "@wssp/locales/src/en-US/auth.json";
import common from "@wssp/locales/src/en-US/common.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const fake = vi.hoisted(() => ({
  kind: "host" as "host" | "user",
  fetch: vi.fn<typeof fetch>(),
  toast: { success: vi.fn(), error: vi.fn() },
  replaced: false,
  guard: vi.fn(),
}));
vi.mock("@/lib/document-identity", () => ({
  isDocumentReplaced: () => fake.replaced,
  withExpectedIdentity: (headers?: HeadersInit) => {
    const result = new Headers(headers);
    result.set("X-Expected-User", "owner-1");
    return result;
  },
  guardIdentityResponse: fake.guard,
}));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://api.example.test" } }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: fake.toast }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children }: { children: ReactNode }) => <a href="/en-US/settings">{children}</a>,
}));
vi.mock("@/utils/friendly-error", () => ({
  friendly: (_error: unknown, fallback: string) => fallback,
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    hostCredentials: {
      deviceLoginRequest: {
        queryOptions: () => ({
          queryFn: async () => ({
            kind: fake.kind,
            requestId: "request-1",
            slug: "desk-1",
            existingHost: null,
            status: "pending",
          }),
        }),
      },
    },
    sandboxHosts: { key: () => ["hosts"] },
    sdkKeys: { list: { key: () => ["sdk-keys"] } },
    sandboxPools: {
      listUsable: {
        key: () => ["pools"],
        infiniteOptions: () => ({
          queryKey: ["pools"],
          initialPageParam: undefined,
          queryFn: async () => ({ items: [], nextCursor: null }),
          getNextPageParam: () => undefined,
        }),
      },
    },
  },
}));

import { DevicePage } from "./device-page";

let client: QueryClient;
beforeEach(() => {
  fake.fetch.mockReset();
  fake.replaced = false;
  fake.guard.mockReset().mockImplementation(async (response: Response) => response);
  fake.toast.error.mockReset();
  fake.toast.success.mockReset();
  vi.stubGlobal("fetch", fake.fetch);
  vi.spyOn(console, "error").mockImplementation(() => {});
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
});
afterEach(() => {
  cleanup();
  client.clear();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

async function mount(kind: "host" | "user") {
  fake.kind = kind;
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { auth: en, common } } });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <DevicePage lang="en-US" ownerId="owner-1" userCode="ABCDEFGH" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await waitFor(() =>
    expect(screen.getByRole("button", { name: en.device.approve })).toHaveProperty(
      "disabled",
      false,
    ),
  );
}

it.each([
  ["host", "approve", en.device.approveError, {}],
  ["host", "deny", en.device.denyError, {}],
  ["user", "approve", en.device.approveError, {}],
  ["user", "deny", en.device.denyError, {}],
  [
    "host",
    "approve",
    en.device.hostLimit_other.replace("{{count}}", "20"),
    { data: { code: "sandbox.owner_host_limit", limit: 20 } },
  ],
  ["user", "approve", en.device.user.poolNotFound, { data: { code: "sandbox.pool_not_found" } }],
] as const)("%s %s refusal appears by the actions: %s", async (kind, action, message, body) => {
  let releaseRetry!: (response: Response) => void;
  fake.fetch
    .mockResolvedValueOnce(Response.json({ deviceRequestId: "request-1" }))
    .mockResolvedValueOnce(Response.json(body, { status: 409 }))
    .mockImplementationOnce(
      () =>
        new Promise<Response>((resolve) => {
          releaseRetry = resolve;
        }),
    );
  await mount(kind);
  const button = screen.getByRole("button", { name: en.device[action] });
  fireEvent.click(button);
  const alert = await screen.findByRole("alert");
  expect(alert.textContent).toBe(message);
  expect(alert.getAttribute("aria-live")).toBe("assertive");
  expect(alert.className).toContain("text-destructive");
  expect(alert.nextElementSibling?.contains(button)).toBe(true);
  if (kind === "user") expect(alert.closest("form")).not.toBeNull();
  expect(fake.toast.error).not.toHaveBeenCalled();
  expect(fake.fetch.mock.calls[1]?.[0]).toBe(`https://api.example.test/api/auth/device/${action}`);

  // Starting either decision clears the refusal while the new request is pending.
  const retryAction = action === "approve" ? "deny" : "approve";
  fireEvent.click(screen.getByRole("button", { name: en.device[retryAction] }));
  await waitFor(() => expect(fake.fetch).toHaveBeenCalledTimes(3));
  expect(screen.queryByRole("alert")).toBeNull();
  releaseRetry(Response.json({ success: true }));
  await waitFor(() => expect(fake.toast.success).toHaveBeenCalledOnce());
  expect(fake.toast.error).not.toHaveBeenCalled();
});

it("carries the owner and stalls an identity-change response before showing an error", async () => {
  fake.fetch.mockResolvedValueOnce(Response.json({ code: "IDENTITY_CHANGED" }, { status: 409 }));
  fake.guard.mockImplementation(() => new Promise(() => {}));
  fake.kind = "host";
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { auth: en, common } } });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <DevicePage lang="en-US" ownerId="owner-1" userCode="ABCDEFGH" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await waitFor(() => expect(fake.guard).toHaveBeenCalledTimes(1));
  expect(new Headers(fake.fetch.mock.calls[0]?.[1]?.headers).get("X-Expected-User")).toBe(
    "owner-1",
  );
  expect(fake.toast.error).not.toHaveBeenCalled();
});

it("does not dispatch a device request from a replaced document", async () => {
  fake.replaced = true;
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { auth: en, common } } });
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <DevicePage lang="en-US" ownerId="owner-1" userCode="ABCDEFGH" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await Promise.resolve();
  expect(fake.fetch).not.toHaveBeenCalled();
});
