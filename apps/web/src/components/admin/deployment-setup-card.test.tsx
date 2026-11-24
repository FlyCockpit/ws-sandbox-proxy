// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import { createInstance } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const server = vi.hoisted(() => ({
  appConfig: { emailEnabled: true } as Record<string, unknown>,
  adminGet: { imageStoreMode: "s3" } as Record<string, unknown>,
  dataKey: { configured: true } as Record<string, unknown>,
  backups: { configured: false, status: null } as Record<string, unknown>,
  tunnel: { configured: false, apiUrl: null } as Record<string, unknown>,
}));
vi.mock("@tanstack/react-router", () => ({
  Link: ({ children, to }: { children: ReactNode; to: string }) => <a href={to}>{children}</a>,
}));
vi.mock("@wssp/env/web", () => ({ env: {} }));
vi.mock("@/utils/orpc", () => {
  const options = (key: keyof typeof server) => ({
    queryOptions: () => ({
      queryKey: [key],
      queryFn: async () => {
        if (server[key].fail) throw new Error("unavailable");
        return server[key];
      },
    }),
  });
  return {
    orpc: {
      appConfig: options("appConfig"),
      settings: { adminGet: options("adminGet") },
      adminDataKeys: { status: options("dataKey") },
      queue: { backupStatus: options("backups") },
      adminTunnel: { get: options("tunnel") },
    },
  };
});

import { DeploymentSetupCard } from "./deployment-setup-card";

afterEach(cleanup);

async function mount() {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["admin"],
    defaultNS: "admin",
    resources: { "en-US": { admin: enAdmin } },
    interpolation: { escapeValue: false },
  });
  const view = render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <I18nextProvider i18n={i18n}>
        <DeploymentSetupCard lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  await waitFor(() =>
    expect(view.container.querySelectorAll('[data-setup-state="loading"]').length).toBe(0),
  );
  return view;
}

const state = (container: HTMLElement, row: string) =>
  container.querySelector(`[data-setup-row="${row}"]`)?.getAttribute("data-setup-state");

it("marks a fully configured deployment and leaves optional features optional", async () => {
  const { container } = await mount();
  expect(state(container, "email")).toBe("ok");
  expect(state(container, "image-store")).toBe("ok");
  expect(state(container, "data-key")).toBe("ok");
  expect(state(container, "backups")).toBe("optional");
  expect(state(container, "tunnels")).toBe("optional");
  expect(screen.getByText(enAdmin.setup.imageStore.s3)).toBeTruthy();
  // No docs base configured: the repository path is shown as text.
  expect(container.querySelector("[data-docs-path]")).not.toBeNull();
});

it("names what a missing email, image store or data key turns off", async () => {
  server.appConfig = { emailEnabled: false };
  server.adminGet = { imageStoreMode: "peer" };
  server.dataKey = { configured: false };
  server.backups = { configured: true, status: { state: "misconfigured", reason: "x" } };
  server.tunnel = { configured: true, apiUrl: "https://tunnel.example.test" };
  const { container } = await mount();
  expect(state(container, "email")).toBe("missing");
  expect(screen.getByText(enAdmin.setup.email.missing)).toBeTruthy();
  expect(state(container, "image-store")).toBe("missing");
  expect(screen.getByText(enAdmin.setup.imageStore.peer)).toBeTruthy();
  expect(state(container, "data-key")).toBe("missing");
  expect(state(container, "backups")).toBe("problem");
  expect(screen.getByText(enAdmin.setup.maintenanceLink)).toBeTruthy();
  expect(state(container, "tunnels")).toBe("ok");
  expect(screen.getByText("Configured to use https://tunnel.example.test.")).toBeTruthy();
});

it("shows an unknown state when a status cannot be read", async () => {
  server.dataKey = { fail: true };
  const { container } = await mount();
  expect(state(container, "data-key")).toBe("unknown");
});

it.each([
  [{ state: "stale", ageHours: 40, maxAgeHours: 26 }, "problem", "problem"],
  [{ state: "empty" }, "problem", "problem"],
  [null, "problem", "unknown"],
  [{ state: "fresh", ageHours: 2, maxAgeHours: 26 }, "ok", "ok"],
])("only a fresh backup reads as healthy (%j)", async (status, rowState, copy) => {
  server.dataKey = { configured: true };
  server.backups = { configured: true, status };
  const { container } = await mount();
  expect(state(container, "backups")).toBe(rowState);
  expect(
    screen.getByText(enAdmin.setup.backups[copy as "ok" | "problem" | "unknown"]),
  ).toBeTruthy();
  if (rowState === "problem") expect(screen.getByText(enAdmin.setup.maintenanceLink)).toBeTruthy();
});

it("tells an admin to remove a SETUP_KEY that is still set, and says nothing otherwise", async () => {
  server.dataKey = { configured: true };
  server.backups = { configured: false, status: null };
  server.adminGet = { imageStoreMode: "s3", setupKeySet: false };
  const quiet = await mount();
  expect(state(quiet.container, "setup-key")).toBeUndefined();
  cleanup();

  server.adminGet = { imageStoreMode: "s3", setupKeySet: true };
  const { container } = await mount();
  expect(state(container, "setup-key")).toBe("problem");
  expect(screen.getByText(enAdmin.setup.setupKey.set)).toBeTruthy();
  // It leads the list: it is the one thing to do after the first sign-in.
  expect(container.querySelector("[data-setup-row]")?.getAttribute("data-setup-row")).toBe(
    "setup-key",
  );
});
