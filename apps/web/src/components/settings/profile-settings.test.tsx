// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import enAuth from "@wssp/locales/src/en-US/auth.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enSettings from "@wssp/locales/src/en-US/settings.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";

const fixture = vi.hoisted(() => ({
  query: {
    data: undefined as { operationalAlerts: boolean } | undefined,
    isPending: false,
    isError: false,
    error: null as unknown,
    refetch: vi.fn(),
  },
  mutate: vi.fn(),
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => fixture.query,
  useMutation: () => ({ mutate: fixture.mutate, isPending: false }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));
vi.mock("@/lib/auth-client", () => ({ authClient: { updateUser: vi.fn() } }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    settings: {
      myNotificationPreferences: { queryOptions: () => ({}), queryKey: () => [] },
      updateMyNotificationPreferences: { mutationOptions: () => ({}) },
    },
  },
}));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import { ProfileSettings } from "./profile-settings";

const i18n = createInstance();
beforeAll(async () => {
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    resources: { "en-US": { common: enCommon, settings: enSettings, auth: enAuth } },
    react: { useSuspense: false },
  });
});
beforeEach(() => {
  fixture.query = {
    data: undefined,
    isPending: false,
    isError: false,
    error: null,
    refetch: vi.fn(),
  };
  fixture.mutate.mockClear();
});
afterEach(cleanup);
const tree = () => (
  <I18nextProvider i18n={i18n}>
    <ProfileSettings user={{ email: "owner@example.test", name: "Owner", role: "admin" }} />
  </I18nextProvider>
);

it("does not fabricate a checked preference before loading or after a first-load failure", () => {
  fixture.query.isPending = true;
  const view = render(tree());
  expect(screen.queryByRole("checkbox")).toBeNull();
  fixture.query.isPending = false;
  fixture.query.isError = true;
  fixture.query.error = new Error("offline");
  view.rerender(tree());
  expect(screen.queryByRole("checkbox")).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: enCommon.actions.tryAgain }));
  expect(fixture.query.refetch).toHaveBeenCalledOnce();
  expect(fixture.mutate).not.toHaveBeenCalled();
});
it("retains the actual false value on a transient failure, with a retry", () => {
  fixture.query.data = { operationalAlerts: false };
  const view = render(tree());
  expect(screen.getByRole("checkbox").getAttribute("aria-checked")).toBe("false");
  fixture.query.isError = true;
  fixture.query.error = new Error("offline");
  view.rerender(tree());
  expect(screen.getByRole("checkbox").getAttribute("aria-checked")).toBe("false");
  expect(screen.getByRole("button", { name: enCommon.actions.tryAgain })).toBeTruthy();
});
it.each([401, 403, 404])("hides the saved preference after access loss (%s)", (status) => {
  fixture.query.data = { operationalAlerts: true };
  const view = render(tree());
  expect(screen.getByRole("checkbox").getAttribute("aria-checked")).toBe("true");
  fixture.query.isError = true;
  fixture.query.error = { status };
  view.rerender(tree());
  expect(screen.queryByRole("checkbox")).toBeNull();
});
