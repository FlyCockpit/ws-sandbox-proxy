// @vitest-environment jsdom
import {
  createBrowserHistory,
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
  Link,
  Outlet,
  RouterProvider,
  useNavigate,
} from "@tanstack/react-router";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import common from "@wssp/locales/src/en-US/common.json";
import credentials from "@wssp/locales/src/en-US/credentials.json";
import { createInstance } from "i18next";
import { type ReactNode, useState } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it } from "vitest";
import { SecretLeaveGuard } from "@/components/credentials/credential-parts";
import { UnsavedChangesGuard } from "./leave-guard-dialog";

/**
 * The leave prompts against the real router (no mocked blocker): a held link
 * or Back shows the dialog, "stay" keeps the page, "leave" goes on, and a
 * navigation with `ignoreBlocker` (a finished create, the forced 2FA
 * takeover) passes without asking.
 */
afterEach(cleanup);
const LIST = "/en-US/dashboard/sandboxes";
const NEW = "/en-US/dashboard/sandboxes/new";

function FormPage({ guard }: { guard: (active: boolean) => ReactNode }) {
  const [typed, setTyped] = useState("");
  const navigate = useNavigate();
  return (
    <>
      <label>
        Name
        <input value={typed} onChange={(event) => setTyped(event.target.value)} />
      </label>
      {guard(typed !== "")}
      <Link to="/$lang/dashboard/sandboxes" params={{ lang: "en-US" }}>
        Cancel
      </Link>
      {/* As the forced 2FA takeover (and a finished create) navigate. */}
      <button
        type="button"
        onClick={() =>
          void navigate({
            to: "/$lang/settings/security",
            params: { lang: "en-US" },
            ignoreBlocker: true,
          })
        }
      >
        Set up 2FA
      </button>
    </>
  );
}

async function setup(guard: (active: boolean) => ReactNode, { browser = false } = {}) {
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { common, credentials } } });
  const root = createRootRoute({ component: () => <Outlet /> });
  const routes = [
    createRoute({
      getParentRoute: () => root,
      path: "/$lang/dashboard/sandboxes",
      component: () => <h1>List</h1>,
    }),
    createRoute({
      getParentRoute: () => root,
      path: "/$lang/settings/security",
      component: () => <h1>Security</h1>,
    }),
    createRoute({
      getParentRoute: () => root,
      path: "/$lang/dashboard/sandboxes/new",
      component: () => <FormPage guard={guard} />,
    }),
  ];
  // Back is a popstate: only the browser history holds it (memory history
  // checks blockers on push and replace only).
  if (browser) {
    window.history.replaceState(null, "", LIST);
    window.history.pushState(null, "", NEW);
  }
  const history = browser
    ? createBrowserHistory()
    : createMemoryHistory({ initialEntries: [LIST, NEW], initialIndex: 1 });
  const router = createRouter({ routeTree: root.addChildren(routes), history });
  render(
    <I18nextProvider i18n={i18n}>
      <RouterProvider router={router} />
    </I18nextProvider>,
  );
  await screen.findByLabelText("Name");
  return { router, history, user: userEvent.setup() };
}

it("an untouched form leaves at once", async () => {
  const { router, user } = await setup((active) => <UnsavedChangesGuard active={active} />);
  await user.click(screen.getByRole("link", { name: "Cancel" }));
  await waitFor(() => expect(router.state.location.pathname).toBe(LIST));
  expect(screen.queryByRole("alertdialog")).toBeNull();
});

it("with input, Cancel asks; Keep editing stays with the input, Discard leaves", async () => {
  const { router, user } = await setup((active) => <UnsavedChangesGuard active={active} />);
  await user.type(screen.getByLabelText("Name"), "half-done");
  await user.click(screen.getByRole("link", { name: "Cancel" }));
  const prompt = within(await screen.findByRole("alertdialog"));
  expect(prompt.getByText(common.form.leave.title)).toBeTruthy();
  await user.click(prompt.getByRole("button", { name: common.form.leave.stay }));
  await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  expect(router.state.location.pathname).toBe(NEW);
  expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("half-done");
  await user.click(screen.getByRole("link", { name: "Cancel" }));
  await user.click(
    within(await screen.findByRole("alertdialog")).getByRole("button", {
      name: common.form.leave.leave,
    }),
  );
  await waitFor(() => expect(router.state.location.pathname).toBe(LIST));
});

it("with input, Back is held the same way", async () => {
  const { router, history, user } = await setup(
    (active) => <UnsavedChangesGuard active={active} />,
    { browser: true },
  );
  await user.type(screen.getByLabelText("Name"), "x");
  history.back();
  expect(await screen.findByRole("alertdialog")).toBeTruthy();
  await user.click(screen.getByRole("button", { name: common.form.leave.stay }));
  await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  expect(router.state.location.pathname).toBe(NEW);
});

it("a navigation that ignores blockers (forced 2FA, a finished create) passes without asking", async () => {
  const { router, user } = await setup((active) => <UnsavedChangesGuard active={active} />);
  await user.type(screen.getByLabelText("Name"), "x");
  await user.click(screen.getByRole("button", { name: "Set up 2FA" }));
  await waitFor(() => expect(router.state.location.pathname).toBe("/en-US/settings/security"));
  expect(screen.queryByRole("alertdialog")).toBeNull();
});

it("the one-time secret guard holds a plain navigation with its own wording", async () => {
  const { router, user } = await setup((active) => <SecretLeaveGuard active={active} />);
  await user.type(screen.getByLabelText("Name"), "x");
  await user.click(screen.getByRole("link", { name: "Cancel" }));
  const prompt = within(await screen.findByRole("alertdialog"));
  expect(prompt.getByText(credentials.leave.title)).toBeTruthy();
  await user.click(prompt.getByRole("button", { name: credentials.leave.stay }));
  await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
  expect(router.state.location.pathname).toBe(NEW);
});
