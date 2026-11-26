// @vitest-environment jsdom

import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import { createInstance, type i18n as I18n } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * The admin data-key card against a scripted server: real TanStack Query and
 * en-US strings. Kids, counts and epochs only.
 */

const K1 = "1111111111111111";
const K2 = "2222222222222222";
const R1 = "aaaaaaaaaaaaaaaa";
const R2 = "bbbbbbbbbbbbbbbb";

const server = vi.hoisted(() => ({
  status: null as unknown,
  returnKeys: [] as unknown[],
  blockers: [] as unknown[],
  mutations: [] as { procedure: string; input: unknown }[],
  fail: null as unknown,
}));

vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

vi.mock("@/utils/orpc", () => {
  const query = (name: string, respond: () => unknown) => ({
    queryOptions: () => ({
      queryKey: ["adminDataKeys", name],
      queryFn: async () => structuredClone(respond()),
    }),
  });
  const infinite = (name: string, respond: () => unknown[]) => ({
    infiniteOptions: (options: {
      initialPageParam: unknown;
      getNextPageParam: (page: { nextCursor: string | null }) => unknown;
    }) => ({
      queryKey: ["adminDataKeys", name],
      initialPageParam: options.initialPageParam,
      getNextPageParam: options.getNextPageParam,
      queryFn: async () => ({ items: structuredClone(respond()), nextCursor: null }),
    }),
  });
  const mutation = (procedure: string) => ({
    mutationOptions: () => ({
      mutationFn: async (input: unknown) => {
        server.mutations.push({ procedure, input });
        if (server.fail) {
          const error = server.fail;
          server.fail = null;
          throw error;
        }
        return {};
      },
    }),
  });
  return {
    orpc: {
      adminDataKeys: {
        key: () => ["adminDataKeys"],
        status: query("status", () => server.status),
        listReturnKeys: infinite("listReturnKeys", () => server.returnKeys),
        listReturnKeyBlockers: infinite("listReturnKeyBlockers", () => server.blockers),
        promote: mutation("promote"),
        rotateReturnKey: mutation("rotateReturnKey"),
        destroyReturnKey: mutation("destroyReturnKey"),
        declareHostLost: mutation("declareHostLost"),
      },
    },
  };
});

import { DataKeyCard } from "./data-key-card";

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

function statusFixture(overrides: Record<string, unknown> = {}) {
  return {
    configured: true,
    epoch: {
      currentKid: K1,
      previousKid: null,
      epoch: "1",
      switchedAt: "2026-11-03T00:00:00.000Z",
    },
    counts: [],
    kids: [
      { kid: K1, rows: 12, current: true, safeToRemove: false },
      { kid: K2, rows: 0, current: false, safeToRemove: true },
    ],
    held: [K1, K2],
    heartbeats: [{ role: "worker", keysHeld: [K1, K2], at: "2026-11-03T00:00:00.000Z" }],
    returnKey: { currentKidR: R2, currentEpoch: "2" },
    ...overrides,
  };
}

function returnKey(kidR: string, extra: Record<string, unknown> = {}) {
  return {
    kidR,
    epoch: "1",
    rootKid: K1,
    createdAt: new Date(0),
    retiredAt: null,
    destroyedAt: null,
    blockingHosts: 0,
    blockingHostsCapped: false,
    quarantined: 0,
    ...extra,
  };
}

/** Waits until `selector` matches (a null match keeps waiting). */
function findElement(selector: string) {
  return waitFor(() => {
    const element = document.querySelector(selector);
    if (!element) throw new Error(`missing ${selector}`);
    return element as HTMLElement;
  });
}

function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <DataKeyCard />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  server.status = statusFixture();
  server.returnKeys = [
    returnKey(R2, { epoch: "2" }),
    returnKey(R1, { retiredAt: new Date(1), blockingHosts: 1, quarantined: 2 }),
  ];
  server.blockers = [{ hostId: "host-7", issuedAt: new Date(0), ackedAt: null, drainedAt: null }];
  server.mutations = [];
  server.fail = null;
});
afterEach(cleanup);

describe("DataKeyCard", () => {
  it("shows the epoch, per-kid rows and states, and advisory heartbeats", async () => {
    mount();
    expect(await screen.findByText(`Epoch 1: writers seal under ${K1}.`)).toBeTruthy();
    const current = document.querySelector(`tr[data-kid="${K1}"]`) as HTMLElement;
    expect(within(current).getByText("12")).toBeTruthy();
    expect(within(current).getByText(/^Current/)).toBeTruthy();
    // Only a held, non-current kid can be promoted.
    expect(within(current).queryByRole("button", { name: "Promote" })).toBeNull();
    const other = document.querySelector(`tr[data-kid="${K2}"]`) as HTMLElement;
    expect(within(other).getByText(/^Safe to remove/)).toBeTruthy();
    expect(screen.getByText(`Worker: ${K1}, ${K2}`)).toBeTruthy();
    expect(screen.getByText(/Advisory only/)).toBeTruthy();
  });

  it("says the key is missing when the server has none", async () => {
    server.status = statusFixture({
      configured: false,
      epoch: null,
      kids: [],
      held: [],
      heartbeats: null,
      returnKey: null,
    });
    server.returnKeys = [];
    mount();
    expect(await screen.findByText(/DATA_ENCRYPTION_KEY is not set/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Rotate return key" })).toBeNull();
  });

  it("promotes after confirmation and shows a typed refusal inside the dialog", async () => {
    const user = userEvent.setup();
    mount();
    const other = await findElement(`tr[data-kid="${K2}"]`);
    server.fail = {
      code: "CONFLICT",
      data: { code: "admin.data_key_refused", reason: "key_not_held" },
    };
    await user.click(within(other).getByRole("button", { name: "Promote" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Promote" }));
    expect(await within(dialog).findByText(/This server does not hold that key/)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: "Promote" }));
    await waitFor(() => expect(screen.queryByRole("alertdialog")).toBeNull());
    expect(server.mutations).toEqual([
      { procedure: "promote", input: { kid: K2 } },
      { procedure: "promote", input: { kid: K2 } },
    ]);
  });

  it("rotates the return key after confirmation", async () => {
    const user = userEvent.setup();
    mount();
    await user.click(await screen.findByRole("button", { name: "Rotate return key" }));
    const dialog = await screen.findByRole("alertdialog");
    await user.click(within(dialog).getByRole("button", { name: "Rotate return key" }));
    await waitFor(() =>
      expect(server.mutations.map((m) => m.procedure)).toEqual(["rotateReturnKey"]),
    );
  });

  it("destroys a retired key only after the kid is typed, and says destroy anyway with quarantined captures", async () => {
    const user = userEvent.setup();
    mount();
    const row = await findElement(`li[data-return-key="${R1}"]`);
    expect(within(row).getByText("1 host still blocks destruction")).toBeTruthy();
    expect(within(row).getByText("2 quarantined captures")).toBeTruthy();
    // The current key offers no destroy.
    const currentRow = document.querySelector(`li[data-return-key="${R2}"]`) as HTMLElement;
    expect(within(currentRow).queryByRole("button", { name: "Destroy" })).toBeNull();

    await user.click(within(row).getByRole("button", { name: "Destroy" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/2 quarantined captures are sealed to it/)).toBeTruthy();
    const confirm = within(dialog).getByRole("button", { name: "Destroy anyway" });
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    const typed = within(dialog).getByLabelText(enAdmin.dataKey.returnKeys.destroyPrompt);
    // The token is shown above the field, never as its placeholder (it would look prefilled).
    expect(typed.getAttribute("placeholder")).toBeNull();
    await user.type(typed, R1);
    expect((confirm as HTMLButtonElement).disabled).toBe(false);
    await user.click(confirm);
    await waitFor(() =>
      expect(server.mutations).toEqual([
        {
          procedure: "destroyReturnKey",
          input: { kidR: R1, confirmKidR: R1, destroyQuarantined: true },
        },
      ]),
    );
  });

  it("lists blocking hosts and declares one lost after confirmation", async () => {
    const user = userEvent.setup();
    mount();
    const row = await findElement(`li[data-return-key="${R1}"]`);
    await user.click(within(row).getByRole("button", { name: "Show blocking hosts" }));
    const host = await findElement('li[data-blocking-host="host-7"]');
    expect(within(host).getByText("Has not acked a newer key")).toBeTruthy();
    await user.click(within(host).getByRole("button", { name: "Declare lost" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(within(dialog).getByText(/Host host-7 will never reconnect/)).toBeTruthy();
    await user.click(within(dialog).getByRole("button", { name: "Declare lost" }));
    await waitFor(() =>
      expect(server.mutations).toEqual([
        { procedure: "declareHostLost", input: { kidR: R1, hostId: "host-7" } },
      ]),
    );
  });

  it("renders no key material", async () => {
    mount();
    await screen.findByText(`Epoch 1: writers seal under ${K1}.`);
    expect(document.body.textContent).not.toMatch(/[0-9a-f]{64}/);
  });
});
