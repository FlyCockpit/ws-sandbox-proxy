// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import { createInstance, type i18n as I18n } from "i18next";
import type { ReactNode } from "react";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeAll, beforeEach, expect, it, vi } from "vitest";

/**
 * Add host: wrapped commands, copyable guide paths, and the live
 * "Waiting for your host… → Connected" row against a scripted host list.
 */

type Host = {
  id: string;
  slug: string;
  label: string;
  status: "CONNECTED" | "DISCONNECTED";
  lastConnectedAt: Date | null;
  lastHeartbeatAt: Date | null;
  deletionRequestedAt: Date | null;
  quarantinedAt: Date | null;
};

const server = vi.hoisted(() => ({ hosts: [] as Host[], calls: 0, fail: false }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://api.example.test" } }));
vi.mock("@tanstack/react-router", () => ({
  Link: ({
    children,
    className,
    to,
    params,
    search,
  }: {
    children: ReactNode;
    className?: string;
    to: string;
    params?: { lang?: string; hostId?: string };
    search?: Record<string, string>;
  }) => (
    <a
      className={className}
      href={
        to
          .replace("$lang", params?.lang ?? "$lang")
          .replace("$hostId", params?.hostId ?? "$hostId") +
        (search ? `?${new URLSearchParams(search)}` : "")
      }
    >
      {children}
    </a>
  ),
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxHosts: {
      listHosts: {
        queryOptions: ({ input }: { input: unknown }) => ({
          queryKey: ["listHosts", input],
          queryFn: async () => {
            server.calls += 1;
            if (server.fail) throw new Error("network down");
            return { items: structuredClone(server.hosts), nextCursor: null };
          },
        }),
      },
    },
  },
}));

import { AddHostPage, hostSlugFromName } from "./add-host-page";

let i18n: I18n;
beforeAll(async () => {
  i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    ns: ["common", "hosts"],
    defaultNS: "common",
    resources: { "en-US": { common: enCommon, hosts: enHosts } },
    interpolation: { escapeValue: false },
    react: { useSuspense: false },
  });
});
let client: QueryClient;
beforeEach(() => {
  server.hosts = [];
  server.calls = 0;
  server.fail = false;
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

function host(overrides: Partial<Host> = {}): Host {
  return {
    id: "old",
    slug: "old",
    label: "Old box",
    status: "DISCONNECTED",
    lastConnectedAt: null,
    lastHeartbeatAt: null,
    deletionRequestedAt: null,
    quarantinedAt: null,
    ...overrides,
  };
}

function mount() {
  client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <AddHostPage lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
}
const status = () => document.querySelector<HTMLElement>("[data-enroll-status]")!;
const poll = () => act(() => client.refetchQueries());

it("numbers the steps, wraps every command and names the guide by a copyable path", async () => {
  mount();
  expect(screen.getByRole("heading", { level: 1 }).textContent).toBe(enHosts.enroll.pageTitle);
  const steps = [...document.querySelectorAll<HTMLElement>("[data-enroll-step]")];
  expect(steps.map((step) => step.dataset.enrollStep)).toEqual([
    "install",
    "enroll",
    "guard",
    "run",
  ]);
  for (const command of document.querySelectorAll("[data-enroll-command] pre"))
    expect(command.className).toMatch(/whitespace-pre-wrap/);
  expect(
    [...document.querySelectorAll("[data-docs-link]")].map((link) => link.getAttribute("href")),
  ).toEqual([
    "https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/guide/hosts.md#quick-start-your-first-host",
    "https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs/guide/hosts.md#run-as-a-service",
  ]);
  expect(screen.queryByText(/Prefer a long-lived token/)).toBeNull();
  // The back link is at the top.
  expect(screen.getByRole("link", { name: enHosts.title }).getAttribute("href")).toBe(
    "/en-US/settings/hosts",
  );
});

it("the host name updates the enroll command, as a slug the CLI accepts", async () => {
  const user = userEvent.setup();
  mount();
  expect(screen.getByText("wssp host enroll --slug my-host --server https://api.example.test"));
  await user.type(screen.getByLabelText(enHosts.enroll.nameLabel), "Desk Box 2");
  expect(screen.getByText("wssp host enroll --slug desk-box-2 --server https://api.example.test"));
  expect(hostSlugFromName("  --Ünïcode!!  ")).toBe("n-code");
  expect(hostSlugFromName("")).toBe("my-host");
});

it("waits, then shows the new host enrolled, then connected with the next step", async () => {
  server.hosts = [host()];
  mount();
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("waiting"));
  expect(within(status()).getByRole("status").textContent).toBe(enHosts.enroll.status.waiting);
  // A host that existed before the page opened is never mistaken for the new one.
  await poll();
  expect(status().dataset.enrollStatus).toBe("waiting");

  server.hosts = [host({ id: "new", slug: "desk", label: "Desk" }), host()];
  await poll();
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("enrolled"));
  expect(within(status()).getByRole("status").textContent).toBe(
    enHosts.enroll.status.enrolled.replace("{{label}}", "Desk"),
  );

  server.hosts[0] = {
    ...server.hosts[0]!,
    status: "CONNECTED",
    lastConnectedAt: new Date(),
    lastHeartbeatAt: new Date(),
  };
  await poll();
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("connected"));
  expect(within(status()).getByRole("status").textContent).toBe(
    enHosts.enroll.status.connected.replace("{{label}}", "Desk"),
  );
  expect(
    within(status())
      .getByRole("link", { name: enHosts.enroll.status.createSandbox })
      .getAttribute("href"),
  ).toBe("/en-US/dashboard/sandboxes/new?host=new");
  expect(
    within(status())
      .getByRole("link", { name: enHosts.enroll.status.openHost })
      .getAttribute("href"),
  ).toBe("/en-US/settings/hosts/new");
});

it("an existing host that was offline and now connects counts as yours", async () => {
  server.hosts = [host()];
  mount();
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("waiting"));
  server.hosts = [
    host({ status: "CONNECTED", lastConnectedAt: new Date(), lastHeartbeatAt: new Date() }),
  ];
  await poll();
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("connected"));
});

it("a failed first hosts read says so with a retry instead of waiting forever", async () => {
  const user = userEvent.setup();
  server.fail = true;
  mount();
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("failed"));
  expect(within(status()).getByRole("status").textContent).toBe(enHosts.enroll.status.failed);
  server.fail = false;
  server.hosts = [host()];
  await user.click(within(status()).getByRole("button", { name: enHosts.enroll.status.retry }));
  await waitFor(() => expect(status().dataset.enrollStatus).toBe("waiting"));
});
