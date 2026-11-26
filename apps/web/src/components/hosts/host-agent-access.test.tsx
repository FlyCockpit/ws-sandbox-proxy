// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import en from "@wssp/locales/src/en-US/agents.json";
import hostsEn from "@wssp/locales/src/en-US/hosts.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const fake = vi.hoisted(() => ({
  lowerCommands: vi.fn(),
  lowerTerminal: vi.fn(),
  liftCommands: vi.fn(),
  liftTerminal: vi.fn(),
  run: vi.fn(),
  dismiss: vi.fn(),
  terminal: vi.fn(),
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({
  useTwoFactorRedirect: () => () => false,
  useTwoFactorRedirectOnError: () => {},
}));
vi.mock("./host-detail-page", () => ({
  HostTerminal: (props: { typeCommand: string }) => {
    fake.terminal(props);
    return <div data-testid="terminal" data-command={props.typeCommand} />;
  },
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxHosts: {
      getHost: { key: () => ["host"] },
      lowerAgentHostCommands: { call: fake.lowerCommands },
      lowerHostTerminal: { call: fake.lowerTerminal },
      liftAgentHostCommandsVeto: { call: fake.liftCommands },
      liftHostTerminalVeto: { call: fake.liftTerminal },
    },
    hostQueuedCommands: {
      list: {
        key: () => ["queue"],
        infiniteOptions: (options: {
          initialPageParam: unknown;
          getNextPageParam: (page: { nextCursor: null }) => unknown;
        }) => ({
          queryKey: ["queue"],
          ...options,
          queryFn: async () => ({
            nextCursor: null,
            items: [
              {
                id: "q1",
                command: "echo hello",
                reason: "inspect",
                credentialName: "agent",
                state: "QUEUED",
                expiresAt: new Date(Date.now() + 3600000).toISOString(),
              },
            ],
          }),
        }),
      },
      run: { mutationOptions: () => ({ mutationFn: fake.run }) },
      dismiss: { mutationOptions: () => ({ mutationFn: fake.dismiss }) },
    },
  },
}));

import { canPretypeQueuedCommand, HostAgentAccess, QueuedHostCommands } from "./host-agent-access";

beforeEach(() => {
  vi.clearAllMocks();
  fake.liftCommands.mockResolvedValue({ ok: true });
  fake.liftTerminal.mockResolvedValue({ ok: true });
  fake.lowerCommands.mockResolvedValue({ confirmed: false });
  fake.lowerTerminal.mockResolvedValue({ confirmed: true });
});
afterEach(cleanup);
const policy = { hostTerminal: true, requireHostTerminalTotp: false, policyRevision: 1, epoch: 1 };
async function mount(element: React.ReactNode) {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    resources: { "en-US": { agents: en, hosts: hostsEn } },
    interpolation: { escapeValue: false },
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>{element}</I18nextProvider>
    </QueryClientProvider>,
  );
}
const host = {
  id: "h1",
  status: "CONNECTED" as const,
  agentAccess: { owned: true as const, hostCommands: true, hostFiles: false },
  agentPolicy: {
    hostCommands: true,
    hostFiles: false,
    hostCommandMaxMs: 600000,
    agentPolicyRevision: 1,
    lowerPending: false,
  },
  terminalPolicy: policy,
  agentHostCommandsVetoedAt: null,
  hostTerminalVetoedAt: null,
};
it("requires confirmation before lowering commands and uses the commands endpoint", async () => {
  await mount(<HostAgentAccess host={host} lang="en-US" />);
  const user = userEvent.setup();
  await user.click(
    screen.getByRole("button", {
      name: en.host.turnOffNamed.replace("{{setting}}", en.host.commands),
    }),
  );
  expect(fake.lowerCommands).not.toHaveBeenCalled();
  await user.click(
    within(screen.getByRole("alertdialog")).getByRole("button", { name: en.host.turnOff }),
  );
  await waitFor(() => expect(fake.lowerCommands).toHaveBeenCalledWith({ id: "h1" }));
  expect(fake.lowerTerminal).not.toHaveBeenCalled();
});
it("shows durable vetoes and prevents another lowering action", async () => {
  await mount(
    <HostAgentAccess
      host={{
        ...host,
        agentHostCommandsVetoedAt: new Date(),
        hostTerminalVetoedAt: new Date(),
      }}
      lang="en-US"
    />,
  );
  expect(screen.getAllByText(en.host.vetoed)).toHaveLength(2);
  expect(screen.queryByRole("button", { name: /Turn off:/ })).toBeNull();
});
it("cancels terminal lowering without changing the node", async () => {
  await mount(<HostAgentAccess host={host} lang="en-US" />);
  const user = userEvent.setup();
  await user.click(
    screen.getByRole("button", {
      name: en.host.turnOffNamed.replace("{{setting}}", en.host.terminal),
    }),
  );
  await user.click(
    within(screen.getByRole("alertdialog")).getByRole("button", { name: en.host.cancel }),
  );
  expect(fake.lowerTerminal).not.toHaveBeenCalled();
});
it("hands a printable wrapper to the host terminal unchanged and without a newline", async () => {
  const wrapper = "env -u ENV /bin/sh -c 'echo hello'";
  fake.run.mockResolvedValue({ typedCommand: wrapper, hostTerminalAvailable: true });
  await mount(<QueuedHostCommands hostId="h1" lang="en-US" policy={policy} />);
  await userEvent.setup().click(await screen.findByRole("button", { name: en.queue.run }));
  const terminal = await screen.findByTestId("terminal");
  expect(terminal.getAttribute("data-command")).toBe(wrapper);
  expect(screen.queryByText(en.queue.copyHint)).toBeNull();
});
it.each([
  ["echo hello\n", true],
  ["echo café", true],
  ["echo hello", false],
])("shows a copy fallback for %s with terminal=%s", async (typedCommand, hostTerminalAvailable) => {
  fake.run.mockResolvedValue({ typedCommand, hostTerminalAvailable });
  const user = userEvent.setup();
  const copy = vi.spyOn(navigator.clipboard, "writeText").mockResolvedValue();
  await mount(<QueuedHostCommands hostId="h1" lang="en-US" policy={policy} />);
  await user.click(await screen.findByRole("button", { name: en.queue.run }));
  await user.click(await screen.findByRole("button", { name: en.queue.copy }));
  expect(copy).toHaveBeenCalledWith(typedCommand);
  expect(fake.terminal).not.toHaveBeenCalled();
});
it("refuses all control characters for pre-typing", () => {
  for (let code = 0; code < 32; code++)
    expect(canPretypeQueuedCommand(`echo a${String.fromCharCode(code)}`, true)).toBe(false);
  expect(canPretypeQueuedCommand("echo hi\x7f", true)).toBe(false);
  expect(canPretypeQueuedCommand("", true)).toBe(false);
});

it.each(["commands", "terminal"] as const)(
  "requires confirmation before lifting the %s veto without enabling the node",
  async (setting) => {
    await mount(
      <HostAgentAccess
        lang="en-US"
        host={{
          ...host,
          agentHostCommandsVetoedAt: new Date(),
          hostTerminalVetoedAt: new Date(),
          agentPolicy: { ...host.agentPolicy, hostCommands: false, nodeHostCommands: false },
          terminalPolicy: { ...policy, hostTerminal: false, nodeHostTerminal: false },
        }}
      />,
    );
    expect(screen.getAllByText(en.host.off)).toHaveLength(2);
    expect(screen.queryAllByRole("alert")).toHaveLength(0);
    const user = userEvent.setup();
    await user.click(
      screen.getByRole("button", {
        name: en.host.allowAgainNamed.replace("{{setting}}", en.host[setting]),
      }),
    );
    const dialog = screen.getByRole("alertdialog");
    expect(within(dialog).getByText(en.host.liftDescription)).toBeDefined();
    expect(fake.liftCommands).not.toHaveBeenCalled();
    expect(fake.liftTerminal).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: en.host.allowAgain }));
    await waitFor(() =>
      expect(setting === "commands" ? fake.liftCommands : fake.liftTerminal).toHaveBeenCalledWith({
        id: "h1",
      }),
    );
    expect(fake.lowerCommands).not.toHaveBeenCalled();
    expect(fake.lowerTerminal).not.toHaveBeenCalled();
  },
);
it("warns when raw node reports are on while effective access is vetoed", async () => {
  await mount(
    <HostAgentAccess
      lang="en-US"
      host={{
        ...host,
        agentHostCommandsVetoedAt: new Date(),
        hostTerminalVetoedAt: new Date(),
        agentPolicy: { ...host.agentPolicy, hostCommands: false, nodeHostCommands: true },
        terminalPolicy: { ...policy, hostTerminal: false, nodeHostTerminal: true },
      }}
    />,
  );
  expect(screen.getAllByRole("alert")).toHaveLength(2);
  for (const setting of ["commands", "terminal"] as const) {
    const command =
      setting === "commands"
        ? "wssp host config set-agent-host-commands off"
        : "wssp host config set-host-terminal off";
    expect(screen.getByText(en.host.tamperWarning.replace("{{command}}", command))).toBeDefined();
    expect(
      screen
        .getByRole("button", {
          name: en.host.allowAgainNamed.replace("{{setting}}", en.host[setting]),
        })
        .hasAttribute("disabled"),
    ).toBe(true);
  }
});

it.each(["offline", "missing raw report"])(
  "disables Allow again for %s even when effective policy is off",
  async (state) => {
    await mount(
      <HostAgentAccess
        lang="en-US"
        host={{
          ...host,
          agentHostCommandsVetoedAt: new Date(),
          hostTerminalVetoedAt: new Date(),
          agentPolicy: state === "offline" ? null : { ...host.agentPolicy, hostCommands: false },
          terminalPolicy: state === "offline" ? null : { ...policy, hostTerminal: false },
        }}
      />,
    );
    for (const setting of ["commands", "terminal"] as const) {
      const button = screen.getByRole("button", {
        name: en.host.allowAgainNamed.replace("{{setting}}", en.host[setting]),
      });
      expect(button.hasAttribute("disabled")).toBe(true);
      expect(
        document.getElementById(button.getAttribute("aria-describedby") ?? "")?.textContent,
      ).toContain("online and report this setting off");
      await userEvent.setup().click(button);
    }
    expect(screen.queryByRole("alertdialog")).toBeNull();
    expect(fake.liftCommands).not.toHaveBeenCalled();
    expect(fake.liftTerminal).not.toHaveBeenCalled();
  },
);

it.each(["DISCONNECTED", "STALE", "REVOKED"] as const)(
  "disables Allow again for a %s host even with remembered off reports",
  async (status) => {
    await mount(
      <HostAgentAccess
        lang="en-US"
        host={{
          ...host,
          status,
          agentHostCommandsVetoedAt: new Date(),
          hostTerminalVetoedAt: new Date(),
          agentPolicy: { ...host.agentPolicy, hostCommands: false, nodeHostCommands: false },
          terminalPolicy: { ...policy, hostTerminal: false, nodeHostTerminal: false },
        }}
      />,
    );
    for (const setting of ["commands", "terminal"] as const) {
      expect(
        screen
          .getByRole("button", {
            name: en.host.allowAgainNamed.replace("{{setting}}", en.host[setting]),
          })
          .hasAttribute("disabled"),
      ).toBe(true);
    }
  },
);

it("warns that host access runs as the daemon user, with no mode control", async () => {
  await mount(
    <HostAgentAccess
      host={{ ...host, agentAccess: { owned: true, hostCommands: true, hostFiles: false } }}
      lang="en-US"
    />,
  );
  expect(screen.getByText(en.consent.hostWarning)).toBeDefined();
  expect(screen.queryByRole("combobox")).toBeNull();
  expect(screen.queryByRole("switch")).toBeNull();
});

it("an Off setting offers Keep off, never Turn off, and its confirmation says what it does", async () => {
  await mount(
    <HostAgentAccess
      host={{
        ...host,
        agentPolicy: { ...host.agentPolicy, hostCommands: false },
        terminalPolicy: { ...policy, hostTerminal: false },
      }}
      lang="en-US"
    />,
  );
  const user = userEvent.setup();
  const commands = document.querySelector<HTMLElement>('[data-agent-setting="commands"]')!;
  expect(within(commands).getByRole("status").textContent).toBe(en.host.off);
  expect(within(commands).queryByRole("button", { name: /Turn off/ })).toBeNull();
  const keep = within(commands).getByRole("button", {
    name: en.host.keepOffNamed.replace("{{setting}}", en.host.commands),
  });
  // The button says it acts from the dashboard, and a one-line hint says what it adds.
  expect(keep.textContent).toBe("Keep off from the dashboard");
  const hint = document.getElementById(keep.getAttribute("aria-describedby") ?? "");
  expect(hint?.textContent).toBe(en.host.keepOffHint);
  await user.click(keep);
  const dialog = await screen.findByRole("alertdialog");
  expect(within(dialog).getByText(en.host.keepTitle)).toBeTruthy();
  await user.click(within(dialog).getByRole("button", { name: en.host.keepOff }));
  await waitFor(() => expect(fake.lowerCommands).toHaveBeenCalledWith({ id: "h1" }));
  // How to turn it on at the node is shown only while it is off.
  expect(within(commands).getByText("wssp host config set-agent-host-commands on")).toBeTruthy();
});
