// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import enAgents from "@wssp/locales/src/en-US/agents.json";
import esAgents from "@wssp/locales/src/es-MX/agents.json";
import { afterEach, expect, it, vi } from "vitest";

const locale = vi.hoisted(() => ({ current: "en-US" }));
vi.mock("@wssp/env/web", () => ({ env: { VITE_SERVER_URL: "https://example.test" } }));
vi.mock("./sdk-keys-page", () => ({ SdkKeysPage: () => null }));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirectOnError: () => {} }));
vi.mock("@/utils/orpc", () => ({ orpc: { mcpGrants: { list: { infiniteOptions: () => ({}) } } } }));
vi.mock("@tanstack/react-query", () => ({
  useInfiniteQuery: () => ({
    data: {
      pages: [
        {
          items: [
            {
              id: "g1",
              clientId: "client",
              SdkKey: {
                name: "agent",
                scopes: [],
                ownSandboxesOnly: false,
                resourceMode: "ALL_OWNED",
                poolMode: "ALL_USABLE",
              },
            },
          ],
        },
      ],
    },
    isPending: false,
    isError: false,
  }),
  useQueryClient: () => ({ invalidateQueries: vi.fn() }),
}));
vi.mock("@/components/credentials/credential-parts", () => ({
  useRevoke: () => {
    const [confirming, setConfirming] = React.useState(false);
    return {
      confirming,
      setConfirming,
      problem: null,
      mutation: { isPending: false, mutate: vi.fn() },
    };
  },
}));
vi.mock("@/components/query-boundary", () => ({
  QueryBoundary: ({
    query,
    children,
  }: {
    query: { data: unknown };
    children: (data: unknown) => React.ReactNode;
  }) => children(query.data),
}));
vi.mock("@/components/confirm-delete-dialog", () => ({
  ConfirmDeleteDialog: ({
    open,
    typePrompt,
    copyAriaLabel,
  }: {
    open: boolean;
    typePrompt: string;
    copyAriaLabel: string;
  }) =>
    open ? (
      <div role="dialog">
        <p>{typePrompt}</p>
        <button type="button" aria-label={copyAriaLabel} />
      </div>
    ) : null,
}));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => {
      const values: Record<string, string> = {
        "agents:revoke.typePrompt":
          locale.current === "es-MX" ? esAgents.revoke.typePrompt : enAgents.revoke.typePrompt,
        "agents:revoke.copyName":
          locale.current === "es-MX" ? esAgents.revoke.copyName : enAgents.revoke.copyName,
      };
      return values[key] ?? key;
    },
  }),
}));

import * as React from "react";
import { AgentTokensPage } from "./agent-tokens-page";

afterEach(cleanup);
it.each([
  ["en-US", enAgents],
  ["es-MX", esAgents],
] as const)("%s connected app confirmation refers to the token", (lang, strings) => {
  locale.current = lang;
  render(<AgentTokensPage lang={lang} />);
  fireEvent.click(screen.getByRole("button", { name: "credentials:revoke.actionNamed" }));
  expect(screen.getByText(strings.revoke.typePrompt)).toBeTruthy();
  expect(screen.getByRole("button", { name: strings.revoke.copyName })).toBeTruthy();
});
