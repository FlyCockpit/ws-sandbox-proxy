// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import en from "@wssp/locales/src/en-US/agents.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it } from "vitest";
import { HostAuditList } from "./host-audit-list";

afterEach(cleanup);
it("renders metadata and never command text, paths or output", async () => {
  const i18n = createInstance();
  await i18n.init({ lng: "en-US", resources: { "en-US": { agents: en } } });
  render(
    <I18nextProvider i18n={i18n}>
      <HostAuditList
        lang="en-US"
        onRetry={() => {}}
        entries={[
          { id: "lift", createdAt: new Date(), actor: "PERSON", kind: "POLICY_VETO_LIFT" },
          {
            id: "event",
            createdAt: new Date(),
            actor: "AGENT",
            kind: "COMMAND",
            program: "sh",
            state: "succeeded",
            command: "secret-command",
            output: "secret-output",
            path: "/secret/path",
          },
        ]}
      />
    </I18nextProvider>,
  );
  expect(screen.getByText(/Host command/)).toBeTruthy();
  expect(screen.getByText(/Dashboard block lifted/)).toBeTruthy();
  expect(document.body.textContent).not.toContain("secret-command");
  expect(document.body.textContent).not.toContain("secret-output");
  expect(document.body.textContent).not.toContain("/secret/path");
});
