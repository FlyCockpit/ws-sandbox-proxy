// @vitest-environment jsdom

import { cleanup, render } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { TerminalStatusIcon, terminalIndicator } from "./terminal-header";

afterEach(cleanup);

/** The picker's icon and colour states, mapped onto wssp's terminal states. */
describe("terminalIndicator", () => {
  it("keyboard green while attached: what you type reaches the shell", () => {
    expect(terminalIndicator("attached", null)).toEqual({ mode: "typing", tone: "connected" });
  });

  it("keyboard amber while opening", () => {
    for (const status of ["loading", "connecting", "verifying"] as const)
      expect(terminalIndicator(status, null)).toEqual({ mode: "typing", tone: "opening" });
  });

  it("eye amber while reconnecting: view only, input stopped", () => {
    expect(terminalIndicator("reconnecting", null)).toEqual({ mode: "viewing", tone: "opening" });
  });

  it("grey once a session that ran has ended", () => {
    for (const kind of ["client", "replaced", "exited", "sandboxStopped", "resumeFailed"] as const)
      expect(terminalIndicator("ended", { kind })).toEqual({ mode: "typing", tone: "ended" });
    expect(terminalIndicator("ended", null)).toEqual({ mode: "typing", tone: "ended" });
  });

  it("red when the terminal was refused or could not open", () => {
    for (const kind of [
      "forbidden",
      "notFound",
      "notReady",
      "rateLimited",
      "couldNotConnect",
      "createFailed",
      "hostRefused",
      "noTerminalIdentity",
    ] as const)
      expect(terminalIndicator("ended", { kind })).toEqual({ mode: "typing", tone: "refused" });
  });
});

describe("TerminalStatusIcon", () => {
  it("draws the keyboard or the eye in the tone's colour, hidden from screen readers", () => {
    const { container, rerender } = render(
      <TerminalStatusIcon indicator={{ mode: "typing", tone: "connected" }} />,
    );
    let icon = container.querySelector("svg");
    expect(icon?.getAttribute("data-terminal-indicator")).toBe("typing-connected");
    expect(icon?.getAttribute("aria-hidden")).toBe("true");
    // Important, so a focused menu item cannot recolour it.
    expect(icon?.getAttribute("class")).toContain("text-emerald-600!");
    expect(icon?.getAttribute("class")).toContain("lucide-keyboard");

    rerender(<TerminalStatusIcon indicator={{ mode: "viewing", tone: "opening" }} />);
    icon = container.querySelector("svg");
    expect(icon?.getAttribute("class")).toContain("lucide-eye");
    expect(icon?.getAttribute("class")).toContain("text-amber-600");

    rerender(<TerminalStatusIcon indicator={{ mode: "typing", tone: "refused" }} />);
    expect(container.querySelector("svg")?.getAttribute("class")).toContain("text-destructive");
    rerender(<TerminalStatusIcon indicator={{ mode: "typing", tone: "ended" }} />);
    expect(container.querySelector("svg")?.getAttribute("class")).toContain(
      "text-muted-foreground",
    );
  });
});
