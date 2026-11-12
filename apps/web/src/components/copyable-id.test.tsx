// @vitest-environment jsdom
import { cleanup, render } from "@testing-library/react";
import en from "@wssp/locales/src/en-US/common.json";
import es from "@wssp/locales/src/es-MX/common.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, describe, expect, it } from "vitest";

import { AdvancedDetails } from "./advanced-details";
import { CopyableId, shortId } from "./copyable-id";

afterEach(cleanup);

async function i18nFor(lng: "en-US" | "es-MX") {
  const i18n = createInstance();
  await i18n.init({
    lng,
    resources: { "en-US": { common: en }, "es-MX": { common: es } },
    interpolation: { escapeValue: false },
  });
  return i18n;
}

describe("shortId", () => {
  it.each([
    ["48b1d9a0-1b2c-4d5e-8f90-1234567890ab", "48b1d9a0…"],
    ["k9fxb5ot17abcdefghij", "k9fxb5ot…"],
    [`sha256:${"7c".repeat(32)}`, "sha256:7c7c7c7c7c7c…"],
    ["ab".repeat(32), `${"ab".repeat(6)}…`],
    ["short-id", "short-id"],
  ])("%s → %s", (value, short) => expect(shortId(value)).toBe(short));
});

describe.each(["en-US", "es-MX"] as const)("CopyableId in %s", (lng) => {
  it("shows the short form, keeps the full value in the tooltip, and labels a 44px copy button", async () => {
    const value = "48b1d9a0-1b2c-4d5e-8f90-1234567890ab";
    const { container } = render(
      <I18nextProvider i18n={await i18nFor(lng)}>
        <CopyableId value={value} label="Sandbox ID" />
      </I18nextProvider>,
    );
    const code = container.querySelector('[data-slot="copy-field-value"]')!;
    expect(code.textContent).toBe("48b1d9a0…");
    expect(code.getAttribute("title")).toBe(value);
    const button = container.querySelector("button")!;
    expect(button.getAttribute("aria-label")).toBe(
      (lng === "en-US" ? en : es).copyableId.copy.replace("{{label}}", "Sandbox ID"),
    );
    expect(button.className).toContain("min-h-[44px]");
    expect(button.className).toContain("min-w-[44px]");
  });

  it("AdvancedDetails is closed by default with a 44px translated summary", async () => {
    const { container } = render(
      <I18nextProvider i18n={await i18nFor(lng)}>
        <AdvancedDetails>
          <p>inside</p>
        </AdvancedDetails>
      </I18nextProvider>,
    );
    const details = container.querySelector("details")!;
    expect(details.hasAttribute("open")).toBe(false);
    const summary = details.querySelector("summary")!;
    expect(summary.textContent).toBe((lng === "en-US" ? en : es).advanced.summary);
    expect(summary.className).toContain("min-h-11");
  });
});
