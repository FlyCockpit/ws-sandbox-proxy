// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import en from "@wssp/locales/src/en-US/common.json";
import es from "@wssp/locales/src/es-MX/common.json";
import { SelectItem } from "@wssp/ui/components/select";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, describe, expect, it } from "vitest";
import { FormSelect } from "./form-select";
import { ResourceIdentity } from "./resource-identity";

afterEach(cleanup);

describe.each(["en-US", "es-MX"])("resource identity in %s", (lng) => {
  it.each([
    "<1>fake</1>",
    "<strong>x</strong>",
    "{{slug}}",
    "<p>para</p>",
    "<1>x</1> {{slug}}",
    "x</0><0>y",
    "R&D <east>",
  ])("renders the stored label %s literally", async (label) => {
    const i18n = createInstance();
    await i18n.init({
      lng,
      resources: { "en-US": { common: en }, "es-MX": { common: es } },
      interpolation: { escapeValue: false },
    });
    const slug = "dev-east";
    const { container } = render(
      <I18nextProvider i18n={i18n}>
        <ResourceIdentity label={label} slug={slug} />
      </I18nextProvider>,
    );
    expect(container.textContent).toBe(`${label} (${slug})`);
    expect(container.querySelector("strong, p")).toBeNull();
  });
});

it("shows the slug only when it differs from the label", async () => {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    resources: { "en-US": { common: en } },
    interpolation: { escapeValue: false },
  });
  const { container, rerender } = render(
    <I18nextProvider i18n={i18n}>
      <ResourceIdentity label="sample-host" slug="sample-host" />
    </I18nextProvider>,
  );
  expect(container.textContent).toBe("sample-host");
  rerender(
    <I18nextProvider i18n={i18n}>
      <ResourceIdentity label="Desk" slug="desk-01" />
    </I18nextProvider>,
  );
  expect(container.textContent).toBe("Desk (desk-01)");
});

it.each(["en-US", "es-MX"])(
  "keeps hostile labels literal in the real picker in %s",
  async (lng) => {
    const i18n = createInstance();
    await i18n.init({
      lng,
      resources: { "en-US": { common: en }, "es-MX": { common: es } },
      interpolation: { escapeValue: false },
    });
    const label = "<1>fake</1> <strong>x</strong> {{slug}}";
    const identity = `${label} (dev-east)`;
    const user = userEvent.setup();
    render(
      <I18nextProvider i18n={i18n}>
        <FormSelect aria-label="Host" value="host-a" onValueChange={() => {}}>
          <SelectItem value="host-a">
            <ResourceIdentity label={label} slug="dev-east" />
          </SelectItem>
        </FormSelect>
      </I18nextProvider>,
    );
    const trigger = screen.getByRole("combobox", { name: "Host" });
    expect(trigger.querySelector('[data-slot="select-value"]')?.textContent).toBe(identity);
    await user.click(trigger);
    expect((await screen.findByRole("option", { name: identity })).textContent).toContain(identity);
    expect(document.querySelector("strong")).toBeNull();
  },
);
