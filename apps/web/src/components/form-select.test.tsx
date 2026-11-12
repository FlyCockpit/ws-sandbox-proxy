// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import common from "@wssp/locales/src/en-US/common.json";
import { SelectItem } from "@wssp/ui/components/select";
import { createInstance } from "i18next";
import { useState } from "react";
import { I18nextProvider } from "react-i18next";

import { afterEach, expect, it, vi } from "vitest";

import { selectOption } from "@/test/select-option";
import { FormSelect } from "./form-select";

const i18n = createInstance();
await i18n.init({
  lng: "en-US",
  resources: { "en-US": { common } },
  interpolation: { escapeValue: false },
});

afterEach(cleanup);

function Example({ disabled = false, onChange = vi.fn(), showBeta = true, optionsSettled = true }) {
  const [value, setValue] = useState("alpha");
  return (
    <I18nextProvider i18n={i18n}>
      <label htmlFor="host">Host</label>
      <FormSelect
        optionsSettled={optionsSettled}
        id="host"
        name="hostId"
        value={value}
        disabled={disabled}
        onValueChange={(next) => {
          setValue(next);
          onChange(next);
        }}
      >
        <SelectItem value="">Choose a host</SelectItem>
        {[
          { id: "alpha", label: "Alpha" },
          ...(showBeta ? [{ id: "beta", label: "Beta" }] : []),
        ].map((host) => (
          <SelectItem key={host.id} value={host.id}>
            {host.label}
          </SelectItem>
        ))}
        <SelectItem value="draining" disabled>
          Draining
        </SelectItem>
      </FormSelect>
    </I18nextProvider>
  );
}

it("shows the selected label before opening, changes by labeled option, and supports clearing", async () => {
  const user = userEvent.setup();
  const changed = vi.fn();
  render(<Example onChange={changed} />);
  const trigger = screen.getByRole("combobox", { name: "Host" });
  expect(trigger.textContent).toContain("Alpha");
  await selectOption(user, trigger, "Beta");
  expect(trigger.textContent).toContain("Beta");
  expect(changed).toHaveBeenLastCalledWith("beta");
  await selectOption(user, trigger, "Choose a host");
  expect(changed).toHaveBeenLastCalledWith("");
  expect(document.querySelector<HTMLInputElement>('input[name="hostId"]')?.value).toBe("");
});

it("preserves disabled choices and keyboard selection", async () => {
  const user = userEvent.setup();
  const changed = vi.fn();
  render(<Example onChange={changed} />);
  const trigger = screen.getByRole("combobox", { name: "Host" });
  await user.click(trigger);
  const draining = await screen.findByRole("option", { name: "Draining" });
  expect(draining.getAttribute("aria-disabled")).toBe("true");
  await user.click(draining);
  expect(changed).not.toHaveBeenCalled();
  await user.keyboard("{Escape}");
  await user.click(trigger);
  const beta = await screen.findByRole("option", { name: "Beta" });
  beta.focus();
  await user.keyboard("{Enter}");
  expect(changed).toHaveBeenLastCalledWith("beta");
});

it("does not open a disabled field", async () => {
  const user = userEvent.setup();
  render(<Example disabled />);
  const trigger = screen.getByRole("combobox", { name: "Host" });
  expect(trigger.hasAttribute("disabled")).toBe(true);
  await user.click(trigger);
  expect(screen.queryByRole("listbox")).toBeNull();
});

it("retains the draft value when refetched options disappear", async () => {
  const user = userEvent.setup();
  const changed = vi.fn();
  const view = render(<Example onChange={changed} />);
  await selectOption(user, screen.getByRole("combobox", { name: "Host" }), "Beta");
  changed.mockClear();
  view.rerender(<Example onChange={changed} showBeta={false} />);
  await user.click(screen.getByRole("combobox", { name: "Host" }));
  expect(screen.queryByRole("option", { name: "Beta" })).toBeNull();
  await user.keyboard("{Escape}");
  expect(changed).not.toHaveBeenCalled();
  expect(screen.getByRole("combobox", { name: "Host" }).textContent).toContain(
    common.optionUnavailable,
  );
  expect(document.querySelector<HTMLInputElement>('input[name="hostId"]')?.value).toBe("beta");
});

it("selects by typing while the trigger is closed", async () => {
  const user = userEvent.setup();
  const changed = vi.fn();
  render(<Example onChange={changed} />);
  const trigger = screen.getByRole("combobox", { name: "Host" });
  trigger.focus();
  await user.keyboard("b");
  expect(changed).toHaveBeenLastCalledWith("beta");
  expect(trigger.textContent).toContain("Beta");
  expect(screen.queryByRole("listbox")).toBeNull();
});

it("waits for settled discovery before declaring a retained value unavailable", async () => {
  const user = userEvent.setup();
  const changed = vi.fn();
  const view = render(<Example onChange={changed} />);
  await selectOption(user, screen.getByRole("combobox", { name: "Host" }), "Beta");
  changed.mockClear();
  // Pending/refetching or a later, unrequested page cannot prove absence.
  view.rerender(<Example onChange={changed} showBeta={false} optionsSettled={false} />);
  const trigger = screen.getByRole("combobox", { name: "Host" });
  expect(trigger.textContent).toContain(common.selectedOption);
  expect(trigger.textContent).not.toContain(common.optionUnavailable);
  expect(document.querySelector<HTMLInputElement>('input[name="hostId"]')?.value).toBe("beta");
  // A later page can resolve the saved label without changing the draft.
  view.rerender(<Example onChange={changed} optionsSettled={false} />);
  expect(trigger.textContent).toContain("Beta");
  view.rerender(<Example onChange={changed} showBeta={false} optionsSettled />);
  expect(trigger.textContent).toContain(common.optionUnavailable);
  expect(changed).not.toHaveBeenCalled();
});

it("shows the placeholder while nothing is chosen, not an unavailable option", () => {
  render(
    <I18nextProvider i18n={i18n}>
      <label htmlFor="definition">Definition</label>
      <FormSelect
        id="definition"
        value=""
        placeholder="Choose a definition"
        onValueChange={vi.fn()}
      >
        <SelectItem value="alpha">Alpha</SelectItem>
      </FormSelect>
    </I18nextProvider>,
  );
  const trigger = screen.getByRole("combobox", { name: "Definition" });
  expect(trigger.textContent).toContain("Choose a definition");
  expect(trigger.textContent).not.toContain(common.optionUnavailable);
});
