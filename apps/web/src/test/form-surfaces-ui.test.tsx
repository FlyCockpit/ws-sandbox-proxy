// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdvancedSection, FormPage } from "@wssp/ui/components/form-page";
import {
  hasKeyValueErrors,
  KeyValueEditor,
  type KeyValueEntry,
  keyValueEditorEnglishLabels,
} from "@wssp/ui/components/key-value-editor";
import { focusFirstInvalidField } from "@wssp/ui/lib/focus-first-invalid";
import { useState } from "react";
import { afterEach, expect, it } from "vitest";

import {
  entriesToRecord,
  isUnreadLine,
  PROTOTYPE_NAMES,
  recordToEntries,
  stateField,
} from "@/lib/key-value-entries";

/**
 * The shared form-surface components (tested in `packages/ui`) as wssp wires
 * them: page state through `stateField`, `PROTOTYPE_NAMES` reserved, entries
 * to the API object through `entriesToRecord`. These are the behaviours the
 * create, register and build pages rely on.
 */
afterEach(cleanup);

const RESERVED = ["HOME", ...PROTOTYPE_NAMES];
const latest: { entries: KeyValueEntry[] } = { entries: [] };

function Editor({ initial = [] as KeyValueEntry[] }) {
  const [entries, setEntries] = useState(initial);
  latest.entries = entries;
  return (
    <form aria-label="Env form">
      <KeyValueEditor
        field={stateField("envs", entries, [], setEntries)}
        label="Environment"
        labels={keyValueEditorEnglishLabels}
        reservedKeys={RESERVED}
        secret
      />
    </form>
  );
}

const blocked = () => hasKeyValueErrors(latest.entries, { reservedKeys: RESERVED });

it("refuses __proto__ inline and keeps it an own key, so the server refuses it too", async () => {
  const user = userEvent.setup();
  render(<Editor />);
  await user.type(screen.getByRole("textbox", { name: "Key, row 1" }), "__proto__");
  expect(screen.getByText("__proto__ is set by the platform")).toBeTruthy();
  expect(blocked()).toBe(true);
  const record = entriesToRecord([{ key: "__proto__", value: "x" }]);
  expect(Object.hasOwn(record, "__proto__")).toBe(true);
  expect(JSON.parse(JSON.stringify(record))).toEqual(JSON.parse('{"__proto__":"x"}'));
});

it("blocks .env text with unreadable lines, marks it invalid and focuses it", async () => {
  const user = userEvent.setup();
  render(<Editor />);
  await user.click(screen.getByRole("button", { name: ".env text" }));
  const text = screen.getByRole("textbox", { name: "Environment" });
  fireEvent.change(text, { target: { value: "A=1\nOOPS\nB=2" } });
  expect(text.getAttribute("aria-invalid")).toBe("true");
  expect(screen.getByText("Line 2: expected KEY=value")).toBeTruthy();
  // The bad line is kept (never sent) and blocks submit.
  expect(latest.entries.some(isUnreadLine)).toBe(true);
  expect(blocked()).toBe(true);
  expect(entriesToRecord(latest.entries.filter((entry) => !isUnreadLine(entry)))).toEqual({
    A: "1",
    B: "2",
  });
  focusFirstInvalidField(screen.getByRole("form"), (run) => run());
  expect(document.activeElement).toBe(text);
  // Fixing the line unblocks.
  fireEvent.change(text, { target: { value: "A=1\nOOPS=3\nB=2" } });
  expect(blocked()).toBe(false);
});

it("a pasted .env with a bad line keeps every line, the bad one flagged, instead of a partial set", () => {
  render(<Editor />);
  fireEvent.paste(screen.getByRole("textbox", { name: "Key, row 1" }), {
    clipboardData: { getData: () => "A=1\nOOPS\nB=2" },
  });
  expect(latest.entries).toEqual([
    { key: "A", value: "1" },
    { key: "", value: "OOPS", unparsed: true },
    { key: "B", value: "2" },
  ]);
  expect(blocked()).toBe(true);
});

it("keeps a multi-line value's line breaks when it is edited in its row", async () => {
  const user = userEvent.setup();
  render(<Editor initial={recordToEntries({ CERT: "first\nsecond" })} />);
  // Masked (secret) until revealed: a read-only mask, so nothing is lost.
  await user.click(screen.getByRole("button", { name: "Show value of CERT" }));
  const value = screen.getByRole("textbox", { name: "Value for CERT" });
  expect(value.tagName).toBe("TEXTAREA");
  await user.type(value, "!");
  expect(entriesToRecord(latest.entries)).toEqual({ CERT: "first\nsecond!" });
});

it("focuses the first invalid field, opening its Advanced section", () => {
  render(
    <FormPage title="Create" actions={<button type="submit">Create</button>} aria-label="Create">
      <input aria-label="ok" />
      <AdvancedSection title="Advanced" summary="2 vCPU">
        <input aria-label="bad" aria-invalid="true" />
      </AdvancedSection>
    </FormPage>,
  );
  const form = screen.getByRole("form", { name: "Create" });
  focusFirstInvalidField(form, (run) => run());
  expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "bad" }));
  expect((form.querySelector("details") as HTMLDetailsElement).open).toBe(true);
});

/** Env rows whose values a refused create cleared: the page says so through the field. */
function Cleared() {
  const [entries, setEntries] = useState<KeyValueEntry[]>([{ key: "TOKEN", value: "" }]);
  return (
    <KeyValueEditor
      field={stateField("envs", entries, ["Enter the values for TOKEN again."], setEntries)}
      label="Environment"
      labels={keyValueEditorEnglishLabels}
    />
  );
}

it("shows a field error from page state under the editor and marks a row for focus", () => {
  render(<Cleared />);
  expect(screen.getByText("Enter the values for TOKEN again.")).toBeTruthy();
  expect(screen.getByRole("textbox", { name: "Key, row 1" }).getAttribute("aria-invalid")).toBe(
    "true",
  );
});
