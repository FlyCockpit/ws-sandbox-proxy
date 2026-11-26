// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdvancedSection, FormPage, focusFirstInvalid } from "@wssp/ui/components/form-page";
import {
  formatDotenv,
  KeyValueEditor,
  type KeyValueEditorLabels,
  type KeyValueRow,
  keyValueProblems,
  newKeyValueRow,
  parseDotenv,
  rowsToRecord,
} from "@wssp/ui/components/key-value-editor";
import { logStops, positionOf, RangeField, valueAt } from "@wssp/ui/components/range-field";
import { useState } from "react";
import { afterEach, expect, it, vi } from "vitest";

// Integration coverage for the form-surface wrappers lives in web, which owns the DOM tools.
afterEach(cleanup);

const labels: KeyValueEditorLabels = {
  key: "Key",
  value: "Value",
  add: "Add variable",
  remove: (key) => `Remove ${key}`,
  rowsMode: "Rows",
  textMode: ".env",
  textHint: "One KEY=value per line",
  show: "Show",
  hide: "Hide",
  problem: (problem, key) => `${problem}:${key}`,
  lineProblem: (line) => `Line ${line}: expected KEY=value`,
  empty: "No variables",
};

it("parses a pasted .env file with comments, export, quotes and trailing comments", () => {
  const { rows, badLines } = parseDotenv(
    [
      "# comment",
      "export A=1",
      'B="two words # not a comment"',
      "C='single'",
      "D=plain # trailing",
      "",
      "not a pair",
      'E="line\\nbreak \\"q\\""',
    ].join("\n"),
  );
  expect(rowsToRecord(rows)).toEqual({
    A: "1",
    B: "two words # not a comment",
    C: "single",
    D: "plain",
    E: 'line\nbreak "q"',
  });
  expect(badLines).toEqual([7]);
});

it("round-trips values through formatDotenv", () => {
  const rows = [newKeyValueRow("A", "x y"), newKeyValueRow("B", 'q"'), newKeyValueRow("C", "z")];
  expect(rowsToRecord(parseDotenv(formatDotenv(rows)).rows)).toEqual(rowsToRecord(rows));
});

it("flags empty, invalid, reserved and duplicate keys per row", () => {
  const rows = [
    newKeyValueRow("", "orphan"),
    newKeyValueRow("1BAD", "v"),
    newKeyValueRow("WSSP_X", "v"),
    newKeyValueRow("OK", "a"),
    newKeyValueRow("OK", "b"),
  ];
  const problems = keyValueProblems(rows, {
    keyPattern: /^[A-Za-z_][A-Za-z0-9_]*$/,
    reservedKey: (key) => key.startsWith("WSSP_"),
  });
  expect(rows.map((row) => problems.get(row.id) ?? null)).toEqual([
    "emptyKey",
    "invalidKey",
    "reservedKey",
    null,
    "duplicateKey",
  ]);
});

function Editor({
  onRows,
  onValidity,
}: {
  onRows?: (rows: KeyValueRow[]) => void;
  onValidity?: (valid: boolean) => void;
}) {
  const [rows, setRows] = useState<KeyValueRow[]>([]);
  return (
    <KeyValueEditor
      label="Environment"
      rows={rows}
      labels={labels}
      onValidityChange={onValidity}
      masked
      problems={keyValueProblems(rows, { keyPattern: /^[A-Z_]+$/ })}
      onChange={(next) => {
        setRows(next);
        onRows?.(next);
      }}
    />
  );
}

it("adds rows, shows inline problems and switches to .env text mode", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  render(<Editor onRows={onRows} />);
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  await user.type(screen.getByRole("textbox", { name: "Key 1" }), "bad-key");
  expect(screen.getByText("invalidKey:bad-key")).toBeTruthy();
  expect(screen.getByRole("textbox", { name: "Key 1" }).getAttribute("aria-invalid")).toBe("true");
  await user.click(screen.getByRole("button", { name: ".env" }));
  const text = screen.getByRole("textbox", { name: "Environment" });
  expect((text as HTMLTextAreaElement).value).toBe("bad-key=");
  fireEvent.change(text, { target: { value: "FOO=bar\nBAZ=qux" } });
  expect(rowsToRecord(onRows.mock.lastCall?.[0] ?? [])).toEqual({ FOO: "bar", BAZ: "qux" });
  await user.click(screen.getByRole("button", { name: "Rows" }));
  expect((screen.getByRole("textbox", { name: "Key 2" }) as HTMLInputElement).value).toBe("BAZ");
});

it("reports .env text with unreadable lines as invalid until they are fixed or dropped", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  const onValidity = vi.fn();
  render(<Editor onRows={onRows} onValidity={onValidity} />);
  await user.click(screen.getByRole("button", { name: ".env" }));
  const text = screen.getByRole("textbox", { name: "Environment" });
  fireEvent.change(text, { target: { value: "FOO=bar\nREQUIRED_SECRET" } });
  // The unreadable line never reaches the rows, so the caller must refuse.
  expect(rowsToRecord(onRows.mock.lastCall?.[0] ?? [])).toEqual({ FOO: "bar" });
  expect(onValidity.mock.calls).toEqual([[false]]);
  expect(screen.getByText("Line 2: expected KEY=value")).toBeTruthy();
  fireEvent.change(text, { target: { value: "FOO=bar\nREQUIRED_SECRET=x" } });
  expect(onValidity.mock.calls).toEqual([[false], [true]]);
  fireEvent.change(text, { target: { value: "FOO=bar\nOOPS" } });
  // Back to rows: the dropped line is gone from view, and what is shown is what is sent.
  await user.click(screen.getByRole("button", { name: "Rows" }));
  expect(onValidity.mock.calls).toEqual([[false], [true], [false], [true]]);
});

it("expands a pasted .env file into rows", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  render(<Editor onRows={onRows} />);
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  const key = screen.getByRole("textbox", { name: "Key 1" });
  fireEvent.paste(key, { clipboardData: { getData: () => "A=1\nB=2" } });
  expect(rowsToRecord(onRows.mock.lastCall?.[0] ?? [])).toEqual({ A: "1", B: "2" });
});

it("keeps a multi-line value's newlines when it is edited in rows", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  render(<Editor onRows={onRows} />);
  await user.click(screen.getByRole("button", { name: ".env" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Environment" }), {
    target: { value: 'NOTE="first\\nsecond"' },
  });
  await user.click(screen.getByRole("button", { name: "Rows" }));
  await user.click(screen.getByRole("button", { name: "Show" }));
  const value = screen.getByRole("textbox", { name: "Value 1" });
  expect(value.tagName).toBe("TEXTAREA");
  await user.type(value, "!");
  expect(rowsToRecord(onRows.mock.lastCall?.[0] ?? [])).toEqual({ NOTE: "first\nsecond!" });
});

it("a hidden multi-line value is read-only until revealed, so its newlines survive", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  render(<Editor onRows={onRows} />);
  await user.click(screen.getByRole("button", { name: ".env" }));
  fireEvent.change(screen.getByRole("textbox", { name: "Environment" }), {
    target: { value: 'NOTE="a\\nb"' },
  });
  await user.click(screen.getByRole("button", { name: "Rows" }));
  const hidden = screen.getByLabelText("Value 1") as HTMLInputElement;
  expect(hidden.tagName).toBe("INPUT");
  expect(hidden.readOnly).toBe(true);
});

it("a pasted .env with unreadable lines opens in text mode instead of dropping them", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  const onValidity = vi.fn();
  render(<Editor onRows={onRows} onValidity={onValidity} />);
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  await user.type(screen.getByRole("textbox", { name: "Key 1" }), "KEEP");
  fireEvent.paste(screen.getByRole("textbox", { name: "Key 1" }), {
    clipboardData: { getData: () => "A=1\nOOPS\nB=2" },
  });
  const text = screen.getByRole("textbox", { name: "Environment" }) as HTMLTextAreaElement;
  expect(text.value).toBe("KEEP=\nA=1\nOOPS\nB=2");
  expect(screen.getByText("Line 3: expected KEY=value")).toBeTruthy();
  expect(onValidity.mock.calls).toEqual([[false]]);
  expect(rowsToRecord(onRows.mock.lastCall?.[0] ?? [])).toEqual({ KEEP: "", A: "1", B: "2" });
});

it("keeps a __proto__ key as an own key and reports it as reserved", () => {
  const rows = [newKeyValueRow("__proto__", "x")];
  const record = rowsToRecord(rows);
  expect(Object.hasOwn(record, "__proto__")).toBe(true);
  expect(JSON.parse(JSON.stringify(record))).toEqual(JSON.parse('{"__proto__":"x"}'));
  expect(keyValueProblems(rows).get(rows[0]!.id)).toBe("reservedKey");
  expect(keyValueProblems(rows, { keyPattern: /^[A-Za-z_][A-Za-z0-9_]*$/ }).get(rows[0]!.id)).toBe(
    "reservedKey",
  );
});

it("refuses .env text while a key can't be written as KEY=value, so it isn't lost", async () => {
  const user = userEvent.setup();
  const onRows = vi.fn();
  render(<Editor onRows={onRows} />);
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  await user.type(screen.getByRole("textbox", { name: "Key 1" }), "#team");
  await user.click(screen.getByRole("button", { name: ".env" }));
  expect(screen.queryByRole("textbox", { name: "Environment" })).toBeNull();
  expect(
    screen.getByText("Some keys can't be written as KEY=value lines; edit them as rows."),
  ).toBeTruthy();
  expect((screen.getByRole("textbox", { name: "Key 1" }) as HTMLInputElement).value).toBe("#team");
  for (const key of ["a=b", "two words", 'q"', "x'y"]) {
    const rows = [newKeyValueRow(key, "v")];
    const { unmount } = render(
      <KeyValueEditor label="Other" rows={rows} labels={labels} onChange={() => {}} />,
    );
    fireEvent.click(screen.getAllByRole("button", { name: ".env" }).at(-1) as HTMLElement);
    expect(screen.queryByRole("textbox", { name: "Other" })).toBeNull();
    unmount();
  }
  // Fixing the key clears the message and lets text mode open.
  await user.clear(screen.getByRole("textbox", { name: "Key 1" }));
  await user.type(screen.getByRole("textbox", { name: "Key 1" }), "TEAM");
  expect(screen.queryByText(/Some keys can't be written/)).toBeNull();
  await user.click(screen.getByRole("button", { name: ".env" }));
  expect((screen.getByRole("textbox", { name: "Environment" }) as HTMLTextAreaElement).value).toBe(
    "TEAM=",
  );
});

it("marks the .env text invalid for row problems and editor errors, described by them", () => {
  const props = {
    label: "Environment",
    labels,
    onChange: () => {},
  };
  const rows = [newKeyValueRow("A", "1"), newKeyValueRow("A", "2")];
  const { rerender } = render(
    <form>
      <KeyValueEditor {...props} id="env" rows={rows} problems={keyValueProblems(rows)} />
    </form>,
  );
  fireEvent.click(screen.getByRole("button", { name: ".env" }));
  const text = screen.getByRole("textbox", { name: "Environment" });
  expect(text.getAttribute("aria-invalid")).toBe("true");
  expect(text.getAttribute("aria-describedby")).toBe("env-problems");
  expect(document.getElementById("env-problems")?.textContent).toContain("duplicateKey:A");
  expect(focusFirstInvalid(text.closest("form"))).toBe(true);
  expect(document.activeElement).toBe(text);
  const fine = [newKeyValueRow("A", "1")];
  rerender(
    <form>
      <KeyValueEditor {...props} id="env" rows={fine} problems={keyValueProblems(fine)} />
    </form>,
  );
  expect(text.getAttribute("aria-invalid")).toBeNull();
  rerender(
    <form>
      <KeyValueEditor {...props} id="env" rows={fine} error="Refused" />
    </form>,
  );
  expect(text.getAttribute("aria-invalid")).toBe("true");
  expect(text.getAttribute("aria-describedby")).toBe("env-error");
});

it("maps values to log stops and clamps to the capacity limit", () => {
  expect(logStops(10, 2048)).toEqual([10, 16, 32, 64, 128, 256, 512, 1024, 2048]);
  expect(logStops(1, 32)).toEqual([1, 2, 4, 8, 16, 32]);
  const stops = [1, 2, 4, 8, 16, 32];
  expect(positionOf(stops, 4)).toBe(2);
  expect(positionOf(stops, 6)).toBeCloseTo(2 + Math.log(1.5) / Math.log(2));
  expect(valueAt(stops, 5, 32)).toBe(32);
  expect(valueAt(stops, 5, 6)).toBe(4);
  expect(valueAt(stops, 0, 0.5)).toBe(0.5);
});

function Range({ capacityMax }: { capacityMax?: number }) {
  const [value, setValue] = useState<number | null>(null);
  return (
    <>
      <RangeField
        label="Memory"
        unit="GiB"
        min={512}
        max={65536}
        step={256}
        stops={[512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]}
        defaultValue={2048}
        defaultLabel="Default (from template)"
        resetLabel="Reset to default"
        capacityMax={capacityMax}
        capacityMessage="This host has 6 GiB free"
        toDisplay={(mib) => mib / 1024}
        fromDisplay={(gib) => gib * 1024}
        value={value}
        onChange={setValue}
      />
      <output data-testid="value">{value === null ? "inherit" : value}</output>
    </>
  );
}

it("types any value (rounded to the step), resets to the default and explains the capacity cap", async () => {
  const user = userEvent.setup();
  render(<Range capacityMax={6144} />);
  const input = screen.getByRole("spinbutton", { name: "Memory" });
  expect((input as HTMLInputElement).value).toBe("2");
  expect(screen.getByText("This host has 6 GiB free")).toBeTruthy();
  await user.clear(input);
  await user.type(input, "3.1");
  await user.tab();
  expect(screen.getByTestId("value").textContent).toBe("3072");
  await user.click(screen.getByRole("button", { name: "Reset to default" }));
  expect(screen.getByTestId("value").textContent).toBe("inherit");
  await user.clear(input);
  await user.type(input, "8");
  await user.tab();
  expect(screen.getByRole("alert").textContent).toBe("This host has 6 GiB free");
  expect(input.getAttribute("aria-invalid")).toBe("true");
});

it("moves the slider between stops with the keyboard and never past capacity", async () => {
  const user = userEvent.setup();
  render(<Range capacityMax={6144} />);
  const slider = screen.getByRole("slider", { name: "Memory" });
  slider.focus();
  await user.keyboard("{ArrowRight}");
  expect(screen.getByTestId("value").textContent).toBe("4096");
  await user.keyboard("{ArrowRight}");
  expect(screen.getByTestId("value").textContent).toBe("4096");
});

it("focuses the first invalid field and opens its Advanced section", () => {
  render(
    <FormPage title="Create" actions={<button type="submit">Create</button>}>
      <input aria-label="ok" />
      <AdvancedSection title="Advanced" summary="2 vCPU">
        <input aria-label="bad" aria-invalid="true" />
      </AdvancedSection>
    </FormPage>,
  );
  const form = screen.getByRole("form", { name: "Create" });
  expect(focusFirstInvalid(form)).toBe(true);
  expect(document.activeElement).toBe(screen.getByRole("textbox", { name: "bad" }));
  expect((form.querySelector("details") as HTMLDetailsElement).open).toBe(true);
  expect(screen.getByRole("heading", { level: 1, name: "Create" })).toBeTruthy();
});

it("on phones pins only back + title and keeps the action bar compact", () => {
  render(
    <FormPage
      title="Build a template"
      description="Runs the steps in a build VM."
      back={<a href="#back">Templates</a>}
      actions={
        <>
          <button type="submit">Start build</button>
          <button type="button">Cancel</button>
        </>
      }
      status={<span>Reserves up to 30 build minutes. Choose where to build.</span>}
    >
      <input aria-label="name" />
    </FormPage>,
  );
  const header = document.querySelector<HTMLElement>('[data-slot="form-page-header"]')!;
  const bar = header.querySelector<HTMLElement>('[data-slot="form-page-header-bar"]')!;
  const description = header.querySelector<HTMLElement>('[data-slot="form-page-description"]')!;
  // Below sm the header box dissolves: the bar (back + title) is the sticky
  // element and the description is not inside it, so it scrolls away.
  expect(header.className.split(" ")).toContain("contents");
  expect(header.className).toContain("sm:sticky");
  expect(bar.className.split(" ")).toContain("sticky");
  expect(bar.contains(screen.getByRole("heading", { level: 1 }))).toBe(true);
  expect(bar.contains(screen.getByRole("link", { name: "Templates" }))).toBe(true);
  expect(bar.contains(description)).toBe(false);
  // The status is one truncated line above the buttons on phones; buttons stay in one row.
  const status = document.querySelector<HTMLElement>('[data-slot="form-page-status"]')!;
  expect(status.className).toContain("max-sm:truncate");
  expect(status.className).toContain("max-sm:order-first");
  const buttons = screen.getByRole("button", { name: "Start build" }).parentElement!;
  expect(buttons.className.split(" ")).toContain("flex-nowrap");
});

it("stacks a key above its value on phones so long names are not cut", async () => {
  const user = userEvent.setup();
  render(<Editor />);
  await user.click(screen.getByRole("button", { name: "Add variable" }));
  const key = screen.getByRole("textbox", { name: "Key 1" });
  const value = screen.getByLabelText("Value 1");
  const row = key.parentElement!;
  // Two columns below sm (key/value stacked beside remove), three from sm.
  expect(row.className).toContain("grid-cols-[minmax(0,1fr)_auto]");
  expect(row.className).toContain("sm:grid-cols-[minmax(0,2fr)_minmax(0,3fr)_auto]");
  expect(key.className).toContain("row-start-1");
  expect(value.parentElement?.className).toContain("row-start-2");
});
