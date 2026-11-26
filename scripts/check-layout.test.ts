/** Fixtures for the pure judge in scripts/check-layout.ts: node --test scripts/check-layout.test.ts */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { judgeLayout, type Probe } from "./check-layout.ts";

const good: Probe = {
  vw: 1280,
  docScroll: 0,
  header: true,
  main: { scrollable: false, scrollbar: 0 },
  rules: [{ name: "header <hr>", left: 0, right: 1280, inMain: false }],
  toast: null,
};

const toast = {
  dark: true,
  fill: "22,27,29",
  popover: "22,27,29",
  title: 16.7,
  badge: 8.5,
  button: 16.7,
};

describe("judgeLayout", () => {
  it("passes a page in its shell with full-width rules", () => {
    assert.deepEqual(judgeLayout("landing", good, {}), []);
  });

  it("reports a page outside any shell (the old bare 404)", () => {
    assert.match(
      judgeLayout("404", { ...good, header: false, main: null, rules: [] }, {}).join("\n"),
      /no <main[\s\S]*no shell header/,
    );
  });

  it("reports a document scroll, a reserved gutter and rules stopped short by it", () => {
    const bad = judgeLayout(
      "admin",
      {
        ...good,
        docScroll: 12,
        main: { scrollable: false, scrollbar: 15 },
        rules: [{ name: "sub-nav border-b", left: 0, right: 1265, inMain: true }],
      },
      {},
    );
    assert.equal(bad.length, 3, bad.join("\n"));
    assert.match(bad.join("\n"), /document scrolls by 12px/);
    assert.match(bad.join("\n"), /reserves a 15px scrollbar gutter on a page that does not scroll/);
    assert.match(bad.join("\n"), /sub-nav border-b spans 0…1265px, not 0…1280px/);
  });

  it("lets a rule inside a scrolling scroller meet the visible scrollbar, never one outside it", () => {
    const scrolling = { scrollable: true, scrollbar: 15 };
    assert.deepEqual(
      judgeLayout(
        "admin long",
        {
          ...good,
          main: scrolling,
          rules: [
            { name: "header <hr>", left: 0, right: 1280, inMain: false },
            { name: "sub-nav border-b", left: 0, right: 1265, inMain: true },
          ],
        },
        {},
      ),
      [],
    );
    assert.equal(
      judgeLayout(
        "admin long",
        {
          ...good,
          main: scrolling,
          rules: [{ name: "header <hr>", left: 0, right: 1265, inMain: false }],
        },
        {},
      ).length,
      1,
    );
  });

  it("holds a band inside the dashboard content column to both edges of that column", () => {
    const band = { name: "banner border-b", right: 1280, inMain: true, start: 240 };
    assert.deepEqual(
      judgeLayout("dashboard", { ...good, rules: [{ ...band, left: 240 }] }, {}),
      [],
    );
    assert.match(
      judgeLayout("dashboard", { ...good, rules: [{ ...band, left: 256 }] }, {}).join(""),
      /banner border-b spans 256…1280px, not 240…1280px/,
    );
    assert.equal(
      judgeLayout("dashboard", { ...good, rules: [{ ...band, left: 240, right: 1265 }] }, {})
        .length,
      1,
    );
    // Overshooting either edge fails too: over the sidebar, or past the viewport.
    assert.match(
      judgeLayout("dashboard", { ...good, rules: [{ ...band, left: 0 }] }, {}).join(""),
      /banner border-b spans 0…1280px, not 240…1280px/,
    );
    assert.equal(
      judgeLayout("dashboard", { ...good, rules: [{ ...band, left: 240, right: 1300 }] }, {})
        .length,
      1,
    );
    // Rounding: 1px either way passes.
    assert.deepEqual(
      judgeLayout("dashboard", { ...good, rules: [{ ...band, left: 241, right: 1279 }] }, {}),
      [],
    );
  });

  it("checks the toast fill against the theme's popover, its contrast and the stored theme", () => {
    assert.deepEqual(judgeLayout("toast dark", { ...good, toast }, { toast: "dark" }), []);
    const inverted = judgeLayout(
      "toast dark",
      { ...good, toast: { ...toast, fill: "242,242,242", title: 3.4, badge: 3.4, button: 3.4 } },
      { toast: "dark" },
    );
    assert.equal(inverted.length, 4, inverted.join("\n"));
    assert.match(inverted[0] ?? "", /filled 242,242,242, not the dark theme's popover 22,27,29/);
    assert.match(
      judgeLayout("toast light", good, { toast: "light" }).join(""),
      /no toast appeared/,
    );
    assert.match(
      judgeLayout("toast light", { ...good, toast }, { toast: "light" }).join(""),
      /stored light theme lost to the OS/,
    );
  });
});
