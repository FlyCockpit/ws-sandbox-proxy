/** Fixtures for the pure judge in scripts/check-layout.ts: node --test scripts/check-layout.test.ts */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseEvalOutput } from "./browser-check-lib.ts";
import { judgeLayout, LOADING_MARKER, type Probe, SETTLED, settle } from "./check-layout.ts";

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

  it("reports <main> scrolling past its layout (a min-h-full box under the admin nav)", () => {
    assert.deepEqual(judgeLayout("admin users", { ...good, overflow: 1 }, {}), []);
    assert.match(
      judgeLayout("admin users", { ...good, overflow: 60 }, {}).join("\n"),
      /<main> scrolls 60px past its layout/,
    );
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

describe("parseEvalOutput", () => {
  it("parses a JSON-encoded page result once more and keeps other values", () => {
    assert.deepEqual(parseEvalOutput(JSON.stringify(JSON.stringify({ a: 1 }))), { a: 1 });
    assert.equal(parseEvalOutput(JSON.stringify(JSON.stringify("settled"))), "settled");
    assert.equal(parseEvalOutput("true"), true);
  });

  it("rejects a bare string result, so page scripts must JSON-encode strings", () => {
    assert.throws(() => parseEvalOutput(JSON.stringify("settled")), SyntaxError);
  });
});

describe("SETTLED", () => {
  /**
   * Runs the page script against a fake visible <main> whose height follows
   * `heights`, then stays at the last. `skeleton[i]` says whether read i still
   * finds a loading marker (the last value holds after the list ends). The
   * result goes through `settle` and the same adapter as a real run
   * (agent-browser prints the value as JSON; `parseEvalOutput` reads it).
   */
  const run = async (heights: number[] | null, skeleton: boolean[] = [false]) => {
    let reads = 0;
    const selectors: string[] = [];
    const main = {
      checkVisibility: () => true,
      get scrollHeight() {
        reads++;
        return heights ? (heights[Math.min(reads - 1, heights.length - 1)] ?? 0) : 0;
      },
      querySelector: (selector: string) => {
        selectors.push(selector);
        return skeleton[Math.min(reads - 1, skeleton.length - 1)] ? {} : null;
      },
    };
    // A suspended route can leave a hidden <main> before the visible one.
    const hidden = { checkVisibility: () => false, scrollHeight: 0, querySelector: () => ({}) };
    // The page script reads the globals `document` and `setTimeout`; parameters
    // stand in for them, and the timer fires at once, so the 8s limit costs no real time.
    const page = new Function("document", "setTimeout", `return ${SETTLED};`) as (
      doc: unknown,
      timer: (done: () => void) => void,
    ) => Promise<unknown>;
    const failure = await settle("admin users 1280×800", async () =>
      parseEvalOutput(
        JSON.stringify(
          await page({ querySelectorAll: () => (heights ? [hidden, main] : []) }, (done) => done()),
        ),
      ),
    );
    return { failure, reads, selectors };
  };

  it("waits until the content stops growing (rows arrive after the sub-nav)", async () => {
    const { failure, reads } = await run([681, 681, 986, 1200]);
    assert.equal(failure, null);
    // Three changes, then five unchanged reads in a row.
    assert.equal(reads, 9);
  });

  it("does not settle on a skeleton that holds one height before the data arrives", async () => {
    // A skeleton at 681px for 10 reads (stable for well over five), then the rows.
    const heights = [...Array(10).fill(681), 1200];
    const skeleton = [...Array(10).fill(true), false];
    const { failure, reads, selectors } = await run(heights, skeleton);
    assert.equal(failure, null);
    // Ten skeleton reads count for nothing; then the loaded height, then five unchanged reads.
    assert.equal(reads, 16);
    assert.equal(selectors[0], LOADING_MARKER);
  });

  it("looks for wssp's skeleton and busy markers", () => {
    assert.match(LOADING_MARKER, /\[data-slot="skeleton"\]/);
    assert.match(LOADING_MARKER, /\[aria-busy="true"\]/);
  });

  it("reports a page still loading after 8s, distinct from one that keeps changing", async () => {
    const loading = await run([681], [true]);
    assert.match(loading.failure ?? "", /admin users 1280×800: still showing a loading skeleton/);
    assert.equal(loading.reads, 80);
    const growing = Array.from({ length: 100 }, (_, i) => 500 + i * 10);
    const changing = await run(growing);
    assert.match(changing.failure ?? "", /kept changing for 8s/);
    assert.equal(changing.reads, 80);
  });

  it("does not wait on a page without the app's scroller", async () => {
    const { failure, reads } = await run(null);
    assert.deepEqual({ failure, reads }, { failure: null, reads: 0 });
  });
});
