/**
 * `pnpm check:layout`: real-browser geometry check of the shell rules
 * against a running dev stack, see docs/design/shell-rules.md § Shell rules
 * It is not part of CI:
 * it needs agent-browser and its Chromium plus the app's server and database.
 * Run it after touching a shell, the header, the 404, page-level chrome or
 * the toast theme.
 *
 *   pnpm check:layout --url http://localhost:3001
 *   pnpm check:layout --url … --accounts <seeded accounts' KEY=value file>
 *   … --no-sandbox                       Ubuntu 23.10+ (AppArmor) Chromium
 *
 * The app has no mock mode, so `--url` (or WSSP_CHECK_URL) points at
 * `pnpm dev` (web + server). With the credentials file (`--accounts`, or
 * WSSP_CHECK_CREDS_FILE; browser-checks.config.ts) it signs in as the admin
 * through the real form, computing the second factor's code, and adds the
 * signed-in pages; without it they are skipped. The admin users page is
 * the one with a sticky sub-nav, and an account without a second factor also
 * shows the 2FA banner inside the scroller.
 *
 * At 390×844, 1280×800, 1440×1600 and 390×300 (where every page scrolls), on
 * the landing page, the 404, the sign-in page and (signed in) the dashboard
 * and admin users pages, it checks that:
 * - the document never scrolls and the shell's `<main>` is the scroller;
 * - the 404 renders inside the public shell (header rule and scroller present);
 * - `<main>` reserves no scrollbar gutter, and every full-width rule (the
 *   headers' `<hr>`, the admin sub-nav's and the 2FA banner's `border-b`)
 *   reaches the viewport's right edge (inside a scrolling `<main>`, its
 *   visible scrollbar) from the start of its column: 0, or the left of the
 *   dashboard content column (`[data-dashboard-content]`), after the sidebar;
 * - a toast (the file-drop notice), stored theme light then dark with the OS
 *   set to the other one, renders in the stored theme and is filled with its
 *   popover colour (not inverted) and its title and badge reach 4.5:1 on it.
 *
 * Classic (non-overlay) scrollbars are what expose a reserved gutter; headless
 * Chromium on Linux draws them, overlay scrollbars on macOS hide the defect.
 */
import { byRole, type CheckRun, pollPage, sessionName, withBrowser } from "./browser-check-lib.ts";
import { credentialsFile, MOCK_SERVER, type Role, signIn } from "./browser-checks.config.ts";

// One session per run: two checks running at once (two checkouts, two agents) must not share a browser.
const SESSION = sessionName("check-layout");
const THEME_KEY = "vite-ui-theme";

/** What the in-page probe reports. Pure data, so `judgeLayout` is testable. */
export interface Probe {
  vw: number;
  docScroll: number;
  header: boolean;
  /** `scrollbar`: the width `<main>` gives up to a scrollbar right now (offsetWidth − clientWidth). */
  main: { scrollable: boolean; scrollbar: number } | null;
  /**
   * `inMain`: the rule is inside the scroller, so a visible scrollbar is its right edge. `start`:
   * where its left edge belongs, 0 or the left of the dashboard content column (after the sidebar).
   */
  rules: { name: string; left: number; right: number; inMain: boolean; start?: number }[];
  toast: {
    dark: boolean;
    fill: string;
    popover: string;
    title: number;
    badge: number;
    button: number | null;
  } | null;
}

export interface Expect {
  /** The theme the stored choice asks for; the OS is set to the opposite one. */
  toast?: "light" | "dark";
}

/** Returns one message per broken rule; empty means the page passes. */
export function judgeLayout(page: string, probe: Probe, expect: Expect): string[] {
  const bad: string[] = [];
  if (probe.docScroll > 0)
    bad.push(`${page}: the document scrolls by ${probe.docScroll}px; only <main> may scroll`);
  if (!probe.main) bad.push(`${page}: no <main> page scroller`);
  if (!probe.header) bad.push(`${page}: no shell header`);
  // A scrollable scroller shows a scrollbar at the viewport's right edge, and a
  // rule inside it meets that scrollbar, as on any scrolling page. A scroller
  // that does not scroll but still gives up width reserves an empty gutter.
  const scrollbar = probe.main?.scrollable ? probe.main.scrollbar : 0;
  if (probe.main && !probe.main.scrollable && probe.main.scrollbar > 0)
    bad.push(
      `${page}: <main> reserves a ${probe.main.scrollbar}px scrollbar gutter on a page that does not scroll`,
    );
  for (const rule of probe.rules) {
    const edge = probe.vw - (rule.inMain ? scrollbar : 0);
    const start = rule.start ?? 0;
    // Both edges, both directions (±1px for rounding): a rule that stops short and one that runs
    // past its column (over the sidebar, under the scrollbar) are both broken.
    if (Math.abs(rule.left - start) > 1 || Math.abs(edge - rule.right) > 1)
      bad.push(
        `${page}: ${rule.name} spans ${rule.left}…${rule.right}px, not ${start}…${edge}px; full-bleed rules reach both edges of their column`,
      );
  }
  if (expect.toast) {
    const toast = probe.toast;
    if (!toast) bad.push(`${page}: no toast appeared`);
    else {
      if (toast.dark !== (expect.toast === "dark"))
        bad.push(
          `${page}: the stored ${expect.toast} theme lost to the OS (the page rendered ${toast.dark ? "dark" : "light"})`,
        );
      if (toast.fill !== toast.popover)
        bad.push(
          `${page}: the toast is filled ${toast.fill}, not the ${toast.dark ? "dark" : "light"} theme's popover ${toast.popover}`,
        );
      for (const [part, ratio] of [
        ["title", toast.title],
        ["badge", toast.badge],
        ["action", toast.button],
      ] as const) {
        if (ratio !== null && ratio < 4.5)
          bad.push(`${page}: toast ${part} contrast ${ratio}:1 is below 4.5:1`);
      }
    }
  }
  return bad;
}

// Runs in the page (agent-browser eval). Self-contained: no closures.
const PROBE = `(async () => {
  const html = document.documentElement;
  const vw = html.clientWidth;
  const main = document.querySelector('[data-scroll-restoration-id="app-main"]');
  // Both headers draw their rule as an <hr> above <main> (the app header is a <div>, not <header>).
  const headerRules = [...document.querySelectorAll("hr")].filter((hr) => !main || !main.contains(hr));
  const out = { vw, docScroll: document.scrollingElement.scrollHeight - window.innerHeight, header: headerRules.length > 0, main: null, rules: [], toast: null };
  if (main) out.main = { scrollable: main.scrollHeight > main.clientHeight, scrollbar: main.offsetWidth - main.clientWidth };
  for (const hr of headerRules) out.rules.push({ name: "header <hr>", left: Math.round(hr.getBoundingClientRect().left), right: Math.round(hr.getBoundingClientRect().right), inMain: false });
  // Bands inside the dashboard content column start where the column starts, after the sidebar.
  const column = document.querySelector("[data-dashboard-content]");
  const startOf = (el) => (column && column.contains(el) ? Math.round(column.getBoundingClientRect().left) : 0);
  for (const nav of document.querySelectorAll("main nav.border-b")) out.rules.push({ name: "sub-nav border-b", left: Math.round(nav.getBoundingClientRect().left), right: Math.round(nav.getBoundingClientRect().right), inMain: true, start: startOf(nav) });
  for (const banner of document.querySelectorAll("main [role=alert].border-b")) out.rules.push({ name: "banner border-b", left: Math.round(banner.getBoundingClientRect().left), right: Math.round(banner.getBoundingClientRect().right), inMain: true, start: startOf(banner) });
  const pill = document.querySelector("[data-sileo-viewport] [data-sileo-pill]");
  if (pill) {
    const ctx = document.createElement("canvas").getContext("2d");
    const rgb = (c) => { ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = "#000"; ctx.fillStyle = c; ctx.fillRect(0, 0, 1, 1); return [...ctx.getImageData(0, 0, 1, 1).data].slice(0, 3); };
    const lin = (v) => { v /= 255; return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
    const lum = (p) => 0.2126 * lin(p[0]) + 0.7152 * lin(p[1]) + 0.0722 * lin(p[2]);
    const ratio = (a, b) => { const x = lum(a), y = lum(b); return Math.round(((Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05)) * 100) / 100; };
    const probe = document.createElement("div");
    probe.style.color = "var(--popover)";
    document.body.append(probe);
    const popover = rgb(getComputedStyle(probe).color);
    probe.remove();
    const fill = rgb(getComputedStyle(pill).fill);
    const color = (sel) => { const el = document.querySelector("[data-sileo-viewport] " + sel); return el ? rgb(getComputedStyle(el).color) : null; };
    const title = color("[data-sileo-title]"), badge = color("[data-sileo-badge]"), button = color("[data-sileo-button]");
    out.toast = { dark: html.classList.contains("dark"), fill: fill.join(","), popover: popover.join(","), title: title ? ratio(title, fill) : 0, badge: badge ? ratio(badge, fill) : 0, button: button ? ratio(button, fill) : null };
  }
  return JSON.stringify(out);
})()`;

/** What wssp marks as still loading: a `Skeleton`, or a busy region (the route skeleton). */
export const LOADING_MARKER = '[data-slot="skeleton"], [aria-busy="true"]';

/**
 * Runs in the page before the probe: waits (8s at most) until the visible
 * `<main>` shows no loading marker and its content stops growing for half a
 * second. On a real stack the sub-nav (a page's `ready`) is there before the
 * rows arrive, so a page probed as soon as `ready` shows can still grow. A
 * skeleton can hold one height for a while before the data comes, so reads
 * while a marker is present never count as still. Returns (JSON-encoded, as
 * every page script) "settled", or why it was not: "loading" (a marker was
 * still there after 8s) or "changing" (the height kept moving).
 * Self-contained: no closures.
 */
export const SETTLED = `(async () => {
  const main = [...document.querySelectorAll("#main-content")].find((el) => el.checkVisibility());
  if (!main) return JSON.stringify("settled");
  let last = -1;
  let still = 0;
  let loading = false;
  for (let i = 0; i < 80 && still < 5; i++) {
    const height = main.scrollHeight;
    loading = !!main.querySelector(${JSON.stringify(LOADING_MARKER)});
    still = !loading && height === last ? still + 1 : 0;
    last = loading ? -1 : height;
    await new Promise((r) => setTimeout(r, 100));
  }
  return JSON.stringify(still >= 5 ? "settled" : loading ? "loading" : "changing");
})()`;

interface Page {
  name: string;
  path: string;
  role: Role;
  expect: Expect;
  /** Wait for this selector before probing. */
  ready: string;
}

const PAGES: Page[] = [
  // wssp has no public footer (docs/design/shell-rules.md rule 1), so nothing measures one.
  { name: "landing", path: "/en-US", role: "anonymous", expect: {}, ready: "main h1" },
  {
    name: "404",
    path: "/en-US/check-layout-missing",
    role: "anonymous",
    expect: {},
    ready: "main h1",
  },
  { name: "sign-in", path: "/en-US/login", role: "anonymous", expect: {}, ready: "main form" },
  {
    name: "dashboard",
    path: "/en-US/dashboard",
    role: "admin",
    expect: {},
    ready: "main [data-dashboard-content] h1",
  },
  {
    name: "admin users",
    path: "/en-US/admin/users",
    role: "admin",
    expect: {},
    ready: "main nav.border-b",
  },
];
const VIEWPORTS = [
  [390, 844],
  [1280, 800],
  [1440, 1600],
  [390, 300],
] as const;

/**
 * An unclaimed file drop shows the neutral "file ignored" toast
 * (FileDropGuard). The guard mounts after hydration (ClientOnly), so each
 * poll drops once more until a toast shows: one short evaluation at a time
 * (`pollPage`), never one long in-page loop a page load could cut off.
 */
const DROP_FILE = `(() => {
  const pill = () => document.querySelector("[data-sileo-viewport] [data-sileo-pill]");
  if (pill()) return "shown";
  const dt = new DataTransfer();
  dt.items.add(new File(["x"], "x.txt"));
  document.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
  return pill() ? "shown" : null;
})()`;

/** Waits for SETTLED; a failure message when the page never settled, else null. */
export async function settle(
  label: string,
  evalJson: (script: string) => Promise<unknown>,
): Promise<string | null> {
  const settled = await evalJson(SETTLED);
  if (settled === "settled") return null;
  return settled === "loading"
    ? `${label}: still showing a loading skeleton after 8s, so it was not measured; check that its data loads`
    : `${label}: the content kept changing for 8s, so it was not measured`;
}

async function measure(run: CheckRun): Promise<string[]> {
  const { base, browser } = run;
  const failures: string[] = [];
  const signedIn = !!credentialsFile(run.args);
  if (!signedIn)
    console.log(
      "check:layout: no --accounts (or WSSP_CHECK_CREDS_FILE), so the signed-in pages are skipped",
    );
  // Page by page, every viewport, grouped by role: each role signs in once.
  for (const page of byRole(PAGES.filter((page) => signedIn || page.role === "anonymous"))) {
    for (const [w, h] of VIEWPORTS) {
      await browser.run(["set", "viewport", String(w), String(h)]);
      await signIn(run, page.role);
      await browser.run(["open", `${base}${page.path}`]);
      await browser.run(["wait", page.ready]);
      const label = `${page.name} ${w}×${h}`;
      const unsettled = await settle(label, (script) => browser.evalJson(script));
      if (unsettled) {
        failures.push(unsettled);
        continue;
      }
      const probe = await browser.evalJson<Probe>(PROBE);
      failures.push(...judgeLayout(label, probe, page.expect));
      console.log(
        `check:layout: ${label} measured (${probe.main?.scrollable ? "long" : "short"} page)`,
      );
    }
  }
  // Toasts, light and dark at one width, each with the OS set to the other.
  await signIn(run, "anonymous");
  await browser.run(["set", "viewport", "1280", "800"]);
  for (const theme of ["light", "dark"] as const) {
    await browser.run(["set", "media", theme === "dark" ? "light" : "dark"]);
    await browser.run(["open", `${base}/en-US`]);
    await browser.run(["eval", `localStorage.setItem('${THEME_KEY}', '${theme}'); true`]);
    await browser.run(["open", `${base}/en-US`]);
    await browser.run(["wait", "main h1"]);
    const shown = await pollPage((args, input) => browser.run(args, input), DROP_FILE);
    if (shown !== "shown") {
      failures.push(`toast ${theme}: no toast appeared for a dropped file (${shown})`);
      continue;
    }
    await browser.run(["wait", "800"]);
    failures.push(
      ...judgeLayout(`toast ${theme}`, await browser.evalJson<Probe>(PROBE), {
        toast: theme,
      }),
    );
    console.log(`check:layout: toast ${theme} measured`);
  }
  return failures;
}

if (import.meta.filename === process.argv[1])
  process.exitCode = await withBrowser("check:layout", SESSION, measure, {
    mockServer: MOCK_SERVER,
  });
