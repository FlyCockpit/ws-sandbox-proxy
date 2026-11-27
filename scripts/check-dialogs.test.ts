import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { byRole, type CheckRun, formSignIn, pollPage, sessionName } from "./browser-check-lib.ts";
import { DIALOGS, SHELL_PAGES, seededAccount, signIn } from "./browser-checks.config.ts";
import { type DialogProbe, judgeDialog, PROBE, stepScript } from "./check-dialogs.ts";

const fits: DialogProbe = {
  vw: 1280,
  vh: 800,
  popup: { top: 200, bottom: 600, left: 440, right: 840 },
  scrollers: [],
  covered: [],
};

describe("judgeDialog", () => {
  it("passes a dialog that shows all of itself inside the viewport", () => {
    assert.deepEqual(judgeDialog("Create project 1280×800", fits), []);
  });

  it("fails a dialog whose popup or a box inside it scrolls", () => {
    const bad = judgeDialog("Create sandbox 390×844", {
      ...fits,
      scrollers: [{ name: "[data-slot=dialog-content]", scrollHeight: 1900, clientHeight: 780 }],
    });
    assert.equal(bad.length, 1);
    assert.match(
      bad[0] ?? "",
      /\[data-slot=dialog-content\] scrolls \(1900px of content in 780px\)/,
    );
    assert.match(bad[0] ?? "", /page or a wide side sheet/);
  });

  it("fails a dialog whose action bar or header sits on top of its fields", () => {
    const bad = judgeDialog("Create project 1280×800", {
      ...fits,
      covered: [{ bar: "action bar", what: "p", overlap: 9 }],
    });
    assert.deepEqual(bad, ["Create project 1280×800: the action bar covers 9px of p"]);
  });

  it("fails a dialog that reaches outside the viewport", () => {
    for (const popup of [
      { top: -4, bottom: 600, left: 440, right: 840 },
      { top: 200, bottom: 801, left: 440, right: 840 },
      { top: 200, bottom: 600, left: -1, right: 840 },
      { top: 200, bottom: 600, left: 440, right: 1281 },
    ])
      assert.match(judgeDialog("x", { ...fits, popup })[0] ?? "", /outside the 1280×800 viewport/);
  });

  it("fails when no dialog opened", () => {
    assert.deepEqual(judgeDialog("x", { ...fits, popup: null }), ["x: no dialog opened"]);
  });

  it("ignores collapsed descendants inside nested closed <details> while keeping visible summaries checked", () => {
    const popupRect = { top: 100, bottom: 500, left: 400, right: 800, width: 400, height: 400 };
    const footerRect = { top: 440, bottom: 500, left: 400, right: 800, width: 400, height: 60 };
    const makeNode = (opts: {
      tagName: string;
      slot?: string | null;
      rect: {
        top: number;
        bottom: number;
        left: number;
        right: number;
        width: number;
        height: number;
      };
      open?: boolean;
      summaryNode?: unknown;
      parentDetails?: unknown;
    }) => {
      const node: Record<string, unknown> = {
        tagName: opts.tagName,
        children: [],
        getAttribute: (name: string) => (name === "data-slot" ? (opts.slot ?? null) : null),
        matches: () => false,
        getBoundingClientRect: () => opts.rect,
        contains: (target: unknown) => target === node,
        querySelector: (sel: string) =>
          sel === ":scope > summary" ? (opts.summaryNode ?? null) : null,
        closest: (sel: string): unknown => {
          if (sel === "details:not([open])") {
            if (opts.tagName === "DETAILS" && !opts.open) return node;
            return opts.parentDetails
              ? (opts.parentDetails as { closest: (s: string) => unknown }).closest(sel)
              : null;
          }
          return null;
        },
        parentElement: opts.parentDetails
          ? {
              closest: (sel: string) =>
                (opts.parentDetails as { closest: (s: string) => unknown }).closest(sel),
            }
          : null,
      };
      return node;
    };

    const footer = makeNode({ tagName: "DIV", slot: "dialog-footer", rect: footerRect });
    const outerSummary = makeNode({
      tagName: "SUMMARY",
      rect: { top: 450, bottom: 470, left: 410, right: 790, width: 380, height: 20 },
    });
    const outerClosed = makeNode({
      tagName: "DETAILS",
      rect: footerRect,
      open: false,
      summaryNode: outerSummary,
    });
    outerSummary.parentElement = { closest: () => outerClosed };
    outerSummary.closest = (sel: string) => (sel === "details:not([open])" ? outerClosed : null);

    const hiddenLabel = makeNode({
      tagName: "LABEL",
      rect: { top: 450, bottom: 465, left: 410, right: 790, width: 380, height: 15 },
      parentDetails: outerClosed,
    });
    const innerSummary = makeNode({
      tagName: "SUMMARY",
      rect: { top: 450, bottom: 470, left: 410, right: 790, width: 380, height: 20 },
    });
    const innerClosed = makeNode({
      tagName: "DETAILS",
      rect: footerRect,
      open: false,
      summaryNode: innerSummary,
      parentDetails: outerClosed,
    });
    innerSummary.parentElement = { closest: () => innerClosed };
    innerSummary.closest = (sel: string) => (sel === "details:not([open])" ? innerClosed : null);

    const runProbe = (elements: unknown[]) => {
      const popup = {
        getBoundingClientRect: () => popupRect,
        scrollHeight: 400,
        clientHeight: 400,
        querySelectorAll: (sel: string) =>
          sel === '[data-slot$="dialog-header"], [data-slot$="dialog-footer"]'
            ? [footer]
            : elements,
      };
      const fakeDoc = {
        documentElement: { clientWidth: 1280 },
        querySelectorAll: () => [popup],
      };
      const fn = new Function("document", "window", "getComputedStyle", `return ${PROBE}`);
      return JSON.parse(
        fn(fakeDoc, { innerHeight: 800 }, () => ({
          overflowY: "visible",
          visibility: "visible",
        })) as string,
      ) as DialogProbe;
    };

    // Collapsed descendants and inner summaries inside a closed outer <details> are ignored.
    assert.equal(runProbe([footer, hiddenLabel, innerSummary]).covered.length, 0);
    // An exposed summary covered by the action bar still fails.
    assert.equal(runProbe([footer, outerSummary]).covered.length, 1);
  });
});

describe("browser-checks.config", () => {
  it("names every dialog once, with a locale path and at least one opening step", () => {
    const names = DIALOGS.map((dialog) => dialog.name);
    assert.equal(new Set(names).size, names.length);
    for (const dialog of DIALOGS) {
      assert.match(dialog.path, /^\/[a-z]{2}-[A-Z]{2}\//);
      assert.ok(dialog.steps.length > 0, dialog.name);
    }
  });

  it("measures at least two signed-in pages for the shell loading check", () => {
    assert.ok(SHELL_PAGES.length >= 2);
    for (const page of SHELL_PAGES) assert.notEqual(page.role, "anonymous", page.name);
  });

  it("turns steps into page scripts that fail loudly when the target is missing", () => {
    assert.match(stepScript({ click: "#a" }), /querySelector\("#a"\)/);
    assert.match(stepScript({ clickText: "New project" }), /"New project"/);
    assert.match(stepScript({ clickText: "x" }), /throw new Error/);
  });
});

const noPause = async () => {};
const navigated = () =>
  new Error(
    "agent-browser eval exited 1: ✗ CDP error (Runtime.evaluate): Inspected target navigated or closed",
  );

describe("pollPage", () => {
  /** A fake agent-browser: each eval answers with the next scripted reply (an Error is thrown). */
  const scripted = (replies: (string | Error)[]) => {
    const calls: string[][] = [];
    const run = async (args: string[]) => {
      calls.push(args);
      const reply = replies.shift();
      if (reply instanceof Error) throw reply;
      return reply ?? "null";
    };
    return { run, calls };
  };

  it("keeps polling across the full page load a sign-in ends in", async () => {
    const { run } = scripted(["null", '"/en-US/login"', navigated(), '"app"']);
    assert.equal(await pollPage(run, "probe", noPause), "app");
  });

  it("also looks again after a destroyed execution context", async () => {
    const destroyed = new Error(
      "agent-browser eval exited 1: ✗ CDP error (Runtime.evaluate): Execution context was destroyed.",
    );
    const { run } = scripted([destroyed, '"code"']);
    assert.equal(await pollPage(run, "probe", noPause), "code");
  });

  it("gives up after 20s with the page it is stuck on", async () => {
    const replies: string[] = [];
    for (let i = 0; i < 40; i++) replies.push("null", '"/en-US/login"');
    const { run } = scripted(replies);
    assert.equal(await pollPage(run, "probe", noPause), "still on /en-US/login after 20s");
  });

  it("passes a closed browser or any other failure on at once", async () => {
    const closed = new Error(
      "agent-browser eval exited 1: Target page, context or browser has been closed",
    );
    const first = scripted([closed, '"app"']);
    await assert.rejects(pollPage(first.run, "probe", noPause), /has been closed/);
    assert.equal(first.calls.length, 1);
    const { run } = scripted([new Error("agent-browser eval exited 1: daemon not running")]);
    await assert.rejects(pollPage(run, "probe", noPause), /daemon not running/);
  });

  it("reports the navigation error, not a page, when every attempt was cut off", async () => {
    const { run } = scripted(Array.from({ length: 40 }, navigated));
    await assert.rejects(pollPage(run, "probe", noPause), /Inspected target navigated/);
  });

  it("sends one short expression per poll, never over stdin", async () => {
    const { run, calls } = scripted(['"app"']);
    await pollPage(run, "probe()", noPause);
    assert.deepEqual(calls, [["eval", "probe()"]]);
  });
});

/**
 * A fake agent-browser for a whole sign-in: `answer` picks the reply to each
 * eval (an Error is thrown); every command and its stdin are recorded.
 */
function fakeBrowser(answer: (script: string) => string | Error = () => "true") {
  const commands: { args: string[]; input?: string }[] = [];
  const browser: CheckRun["browser"] = {
    async run(args, input) {
      commands.push({ args, input });
      if (args[0] !== "eval") return "";
      const reply = answer(input ?? args[1] ?? "");
      if (reply instanceof Error) throw reply;
      return reply;
    },
    async evalJson<T>(): Promise<T> {
      throw new Error("not used");
    },
    close() {},
  };
  return { browser, commands };
}

/** A stack whose sign-in ends in a full page load: the first poll after the submit is cut off. */
function stack(
  options: { secondFactor?: boolean; landsOn?: string; clickNavigates?: boolean } = {},
) {
  let submitted = false;
  let verified = false;
  let cutOff = false;
  return (script: string): string | Error => {
    if (script.includes("__reactProps")) return '"ready"';
    if (script.includes("requestSubmit")) {
      submitted = true;
      return "true";
    }
    if (script.includes("button.click()")) {
      // Once verified, the page is the landing page: no code field, no button.
      if (verified) return script.includes("if (location.pathname ===") ? '"app"' : "null";
      verified = true;
      // The navigation the click starts can cut off the clicking evaluation itself.
      return options.clickNavigates ? navigated() : '"clicked"';
    }
    if (script === "location.pathname") return JSON.stringify(options.landsOn ?? "/en-US/login");
    if (script.startsWith("location.pathname ===")) {
      if (!submitted || (options.secondFactor && !verified))
        return options.secondFactor && script.includes("totp-code") ? '"code"' : "null";
      if (!cutOff) {
        cutOff = true;
        return navigated();
      }
      return options.landsOn ? "null" : '"app"';
    }
    return "true";
  };
}

describe("formSignIn", () => {
  const base = "http://127.0.0.1:3001";
  const account = { email: "admin@example.test", password: "correct horse battery" };

  it("signs in through the form and survives the page load the redirect ends in", async () => {
    const { browser, commands } = fakeBrowser(stack());
    await formSignIn({ base, browser }, account, undefined, noPause);
    // The default landing is the app's home (apps/web/src/lib/app-home.ts).
    assert.deepEqual(commands[0]?.args, [
      "open",
      `${base}/en-US/login?redirectTo=%2Fen-US%2Fdashboard%2Fsandboxes`,
    ]);
  });

  it("sends the password over stdin only", async () => {
    const { browser, commands } = fakeBrowser(stack());
    await formSignIn({ base, browser }, account, undefined, noPause);
    assert.ok(commands.some((command) => command.input?.includes(account.password)));
    for (const command of commands)
      assert.ok(!command.args.join(" ").includes(account.password), command.args.join(" "));
  });

  it("types a code at the second-factor step once and waits for the app", async () => {
    let asked = 0;
    const { browser, commands } = fakeBrowser(stack({ secondFactor: true }));
    await formSignIn(
      { base, browser },
      {
        ...account,
        totp: async () => {
          asked++;
          return "123456";
        },
      },
      undefined,
      noPause,
    );
    assert.equal(asked, 1);
    assert.ok(commands.some((command) => command.input?.includes('"123456"')));
    for (const command of commands) assert.ok(!command.args.join(" ").includes("123456"));
  });

  it("accepts a Verify click whose own evaluation the navigation cut off", async () => {
    const { browser } = fakeBrowser(stack({ secondFactor: true, clickNavigates: true }));
    await formSignIn(
      { base, browser },
      { ...account, totp: () => "123456" },
      "/en-US/settings",
      noPause,
    );
  });

  it("says what is wrong when the account has a second factor and no code", async () => {
    const { browser } = fakeBrowser(stack({ secondFactor: true }));
    await assert.rejects(
      formSignIn({ base, browser }, account, undefined, noPause),
      /has a second factor and no code source/,
    );
  });

  it("reports where a refused sign-in is stuck, never the password", async () => {
    const { browser } = fakeBrowser(stack({ landsOn: "/en-US/login" }));
    await assert.rejects(
      formSignIn({ base, browser }, account, undefined, noPause),
      (error: Error) =>
        /sign-in did not open the app \(still on \/en-US\/login after 20s\)/.test(error.message) &&
        !error.message.includes(account.password),
    );
  });
});

describe("sessionName", () => {
  it("is one session per process, behind an optional prefix", () => {
    assert.equal(sessionName("check-layout", "", 42), "check-layout-42");
    assert.equal(sessionName("check-layout", "lane-d-", 42), "lane-d-check-layout-42");
    assert.match(sessionName("check-dialogs"), new RegExp(`check-dialogs-${process.pid}$`));
  });
});

describe("byRole", () => {
  it("groups the cases by role and keeps the listed order inside each", () => {
    const cases = [
      { name: "a", role: "user" },
      { name: "b", role: "admin" },
      { name: "c", role: "user" },
    ];
    assert.deepEqual(
      byRole(cases).map((item) => item.name),
      ["a", "c", "b"],
    );
  });
});

describe("signing in to a running stack", () => {
  const withFile = async (content: string | undefined, body: (path: string) => Promise<void>) => {
    const dir = mkdtempSync(join(tmpdir(), "browser-checks-"));
    const path = join(dir, "accounts.env");
    if (content !== undefined) writeFileSync(path, content);
    try {
      await body(path);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  const saved = process.env.WSSP_CHECK_CREDS_FILE;

  it("says what to do when the credentials are not usable, naming keys, never values", async () => {
    delete process.env.WSSP_CHECK_CREDS_FILE;
    try {
      assert.throws(() => seededAccount([], "admin"), /pass --accounts <file>/);
      assert.throws(() => seededAccount(["--accounts"], "admin"), /needs the seeded accounts/);
      await withFile(undefined, async (path) => {
        assert.throws(
          () => seededAccount(["--accounts", path], "admin"),
          new RegExp(`no credentials file at ${path.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`),
        );
      });
      await withFile("ADMIN_EMAIL=a@example.test\nUSER_PASSWORD=hunter2-secret\n", async (path) => {
        assert.throws(
          () => seededAccount(["--accounts", path], "admin"),
          (error: Error) =>
            /has no ADMIN_EMAIL \/ ADMIN_PASSWORD/.test(error.message) &&
            !error.message.includes("hunter2"),
        );
      });
    } finally {
      if (saved === undefined) delete process.env.WSSP_CHECK_CREDS_FILE;
      else process.env.WSSP_CHECK_CREDS_FILE = saved;
    }
  });

  it("takes --accounts over WSSP_CHECK_CREDS_FILE", async () => {
    await withFile(
      "USER_EMAIL=u@example.test\nUSER_PASSWORD=user-password-1234\n",
      async (path) => {
        process.env.WSSP_CHECK_CREDS_FILE = join(tmpdir(), "no-such-wssp-accounts.env");
        try {
          assert.equal(seededAccount(["--accounts", path], "user").email, "u@example.test");
          assert.throws(() => seededAccount([], "user"), /no credentials file at/);
        } finally {
          if (saved === undefined) delete process.env.WSSP_CHECK_CREDS_FILE;
          else process.env.WSSP_CHECK_CREDS_FILE = saved;
        }
      },
    );
  });

  it("signs in once per role, signing the other role out first", async () => {
    await withFile(
      "USER_EMAIL=u@example.test\nUSER_PASSWORD=user-password-1234\n",
      async (path) => {
        const { browser, commands } = fakeBrowser(stack());
        const run = { base: "http://127.0.0.1:3001", browser, args: ["--accounts", path] };
        await signIn(run, "user");
        await signIn(run, "user");
        await signIn(run, "anonymous");
        const opens = commands.filter((command) => command.args[0] === "open");
        assert.equal(opens.length, 1);
        assert.equal(commands.filter((command) => command.args[1] === "clear").length, 2);
        assert.ok(
          commands.some((command) => command.input?.includes("user-password-1234")),
          "the user's password was typed",
        );
      },
    );
  });

  it("stops before touching the browser when the credentials are missing", async () => {
    const { browser, commands } = fakeBrowser();
    await assert.rejects(
      signIn({ base: "x", browser, args: ["--accounts", join(tmpdir(), "missing.env")] }, "admin"),
      /no credentials file at/,
    );
    assert.equal(commands.length, 0);
  });
});
