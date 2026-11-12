import { describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
  sandboxTemplateBuild: { findFirst: vi.fn() },
  $executeRaw: vi.fn(),
}));
vi.mock("@wssp/db", () => ({ default: db }));
vi.mock("@wssp/env/server", () => ({ env: {} }));
vi.mock("@wssp/queue", () => ({ redisConnection: {} }));
const wake = vi.hoisted(() => vi.fn());
vi.mock("./wake", () => ({ notifyTemplateBuildProgress: wake }));

const {
  hintStep,
  parseStoredHints,
  planHintAppend,
  recordBuildEgressHints,
  renderBuildHint,
  sanitizeHintNames,
  stepHints,
} = await import("./hints");

const at = "2026-11-03T00:00:00.000Z";

describe("hint sanitization", () => {
  it("keeps only unique DNS-grammar names, at most 16", () => {
    expect(
      sanitizeHintNames([
        "pypi.org",
        "pypi.org",
        "PyPI.org",
        "evil\u001b[31m.example",
        "a‮b.example",
        "x".repeat(254),
        `${"a".repeat(64)}.com`,
        "-bad.example",
        "pypi.org.",
        42,
        null,
        "files.pythonhosted.org",
      ]),
    ).toEqual(["pypi.org", "files.pythonhosted.org"]);
    const many = Array.from({ length: 40 }, (_, i) => `h${i}.example`);
    expect(sanitizeHintNames(many)).toHaveLength(16);
  });

  it("E2-A-02: drops the bridge's .incus search-suffix expansions, granted or not", () => {
    expect(
      sanitizeHintNames([
        "archive.ubuntu.com.incus",
        "www.wikipedia.org.incus",
        "e2e-blocked.example.org.incus",
        "incus",
        "e2e-blocked.example.org",
        "www.wikipedia.org",
        "incus.example.org",
      ]),
    ).toEqual(["e2e-blocked.example.org", "www.wikipedia.org", "incus.example.org"]);
    // Hints stored before the filter are never shown either.
    expect(
      parseStoredHints([
        { n: 2, name: "archive.ubuntu.com.incus", at },
        { n: 2, name: "www.wikipedia.org", at },
      ]).map((hint) => hint.name),
    ).toEqual(["www.wikipedia.org"]);
  });

  it("E3-A-05: drops service lookups no grant can name", () => {
    expect(
      sanitizeHintNames([
        "_http._tcp.archive.ubuntu.com",
        "_https._tcp.esm.ubuntu.com",
        "a_b.example",
        "esm.ubuntu.com",
      ]),
    ).toEqual(["esm.ubuntu.com"]);
    // Hints stored before the filter are never shown either.
    expect(
      parseStoredHints([
        { n: 2, name: "_http._tcp.security.ubuntu.com", at },
        { n: 2, name: "security.ubuntu.com", at },
      ]).map((hint) => hint.name),
    ).toEqual(["security.ubuntu.com"]);
  });

  it("re-validates stored hints before display", () => {
    expect(
      parseStoredHints([
        { n: 1, name: "pypi.org", at },
        { n: 1, name: "bad\nname", at },
        { n: -1, name: "ok.example", at },
        { n: 1, name: "ok.example", at: "not a date" },
        "junk",
        null,
      ]),
    ).toEqual([{ n: 1, name: "pypi.org", at }]);
    expect(parseStoredHints({})).toEqual([]);
  });

  it("appends only new names of the step, within the build cap", () => {
    const now = new Date(at);
    const existing = [{ n: 2, name: "a.example", at }];
    expect(planHintAppend(existing, 2, ["a.example", "b.example"], now)).toEqual([
      { n: 2, name: "b.example", at },
    ]);
    // Another step may repeat a name.
    expect(planHintAppend(existing, 3, ["a.example"], now)).toHaveLength(1);
    const full = Array.from({ length: 63 }, (_, i) => ({ n: 0, name: `h${i}.example`, at }));
    expect(planHintAppend(full, 1, ["x.example", "y.example"], now)).toHaveLength(1);
    expect(planHintAppend([...full, ...existing], 1, ["z.example"], now)).toEqual([]);
  });

  it("attributes to the running step, else the latest started one", () => {
    const step = (n: number, state: "pending" | "running" | "succeeded") => ({
      n,
      stepIndex: n,
      kind: "run" as const,
      state,
      operationId: null,
      exitCode: null,
    });
    expect(hintStep([step(0, "succeeded"), step(1, "running"), step(2, "pending")])?.n).toBe(1);
    expect(hintStep([step(0, "succeeded"), step(1, "succeeded"), step(2, "pending")])?.n).toBe(1);
    expect(hintStep([step(0, "pending")])).toBeNull();
  });
});

describe("foreign labelling (N24)", () => {
  const hint = { n: 1, name: "pypi.org", at };

  it("own-node hints suggest the grant and a matching preset", () => {
    expect(renderBuildHint(hint, false)).toEqual({
      type: "blocked_name",
      step: 1,
      name: "pypi.org",
      source: "own_node",
      preset: "pypi",
      message: "blocked: `pypi.org` — add it to egress or use preset `pypi`",
      at,
    });
    expect(renderBuildHint({ ...hint, name: "evil.example" }, false).message).toBe(
      "blocked: `evil.example` — add it to egress",
    );
  });

  it("foreign-node hints are labelled reported, with no grant advice, preset or host identity", () => {
    const rendered = renderBuildHint(hint, true);
    expect(rendered).toEqual({
      type: "blocked_name",
      step: 1,
      name: "pypi.org",
      source: "foreign_node",
      preset: null,
      message: "the build node reported a blocked name: `pypi.org`",
      at,
    });
    expect(rendered.message).not.toMatch(/add it|preset|egress/);
  });

  it("step hints follow the build's foreign flag", () => {
    const row = {
      egressHints: [hint, { n: 2, name: "npmjs.org", at }],
      foreignHost: true,
    };
    expect(stepHints(row, 1).map((h) => h.source)).toEqual(["foreign_node"]);
    expect(stepHints({ ...row, foreignHost: false }, 2)[0]?.source).toBe("own_node");
  });
});

describe("recordBuildEgressHints", () => {
  const running = {
    id: "build-1",
    steps: [
      { n: 0, stepIndex: 0, kind: "prelude", state: "succeeded", operationId: "op-0", exitCode: 0 },
      { n: 1, stepIndex: 1, kind: "run", state: "running", operationId: "op-1", exitCode: null },
    ],
    egressHints: [],
  };

  it("binds to the RUNNING build of that sandbox on the reporting host and wakes progress", async () => {
    db.sandboxTemplateBuild.findFirst.mockResolvedValueOnce(running);
    db.$executeRaw.mockResolvedValueOnce(1);
    wake.mockClear();
    await expect(
      recordBuildEgressHints({
        hostId: "host-1",
        sandboxId: "sbx-1",
        names: ["pypi.org", "bad\u0007"],
        now: new Date(at),
      }),
    ).resolves.toBe(true);
    expect(db.sandboxTemplateBuild.findFirst).toHaveBeenLastCalledWith(
      expect.objectContaining({
        where: { buildSandboxId: "sbx-1", hostId: "host-1", state: "RUNNING" },
      }),
    );
    const [, payload] = db.$executeRaw.mock.lastCall ?? [];
    expect(JSON.parse(payload as string)).toEqual([{ n: 1, name: "pypi.org", at }]);
    expect(wake).toHaveBeenCalledWith("build-1");
  });

  it("ignores frames for anything but a running build VM, and invalid-only frames", async () => {
    db.$executeRaw.mockClear();
    db.sandboxTemplateBuild.findFirst.mockResolvedValueOnce(null);
    await expect(
      recordBuildEgressHints({ hostId: "h", sandboxId: "s", names: ["pypi.org"] }),
    ).resolves.toBe(false);
    db.sandboxTemplateBuild.findFirst.mockClear();
    await expect(
      recordBuildEgressHints({ hostId: "h", sandboxId: "s", names: ["\u001b"] }),
    ).resolves.toBe(false);
    expect(db.sandboxTemplateBuild.findFirst).not.toHaveBeenCalled();
    expect(db.$executeRaw).not.toHaveBeenCalled();
  });
});
