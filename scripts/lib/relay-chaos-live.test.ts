import assert from "node:assert/strict";
import { test } from "node:test";
import { OPERATION_DISPATCH_KIND } from "../../packages/api/src/sandbox/contracts.ts";
import {
  CHAOS_ENV,
  cleanupVerdict,
  DEFAULT_WSSP_BIN,
  exactOutputProblem,
  type GuardFacts,
  guardRefusals,
  honorsSharedIncusOverride,
  hostAvailabilityRefusal,
  hostRelayHash,
  L2_CREATE_DISPATCH,
  LIVE_CELLS,
  type LiveCell,
  type LiveConfig,
  LiveVmCap,
  MAX_LIVE_VMS,
  parseIncusNames,
  parseLiveConfig,
  parseSystemctlShow,
  pathsOverlap,
  productionFootprint,
  runLiveCells,
  systemdRunArgv,
  tickerOutput,
} from "./relay-chaos-live.ts";

const HOME = "/home/op";
const SDK_KEY = "wssp_sdk_secretvalue123";
const HOST_TOKEN = "wssp_host_secretvalue456";
const HOST_ID = "host_chaos01";

const baseEnv = {
  [CHAOS_ENV.gate]: "1",
  [CHAOS_ENV.apiUrl]: "http://127.0.0.1:4310",
  [CHAOS_ENV.upstreamUrl]: "http://127.0.0.1:4300",
  [CHAOS_ENV.sdkKey]: SDK_KEY,
  [CHAOS_ENV.hostToken]: HOST_TOKEN,
  [CHAOS_ENV.hostId]: HOST_ID,
  [CHAOS_ENV.template]: "base:latest",
  [CHAOS_ENV.runId]: "abc123",
};

function config(env: Record<string, string | undefined> = {}): LiveConfig {
  const parsed = parseLiveConfig({ ...baseEnv, ...env }, { home: HOME, randomRunId: () => "x" });
  assert.ok(parsed.ok, parsed.ok ? "" : parsed.errors.join("; "));
  return parsed.config;
}

const notFound = parseSystemctlShow("LoadState=not-found\nActiveState=inactive\nMainPID=0\n");

function facts(overrides: Partial<GuardFacts> = {}): GuardFacts {
  return {
    chaosUnit: notFound,
    runDirExists: false,
    productionRelayDirExists: () => false,
    ...overrides,
  };
}

const productionShow = parseSystemctlShow(
  [
    "LoadState=loaded",
    "ActiveState=active",
    "MainPID=4242",
    "ExecStart={ path=/home/op/.local/bin/wssp ; argv[]=/home/op/.local/bin/wssp host run --runtime incus ; ignore_errors=no }",
    "WorkingDirectory=",
    `Environment=WSSP_HOST_TOKEN=${HOST_TOKEN} "WSSP_LOG=info debug"`,
  ].join("\n"),
);

test("the gate is required and nothing else is reported without it", () => {
  const parsed = parseLiveConfig(
    { ...baseEnv, [CHAOS_ENV.gate]: undefined },
    { home: HOME, randomRunId: () => "abcdef" },
  );
  assert.equal(parsed.ok, false);
  assert.match(parsed.ok ? "" : parsed.errors.join(), /RELAY_CHAOS_LIVE=1/);
});

test("config errors name variables, never secret values", () => {
  const parsed = parseLiveConfig(
    {
      ...baseEnv,
      [CHAOS_ENV.sdkKey]: "sk-wrong-secret",
      [CHAOS_ENV.hostToken]: "wssp_device_wrongsecret",
      [CHAOS_ENV.apiUrl]: "https://wssp.example.com",
      [CHAOS_ENV.upstreamUrl]: "http://127.0.0.1:4310/path",
      [CHAOS_ENV.cells]: "L1,L4",
    },
    { home: HOME, randomRunId: () => "abcdef" },
  );
  assert.equal(parsed.ok, false);
  const text = parsed.ok ? "" : parsed.errors.join("\n");
  assert.doesNotMatch(text, /wrong-secret|wrongsecret/);
  assert.match(text, /WSSP_CHAOS_SDK_KEY/);
  assert.match(text, /WSSP_CHAOS_HOST_TOKEN/);
  assert.match(text, /WSSP_CHAOS_API_URL must be a loopback/);
  assert.match(text, /WSSP_CHAOS_UPSTREAM_URL must be a loopback/);
  assert.match(text, /L4 .*manual/);
});

test("the front door and the server need distinct ports", () => {
  const parsed = parseLiveConfig(
    { ...baseEnv, [CHAOS_ENV.upstreamUrl]: "http://localhost:4310" },
    { home: HOME, randomRunId: () => "abcdef" },
  );
  assert.equal(parsed.ok, false);
});

test("defaults: own run dir, own unit, own project", () => {
  const c = config();
  assert.equal(c.unitName, "wssp-chaos-abc123");
  assert.equal(c.runDir, "/home/op/.local/share/wssp-chaos/abc123");
  assert.equal(c.dataDir, "/home/op/.local/share/wssp-chaos/abc123/data");
  assert.equal(c.configDir, "/home/op/.local/share/wssp-chaos/abc123/config");
  assert.equal(c.incusProject, "wssp-chaos");
  assert.deepEqual(c.cells, ["L1", "L2", "L3"]);
  assert.equal(c.outageMs, 90_000);
});

test("systemctl show parsing keeps quoted environment words together", () => {
  assert.equal(productionShow.mainPid, 4242);
  assert.equal(productionShow.environment.get("WSSP_LOG"), "info debug");
  assert.equal(notFound.loadState, "not-found");
});

test("a dedicated config passes every guard", () => {
  const footprint = productionFootprint(productionShow, [], HOME);
  assert.deepEqual(guardRefusals(config(), footprint, facts()), []);
});

test("refuses a data root inside or equal to the wssp-host default data dir", () => {
  const footprint = productionFootprint(null, [], HOME);
  for (const root of ["/home/op/.local/share/wssp", "/home/op/.local/share/wssp/chaos"]) {
    const refusals = guardRefusals(config({ [CHAOS_ENV.dataRoot]: root }), footprint, facts());
    assert.ok(
      refusals.some((r) => r.includes("overlaps the wssp-host data dir")),
      root,
    );
  }
  // A sibling sharing the prefix is not inside it.
  assert.equal(
    pathsOverlap("/home/op/.local/share/wssp-chaos", "/home/op/.local/share/wssp"),
    false,
  );
});

test("refuses the data dir wssp-host's unit environment or open files point at", () => {
  const unit = parseSystemctlShow(
    "LoadState=loaded\nMainPID=7\nEnvironment=WSSP_DATA_DIR=/srv/chaos\nExecStart=\n",
  );
  const refusals = guardRefusals(
    config({ [CHAOS_ENV.dataRoot]: "/srv/chaos" }),
    productionFootprint(unit, [], HOME),
    facts(),
  );
  assert.ok(refusals.some((r) => r.includes("/srv/chaos")));

  const hash = hostRelayHash("host_other");
  const fromFds = productionFootprint(productionShow, [`/data/x/relay/${hash}/journal.lock`], HOME);
  assert.ok(fromFds.dataDirs.includes("/data/x"));
  const nested = guardRefusals(config({ [CHAOS_ENV.dataRoot]: "/data/x" }), fromFds, facts());
  assert.ok(nested.some((r) => r.includes("overlaps the wssp-host data dir /data/x")));
});

test("refuses a config dir that is wssp-host's", () => {
  const refusals = guardRefusals(
    config({ [CHAOS_ENV.dataRoot]: "/home/op/.config/wssp/chaos" }),
    productionFootprint(null, [], HOME),
    facts(),
  );
  assert.ok(refusals.some((r) => r.includes("config dir")));
});

test("refuses the host id wssp-host serves (ExecStart, open journal, or on-disk journal)", () => {
  const byFlag = parseSystemctlShow(
    `LoadState=loaded\nExecStart={ argv[]=/bin/wssp host run --host-id ${HOST_ID} ; }\n`,
  );
  assert.ok(
    guardRefusals(config(), productionFootprint(byFlag, [], HOME), facts()).some((r) =>
      r.includes("ExecStart serves"),
    ),
  );
  const open = productionFootprint(
    productionShow,
    [`/home/op/.local/share/wssp/relay/${hostRelayHash(HOST_ID)}/lock`],
    HOME,
  );
  assert.ok(guardRefusals(config(), open, facts()).some((r) => r.includes("holds the test host")));
  const onDisk = guardRefusals(
    config(),
    productionFootprint(null, [], HOME),
    facts({
      productionRelayDirExists: (dir, hash) =>
        dir === "/home/op/.local/share/wssp" && hash === hostRelayHash(HOST_ID),
    }),
  );
  assert.ok(onDisk.some((r) => r.includes("already has a relay journal")));
});

test("refuses an existing unit, an existing run dir, and a production Incus project", () => {
  const footprint = productionFootprint(
    parseSystemctlShow("LoadState=loaded\nEnvironment=WSSP_INCUS_PROJECT=lab\n"),
    [],
    HOME,
  );
  const refusals = guardRefusals(
    config({ [CHAOS_ENV.incusProject]: "lab" }),
    footprint,
    facts({ chaosUnit: productionShow, runDirExists: true }),
  );
  assert.ok(refusals.some((r) => r.includes("already exists; pick a new run id")));
  assert.ok(refusals.some((r) => r.startsWith("run directory")));
  assert.ok(refusals.some((r) => r.includes("Incus project lab")));
  for (const project of ["wssp", "default"]) {
    assert.ok(
      guardRefusals(
        config({ [CHAOS_ENV.incusProject]: project }),
        productionFootprint(null, [], HOME),
        facts(),
      ).some((r) => r.includes(`Incus project ${project}`)),
    );
  }
});

test("refuses a wssp-host WorkingDirectory inside the run directory", () => {
  const unit = parseSystemctlShow(
    "LoadState=loaded\nWorkingDirectory=!/home/op/.local/share/wssp-chaos/abc123\n",
  );
  assert.ok(
    guardRefusals(config(), productionFootprint(unit, [], HOME), facts()).some((r) =>
      r.includes("WorkingDirectory"),
    ),
  );
});

test("guard messages never carry a secret from the production environment", () => {
  const footprint = productionFootprint(productionShow, [], HOME);
  const refusals = guardRefusals(
    config({ [CHAOS_ENV.dataRoot]: "/home/op/.local/share/wssp" }),
    footprint,
    facts({ chaosUnit: productionShow, runDirExists: true }),
  );
  assert.ok(refusals.length > 0);
  assert.doesNotMatch(refusals.join("\n"), /secretvalue/);
});

test("the host must be visible, not connected, not revoked, not draining", () => {
  assert.match(hostAvailabilityRefusal(undefined) ?? "", /not visible/);
  assert.match(
    hostAvailabilityRefusal({ status: "CONNECTED", draining: false }) ?? "",
    /already CONNECTED/,
  );
  assert.match(hostAvailabilityRefusal({ status: "REVOKED", draining: false }) ?? "", /revoked/);
  assert.match(hostAvailabilityRefusal({ status: "DISCONNECTED", draining: true }) ?? "", /drain/);
  assert.equal(hostAvailabilityRefusal({ status: "DISCONNECTED", draining: false }), null);
  assert.equal(hostAvailabilityRefusal({ status: "STALE", draining: false }), null);
});

test("the transient unit argv passes the token by name and pins the dedicated dirs", () => {
  const c = config();
  const argv = systemdRunArgv(c);
  assert.doesNotMatch(argv.join(" "), /secretvalue/);
  assert.ok(argv.includes("--user"));
  assert.ok(argv.includes("--unit=wssp-chaos-abc123"));
  assert.ok(argv.includes(`--setenv=${CHAOS_ENV.hostToken}`));
  assert.ok(argv.includes(`--setenv=WSSP_DATA_DIR=${c.dataDir}`));
  assert.ok(argv.includes(`--setenv=WSSP_CONFIG_DIR=${c.configDir}`));
  assert.ok(argv.includes("--setenv=WSSP_TEST_SHARED_INCUS=1"));
  assert.deepEqual(argv.slice(argv.indexOf("--server"), argv.indexOf("--server") + 2), [
    "--server",
    "http://127.0.0.1:4310",
  ]);
  assert.ok(argv.includes("wssp-chaos"));
  assert.ok(!argv.includes("sudo"));
  assert.ok(!argv.includes("--setenv=WSSP_TEST_RELAY_TIMING"));
  assert.ok(systemdRunArgv(c, "1s,1s,1s,1s,1s").includes("--setenv=WSSP_TEST_RELAY_TIMING"));
});

test("incus csv parsing keeps only sandbox instances", () => {
  assert.deepEqual(parseIncusNames("wssp-sbx-a\nother\n wssp-sbx-b \n\n"), [
    "wssp-sbx-a",
    "wssp-sbx-b",
  ]);
});

const clean = {
  tracked: ["sbx1", "sbx2"],
  remaining: [
    { id: "sbx1", state: "DELETED" },
    { id: "sbx2", state: "DELETED" },
  ],
  destroyFailures: [],
  listed: true,
  unitStopped: true,
  baseline: ["wssp-sbx-preexisting"],
  after: ["wssp-sbx-preexisting"],
};

test("cleanup: a fully verified run is clean", () => {
  assert.deepEqual(cleanupVerdict(clean), { ok: true, leaks: [], problems: [] });
});

test("cleanup: a run VM left in Incus is a leak", () => {
  const verdict = cleanupVerdict({ ...clean, after: ["wssp-sbx-preexisting", "wssp-sbx-sbx2"] });
  assert.equal(verdict.ok, false);
  assert.deepEqual(verdict.leaks, ["wssp-sbx-sbx2"]);
});

test("cleanup: an untracked new VM (a create the run lost track of) is a leak", () => {
  const verdict = cleanupVerdict({
    ...clean,
    tracked: [],
    remaining: [{ id: "sbx9", state: "DELETED" }],
    after: ["wssp-sbx-preexisting", "wssp-sbx-unknown"],
  });
  assert.deepEqual(verdict.leaks, ["wssp-sbx-unknown"]);
});

test("cleanup: label-listed sandboxes count even when never tracked", () => {
  const verdict = cleanupVerdict({
    ...clean,
    tracked: [],
    remaining: [{ id: "sbx7", state: "READY" }],
    baseline: null,
    after: ["wssp-sbx-sbx7"],
  });
  assert.equal(verdict.ok, false);
  assert.deepEqual(verdict.leaks, ["wssp-sbx-sbx7"]);
  assert.ok(verdict.problems.some((p) => p.includes("sbx7 is still READY")));
  assert.ok(verdict.problems.some((p) => p.includes("no incus baseline")));
});

test("cleanup: anything unverified fails the run", () => {
  for (const broken of [
    { destroyFailures: [{ id: "sbx1", code: "unavailable" }] },
    { listed: false },
    { unitStopped: false },
    { after: null },
  ]) {
    const verdict = cleanupVerdict({ ...clean, ...broken });
    assert.equal(verdict.ok, false, JSON.stringify(broken));
    assert.equal(verdict.leaks.length, 0);
    assert.equal(verdict.problems.length, 1);
  }
});

test("output checks: exact bytes, no gap, exit 0", () => {
  const expected = tickerOutput(3);
  assert.equal(expected, "tick-1\ntick-2\ntick-3\n");
  assert.equal(
    exactOutputProblem({ exitCode: 0, stdout: expected, truncated: false }, expected),
    null,
  );
  assert.match(
    exactOutputProblem({ exitCode: 0, stdout: expected, truncated: true }, expected) ?? "",
    /gap/,
  );
  assert.match(
    exactOutputProblem({ exitCode: 0, stdout: "tick-1\ntick-3\n", truncated: false }, expected) ??
      "",
    /differs/,
  );
  assert.match(
    exactOutputProblem({ exitCode: 1, stdout: expected, truncated: false }, expected) ?? "",
    /exit/,
  );
  assert.equal(MAX_LIVE_VMS, 2);
});

/** A stubbed live run: every external operation (SDK, Incus, faults) is a
 * fake that tracks live VMs under the real D7 cap. */
function stubbedRun(cells: readonly LiveCell[]) {
  const cap = new LiveVmCap();
  const live = new Set<string>();
  let peak = 0;
  const create = async (cell: string) => {
    cap.reserve();
    const id = `sbx-${cell}-${cap.creates}`;
    live.add(id);
    peak = Math.max(peak, live.size);
    return id;
  };
  const used: string[] = [];
  const run = runLiveCells(cells, {
    createSandbox: create,
    l1: async (primary) => {
      assert.ok(live.has(primary), "L1 runs on a live sandbox");
      used.push(`L1:${primary}`);
    },
    l2: async () => {
      const id = await create("L2");
      used.push(`L2:${id}`);
      live.delete(id);
    },
    l3: async (primary) => {
      assert.ok(live.has(primary), "L3 runs on a live sandbox");
      used.push(`L3:${primary}`);
    },
    recover: () => undefined,
    describe: (error) => (error instanceof Error ? error.message : String(error)),
    log: () => undefined,
  });
  return { run, cap, used, peak: () => peak };
}

test("live sequence: the default L1→L2→L3 run passes within the two-VM cap", async () => {
  const { run, cap, used, peak } = stubbedRun(LIVE_CELLS);
  const results = await run;
  assert.deepEqual(
    [...results],
    LIVE_CELLS.map((cell) => [cell, null]),
  );
  assert.equal(cap.creates, MAX_LIVE_VMS);
  assert.ok(peak() <= MAX_LIVE_VMS, `peak ${peak()} live VMs`);
  // L1 and L3 share the primary; L2 makes the run's second VM.
  assert.deepEqual(used, ["L1:sbx-primary-1", "L2:sbx-L2-2", "L3:sbx-primary-1"]);
});

test("live sequence: every cell subset and order stays within the cap", async () => {
  const orders: LiveCell[][] = [
    ["L1"],
    ["L2"],
    ["L3"],
    ["L1", "L3"],
    ["L2", "L1", "L3"],
    ["L3", "L2", "L1"],
  ];
  for (const cells of orders) {
    const { run, peak } = stubbedRun(cells);
    const results = await run;
    for (const cell of cells) assert.equal(results.get(cell), null, `${cells.join(",")}: ${cell}`);
    assert.ok(peak() <= MAX_LIVE_VMS);
  }
});

test("live sequence: a failed cell is reported and recovered, and later cells still run", async () => {
  let recovered = 0;
  const cap = new LiveVmCap();
  const results = await runLiveCells(LIVE_CELLS, {
    createSandbox: async (cell) => {
      cap.reserve();
      return cell;
    },
    l1: async () => {
      throw new Error("L1 broke");
    },
    l2: async () => cap.reserve(),
    l3: async () => undefined,
    recover: () => {
      recovered += 1;
    },
    describe: (error) => (error instanceof Error ? error.message : String(error)),
    log: () => undefined,
  });
  assert.deepEqual(
    [...results],
    [
      ["L1", "L1 broke"],
      ["L2", null],
      ["L3", null],
    ],
  );
  assert.equal(recovered, 1);
});

test("the D7 cap refuses a third create", () => {
  const cap = new LiveVmCap();
  cap.reserve();
  cap.reserve();
  assert.throws(() => cap.reserve(), /At most 2 VMs per run/);
});

test("L2 waits for the create dispatch by its wire kind, not the operation kind", () => {
  assert.deepEqual(L2_CREATE_DISPATCH, {
    dir: "s2n",
    type: "operation.dispatch",
    kind: OPERATION_DISPATCH_KIND.CREATE_SANDBOX,
  });
  assert.notEqual(L2_CREATE_DISPATCH.kind, "CREATE_SANDBOX");
});

test("only a binary that names the shared-Incus override (a debug build) is accepted", () => {
  assert.equal(honorsSharedIncusOverride(Buffer.from("\0x WSSP_TEST_SHARED_INCUS y\0")), true);
  assert.equal(honorsSharedIncusOverride(Buffer.from("\0WSSP_TEST_RELAY_TIMING\0")), false);
  assert.equal(honorsSharedIncusOverride(new Uint8Array()), false);
});

test("the default daemon binary is this checkout's debug build", () => {
  assert.ok(DEFAULT_WSSP_BIN.endsWith("/target/debug/wssp"), DEFAULT_WSSP_BIN);
  assert.ok(!DEFAULT_WSSP_BIN.includes(".local/bin"));
});
