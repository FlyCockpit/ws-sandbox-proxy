import { createSandboxInput } from "@wssp/api/sandbox/contracts";
import { TRANSIENT_RESTORE_LOGIN_CODES } from "@wssp/api/sandbox/restore-login-codes";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import { describe, expect, it } from "vitest";

import {
  capacityWaitChoices,
  DEFAULT_SANDBOX_DRAFT,
  type DiskView,
  formatBytes,
  hasStoredCopy,
  IntentKeys,
  isCreateInputMistake,
  isGuestPath,
  isTransitional,
  LEASE_MAX_MS,
  leaseView,
  lifetimeOptions,
  newIntentKey,
  offersRestoreOverride,
  parseLabels,
  renewalInput,
  restoreLoginWait,
  type SandboxDraft,
  type SandboxState,
  sandboxActions,
  sandboxDraftInput,
  sandboxDraftProblems,
  sandboxHostView,
  sandboxLabels,
  sandboxPhase,
  sandboxProblem,
} from "./sandbox-rules";

const NOW = Date.parse("2026-09-26T12:00:00Z");
const ALL_STATES: SandboxState[] = [
  "REQUESTED",
  "SCHEDULED",
  "PROVISIONING",
  "READY",
  "STOPPING",
  "STOPPED",
  "RECLAIMING",
  "DELETED",
  "UNREACHABLE",
  "RECOVERED",
  "HOST_LOST",
  "ERROR",
  "WAITING_FOR_CAPACITY",
  "OFFLOADED",
];

const templates = [
  { id: "tpl-a", availability: [{ hostId: "host-a", status: "AVAILABLE" as const }] },
  { id: "tpl-b", availability: [{ hostId: "host-b", status: "AVAILABLE" as const }] },
];
const draft = (overrides: Partial<SandboxDraft> = {}): SandboxDraft => ({
  ...DEFAULT_SANDBOX_DRAFT,
  hostId: "host-a",
  templateId: "tpl-a",
  ...overrides,
});

describe("lifecycle controls follow the server's own state sets", () => {
  it.each(ALL_STATES)("%s offers only what the server would accept", (state) => {
    const actions = sandboxActions(state);
    expect(actions.has("stop")).toBe(
      ["REQUESTED", "SCHEDULED", "PROVISIONING", "READY", "RECOVERED"].includes(state),
    );
    // Renew, warm reconnect and files need a healthy guest.
    for (const action of ["renew", "reconnectWarm", "files"] as const)
      expect(actions.has(action), action).toBe(state === "READY");
    // OFFLOADED: the start restores the stored disk onto an eligible host.
    expect(actions.has("startCold")).toBe(state === "STOPPED" || state === "OFFLOADED");
    // Destroy is offered for every killable state; never for a deleted or stopping one.
    expect(actions.has("destroy")).toBe(
      !["DELETED", "STOPPING", "RECLAIMING", "HOST_LOST"].includes(state),
    );
  });

  it("every state has a label and a phase; only starting/stopping phases poll fast", () => {
    for (const state of ALL_STATES) {
      expect(enSandboxes.state[state], state).toBeTruthy();
      expect(esSandboxes.state[state], state).toBeTruthy();
      expect(isTransitional(state)).toBe(["starting", "stopping"].includes(sandboxPhase(state)));
    }
    expect(sandboxPhase("READY")).toBe("ready");
    expect(sandboxPhase("DELETED")).toBe("deleted");
  });
});

describe("host view", () => {
  const host = {
    status: "CONNECTED" as const,
    lastConnectedAt: new Date(NOW - 60_000),
    lastHeartbeatAt: new Date(NOW - 1_000),
    deletionRequestedAt: null,
  };
  it("online only while connected with a fresh heartbeat", () => {
    expect(sandboxHostView(host, NOW)).toBe("online");
    expect(sandboxHostView({ ...host, lastHeartbeatAt: new Date(NOW - 60_000) }, NOW)).toBe(
      "offline",
    );
    expect(sandboxHostView({ ...host, status: "DISCONNECTED" }, NOW)).toBe("offline");
    expect(sandboxHostView(null, NOW)).toBe("none");
  });
});

describe("requested versus host-acknowledged lifetime", () => {
  const at = new Date(NOW + 3_600_000);
  const base = {
    leaseRevision: 2,
    leaseExpiresAtRequested: at,
    leaseExpireActionRequested: "STOP" as const,
    leaseExpiresAtEffective: null,
    leaseExpireActionEffective: null,
  };
  it("pending until the host acknowledges; acknowledged only for the exact term", () => {
    expect(leaseView(base)).toMatchObject({
      revision: 2,
      requested: { expiresAt: at.getTime(), onExpire: "stop" },
      effective: null,
      ack: "pending",
    });
    expect(
      leaseView({
        ...base,
        leaseExpiresAtEffective: at.toISOString(),
        leaseExpireActionEffective: "STOP",
      }).ack,
    ).toBe("acknowledged");
    // The host still holds the previous term (an older expiry or action).
    expect(
      leaseView({
        ...base,
        leaseExpiresAtEffective: new Date(NOW + 60_000),
        leaseExpireActionEffective: "STOP",
      }).ack,
    ).toBe("differs");
    expect(
      leaseView({ ...base, leaseExpiresAtEffective: at, leaseExpireActionEffective: "DESTROY" })
        .ack,
    ).toBe("differs");
  });
});

describe("labels", () => {
  it("parses key=value lines and refuses malformed or repeated keys", () => {
    expect(parseLabels("")).toEqual({});
    expect(parseLabels(" team = infra \n\nenv=dev=1 ")).toEqual({ team: "infra", env: "dev=1" });
    expect(parseLabels("novalue")).toBeNull();
    expect(parseLabels("=x")).toBeNull();
    expect(parseLabels("a=1\na=2")).toBeNull();
  });

  it("a __proto__ key is kept as a key, so the server schema refuses it", () => {
    const parsed = parseLabels("__proto__=x");
    expect(parsed && Object.hasOwn(parsed, "__proto__")).toBe(true);
    expect(sandboxDraftProblems(draft({ labels: "__proto__=x" }), templates)).toContain("labels");
  });

  it("shows stored string labels sorted without coercion", () => {
    expect(sandboxLabels({ b: "2", a: "x", c: "", d: "true" })).toEqual([
      ["a", "x"],
      ["b", "2"],
      ["c", ""],
      ["d", "true"],
    ]);
  });
});

describe("create draft", () => {
  it("sends a non-blank name as typed and omits a blank one; an invalid name is a draft problem", () => {
    expect(sandboxDraftInput(draft({ name: "ci-runner" }), "k").name).toBe("ci-runner");
    expect(sandboxDraftInput(draft({ name: "" }), "k")).not.toHaveProperty("name");
    for (const bad of ["Bad_Name", "wssp-x", "-lead", "123e4567-e89b-12d3-a456-426614174000"])
      expect(sandboxDraftProblems(draft({ name: bad }), [{ id: "tpl-a" }])).toContain("name");
    expect(sandboxDraftProblems(draft({ name: "ok-name" }), [{ id: "tpl-a" }])).not.toContain(
      "name",
    );
  });

  it("maps name refusals to their own problems, as input mistakes", () => {
    for (const [code, problem] of [
      ["sandbox.name_taken", "nameTaken"],
      ["sandbox.name_invalid", "nameInvalid"],
    ] as const) {
      const error = { code: "CONFLICT", data: { code } };
      expect(sandboxProblem(error)).toBe(problem);
      expect(isCreateInputMistake(error)).toBe(true);
    }
  });

  it("accepts a pinned host and one of its templates, and builds the exact server input", () => {
    expect(sandboxDraftProblems(draft({ labels: "team=infra" }), templates)).toEqual([]);
    const input = sandboxDraftInput(
      draft({ labels: "team=infra", lifetimeMinutes: "120", onExpire: "destroy" }),
      "web.create.k1",
    );
    expect(input).toEqual({
      template: "revision/" + "tpl-a",
      sandboxHostId: "host-a",
      idempotencyKey: "web.create.k1",
      envs: {},
      metadata: { team: "infra" },
      egress: { mode: "open", domains: [], cidrs: [] },
      guestSudo: true,
      timeoutMs: 120 * 60_000,
      lifecycle: { onTimeout: "kill" },
    });
    expect(createSandboxInput.safeParse(input).success).toBe(true);
    expect(sandboxDraftInput(draft(), "k")).not.toHaveProperty("metadata");
  });

  it("guestSudo defaults on and is always sent, so the idempotency intent is explicit", () => {
    expect(DEFAULT_SANDBOX_DRAFT.guestSudo).toBe(true);
    expect(sandboxDraftInput(draft(), "k").guestSudo).toBe(true);
    expect(sandboxDraftInput(draft({ guestSudo: false }), "k").guestSudo).toBe(false);
  });

  it("egress always carries an explicit mode: open with fallback grants, or an allowlist", () => {
    const grants = { egressDomains: " example.com \n\n", egressCidrs: "8.8.8.8/32" };
    expect(sandboxDraftInput(draft(grants), "k").egress).toEqual({
      mode: "open",
      domains: ["example.com"],
      cidrs: ["8.8.8.8/32"],
    });
    expect(sandboxDraftInput(draft({ ...grants, internetAccess: false }), "k").egress).toEqual({
      mode: "allowlist",
      domains: ["example.com"],
      cidrs: ["8.8.8.8/32"],
    });
    expect(sandboxDraftInput(draft({ internetAccess: false }), "k").egress).toEqual({
      mode: "allowlist",
      domains: [],
      cidrs: [],
    });
    // An invalid list never silently falls back to open (or anything else).
    const invalid = draft({ egressDomains: "a".repeat(300) });
    expect(sandboxDraftProblems(invalid, templates)).toContain("egress");
    expect(() => sandboxDraftInput(invalid, "k")).toThrow();
  });

  it("maps egress refusal reasons to their own problems", () => {
    const refusal = (reason?: string) => ({
      data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress", reason },
    });
    expect(sandboxProblem(refusal("egress_guard_unavailable"))).toBe("egressGuardUnavailable");
    expect(sandboxProblem(refusal("open_egress_not_permitted"))).toBe("openEgressNotPermitted");
    expect(sandboxProblem(refusal())).toBe("hostNoEgress");
  });

  it.each([
    [{ hostId: "" }, "noHost"],
    [{ templateId: "" }, "noTemplate"],
    [{ templateId: "tpl-gone" }, "templateOffHost"],
    [{ lifetimeMinutes: "0" }, "lifetime"],
    [{ lifetimeMinutes: String(LEASE_MAX_MS / 60_000 + 1) }, "lifetime"],
    [{ labels: "nope" }, "labelsSyntax"],
    [{ labels: `k=${"v".repeat(1025)}` }, "labels"],
  ] as const)("refuses %j as %s", (overrides, problem) => {
    expect(sandboxDraftProblems(draft(overrides), templates)).toContain(problem);
  });

  it("every draft problem and refusal has copy in both locales", () => {
    for (const problem of [
      "noHost",
      "noTemplate",
      "templateOffHost",
      "lifetime",
      "labelsSyntax",
      "labels",
    ] as const) {
      expect(enSandboxes.draft[problem]).toBeTruthy();
      expect(esSandboxes.draft[problem]).toBeTruthy();
    }
    for (const problem of Object.keys(enSandboxes.problem)) {
      expect(esSandboxes.problem[problem as keyof typeof esSandboxes.problem]).toBeTruthy();
    }
  });
});

describe("renewal and guest paths", () => {
  it("builds relative lifetimes and refuses over-cap drafts without clamping", () => {
    expect(renewalInput("sbx", "60", "web.renew.k")).toEqual({
      id: "sbx",
      idempotencyKey: "web.renew.k",
      timeoutMs: 3_600_000,
    });
    expect(() => renewalInput("sbx", "10000", "k")).toThrow();
    expect(() => sandboxDraftInput(draft({ lifetimeMinutes: "10000" }), "k")).toThrow();
    // "No time limit" (0) is never a fallback: only an allowed, explicit choice.
    expect(() => sandboxDraftInput(draft({ lifetimeMinutes: "0" }), "k")).toThrow();
    expect(() => renewalInput("sbx", "0", "k")).toThrow();
    expect(() => sandboxDraftInput(draft({ lifetimeMinutes: "" }), "k")).toThrow();
  });

  it("bounds lifetimes by the target's policy limit and offers no limit only where allowed", () => {
    const six = { maxTimeoutMs: 21_600_000, allowUnlimited: false };
    expect(lifetimeOptions(six.maxTimeoutMs)).toEqual([5, 15, 30, 60, 120, 240]);
    expect(lifetimeOptions(2_073_600_000, true).at(-1)).toBe(0);
    expect(() => renewalInput("sbx", "480", "k", six)).toThrow();
    expect(renewalInput("sbx", "360", "k", six).timeoutMs).toBe(21_600_000);
    const open = { maxTimeoutMs: 2_073_600_000, allowUnlimited: true };
    expect(renewalInput("sbx", "0", "k", open).timeoutMs).toBe(0);
    expect(sandboxDraftInput(draft({ lifetimeMinutes: "0" }), "k", open).timeoutMs).toBe(0);
    expect(sandboxDraftInput(draft({ lifetimeMinutes: "2880" }), "k", open).timeoutMs).toBe(
      172_800_000,
    );
    expect(
      sandboxDraftProblems(draft({ lifetimeMinutes: "0" }), templates, 2_073_600_000, false),
    ).toContain("lifetime");
    expect(
      sandboxDraftProblems(draft({ lifetimeMinutes: "0" }), templates, 2_073_600_000, true),
    ).not.toContain("lifetime");
  });

  it("renders the far-future end as no time limit", () => {
    const view = leaseView({
      leaseRevision: 2,
      leaseExpiresAtRequested: "9999-12-31T23:59:59.999Z",
      leaseExpireActionRequested: "STOP",
      leaseExpiresAtEffective: "2030-01-01T00:00:00.000Z",
      leaseExpireActionEffective: "STOP",
    });
    expect(view.requested?.unlimited).toBe(true);
    expect(view.effective?.unlimited).toBe(false);
    expect(sandboxProblem({ data: { code: "lease_exceeds_policy", maxTimeoutMs: 1 } })).toBe(
      "leaseExceedsPolicy",
    );
  });

  it("accepts absolute guest paths without ..", () => {
    expect(isGuestPath("/home/user/a.txt")).toBe(true);
    expect(isGuestPath("home/user")).toBe(false);
    expect(isGuestPath("/home/../etc/passwd")).toBe(false);
    expect(isGuestPath("/a\0b")).toBe(false);
    expect(isGuestPath("")).toBe(false);
    // E-28: the guest file helper's rules.
    expect(isGuestPath("/home/user/my report.txt")).toBe(true);
    for (const bad of [
      // G4R1-1: refused, never trimmed.
      " /home/user/a.txt",
      "/home/user/a.txt ",
      "\t/home/user/a.txt",
      "\n/home/user/a.txt",
      "/home/user/./a.txt",
      "/.",
      "/",
      "//",
      "/a\nb",
      "/a\u007fb",
      "/a\ud800b",
      `/${"a".repeat(4096)}`,
    ])
      expect(isGuestPath(bad), JSON.stringify(bad)).toBe(false);
  });

  it("formats byte sizes with binary multiples and IEC units, one format everywhere (M7-S19)", () => {
    expect(formatBytes(1024 ** 3, "en-US")).toBe("1 GiB");
    expect(formatBytes(10 * 1024 ** 3, "en-US")).toBe("10 GiB");
    expect(formatBytes(1536, "en-US")).toBe("1.5 KiB");
    expect(formatBytes(12, "en-US")).toBe("12 B");
    expect(formatBytes(1536, "es-MX")).toBe("1.5 KiB");
    expect(formatBytes(300_000, "en-US")).toBe("293 KiB");
  });
});

describe("idempotency keys per intent", () => {
  it("a retry of the same intent reuses the key and the exact first input", () => {
    let n = 0;
    const keys = new IntentKeys(() => `r${++n}`);
    const first = keys.for("create", "draft-1", (key) => ({ key, at: Date.now() + n }));
    const again = keys.for("create", "draft-1", (key) => ({ key, at: -1 }));
    expect(again).toBe(first);
    expect(first.key).toBe("web.create.r1");
    // A different intent (changed draft or action) is a new request.
    expect(keys.for("create", "draft-2", (key) => key)).toBe("web.create.r2");
    expect(keys.for("stop", "draft-2", (key) => key)).toBe("web.stop.r3");
    // Once the server answered, the same click is a new intent.
    keys.settle();
    expect(keys.for("stop", "draft-2", (key) => key)).toBe("web.stop.r4");
  });

  it("keys satisfy the server's idempotency-key schema", () => {
    expect(newIntentKey("upload-commit", () => crypto.randomUUID())).toMatch(
      /^web\.upload-commit\.[0-9a-f-]{36}$/,
    );
  });
});

describe("refusal mapping", () => {
  const coded = (code: string, orpc = "CONFLICT") => ({ code: orpc, data: { code } });
  it.each([
    [coded("sandbox.state_conflict"), "stateChanged"],
    [coded("sandbox.invalid_transition"), "stateChanged"],
    [coded("sandbox.idempotency_conflict"), "keyReused"],
    [coded("sandbox.host_capacity"), "hostCapacity"],
    [coded("sandbox.host_draining"), "hostDraining"],
    [coded("sandbox.template_not_found", "NOT_FOUND"), "templateMissing"],
    [coded("sandbox.metadata_invalid", "BAD_REQUEST"), "labels"],
    // E-07: the host lacks egress enforcement — never "the request was not valid".
    [
      { code: "BAD_REQUEST", data: { code: "UNSUPPORTED_CAPABILITY", capability: "egress" } },
      "hostNoEgress",
    ],
    // Inverse: another capability, or none named, keeps the generic copy.
    [
      { code: "BAD_REQUEST", data: { code: "UNSUPPORTED_CAPABILITY", capability: "snapshot" } },
      "invalid",
    ],
    [coded("UNSUPPORTED_CAPABILITY", "BAD_REQUEST"), "invalid"],
    [{ code: "NOT_FOUND" }, "notFound"],
    [{ status: 409 }, "stateChanged"],
    [{ code: "BAD_REQUEST" }, "invalid"],
    [{ code: "FORBIDDEN" }, "forbidden"],
    [new Error("network"), "generic"],
  ] as const)("%j → %s", (error, problem) => {
    expect(sandboxProblem(error)).toBe(problem);
  });
});

it("form metadata stays string-only, rejects malformed drafts and preserves textual scalar lookalikes", () => {
  expect(
    sandboxDraftInput(draft({ labels: "count=0\nenabled=false\nempty=null" }), "k").metadata,
  ).toEqual({ count: "0", enabled: "false", empty: "null" });
  expect(() => sandboxDraftInput(draft({ labels: "duplicate=a\nduplicate=b" }), "k")).toThrow();
  for (const labels of ["key=" + "x".repeat(1025), "k\0=v", "constructor=x", "a=" + "\ud800"]) {
    expect(sandboxDraftProblems(draft({ labels }), templates)).toContain("labels");
    expect(() => sandboxDraftInput(draft({ labels }), "k")).toThrow();
  }
});

it("3D preserves private env whitespace/newlines and refuses identity, invalid and oversized maps", () => {
  const draft = {
    ...DEFAULT_SANDBOX_DRAFT,
    hostId: "h",
    templateId: "t",
    envs: JSON.stringify({ APP: " a\nb " }),
  };
  expect(sandboxDraftInput(draft, "env").envs).toEqual({ APP: " a\nb " });
  for (const envs of [
    '{"HOME":"private"}',
    '{"APP":1}',
    '{"APP":"\\u0000"}',
    JSON.stringify({ APP: "x".repeat(4097) }),
    "invalid",
  ]) {
    expect(
      sandboxDraftProblems({ ...draft, envs }, [
        { id: "t", availability: [{ hostId: "h", status: "AVAILABLE" as const }] },
      ]),
    ).toContain("envs");
  }
});

it("template identity is independent of placement and rejects retired or absent IDs", () => {
  expect(sandboxDraftProblems(draft({ templateId: "tpl-b" }), templates)).toEqual([]);
  expect(
    sandboxDraftInput(
      draft({ templateMode: "logical", templateId: "logical-a", hostId: "", poolId: "pool-a" }),
      "logical",
    ),
  ).toMatchObject({ template: "template/logical-a", poolId: "pool-a" });
  expect(sandboxDraftProblems(draft(), [{ id: "tpl-a", retiredAt: new Date() }])).toContain(
    "templateOffHost",
  );
  expect(
    sandboxDraftProblems(draft({ templateMode: "logical" }), [
      { id: "tpl-a", archivedAt: new Date() },
    ]),
  ).toContain("templateOffHost");
});

it.each([
  ["sandbox.pool_full", "poolFull"],
  ["sandbox.pool_no_compatible_host", "poolIncompatible"],
  ["sandbox.pool_unavailable", "poolUnavailable"],
  ["sandbox.pool_not_found", "poolMissing"],
  ["sandbox.host_capacity", "hostCapacity"],
  ["sandbox.host_unavailable", "hostUnavailable"],
  ["sandbox.host_draining", "hostDraining"],
  ["sandbox.disk_evicting", "diskEvicting"],
  ["sandbox.restoring", "restoring"],
  ["restore_no_allowed_host", "restoreNoAllowedHost"],
] as const)("maps %s before generic HTTP status", (code, problem) => {
  expect(sandboxProblem({ code: "CONFLICT", status: 409, data: { code } })).toBe(problem);
  expect(enSandboxes.problem[problem]).toBeTruthy();
  expect(esSandboxes.problem[problem]).toBeTruthy();
});

it("maps exact image absence to the missing-image explanation", () => {
  expect(
    sandboxProblem({ code: "CONFLICT", data: { code: "sandbox.template_image_missing" } }),
  ).toBe("imageMissing");
});

it.each([300_000, 900_000, 17 * 60_000, 3_600_000, LEASE_MAX_MS])(
  "lifetime options never exceed the advertised maximum %i",
  (max) => {
    expect(lifetimeOptions(max).length).toBeGreaterThan(0);
    expect(lifetimeOptions(max).every((minutes) => minutes * 60_000 <= max)).toBe(true);
  },
);
it("draft validation applies the deployment cap independently of the global ceiling", () => {
  expect(
    sandboxDraftProblems({ ...DEFAULT_SANDBOX_DRAFT, lifetimeMinutes: "30" }, [], 900_000),
  ).toContain("lifetime");
});

describe("independent VM size overrides", () => {
  it("omits blank fields, including whitespace, instead of filling global defaults", () => {
    for (const blank of ["", " "]) {
      const input = sandboxDraftInput(
        draft({ cpuCount: blank, memoryMiB: blank }),
        "web.size.blank",
      );
      expect(input).not.toHaveProperty("cpuCount");
      expect(input).not.toHaveProperty("memoryMiB");
    }
    expect(sandboxDraftInput(draft({ cpuCount: "2" }), "web.size.cpu")).toMatchObject({
      cpuCount: 2,
    });
    expect(sandboxDraftInput(draft({ cpuCount: "2" }), "web.size.cpu")).not.toHaveProperty(
      "memoryMiB",
    );
    expect(sandboxDraftInput(draft({ memoryMiB: "2048" }), "web.size.ram")).toMatchObject({
      memoryMiB: 2048,
    });
    expect(sandboxDraftInput(draft({ memoryMiB: "2048" }), "web.size.ram")).not.toHaveProperty(
      "cpuCount",
    );
  });
  it.each([
    [{ cpuCount: "0" }, "cpuCount"],
    [{ cpuCount: "33" }, "cpuCount"],
    [{ cpuCount: "1.5" }, "cpuCount"],
    [{ cpuCount: "1e1" }, "cpuCount"],
    [{ memoryMiB: "511" }, "memoryMiB"],
    [{ memoryMiB: "1025" }, "memoryMiB"],
    [{ memoryMiB: "65792" }, "memoryMiB"],
  ] as const)("rejects invalid overrides %j before IO", (overrides, problem) => {
    expect(sandboxDraftProblems(draft(overrides), templates)).toContain(problem);
    expect(() => sandboxDraftInput(draft(overrides), "web.size.invalid")).toThrow();
  });
  it.each([
    ["sandbox.vm_size_invalid", "sizeInvalid"],
    ["sandbox.vm_size_unsupported", "sizeUnsupported"],
    ["sandbox.vm_size_mismatch", "sizeMismatch"],
  ])("maps %s to safe typed copy", (code, problem) => {
    expect(sandboxProblem({ data: { code } })).toBe(problem);
  });
});

it("disk overrides inherit independently and reject non-integer/out-of-bounds roots", () => {
  const draft = { ...DEFAULT_SANDBOX_DRAFT, hostId: "h1", templateId: "t1", diskGiB: "48" };
  expect(sandboxDraftInput(draft, "disk")).toMatchObject({ diskGiB: 48 });
  expect(sandboxDraftInput(draft, "disk")).not.toHaveProperty("cpuCount");
  expect(sandboxDraftInput({ ...draft, diskGiB: "" }, "inherit")).not.toHaveProperty("diskGiB");
  for (const diskGiB of ["0", "2049", "1.5"])
    expect(sandboxDraftProblems({ ...draft, diskGiB }, [{ id: "t1" }])).toContain("diskGiB");
});

it.each([
  ["ram", "capacityRam"],
  ["vcpu", "capacityVcpu"],
  ["disk", "capacityDisk"],
  ["storage", "capacityStorage"],
  ["ceiling", "capacityCeiling"],
])("keeps capacity reason %s in browser copy", (reason, expected) => {
  for (const code of ["sandbox.host_capacity", "sandbox.pool_full"])
    expect(sandboxProblem({ data: { code, reason } })).toBe(expected);
  expect(sandboxProblem({ data: { code: "sandbox.state_conflict", reason } })).toBe("stateChanged");
});

describe("capacity wait (pool creates)", () => {
  it("offers only the choices the effective limit allows; unlimited only without any limit", () => {
    expect(capacityWaitChoices(null)).toEqual(["none", "15m", "1h", "4h", "24h", "unlimited"]);
    expect(capacityWaitChoices(3_600_000)).toEqual(["none", "15m", "1h"]);
    expect(capacityWaitChoices(0)).toEqual(["none"]);
  });

  it("sends waitForCapacityMs only for a pool target and a waiting choice", () => {
    const pooled = draft({ hostId: "", poolId: "pool-a", capacityWait: "1h" });
    expect(sandboxDraftInput(pooled, "k")).toMatchObject({
      poolId: "pool-a",
      waitForCapacityMs: 3_600_000,
    });
    expect(sandboxDraftInput({ ...pooled, capacityWait: "unlimited" }, "k")).toMatchObject({
      waitForCapacityMs: "unlimited",
    });
    expect(sandboxDraftInput({ ...pooled, capacityWait: "none" }, "k")).not.toHaveProperty(
      "waitForCapacityMs",
    );
    expect(sandboxDraftInput(draft({ capacityWait: "1h" }), "k")).not.toHaveProperty(
      "waitForCapacityMs",
    );
  });

  it("explains the queue refusals and reserved capacity", () => {
    const refusal = (data: Record<string, unknown>) => ({ code: "CONFLICT", data });
    expect(sandboxProblem(refusal({ code: "sandbox.pool_full", reason: "reserved" }))).toBe(
      "capacityReserved",
    );
    expect(sandboxProblem(refusal({ code: "sandbox.template_unavailable" }))).toBe(
      "templateUnavailable",
    );
    expect(sandboxProblem(refusal({ code: "sandbox.capacity_queue_full", scope: "key" }))).toBe(
      "queueFull",
    );
    expect(
      sandboxProblem({
        code: "BAD_REQUEST",
        data: { code: "capacity_wait_exceeds_policy", maxWaitMs: 0 },
      }),
    ).toBe("waitExceedsPolicy");
    expect(sandboxPhase("WAITING_FOR_CAPACITY")).toBe("waiting");
    expect(isTransitional("WAITING_FOR_CAPACITY")).toBe(false);
    expect(sandboxActions("WAITING_FOR_CAPACITY").has("destroy")).toBe(true);
  });
});

describe("disk offload (C8)", () => {
  const disk = (location: DiskView["location"]): DiskView => ({
    location,
    offloadState: location === "host" ? "none" : "stored",
    offloadFailure: null,
    offloadedAt: null,
    sizeBytes: null,
    eligibility: "any_host",
    offloadPin: "ANY",
  });

  it("a destroy deletes a stored copy whenever the store holds one", () => {
    expect(hasStoredCopy(null)).toBe(false);
    expect(hasStoredCopy(disk("host"))).toBe(false);
    expect(hasStoredCopy(disk("host_and_store"))).toBe(true);
    expect(hasStoredCopy(disk("store"))).toBe(true);
  });

  it("OFFLOADED is a stopped phase that offers restore and destroy, never stop", () => {
    const actions = sandboxActions("OFFLOADED");
    expect(sandboxPhase("OFFLOADED")).toBe("stopped");
    expect([...actions].sort()).toEqual(["destroy", "startCold"]);
  });

  it("offers the creator-allowlist override only after an OFFLOADED restore found no allowed host", () => {
    const failed = {
      kind: "RECONNECT_SANDBOX",
      state: "FAILED",
      errorCode: "restore_no_allowed_host",
    };
    expect(offersRestoreOverride("OFFLOADED", "restoreNoAllowedHost", null)).toBe(true);
    expect(offersRestoreOverride("OFFLOADED", null, failed)).toBe(true);
    expect(offersRestoreOverride("OFFLOADED", null, { ...failed, errorCode: "timeout" })).toBe(
      false,
    );
    expect(offersRestoreOverride("OFFLOADED", null, null)).toBe(false);
    expect(offersRestoreOverride("STOPPED", "restoreNoAllowedHost", failed)).toBe(false);
  });

  it("explains a restore whose wait ended on a transient login refusal", () => {
    const failed = (errorCode: string | null) => ({
      kind: "RECONNECT_SANDBOX",
      state: "FAILED",
      errorCode,
    });
    for (const code of TRANSIENT_RESTORE_LOGIN_CODES) {
      const key = restoreLoginWait("OFFLOADED", failed(code));
      expect(key, code).not.toBeNull();
      expect(enSandboxes.restoreLoginWait[key!], code).toBeTruthy();
      expect(esSandboxes.restoreLoginWait[key!], code).toBeTruthy();
    }
    expect(restoreLoginWait("OFFLOADED", failed("credential.busy"))).toBe("busy");
    expect(restoreLoginWait("OFFLOADED", failed("restore_no_allowed_host"))).toBeNull();
    expect(restoreLoginWait("OFFLOADED", failed("credential.not_attached"))).toBeNull();
    expect(restoreLoginWait("OFFLOADED", null)).toBeNull();
    expect(
      restoreLoginWait("OFFLOADED", { ...failed("credential.busy"), kind: "START_SANDBOX" }),
    ).toBeNull();
    expect(
      restoreLoginWait("OFFLOADED", { ...failed("credential.busy"), state: "SUCCEEDED" }),
    ).toBeNull();
    expect(restoreLoginWait("STOPPED", failed("credential.busy"))).toBeNull();
  });

  it("maps disk_unavailable to its own problem", () => {
    expect(
      sandboxProblem({ code: "CONFLICT", status: 409, data: { code: "sandbox.disk_unavailable" } }),
    ).toBe("diskUnavailable");
    expect(enSandboxes.problem.diskUnavailable).toBeTruthy();
  });
});
