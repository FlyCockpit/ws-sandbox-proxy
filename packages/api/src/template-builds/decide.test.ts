import { ORPCError } from "@orpc/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const {
  BUILD_ACTIONS,
  buildActionKey,
  buildKeyAttempt,
  chargedMinutes,
  classifyServiceError,
  decide,
  deadlineFailure,
  QUIESCE_HOLD_MAX_MS,
  quiesceHeldMs,
  retryBackoffMs,
} = await import("./decide");
const { buildAuthorityLost } = await import("./build-authority");
const { BuildContextPortError } = await import("./context-port");
const { TEMPLATE_BUILD_CAPTURE_DETAIL_ERROR_CODES } = await import("@wssp/sandbox-contracts");

type View = Parameters<typeof decide>[0];
type Obs = Parameters<typeof decide>[1];

const NOW = new Date("2026-11-03T12:00:00Z");
const limits = { now: NOW, contextSealedMaxMs: 6 * 3_600_000, contextIdleMs: 15 * 60_000 };
const minutes = (n: number) => new Date(NOW.getTime() + n * 60_000);

const view = (over: Partial<View> = {}): View => ({
  state: "RUNNING",
  phase: "step",
  stepIndex: 0,
  cancelRequestedAt: null,
  deadlineAt: minutes(30),
  captureDeadlineAt: null,
  createdAt: minutes(-5),
  hasContext: false,
  waitForCapacityMs: null,
  execSteps: 2,
  captureAttempt: 0,
  ...over,
});
const obs = (over: Partial<Obs> = {}): Obs => ({
  op: null,
  sandbox: null,
  capture: null,
  context: null,
  ...over,
});
const op = (state: string, extra: { errorCode?: string; exitCode?: number | null } = {}) => ({
  state: state as never,
  errorCode: extra.errorCode ?? null,
  exitCode: extra.exitCode ?? null,
  idempotencyKey: "tb:b1:run:0:0",
});
const capture = (
  state: string,
  extra: {
    opState?: string;
    errorCode?: string;
    errorDetail?: string;
    capturedAt?: Date;
    attempt?: number;
    revisionId?: string;
  } = {},
) => ({
  state: state as never,
  errorCode: extra.errorCode ?? null,
  errorDetail: extra.errorDetail ?? null,
  capturedAt: extra.capturedAt ?? null,
  opState: (extra.opState ?? "RUNNING") as never,
  attempt: extra.attempt ?? 0,
  revisionId: extra.revisionId ?? null,
});

describe("orchestrator keys (§3.3)", () => {
  it("has no cancel action; kill is the cleanup invariant's (r2 N2)", () => {
    expect(BUILD_ACTIONS).not.toContain("cancel");
    expect(BUILD_ACTIONS).toEqual(
      expect.arrayContaining([
        "create",
        "import",
        "context",
        "run",
        "stop",
        "timeout",
        "capture",
        "kill",
      ]),
    );
  });
  it("mints tb:<id>:<action>:<n>:<attempt> and reads the attempt back", () => {
    const key = buildActionKey("b1", "capture", 0, 2);
    expect(key).toBe("tb:b1:capture:0:2");
    expect(buildKeyAttempt(key)).toBe(2);
    expect(buildKeyAttempt("user-key")).toBeNull();
  });
});

describe("decision table (§3.2, §3.3)", () => {
  it("AWAITING_CONTEXT: sealed → QUEUED; ended → the context's own code; never opened → timeout", () => {
    const awaiting = view({ state: "AWAITING_CONTEXT", hasContext: true });
    expect(
      decide(
        awaiting,
        obs({ context: { state: "SEALED", transferId: null, errorCode: null } }),
        limits,
      ),
    ).toMatchObject({ kind: "transition", to: "QUEUED" });
    for (const code of ["build_context_timeout", "build_context_mismatch", "build_context_expired"])
      expect(
        decide(
          awaiting,
          obs({ context: { state: "EXPIRED", transferId: null, errorCode: code } }),
          limits,
        ),
      ).toEqual({ kind: "fail", failure: { errorCode: code } });
    expect(
      decide(
        awaiting,
        obs({ context: { state: "OPEN", transferId: null, errorCode: null } }),
        limits,
      ),
    ).toMatchObject({ kind: "wait" });
    expect(decide({ ...awaiting, createdAt: minutes(-16) }, obs(), limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_context_timeout" },
    });
  });

  it("QUEUED claims the create and moves to PLACING", () => {
    expect(decide(view({ state: "QUEUED" }), obs(), limits)).toMatchObject({
      kind: "claim",
      action: "create",
      attempt: 0,
      state: "PLACING",
    });
  });

  it("PLACING: READY → RUNNING (context first when there is one); create failed → placement failed", () => {
    const placing = view({ state: "PLACING", phase: "placing" });
    const ready = obs({ op: op("SUCCEEDED"), sandbox: { state: "READY", leaseExpiresAt: null } });
    expect(decide(placing, ready, limits)).toMatchObject({
      kind: "transition",
      to: "RUNNING",
      phase: "step",
      stepIndex: 0,
      ready: true,
    });
    expect(decide({ ...placing, hasContext: true }, ready, limits)).toMatchObject({
      phase: "context_import",
      stepIndex: -1,
    });
    for (const code of ["placement_infeasible", "capacity_wait_timeout", "provision_timeout"])
      expect(decide(placing, obs({ op: op("FAILED", { errorCode: code }) }), limits)).toEqual({
        kind: "fail",
        failure: { errorCode: "build_placement_failed", errorDetail: code },
      });
    expect(
      decide(
        placing,
        obs({ op: op("QUEUED"), sandbox: { state: "WAITING_FOR_CAPACITY", leaseExpiresAt: null } }),
        limits,
      ),
    ).toEqual({ kind: "wait", phase: "waiting_for_capacity" });
  });

  it("context: import while SEALED, commit once ADOPTED, PUT_FILE failure ends the build", () => {
    const importing = view({ phase: "context_import", hasContext: true, stepIndex: -1 });
    expect(
      decide(
        importing,
        obs({ context: { state: "SEALED", transferId: null, errorCode: null } }),
        limits,
      ),
    ).toMatchObject({ kind: "claim", action: "import" });
    expect(
      decide(
        importing,
        obs({ context: { state: "ADOPTED", transferId: "t1", errorCode: null } }),
        limits,
      ),
    ).toMatchObject({ kind: "transition", phase: "context_commit" });
    const committing = view({ phase: "context_commit", hasContext: true, stepIndex: -1 });
    expect(decide(committing, obs(), limits)).toMatchObject({ kind: "claim", action: "context" });
    expect(decide(committing, obs({ op: op("SUCCEEDED") }), limits)).toMatchObject({
      phase: "step",
      stepIndex: 0,
    });
    expect(
      decide(committing, obs({ op: op("FAILED", { errorCode: "sha_mismatch" }) }), limits),
    ).toEqual({
      kind: "fail",
      failure: { errorCode: "build_context_failed", errorDetail: "sha_mismatch" },
    });
  });

  it("run steps: exit 0 → next; exit ≠ 0 → step_failed + tail; timeout; anything else is unknown (never retried)", () => {
    const step = view({ stepIndex: 1 });
    expect(decide(step, obs(), limits)).toMatchObject({
      kind: "claim",
      action: "run",
      n: 1,
      attempt: 0,
    });
    expect(decide(step, obs({ op: op("SUCCEEDED", { exitCode: 0 }) }), limits)).toMatchObject({
      kind: "transition",
      stepIndex: 2,
    });
    expect(decide(step, obs({ op: op("SUCCEEDED", { exitCode: 3 }) }), limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_step_failed", failureExitCode: 3, tail: true },
    });
    expect(decide(step, obs({ op: op("FAILED", { errorCode: "timeout" }) }), limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_step_timeout", tail: true },
    });
    // D8: a step the host stopped at its `max_carry` cap fails explicitly.
    expect(
      decide(step, obs({ op: op("FAILED", { errorCode: "host_disconnect_expired" }) }), limits),
    ).toEqual({
      kind: "fail",
      failure: { errorCode: "build_step_host_disconnected", tail: true },
    });
    for (const state of ["UNKNOWN_OUTCOME", "CANCELLED", "FAILED"])
      expect(
        decide(step, obs({ op: op(state, { errorCode: "host_lost" }) }), limits),
      ).toMatchObject({
        kind: "fail",
        failure: { errorCode: "build_step_unknown" },
      });
    expect(decide(step, obs({ op: op("RUNNING") }), limits)).toEqual({
      kind: "wait",
      phase: "step",
    });
  });

  it("after the last step: lease re-anchor, then STOPPING, stop, then CAPTURING", () => {
    expect(decide(view({ stepIndex: 2 }), obs(), limits)).toMatchObject({
      kind: "transition",
      phase: "lease",
    });
    expect(decide(view({ phase: "lease", stepIndex: 2 }), obs(), limits)).toMatchObject({
      kind: "claim",
      action: "timeout",
    });
    expect(
      decide(view({ phase: "lease", stepIndex: 2 }), obs({ op: op("QUEUED") }), limits),
    ).toMatchObject({
      kind: "transition",
      to: "STOPPING",
    });
    const stopping = view({ state: "STOPPING", phase: "stopping" });
    expect(decide(stopping, obs(), limits)).toMatchObject({ kind: "claim", action: "stop" });
    expect(
      decide(
        stopping,
        obs({ op: op("SUCCEEDED"), sandbox: { state: "STOPPED", leaseExpiresAt: null } }),
        limits,
      ),
    ).toMatchObject({ kind: "transition", to: "CAPTURING", stopped: true });
    expect(
      decide(
        stopping,
        obs({ op: op("FAILED"), sandbox: { state: "HOST_LOST", leaseExpiresAt: null } }),
        limits,
      ),
    ).toEqual({ kind: "fail", failure: { errorCode: "build_host_lost" } });
  });

  it("deadline passed while a step is in flight: build_timeout (the cleanup kill ends the step)", () => {
    const late = view({ deadlineAt: minutes(-1) });
    expect(decide(late, obs({ op: op("RUNNING") }), limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_timeout" },
    });
    expect(deadlineFailure(late, obs(), limits)).toEqual({ errorCode: "build_timeout" });
  });

  it("WP7: a step held by a quiescing host extends the deadline by the hold", () => {
    const late = view({ deadlineAt: minutes(-1) });
    expect(deadlineFailure({ ...late, quiesceHeldMs: 2 * 60_000 }, obs(), limits)).toBeNull();
    expect(deadlineFailure({ ...late, quiesceHeldMs: 60_000 }, obs(), limits)).toEqual({
      errorCode: "build_timeout",
    });
  });

  it("WP7: held time runs from the later of the quiesce and the op, until its dispatch", () => {
    const run = (state: string, createdAt: Date, dispatchedAt: Date | null = null) => ({
      kind: "RUN_COMMAND",
      state: state as never,
      createdAt,
      dispatchedAt,
    });
    const since = minutes(-10);
    expect(quiesceHeldMs(since, run("QUEUED", minutes(-4)), NOW)).toBe(4 * 60_000);
    expect(quiesceHeldMs(since, run("QUEUED", minutes(-20)), NOW)).toBe(10 * 60_000);
    expect(quiesceHeldMs(since, run("DISPATCHED", minutes(-4), minutes(-1)), NOW)).toBe(3 * 60_000);
    // Dispatched before the quiesce began, not held; nor ended undispatched.
    expect(quiesceHeldMs(since, run("DISPATCHED", minutes(-20), minutes(-15)), NOW)).toBe(0);
    expect(quiesceHeldMs(since, run("FAILED", minutes(-4)), NOW)).toBe(0);
    // Not quiescing, no op, or work the hold never applies to.
    expect(quiesceHeldMs(null, run("QUEUED", minutes(-4)), NOW)).toBe(0);
    expect(quiesceHeldMs(since, null, NOW)).toBe(0);
    expect(quiesceHeldMs(since, { ...run("QUEUED", minutes(-4)), kind: "PUT_FILE" }, NOW)).toBe(0);
    // An orphaned marker credits at most QUIESCE_HOLD_MAX_MS.
    const old = minutes(-500);
    expect(quiesceHeldMs(old, run("QUEUED", minutes(-490)), NOW)).toBe(
      QUIESCE_HOLD_MAX_MS - 10 * 60_000,
    );
    expect(quiesceHeldMs(old, run("QUEUED", minutes(-400)), NOW)).toBe(0);
  });

  it("CAPTURING: capture rows, the unknown-outcome retry (≤ 2), store failure, lease backstop, window", () => {
    const capturing = view({
      state: "CAPTURING",
      phase: "capturing",
      captureDeadlineAt: minutes(30),
    });
    expect(decide(capturing, obs(), limits)).toMatchObject({
      kind: "claim",
      action: "capture",
      attempt: 0,
    });
    // A raised attempt whose capture is not linked yet replays THAT attempt.
    expect(decide({ ...capturing, captureAttempt: 1 }, obs(), limits)).toMatchObject({
      kind: "claim",
      action: "capture",
      attempt: 1,
    });
    expect(decide(capturing, obs({ capture: capture("PENDING") }), limits)).toMatchObject({
      kind: "wait",
    });
    expect(decide(capturing, obs({ capture: capture("STORING") }), limits)).toEqual({
      kind: "wait",
      phase: "storing",
    });
    expect(
      decide(
        capturing,
        obs({ capture: capture("FAILED", { opState: "UNKNOWN_OUTCOME" }) }),
        limits,
      ),
    ).toMatchObject({ kind: "claim", action: "capture", attempt: 1 });
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", { opState: "UNKNOWN_OUTCOME", attempt: 2 }),
        }),
        limits,
      ),
    ).toMatchObject({ kind: "fail", failure: { errorCode: "build_capture_failed" } });
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", { opState: "FAILED", errorCode: "capture_store_failed" }),
        }),
        limits,
      ),
    ).toEqual({ kind: "fail", failure: { errorCode: "build_store_failed", errorDetail: null } });
    // The capture's storage cause rides on the build failure (I4).
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", {
            opState: "FAILED",
            errorCode: "capture_store_failed",
            errorDetail: "upload_stalled",
          }),
        }),
        limits,
      ),
    ).toEqual({
      kind: "fail",
      failure: { errorCode: "build_store_failed", errorDetail: "upload_stalled" },
    });
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", { opState: "FAILED", errorCode: "capture_failed" }),
          sandbox: { state: "STOPPED", leaseExpiresAt: minutes(-1) },
        }),
        limits,
      ),
    ).toEqual({ kind: "fail", failure: { errorCode: "build_capture_lease_expired" } });
    // The window bounds captures without a host result, not recorded ones.
    const late = { ...capturing, captureDeadlineAt: minutes(-1) };
    expect(decide(late, obs({ capture: capture("PENDING") }), limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_capture_failed", errorDetail: "capture_deadline" },
    });
    expect(decide(late, obs({ capture: capture("CAPTURED") }), limits)).toMatchObject({
      kind: "wait",
    });
    // Past the window, a recorded capture whose storing then failed keeps
    // its store failure and cause; the window never relabels it.
    const storeFailed = { opState: "FAILED", errorCode: "capture_store_failed" };
    for (const failed of [
      capture("FAILED", {
        ...storeFailed,
        errorDetail: "upload_http_503",
        capturedAt: minutes(-40),
      }),
      capture("FAILED", { ...storeFailed, errorDetail: "upload_http_503" }),
    ])
      for (const build of [late, capturing])
        expect(decide(build, obs({ capture: failed }), limits)).toEqual({
          kind: "fail",
          failure: { errorCode: "build_store_failed", errorDetail: "upload_http_503" },
        });
    // A capture failed before its result (no capturedAt) still meets the window.
    expect(
      decide(
        late,
        obs({ capture: capture("FAILED", { opState: "FAILED", errorCode: "capture_failed" }) }),
        limits,
      ),
    ).toEqual({
      kind: "fail",
      failure: { errorCode: "build_capture_failed", errorDetail: "capture_deadline" },
    });
    // Within it, a host-reported storage cause names the capture failure.
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", {
            opState: "FAILED",
            errorCode: "capture_failed",
            errorDetail: "upload_export",
          }),
        }),
        limits,
      ),
    ).toEqual({
      kind: "fail",
      failure: { errorCode: "build_capture_failed", errorDetail: "upload_export" },
    });
    // An unknown outcome still retries with a new attempt, evidence or not.
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", { opState: "UNKNOWN_OUTCOME", errorDetail: "upload_export" }),
        }),
        limits,
      ),
    ).toMatchObject({ kind: "claim", action: "capture", attempt: 1 });
  });

  it("known capture evidence is never replaced by the window or the lease (I4)", () => {
    const capturing = view({
      state: "CAPTURING",
      phase: "capturing",
      captureDeadlineAt: minutes(30),
    });
    const late = { ...capturing, captureDeadlineAt: minutes(-1) };
    const failedEarly = (errorDetail?: string) =>
      capture("FAILED", {
        opState: "FAILED",
        errorCode: "capture_failed",
        ...(errorDetail ? { errorDetail } : {}),
      });
    const fail = (errorCode: string, errorDetail?: string | null) => ({
      kind: "fail",
      failure: errorDetail === undefined ? { errorCode } : { errorCode, errorDetail },
    });
    // Pre-result window: export evidence keeps its code, store evidence
    // becomes a store failure, none stays `capture_deadline`.
    for (const [row, expected] of [
      [
        capture("PENDING", { errorDetail: "upload_export" }),
        fail("build_capture_failed", "upload_export"),
      ],
      [failedEarly("upload_export"), fail("build_capture_failed", "upload_export")],
      [
        capture("PENDING", { errorDetail: "upload_http_503" }),
        fail("build_store_failed", "upload_http_503"),
      ],
      [failedEarly("store_unavailable"), fail("build_store_failed", "store_unavailable")],
      [capture("PENDING"), fail("build_capture_failed", "capture_deadline")],
      [failedEarly(), fail("build_capture_failed", "capture_deadline")],
    ] as const)
      expect(decide(late, obs({ capture: row }), limits)).toEqual(expected);
    // Expired lease: the same rule; without evidence the lease code alone.
    const expired = { state: "STOPPED", leaseExpiresAt: minutes(-1) };
    for (const [row, expected] of [
      [failedEarly("upload_export"), fail("build_capture_lease_expired", "upload_export")],
      [failedEarly("upload_reset"), fail("build_store_failed", "upload_reset")],
      [failedEarly(), fail("build_capture_lease_expired")],
    ] as const)
      expect(decide(capturing, obs({ capture: row, sandbox: expired }), limits)).toEqual(expected);
    // An unknown outcome inside the window still retries with a new attempt.
    expect(
      decide(
        capturing,
        obs({
          capture: capture("FAILED", { opState: "UNKNOWN_OUTCOME", errorDetail: "upload_reset" }),
          sandbox: expired,
        }),
        limits,
      ),
    ).toMatchObject({ kind: "claim", action: "capture", attempt: 1 });
  });

  it("every failure that carries a capture's detail uses a code the dashboard explains", () => {
    const codes: ReadonlySet<string> = new Set(TEMPLATE_BUILD_CAPTURE_DETAIL_ERROR_CODES);
    const seen = new Set<string>();
    for (const deadline of [minutes(30), minutes(-1)])
      for (const sandbox of [undefined, { state: "STOPPED", leaseExpiresAt: minutes(-1) }])
        for (const state of ["PENDING", "CAPTURED", "STORING", "FAILED"])
          for (const errorCode of ["capture_failed", "capture_store_failed"])
            for (const errorDetail of ["upload_export", "upload_http_503", "store_deadline"]) {
              const decision = decide(
                view({ state: "CAPTURING", phase: "capturing", captureDeadlineAt: deadline }),
                obs({
                  capture: capture(state, { opState: "FAILED", errorCode, errorDetail }),
                  ...(sandbox ? { sandbox } : {}),
                }),
                limits,
              );
              if (decision.kind !== "fail" || decision.failure.errorDetail !== errorDetail)
                continue;
              seen.add(decision.failure.errorCode);
              expect(codes.has(decision.failure.errorCode)).toBe(true);
            }
    // Every listed code is reached, so the list is exactly what decide emits.
    expect([...seen].sort()).toEqual([...codes].sort());
  });

  it("cancel vs finalizer (r3 N22): a recorded host result waits for the finalizer; otherwise CANCELLED", () => {
    const cancelling = view({ state: "CANCELLING", cancelRequestedAt: minutes(-1) });
    for (const state of ["PENDING", "CAPTURED", "STORING"])
      expect(decide(cancelling, obs({ capture: capture(state) }), limits)).toEqual({
        kind: "wait",
      });
    expect(decide(cancelling, obs({ capture: capture("FAILED") }), limits)).toEqual({
      kind: "cancelled",
    });
    expect(decide(cancelling, obs(), limits)).toEqual({ kind: "cancelled" });
    expect(
      decide(cancelling, obs({ capture: capture("FINALIZED", { revisionId: "r1" }) }), limits),
    ).toMatchObject({ kind: "transition", to: "SUCCEEDED", revisionId: "r1" });
    // A cancel never claims an action (no operation is ever cancelled).
    expect(
      decide({ ...cancelling, state: "CANCELLING" }, obs({ op: op("RUNNING") }), limits).kind,
    ).not.toBe("claim");
  });

  it("the deadline spares the post-step lease phase; a stop is bounded by its window", () => {
    const late = minutes(-1);
    expect(
      decide(view({ phase: "lease", stepIndex: 2, deadlineAt: late }), obs(), limits),
    ).toMatchObject({ kind: "claim", action: "timeout" });
    const stopping = view({ state: "STOPPING", phase: "stopping", deadlineAt: minutes(-10) });
    expect(decide(stopping, obs({ op: op("DISPATCHED") }), limits)).toEqual({
      kind: "wait",
      phase: "stopping",
    });
    expect(
      decide({ ...stopping, captureDeadlineAt: late }, obs({ op: op("DISPATCHED") }), limits),
    ).toEqual({
      kind: "fail",
      failure: { errorCode: "build_internal", errorDetail: "stop_timeout" },
    });
    expect(decide({ ...stopping, deadlineAt: minutes(-61) }, obs(), limits)).toMatchObject({
      kind: "fail",
      failure: { errorDetail: "stop_timeout" },
    });
  });

  it("terminal builds decide nothing (the cleanup invariant owns their VM)", () => {
    for (const state of ["SUCCEEDED", "FAILED", "CANCELLED"] as const)
      expect(decide(view({ state }), obs(), limits)).toEqual({ kind: "wait" });
  });

  it("placing has a backstop beyond upload ceiling + wait", () => {
    const stuck = view({ state: "PLACING", phase: "placing", createdAt: minutes(-(6 * 60 + 16)) });
    expect(decide(stuck, obs({ op: op("QUEUED") }), limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_placement_failed", errorDetail: "placement_timeout" },
    });
  });
});

describe("retry classification (§3.3; typed build.authority_lost only, r2 N12)", () => {
  it("the typed code is terminal; a FORBIDDEN without it is ambiguous", () => {
    expect(classifyServiceError("run", buildAuthorityLost())).toEqual({
      kind: "terminal",
      failure: { errorCode: "build_authority_lost" },
    });
    const sameMessage = new ORPCError("FORBIDDEN", {
      message: "Build authority is no longer active.",
    });
    expect(classifyServiceError("run", sameMessage)).toEqual({ kind: "ambiguous" });
    expect(
      classifyServiceError(
        "run",
        new ORPCError("FORBIDDEN", { message: "Authority changed during request." }),
      ),
    ).toEqual({ kind: "ambiguous" });
  });

  it("unknown outcomes are ambiguous (replay the same key)", () => {
    expect(classifyServiceError("create", new Error("socket hang up"))).toEqual({
      kind: "ambiguous",
    });
    expect(classifyServiceError("create", new ORPCError("INTERNAL_SERVER_ERROR"))).toEqual({
      kind: "ambiguous",
    });
  });

  it("refusals before any effect are retryable", () => {
    expect(classifyServiceError("create", new ORPCError("SERVICE_UNAVAILABLE"))).toEqual({
      kind: "retryable",
    });
    expect(
      classifyServiceError(
        "capture",
        new ORPCError("CONFLICT", { data: { code: "sandbox.capture_busy" } }),
      ),
    ).toEqual({ kind: "retryable" });
    // E1-A-07: a capture waiting for host capacity names that blocker.
    expect(
      classifyServiceError(
        "capture",
        new ORPCError("CONFLICT", { data: { code: "sandbox.host_capacity", reason: "disk" } }),
      ),
    ).toEqual({ kind: "retryable", phase: "capture_waiting_capacity" });
    expect(classifyServiceError("import", new BuildContextPortError("busy", true))).toEqual({
      kind: "retryable",
    });
    expect(classifyServiceError("import", new BuildContextPortError("unbound", true))).toEqual({
      kind: "retryable",
    });
  });

  it("validation, policy and quota refusals end the build with the action's code", () => {
    expect(
      classifyServiceError(
        "capture",
        new ORPCError("CONFLICT", { data: { code: "sandbox.capture_policy_forbidden" } }),
      ),
    ).toEqual({
      kind: "terminal",
      failure: {
        errorCode: "build_capture_failed",
        errorDetail: "sandbox.capture_policy_forbidden",
      },
    });
    expect(
      classifyServiceError(
        "create",
        new ORPCError("CONFLICT", { data: { code: "template.build_no_builder" } }),
      ),
    ).toMatchObject({ kind: "terminal", failure: { errorCode: "build_placement_failed" } });
    expect(classifyServiceError("run", new ORPCError("BAD_REQUEST"))).toEqual({
      kind: "terminal",
      failure: { errorCode: "build_internal", errorDetail: "bad_request" },
    });
    expect(
      classifyServiceError(
        "import",
        new BuildContextPortError("missing", false, "build_context_expired"),
      ),
    ).toEqual({
      kind: "terminal",
      failure: { errorCode: "build_context_expired", errorDetail: "missing" },
    });
  });

  it("backs off 2 s → 60 s", () => {
    expect(retryBackoffMs(0)).toBe(2_000);
    expect(retryBackoffMs(1)).toBe(4_000);
    expect(retryBackoffMs(10)).toBe(60_000);
  });
});

describe("minutes (§3.3, r2 N15)", () => {
  it("charges READY → end rounded up, clamped to the reservation; nothing before READY", () => {
    expect(chargedMinutes(null, NOW, 30)).toBe(0);
    expect(chargedMinutes(minutes(-10), NOW, 30)).toBe(10);
    expect(chargedMinutes(new Date(NOW.getTime() - 61_000), NOW, 30)).toBe(2);
    expect(chargedMinutes(minutes(-45), NOW, 30)).toBe(30);
    expect(chargedMinutes(minutes(1), NOW, 30)).toBe(0);
  });
});

describe("community verify (community-base S9, review4 U9)", () => {
  const verifying = (over: Partial<View> = {}) =>
    view({
      state: "CAPTURING",
      phase: "verifying",
      verifyRequired: true,
      verifyDeadlineAt: minutes(5),
      ...over,
    });
  const finalized = capture("FINALIZED", { revisionId: "rev-1" });
  const vfacts = (over: Partial<NonNullable<Obs["verify"]>> = {}) => ({
    vm: null,
    createOp: null,
    smokeOp: null,
    revisionRetired: false,
    ...over,
  });

  it("the new action keys are distinct, with vkill outside the advance loop", () => {
    expect(BUILD_ACTIONS).toEqual(expect.arrayContaining(["vcreate", "vrun", "vkill"]));
    expect(buildActionKey("b1", "vkill", 0, 2)).toBe("tb:b1:vkill:0:2");
    expect(buildKeyAttempt("tb:b1:vcreate:0:3")).toBe(3);
  });

  it("no verify VM → vcreate; READY with no smoke → vrun; booting → wait", () => {
    expect(
      decide(verifying(), obs({ capture: finalized, verify: vfacts() }), limits),
    ).toMatchObject({ kind: "claim", action: "vcreate" });
    expect(
      decide(
        verifying(),
        obs({
          capture: finalized,
          verify: vfacts({
            vm: { state: "READY" },
            createOp: { state: "SUCCEEDED" as never, detail: null },
          }),
        }),
        limits,
      ),
    ).toMatchObject({ kind: "claim", action: "vrun" });
    expect(
      decide(
        verifying(),
        obs({
          capture: finalized,
          verify: vfacts({
            vm: { state: "PROVISIONING" },
            createOp: { state: "DISPATCHED" as never, detail: null },
          }),
        }),
        limits,
      ),
    ).toEqual({ kind: "wait", phase: "verifying" });
  });

  it("a recorded smoke result finishes: exit 0 passes, anything else fails with the tail", () => {
    const smoke = (state: string, exitCode: number | null) =>
      obs({
        capture: finalized,
        verify: vfacts({
          vm: { state: "READY" },
          createOp: { state: "SUCCEEDED" as never, detail: null },
          smokeOp: { state: state as never, exitCode },
        }),
      });
    expect(decide(verifying(), smoke("SUCCEEDED", 0), limits)).toEqual({
      kind: "verify_finish",
      pass: true,
    });
    expect(decide(verifying(), smoke("SUCCEEDED", 13), limits)).toEqual({
      kind: "verify_finish",
      pass: false,
      failure: { errorCode: "build_verify_failed", errorDetail: "smoke_failed", tail: true },
    });
    expect(decide(verifying(), smoke("UNKNOWN_OUTCOME", null), limits)).toMatchObject({
      kind: "verify_finish",
      pass: false,
    });
    // Recorded before the deadline: it still settles after it.
    expect(
      decide(verifying({ verifyDeadlineAt: minutes(-1) }), smoke("SUCCEEDED", 0), limits),
    ).toEqual({ kind: "verify_finish", pass: true });
  });

  it("past the deadline without a result → build_verify_failed", () => {
    const decision = decide(
      verifying({ verifyDeadlineAt: minutes(-1) }),
      obs({ capture: finalized, verify: vfacts({ vm: { state: "READY" } }) }),
      limits,
    );
    expect(decision).toEqual({
      kind: "fail",
      failure: { errorCode: "build_verify_failed", errorDetail: "verify_deadline" },
    });
  });

  it("a terminal verify VM or a failed create fails, carrying the readiness reason (L1)", () => {
    expect(
      decide(
        verifying(),
        obs({
          capture: finalized,
          verify: vfacts({
            vm: { state: "DELETED" },
            createOp: { state: "FAILED" as never, detail: "guest_restarts" },
          }),
        }),
        limits,
      ),
    ).toMatchObject({
      kind: "verify_finish",
      pass: false,
      failure: { errorCode: "build_verify_failed", errorDetail: "guest_restarts" },
    });
  });

  it("a manual retire during verify wins (D-L)", () => {
    expect(
      decide(
        verifying(),
        obs({ capture: finalized, verify: vfacts({ revisionRetired: true }) }),
        limits,
      ),
    ).toMatchObject({
      kind: "verify_finish",
      pass: false,
      failure: { errorDetail: "revision_retired" },
    });
  });

  it("cancel waits for the verify VM to die, then ends CANCELLED; never SUCCEEDED", () => {
    const cancelling = verifying({ state: "CANCELLING", cancelRequestedAt: minutes(-1) });
    expect(
      decide(
        cancelling,
        obs({ capture: finalized, verify: vfacts({ vm: { state: "READY" } }) }),
        limits,
      ),
    ).toEqual({ kind: "wait" });
    expect(
      decide(
        cancelling,
        obs({ capture: finalized, verify: vfacts({ vm: { state: "DELETED" } }) }),
        limits,
      ),
    ).toEqual({ kind: "cancelled" });
  });

  it("a user build's FINALIZED capture still succeeds directly", () => {
    expect(
      decide(view({ state: "CAPTURING", phase: "storing" }), obs({ capture: finalized }), limits),
    ).toEqual({ kind: "transition", to: "SUCCEEDED", phase: null, revisionId: "rev-1" });
  });

  it("a refused verify create retries (bounded by the deadline), a refused smoke is terminal", () => {
    const refused = new ORPCError("NOT_FOUND", { data: { code: "sandbox.template_not_found" } });
    expect(classifyServiceError("vcreate", refused)).toEqual({
      kind: "retryable",
      phase: "verifying",
    });
    expect(classifyServiceError("vrun", refused)).toMatchObject({
      kind: "terminal",
      failure: { errorCode: "build_verify_failed" },
    });
    expect(classifyServiceError("vcreate", buildAuthorityLost())).toMatchObject({
      kind: "terminal",
      failure: { errorCode: "build_authority_lost" },
    });
  });
});

describe("community upstream gone (S11)", () => {
  it("a community build VM create refused image_unavailable → build_upstream_unavailable", () => {
    const placing = view({ state: "PLACING", phase: "placing", verifyRequired: true });
    const failed = obs({ op: op("FAILED", { errorCode: "image_unavailable" }) });
    expect(decide(placing, failed, limits)).toEqual({
      kind: "fail",
      failure: { errorCode: "build_upstream_unavailable", errorDetail: "image_unavailable" },
    });
    expect(decide({ ...placing, verifyRequired: false }, failed, limits)).toMatchObject({
      kind: "fail",
      failure: { errorCode: "build_placement_failed" },
    });
  });
});

describe("host reconnecting (daemon restart during a step)", () => {
  it("sandbox.host_unavailable is retryable for every action, never a terminal failure", () => {
    const error = new ORPCError("CONFLICT", { data: { code: "sandbox.host_unavailable" } });
    for (const action of ["create", "run", "stop", "capture", "vcreate", "vrun"] as const)
      expect(classifyServiceError(action, error)).toEqual({ kind: "retryable" });
  });
});
