import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const {
  BUILD_VM_DEAD_STATES,
  buildVmMustDie,
  buildVmMustDieSql,
  cleanupCandidatesSql,
  rotatingPage,
} = await import("./cleanup");

const BUILD_STATES = [
  "AWAITING_CONTEXT",
  "QUEUED",
  "PLACING",
  "RUNNING",
  "STOPPING",
  "CAPTURING",
  "CANCELLING",
  "SUCCEEDED",
  "FAILED",
  "CANCELLED",
] as const;
const CAPTURE_STATES = [null, "PENDING", "CAPTURED", "STORING", "FINALIZED", "FAILED"] as const;

/** §3.10: killed when the build is missing, terminal, CANCELLING (unless a
 * capture recorded before the cancel is still storing), or CAPTURING with the
 * capture FINALIZED (its image stored). */
function expected(
  state: (typeof BUILD_STATES)[number],
  capture: (typeof CAPTURE_STATES)[number],
  marked: boolean,
  verifyRequired: boolean,
) {
  if (["SUCCEEDED", "FAILED", "CANCELLED"].includes(state)) return true;
  if (state === "CANCELLING")
    // A user build's recorded result wins over the cancel and its upload
    // needs the VM; a community build's cancel always wins (S9).
    return verifyRequired || !((capture === "CAPTURED" || capture === "STORING") && !marked);
  return (
    state === "CAPTURING" &&
    // The VM outlives the S3 upload (CAPTURED/STORING): only FINALIZED frees it.
    capture === "FINALIZED"
  );
}

describe("builds are never offloaded (offload plan R15.1, §10 C7)", () => {
  it("no build or verify purpose is offloadable, so cleanup never meets OFFLOADED", async () => {
    const { OFFLOADABLE_SANDBOX_PURPOSES } = await import("../sandbox/managed-sandbox");
    expect(OFFLOADABLE_SANDBOX_PURPOSES).not.toContain("TEMPLATE_BUILD");
    expect(OFFLOADABLE_SANDBOX_PURPOSES).not.toContain("TEMPLATE_VERIFY");
    expect(OFFLOADABLE_SANDBOX_PURPOSES).toEqual(["WORKLOAD"]);
  });
});

describe("cleanup predicate (§3.10, r3 N18)", () => {
  it("a missing build row kills its VM", () => {
    expect(buildVmMustDie(null)).toBe(true);
  });

  for (const state of BUILD_STATES)
    for (const captureState of CAPTURE_STATES)
      for (const marked of [false, true])
        for (const verifyRequired of [false, true])
          it(`${verifyRequired ? "community " : ""}${state} with capture ${captureState ?? "none"}${marked ? " (cancel-marked)" : ""} → ${expected(state, captureState, marked, verifyRequired)}`, () => {
            expect(
              buildVmMustDie({ state, captureState, captureCancelMarked: marked, verifyRequired }),
            ).toBe(expected(state, captureState, marked, verifyRequired));
          });

  it("the SQL builder encodes the same tables (missing row, dead states, recorded capture)", () => {
    const sql = buildVmMustDieSql();
    expect(sql.sql).toContain("b.id IS NULL");
    expect(sql.sql).toContain("b.state::text = 'CAPTURING'");
    expect(sql.sql).toContain(`b.state::text = 'CANCELLING' AND (b."verifyRequired" OR NOT EXISTS`);
    expect(sql.sql).toContain(`c."buildCancelledAt" IS NULL`);
    expect(sql.sql).toContain(`c."operationId" = b."captureOperationId"`);
    expect(sql.values).toEqual([
      ...BUILD_VM_DEAD_STATES.filter((s) => s !== "CANCELLING"),
      "CAPTURED",
      "STORING",
      "FINALIZED",
    ]);
    // A live build never matches: no live state is a parameter.
    for (const live of ["AWAITING_CONTEXT", "QUEUED", "PLACING", "RUNNING", "STOPPING"])
      expect(sql.values).not.toContain(live);
  });

  it("the candidate query only sees live, killable build VMs and is bounded", () => {
    const sql = cleanupCandidatesSql();
    expect(sql.sql).toContain(`s."buildId" IS NOT NULL`);
    expect(sql.sql).toContain(`s.state::text <> 'DELETED'`);
    expect(sql.sql).toContain("LEFT JOIN sandbox_template_build b");
    expect(sql.sql).toMatch(/LIMIT \?/);
    expect(sql.values.at(-1)).toBe(32);
    expect(sql.values).toContain("WAITING_FOR_CAPACITY");
    expect(sql.values).not.toContain("STOPPING");
  });

  it("the candidate query continues after the cursor and wraps up to it", () => {
    const sql = cleanupCandidatesSql({ after: "b", upTo: "x", take: 5 });
    expect(sql.sql).toContain("AND s.id > ?");
    expect(sql.sql).toContain("AND s.id <= ?");
    expect(sql.values.slice(-3)).toEqual(["b", "x", 5]);
  });
});

describe("rotatingPage (§3.10 fairness)", () => {
  const ids = ["a", "b", "c", "d", "e"];
  const fetch = async ({
    after,
    upTo,
    take,
  }: {
    after: string | null;
    upTo: string | null;
    take: number;
  }) =>
    ids
      .filter((id) => (after === null || id > after) && (upTo === null || id <= upTo))
      .slice(0, take)
      .map((id) => ({ id }));

  it("visits every row within ceil(n / take) passes, even when none is ever removed", async () => {
    const cursor = { after: null as string | null };
    const seen: string[][] = [];
    for (let pass = 0; pass < 3; pass++)
      seen.push((await rotatingPage(cursor, 2, fetch)).map((row) => row.id));
    expect(seen).toEqual([
      ["a", "b"],
      ["c", "d"],
      ["e", "a"],
    ]);
  });

  it("visits all rows every pass when they fit in one page", async () => {
    const cursor = { after: "c" as string | null };
    expect((await rotatingPage(cursor, 10, fetch)).map((row) => row.id)).toEqual([
      "d",
      "e",
      "a",
      "b",
      "c",
    ]);
    expect(cursor.after).toBe("c");
  });
});

describe("verify-VM cleanup (community-base T2, review4 U2)", () => {
  it("a verify VM lives while its build verifies, dies when the build ends or is gone", async () => {
    const { verifyVmMustDie } = await import("./cleanup");
    expect(verifyVmMustDie(null)).toBe(true);
    for (const state of BUILD_STATES)
      expect(verifyVmMustDie({ state }), state).toBe(
        ["CANCELLING", "SUCCEEDED", "FAILED", "CANCELLED"].includes(state),
      );
    // The build VM must die in the same CAPTURING+FINALIZED state.
    expect(
      buildVmMustDie({
        state: "CAPTURING",
        captureState: "FINALIZED",
        captureCancelMarked: false,
        verifyRequired: false,
      }),
    ).toBe(true);
    expect(verifyVmMustDie({ state: "CAPTURING" })).toBe(false);
  });

  it("the candidate query branches the must-die rule by VM role", () => {
    const sql = cleanupCandidatesSql();
    expect(sql.sql).toContain(`COALESCE(s."buildId", s."verifyBuildId") AS "buildId"`);
    expect(sql.sql).toContain(`(s."verifyBuildId" IS NOT NULL) AS verify`);
    expect(sql.sql).toContain(`(s."verifyBuildId" IS NULL AND (b.id IS NULL`);
    expect(sql.sql).toContain(
      `(s."verifyBuildId" IS NOT NULL AND (b.id IS NULL OR b.state::text IN`,
    );
  });
});
