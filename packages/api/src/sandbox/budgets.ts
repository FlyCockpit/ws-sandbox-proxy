import { env } from "@wssp/env/server";
import { createProcedureBudget } from "../lib/procedure-budget";
import { rpcRateFamily } from "../lib/rate-limit-families";

const common = {
  failClosed: true,
  redactErrors: true,
  overBudgetMessage: (seconds: number) => `Too many sandbox actions. Retry in ${seconds} seconds.`,
  unavailableMessage: "Sandbox action budget is unavailable.",
  unavailableLog: "Sandbox action budget unavailable",
};
let launch: ((key: string) => Promise<void>) | undefined;
export function consumeCreateConnectBudget(ownerId: string) {
  launch ??= createProcedureBudget({
    ...common,
    keyPrefix: "sandbox-create-connect",
    points: env.SANDBOX_CREATE_CONNECT_BUDGET_POINTS,
    durationSeconds: env.SANDBOX_CREATE_CONNECT_BUDGET_WINDOW_SECONDS,
  });
  return launch(`uid:${ownerId}`);
}
/** Independent owner buckets, including all three guest-work families through
 * /v1. Racing preflight misses may charge twice; DB receipts alone own effects.
 * Existing lease/template/tag/pool keys and budgets stay unchanged. */
const FAMILY_POINTS = {
  lease: 100,
  template: 100,
  tag: 100,
  pool: 30,
  ordinary: 100,
  stdin: 600,
  termination: 30,
  /** Capture, publish-now, prune-now and image settings: each may start host work. */
  image: 30,
  /** Template-build acceptance, cancel and context (re)open (template-builds §7). */
  build: 30,
} as const;
const mutations = new Map<string, (key: string) => Promise<void>>();
export function consumeSandboxWriteBudget(ownerId: string, family: keyof typeof FAMILY_POINTS) {
  let budget = mutations.get(family);
  if (!budget) {
    budget = createProcedureBudget({
      ...common,
      keyPrefix: `sandbox-${family}`,
      ...rpcRateFamily({ points: FAMILY_POINTS[family], windowSeconds: 60 }),
    });
    mutations.set(family, budget);
  }
  return budget(`uid:${ownerId}`);
}

let imageGrant: ((key: string) => Promise<void>) | undefined;
/**
 * Per-host image grant budget (P2-8): every host-plane request that mints a
 * transfer, link or presigned URL (fetch, link renewal, upload begin and
 * continuation) spends one point. Fail-closed: grants are spend-bearing.
 */
export function consumeImageGrantBudget(hostId: string) {
  imageGrant ??= createProcedureBudget({
    ...common,
    keyPrefix: "image-grant",
    points: 240,
    durationSeconds: 60,
  });
  return imageGrant(`host:${hostId}`);
}
