import type { ProcedureBudgetOptions } from "../lib/procedure-budget";

// Metadata/service discovery must not initialize Redis or auth. One lazy promise
// per budget also makes concurrent first attempts share the same limiter.
function terminalBudget(options: ProcedureBudgetOptions) {
  let budget: Promise<(key: string) => Promise<void>> | undefined;
  return async (key: string) => {
    budget ??= import("../lib/procedure-budget").then(({ createProcedureBudget }) =>
      createProcedureBudget(options),
    );
    await (await budget)(key);
  };
}

const common = {
  failClosed: true,
  redactErrors: true,
  overBudgetMessage: (seconds: number) =>
    `Too many terminal attempts. Retry in ${seconds} seconds.`,
  unavailableMessage: "Terminal sessions are temporarily unavailable.",
  unavailableLog: "[terminal] budget unavailable",
};
export const consumeTerminalMintBudget = terminalBudget({
  ...common,
  keyPrefix: "sandbox-terminal-session",
  points: 20,
  durationSeconds: 60,
});
const day = terminalBudget({
  ...common,
  keyPrefix: "host-terminal-proof-day",
  points: 20,
  durationSeconds: 86400,
});
const minute = terminalBudget({
  ...common,
  keyPrefix: "host-terminal-proof-minute",
  points: 5,
  durationSeconds: 60,
});
export async function consumeHostProofBudget(userId: string) {
  // The daily attempt is charged even when the minute budget refuses.
  await day(`uid:${userId}`);
  await minute(`uid:${userId}`);
}
