import { createHash } from "node:crypto";

function budget(name: string, points: number, durationSeconds: number) {
  let consume: ((key: string) => Promise<void>) | undefined;
  return async (key: string) => {
    const { createProcedureBudget } = await import("../lib/procedure-budget");
    consume ??= createProcedureBudget({
      keyPrefix: `pool-sharing-${name}`,
      points,
      durationSeconds,
      failClosed: true,
      redactErrors: true,
      overBudgetMessage: () => "Too many sharing actions.",
      unavailableMessage: "Sharing budget is unavailable.",
      unavailableLog: "Sharing budget unavailable",
    });
    return consume(key);
  };
}
export const consumeSharingWrite = budget("write", 30, 60);
export const consumeInviteAccept = budget("accept", 10, 60);
/** Lease-lowering preview: a read-only policy join, budgeted per procedure
 * because one batched /rpc request can carry many calls. */
export const consumeLeasePreview = budget("lease-preview", 30, 60);
/** Pool capacity view (both planes): a bounded read joining every visible
 * member; 30/min per owner covers a dashboard refetching a few pools. */
export const consumePoolCapacityRead = budget("capacity-read", 30, 60);
const minute = budget("invite-minute", 5, 60);
const day = budget("invite-day", 50, 86400);
const recipient = budget("invite-recipient", 3, 3600);
const signup = budget("signup-issuer", 5, 86400);
export async function consumeInviteIssue(
  ownerId: string,
  poolId: string,
  email: string,
  signupAllowed: boolean,
) {
  await minute(ownerId);
  await day(ownerId);
  await recipient(
    createHash("sha256")
      .update(JSON.stringify([poolId, email]))
      .digest("hex"),
  );
  if (signupAllowed) await signup(ownerId);
}
