/**
 * CLI-login spend budgets (fail-closed, Redis-backed), consumed inside the
 * shared services so the browser (oRPC) and `/v1` share one count per owner.
 * Value writes and re-pins decrypt/encrypt up to 4 MiB bundles, so they get
 * their own, tighter budgets.
 */
function budget(name: string, points: number, durationSeconds: number) {
  let consume: ((key: string) => Promise<void>) | undefined;
  return async (key: string) => {
    const { createProcedureBudget } = await import("../lib/procedure-budget");
    consume ??= createProcedureBudget({
      keyPrefix: `credential-${name}`,
      points,
      durationSeconds,
      failClosed: true,
      redactErrors: true,
      overBudgetMessage: () => "Too many login actions.",
      unavailableMessage: "Login budget is unavailable.",
      unavailableLog: "Credential budget unavailable",
    });
    return consume(key);
  };
}

// A dashboard session that sets up a login with a few accounts and instances
// and pauses one issues on the order of 10-20 writes; 60/min leaves headroom.
const writeMinute = budget("write-minute", 60, 60);
const writeDay = budget("write-day", 1000, 86_400);
const valueMinute = budget("value-minute", 10, 60);
const valueDay = budget("value-day", 200, 86_400);
const repinMinute = budget("repin-minute", 3, 60);
const repinDay = budget("repin-day", 30, 86_400);

/** Definition, login, account and instance create/update/delete, and pause. */
export async function consumeCredentialWrite(ownerId: string): Promise<void> {
  await writeMinute(ownerId);
  await writeDay(ownerId);
}

/** Value upload (decodes, validates and encrypts a bundle). */
export async function consumeCredentialValueWrite(ownerId: string): Promise<void> {
  await valueMinute(ownerId);
  await valueDay(ownerId);
}

/** Re-pin (decrypts and re-encrypts every instance value of a login). */
export async function consumeCredentialRepin(ownerId: string): Promise<void> {
  await repinMinute(ownerId);
  await repinDay(ownerId);
}

// Live attach / free: each dispatches a host operation that installs or
// captures a bundle. A dashboard user toggling a few logins on a few sandboxes
// stays far inside 20 per minute.
const attachMinute = budget("attach-minute", 20, 60);
const attachDay = budget("attach-day", 500, 86_400);

/** Live attach and free (each dispatches a host operation that moves a bundle). */
export async function consumeCredentialAttach(ownerId: string): Promise<void> {
  await attachMinute(ownerId);
  await attachDay(ownerId);
}

// Force-release and quarantine discard are recovery actions on a stuck
// instance: an owner clearing a handful of sandboxes after losing a host
// issues a few per minute; promotion decrypts and re-encrypts one value.
const forceReleaseMinute = budget("force-release-minute", 10, 60);
const forceReleaseDay = budget("force-release-day", 200, 86_400);
const discardMinute = budget("discard-minute", 10, 60);
const discardDay = budget("discard-day", 200, 86_400);

/** Force-release (optionally promoting a checkpoint). */
export async function consumeCredentialForceRelease(ownerId: string): Promise<void> {
  await forceReleaseMinute(ownerId);
  await forceReleaseDay(ownerId);
}

/** Owner "Discard rejected captures". */
export async function consumeCredentialDiscard(ownerId: string): Promise<void> {
  await discardMinute(ownerId);
  await discardDay(ownerId);
}

// One bundle grant decrypts up to a 4.6 MiB value. A host starting a few
// sandboxes with eight logins each, plus a daemon restart re-requesting env,
// stays well inside 60 grants per minute (the plan's §6 budget).
const bundleMinute = budget("bundle-minute", 60, 60);

/** One bundle grant (install or restore) per host. */
export async function consumeCredentialBundle(hostId: string): Promise<void> {
  await bundleMinute(hostId);
}

// Login sessions (§11): each start creates a managed sandbox (it also spends
// the create budget); ≤ 2 run at once. A user retrying a few logins in a
// sitting stays inside 6 starts per minute. Finish, verify and cancel each
// dispatch one host operation and share the attach/free budget.
const loginMinute = budget("login-minute", 6, 60);
const loginDay = budget("login-day", 100, 86_400);

/** Starting a login session. */
export async function consumeCredentialLogin(ownerId: string): Promise<void> {
  await loginMinute(ownerId);
  await loginDay(ownerId);
}
