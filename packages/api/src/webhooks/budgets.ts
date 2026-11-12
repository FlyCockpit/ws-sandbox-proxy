/**
 * Webhook spend budgets (fail-closed, Redis-backed). Consumed inside the shared
 * service functions, so the browser (oRPC) and `/v1` share one count per owner.
 * Test-send and redeliver create outbound traffic, so they also bound per
 * endpoint: neither can become a traffic amplifier against one receiver.
 */
function budget(name: string, points: number, durationSeconds: number) {
  let consume: ((key: string) => Promise<void>) | undefined;
  return async (key: string) => {
    const { createProcedureBudget } = await import("../lib/procedure-budget");
    consume ??= createProcedureBudget({
      keyPrefix: `webhook-${name}`,
      points,
      durationSeconds,
      failClosed: true,
      redactErrors: true,
      overBudgetMessage: () => "Too many webhook actions.",
      unavailableMessage: "Webhook budget is unavailable.",
      unavailableLog: "Webhook budget unavailable",
    });
    return consume(key);
  };
}

const writeMinute = budget("write-minute", 20, 60);
const writeDay = budget("write-day", 200, 86_400);
const testMinute = budget("test-minute", 5, 60);
const testDay = budget("test-day", 50, 86_400);
const testEndpointMinute = budget("test-endpoint-minute", 2, 60);
const redeliverMinute = budget("redeliver-minute", 30, 60);
const redeliverDay = budget("redeliver-day", 300, 86_400);

/** Create, update, delete, rotate and enable/disable. */
export async function consumeWebhookWrite(ownerId: string): Promise<void> {
  await writeMinute(ownerId);
  await writeDay(ownerId);
}

export async function consumeWebhookTest(ownerId: string, endpointId: string): Promise<void> {
  await testMinute(ownerId);
  await testDay(ownerId);
  await testEndpointMinute(endpointId);
}

export async function consumeWebhookRedeliver(ownerId: string): Promise<void> {
  await redeliverMinute(ownerId);
  await redeliverDay(ownerId);
}
