import { ORPCError } from "@orpc/server";
import { createProcedureBudget } from "./procedure-budget";

const consumeExchangeBudget = createProcedureBudget({
  // Unchanged prefix: both exchanges share the host exchange's existing budget.
  keyPrefix: "host-device-exchange",
  points: 30,
  durationSeconds: 60,
  failClosed: true,
  overBudgetMessage: (seconds) => `Too many device exchanges. Retry in ${seconds} seconds.`,
  unavailableMessage: "Device exchange is temporarily unavailable.",
  unavailableLog: "[device-exchange] budget unavailable",
});

/** One per-IP budget across every device-code exchange. */
export async function consumeDeviceExchangeBudget(clientIp: string | undefined): Promise<void> {
  try {
    await consumeExchangeBudget(`ip:${clientIp ?? "unknown"}`);
  } catch (error) {
    if (
      error instanceof ORPCError &&
      error.code === "SERVICE_UNAVAILABLE" &&
      (error.data === undefined ||
        error.data === null ||
        typeof error.data !== "object" ||
        !("deviceFlowError" in error.data))
    ) {
      throw new ORPCError("SERVICE_UNAVAILABLE", {
        message: error.message,
        data: { deviceFlowError: "authorization_pending" },
        cause: error,
      });
    }
    throw error;
  }
}
