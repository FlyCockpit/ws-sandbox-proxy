import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { deviceDatabaseNow, rethrowDeviceTransactionError } from "./device-code-transitions";

/**
 * Shared by the two device-code exchanges (`hostCredentials.exchangeDeviceCode`
 * and `userLogins.exchangeDeviceCode`): one IP budget and one RFC 8628 poll
 * contract (authorization_pending / slow_down / access_denied / expired_token).
 */
type DeviceFlowError = "authorization_pending" | "slow_down" | "access_denied" | "expired_token";

function deviceFlowErrorData(deviceFlowError: DeviceFlowError): {
  deviceFlowError: DeviceFlowError;
} {
  return { deviceFlowError };
}

/**
 * `DeviceCode.pollingInterval` is in MILLISECONDS: Better Auth writes
 * `ms(opts.interval)` (5000 for the configured "5s") and compares it against
 * elapsed milliseconds in its own redeem path, while it tells the client the
 * interval in seconds.
 */
const DEFAULT_DEVICE_POLLING_INTERVAL_MS = 5_000;

function devicePendingError() {
  return new ORPCError("BAD_REQUEST", {
    message: "Device authorization is pending.",
    data: deviceFlowErrorData("authorization_pending"),
  });
}

export function deviceExpiredError() {
  return new ORPCError("BAD_REQUEST", {
    message: "Device code expired.",
    data: deviceFlowErrorData("expired_token"),
  });
}

export type PolledDeviceCode = {
  id: string;
  userId: string | null;
  lastPolledAt: Date | null;
  pollingInterval: number | null;
};

/**
 * The poll answer for a code that is not (yet) approved: records the poll and
 * returns pending, or slow_down when polled faster than its interval; deletes
 * and reports an expired or denied code. Always returns the error to throw.
 */
export async function pollUnapprovedDeviceCode(
  row: PolledDeviceCode,
): Promise<ORPCError<string, unknown>> {
  return prisma
    .$transaction(async (tx) => {
      await tx.$queryRaw`SELECT id FROM device_code WHERE id = ${row.id} FOR UPDATE`;
      const pollNow = await deviceDatabaseNow(tx);
      const intervalMs = row.pollingInterval ?? DEFAULT_DEVICE_POLLING_INTERVAL_MS;
      const tooFast =
        !!row.lastPolledAt && row.lastPolledAt.getTime() + intervalMs > pollNow.getTime();
      if (!tooFast) {
        const polled = await tx.deviceCode.updateMany({
          where: {
            id: row.id,
            status: "pending",
            userId: row.userId,
            lastPolledAt: row.lastPolledAt,
            expiresAt: { gt: pollNow },
          },
          data: { lastPolledAt: pollNow },
        });
        if (polled.count === 1) return devicePendingError();
      }
      // A CAS miss is a state transition, not disappearance. Read under the same lock.
      const current = await tx.deviceCode.findUnique({
        where: { id: row.id },
        select: { expiresAt: true, status: true, lastPolledAt: true },
      });
      if (!current) return new ORPCError("NOT_FOUND", { message: "Device code not found." });
      const currentNow = await deviceDatabaseNow(tx);
      const lockedTooFast =
        !!current.lastPolledAt &&
        current.lastPolledAt.getTime() + intervalMs > currentNow.getTime();
      if (current.expiresAt <= currentNow) {
        await tx.deviceCode.deleteMany({ where: { id: row.id, expiresAt: { lte: currentNow } } });
        return deviceExpiredError();
      }
      if (current.status === "denied") {
        await tx.deviceCode.deleteMany({ where: { id: row.id, status: "denied" } });
        return new ORPCError("FORBIDDEN", {
          message: "Device authorization denied.",
          data: deviceFlowErrorData("access_denied"),
        });
      }
      // Approval raced this poll: the next poll takes the mint path.
      if (!lockedTooFast || current.status === "approved") return devicePendingError();
      return new ORPCError("BAD_REQUEST", {
        message: "Device authorization polling too fast.",
        data: deviceFlowErrorData("slow_down"),
      });
    })
    .catch(rethrowDeviceTransactionError);
}
