import prisma from "@wssp/db";
import { safeErrorLog } from "../sandbox/sensitive-errors";
import type { WebhookConfig } from "./config";
import { WebhookSecretUnavailableError } from "./crypto";
import { destinationHost } from "./destination-policy";
import { type AttemptResult, type DeliveryRequest, deliverOnce } from "./http-client";
import {
  type ClaimOutcome,
  claimDelivery,
  type EnqueueJobs,
  type RecordOutcome,
  recordAttempt,
  releaseEndpoints,
  signingKeys,
} from "./ledger";
import { webhookSignedHeaders } from "./signing";

/**
 * One webhook delivery job, end to end: claim (CAS), sign, send through the
 * SSRF-safe client, record, then release the endpoint's next due delivery into
 * the slot this attempt freed (a retry itself waits in Postgres until due, and
 * the dispatcher's poll is the backstop). Never throws on
 * a delivery outcome: the BullMQ job succeeds whatever the receiver did, so no
 * operational alert (which emails `err.message` to admins) can carry a URL.
 * Logs carry only ids, the destination host and an error class.
 */

export type DeliveryDeps = {
  config: WebhookConfig | null;
  enqueue: EnqueueJobs;
  /** Sends the disable notice; failures are logged, never rolled back. */
  notifyDisabled?: (input: {
    userId: string;
    host: string;
    consecutiveFailures: number;
  }) => Promise<void>;
  transport?: Pick<DeliveryRequest, "resolve" | "connect" | "ca" | "deadlineMs">;
  /** Test seam. Ledger times default to the DATABASE clock, never the worker's. */
  now?: () => Date;
  random?: () => number;
  client?: Parameters<typeof claimDelivery>[1]["client"];
};

export type DeliveryJobResult =
  | { outcome: "skipped"; reason: string }
  | { outcome: "deferred" }
  | { outcome: RecordOutcome["state"]; errorClass: string | null; statusCode: number | null };

export async function runDeliveryJob(
  job: { deliveryId: string; attempt: number; seq: number },
  deps: DeliveryDeps,
): Promise<DeliveryJobResult> {
  const clock = deps.now ?? (() => new Date());
  const client = deps.client ?? prisma;
  const claim: ClaimOutcome = await claimDelivery(job, {
    configured: deps.config !== null,
    privateScope: deps.config?.privateScope ?? "admins",
    client,
    now: deps.now?.(),
  });
  if (claim.kind === "skipped") {
    // A row that ended here (expired, cancelled) gave its slot back.
    if (claim.endpointId) await releaseNext(deps, client, claim.endpointId);
    return { outcome: "skipped", reason: claim.reason };
  }
  // Back in the Postgres backlog; the releaser hands it out again (no re-add).
  if (claim.kind === "deferred") return { outcome: "deferred" };
  const delivery = claim.delivery;
  const config = deps.config as WebhookConfig;
  const startedAt = clock();
  let result: AttemptResult;
  try {
    const keys = signingKeys(delivery, config.keys);
    const timestamp = Math.floor(startedAt.getTime() / 1000);
    result = await deliverOnce({
      url: delivery.url,
      body: delivery.body,
      headers: webhookSignedHeaders({
        keys,
        eventId: delivery.eventId,
        eventType: delivery.eventType,
        deliveryId: delivery.deliveryId,
        attempt: delivery.attempt,
        timestamp,
        body: delivery.body,
      }),
      allowlist: config.allowlist,
      ownerMayUsePrivate: delivery.ownerMayUsePrivate,
      ...deps.transport,
    });
  } catch (error) {
    // Only the key path can throw here: report "not configured", never count it.
    result = {
      statusCode: null,
      errorClass:
        error instanceof WebhookSecretUnavailableError ? "not_configured" : "protocol_error",
      resolvedAddress: null,
      responseExcerpt: null,
      retryAfterSeconds: null,
      durationMs: Math.max(0, clock().getTime() - startedAt.getTime()),
    };
  }
  const recorded = await recordAttempt(
    delivery,
    { startedAt, ...result },
    {
      client,
      now: deps.now?.(),
      random: deps.random?.(),
    },
  );
  await releaseNext(deps, client, delivery.endpointId);
  if (result.errorClass)
    console.warn(
      `[webhook-delivery] delivery ${delivery.deliveryId} attempt ${delivery.attempt} to ${destinationHost(delivery.url)}: ${result.errorClass}${result.statusCode ? ` (${result.statusCode})` : ""}`,
    );
  if (recorded.disabled && deps.notifyDisabled) {
    try {
      await deps.notifyDisabled({
        userId: recorded.disabled.userId,
        host: destinationHost(recorded.disabled.url),
        consecutiveFailures: recorded.disabled.consecutiveFailures,
      });
    } catch (error) {
      console.error(
        "[webhook-delivery] disable notice failed:",
        safeErrorLog(error, "webhook_disable_notice_failed"),
      );
    }
  }
  return { outcome: recorded.state, errorClass: result.errorClass, statusCode: result.statusCode };
}

/** Fill the endpoint's freed slot now. A failure only delays it to the next poll. */
async function releaseNext(
  deps: DeliveryDeps,
  client: NonNullable<DeliveryDeps["client"]>,
  endpointId: string,
): Promise<void> {
  try {
    await releaseEndpoints(deps.enqueue, [endpointId], { client, now: deps.now?.() });
  } catch (error) {
    console.error(
      "[webhook-delivery] release after attempt failed:",
      safeErrorLog(error, "webhook_release_failed"),
    );
  }
}
