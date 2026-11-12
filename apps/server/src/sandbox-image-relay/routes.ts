import { authenticateSandboxHostWebsocketSecret } from "@wssp/api/lib/host-token-access";
import prisma from "@wssp/db";
import { IMAGE_RELAY_PART_BYTES } from "@wssp/sandbox-contracts";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { createRateLimiterMiddleware, imageRelayLimiter } from "../rate-limit.js";
import { transferAuthoritySelect, transferAuthorized } from "../sandbox-relay/image-authority.js";
import { linkTokenDigest } from "../sandbox-relay/image-handlers.js";
import { type ImageRelaySpool, SpoolError } from "./spool.js";

export const IMAGE_RELAY_ROUTE = "/host/image-relay";
/** Destination GET waits this long for the source's PUT of the same part. */
const PART_WAIT_MS = 60_000;

type Env = { Variables: { relayHost: { hostId: string; userId: string } } };

/**
 * Relayed peer image parts (host plane). Every request needs BOTH a host
 * credential (`wssp_host_` / `wssp_device_`, Authorization header) AND a
 * one-time link token (`X-Wssp-Image-Link` header, never in the path or query)
 * bound to that host and its current connection epoch. A link is consumed by
 * one `DELETE ... RETURNING`, so a replay finds nothing.
 *
 * Mounted before the global 10 MB body limit with its own 33 MiB limit and its
 * own per-host rate-limit bucket. Responses are `Content-Encoding: identity`
 * so a compressing proxy never re-encodes part bytes.
 */
export function createImageRelayApi(spool: () => ImageRelaySpool) {
  const app = new Hono<Env>();
  app.onError((error, c) => {
    if (error instanceof SpoolError) return c.json({ error: { code: error.code } }, error.status);
    return c.json({ error: { code: "INTERNAL_SERVER_ERROR" } }, 500);
  });
  app.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    c.header("Content-Encoding", "identity");
    await next();
  });
  app.use("*", async (c, next) => {
    const secret = /^Bearer (\S+)$/i.exec(c.req.header("authorization") ?? "")?.[1];
    const identity = secret ? await authenticateSandboxHostWebsocketSecret(secret) : null;
    if (!identity) return c.json({ error: { code: "UNAUTHORIZED" } }, 401);
    c.set("relayHost", { hostId: identity.hostId, userId: identity.userId });
    await next();
  });
  app.use(
    "*",
    createRateLimiterMiddleware(imageRelayLimiter, {
      failClosed: true,
      resolveKey: (c) => `host:${(c.get("relayHost") as { hostId: string }).hostId}`,
    }),
  );
  app.use(
    "*",
    bodyLimit({
      maxSize: IMAGE_RELAY_PART_BYTES + 1024 * 1024,
      onError: (c) => c.json({ error: { code: "PAYLOAD_TOO_LARGE" } }, 413),
    }),
  );

  async function consume(
    linkId: string,
    token: string | undefined,
    host: { hostId: string; userId: string },
    role: "SOURCE" | "DEST",
  ) {
    if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token) || !/^[A-Za-z0-9_-]{1,128}$/.test(linkId))
      return null;
    const rows = await prisma.$queryRaw<
      { transferId: string; partNumber: number; hostEpoch: number }[]
    >`DELETE FROM sandbox_image_link
      WHERE id = ${linkId} AND "tokenDigest" = ${linkTokenDigest(token)}
        AND "hostId" = ${host.hostId} AND role = ${role} AND "expiresAt" > (clock_timestamp() AT TIME ZONE 'UTC')
      RETURNING "transferId", "partNumber", "hostEpoch"`;
    const link = rows[0];
    if (!link) return null;
    const transfer = await prisma.sandboxImageTransfer.findFirst({
      where: {
        id: link.transferId,
        state: "OPEN",
        mode: "RELAY",
        ...(role === "SOURCE"
          ? { sourceHostId: host.hostId, sourceEpoch: link.hostEpoch }
          : { destHostId: host.hostId, destEpoch: link.hostEpoch }),
      },
      select: {
        id: true,
        sizeBytes: true,
        partSize: true,
        partCount: true,
        ...transferAuthoritySelect,
      },
    });
    const current = await prisma.sandboxHost.findFirst({
      where: { id: host.hostId, userId: host.userId, connectionEpoch: link.hostEpoch },
      select: { id: true },
    });
    if (!transfer || !current || link.partNumber > transfer.partCount) return null;
    // Every spool request re-checks the workload the link serves (P1-1).
    const authorized = await prisma.$transaction(async (tx) => {
      const [clock] = await tx.$queryRaw<
        { now: Date }[]
      >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
      return transferAuthorized(tx, transfer, clock!.now);
    });
    if (!authorized) return null;
    const start = BigInt(link.partNumber - 1) * BigInt(transfer.partSize);
    const remaining = transfer.sizeBytes - start;
    const size = Number(
      remaining < BigInt(transfer.partSize) ? remaining : BigInt(transfer.partSize),
    );
    return { transferId: transfer.id, part: link.partNumber, size };
  }

  app.put("/v1/parts/:linkId", async (c) => {
    const link = await consume(
      c.req.param("linkId"),
      c.req.header("x-wssp-image-link"),
      c.get("relayHost"),
      "SOURCE",
    );
    if (!link) return c.json({ error: { code: "NOT_FOUND" } }, 404);
    const declared = Number(c.req.header("content-length") ?? "-1");
    if (declared !== link.size) return c.json({ error: { code: "BAD_REQUEST" } }, 400);
    const spooled = await spool().put(link.transferId, link.part, link.size, c.req.raw.body);
    c.header("X-Wssp-Part-Sha256", spooled.sha256);
    return c.body(null, 204);
  });

  app.get("/v1/parts/:linkId", async (c) => {
    const link = await consume(
      c.req.param("linkId"),
      c.req.header("x-wssp-image-link"),
      c.get("relayHost"),
      "DEST",
    );
    if (!link) return c.json({ error: { code: "NOT_FOUND" } }, 404);
    const spooled = await spool().waitFor(link.transferId, link.part, PART_WAIT_MS);
    if (!spooled) return c.json({ error: { code: "PART_NOT_READY" } }, 409);
    c.header("Content-Type", "application/octet-stream");
    c.header("Content-Length", String(spooled.size));
    c.header("X-Wssp-Part-Sha256", spooled.sha256);
    return c.body(spool().read(spooled), 200);
  });

  app.all("*", (c) => c.json({ error: { code: "NOT_FOUND" } }, 404));
  return app;
}
