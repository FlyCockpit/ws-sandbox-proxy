import { randomUUID } from "node:crypto";
import type { PgTestDatabase } from "@wssp/db/testing/pg";
import { authenticateSdkKeySecret } from "../../lib/sdk-key-access";
import { SERVICE_SCOPES } from "../../lib/service-scopes";
import { sessionPrincipal } from "../contracts";
import { createSdkKey } from "../services/sdk-keys";
import { seedLaunchHost, seedMintSession, seedTemplateRevision } from "./resource-fixtures";

export async function poolFixture(db: PgTestDatabase) {
  const id = randomUUID();
  await db.inspect.user.create({
    data: {
      id,
      name: "Pool owner",
      email: `${id}@example.test`,
      twoFactorEnabled: true,
      emailVerified: true,
    },
  });
  const owner = await seedMintSession(db.inspect, sessionPrincipal(id));
  const hosts = await Promise.all(
    ["one", "two"].map((slug) =>
      seedLaunchHost(db.inspect, {
        data: {
          userId: id,
          slug,
          label: slug,
          status: "CONNECTED",
          egressEnforcement: true,
          // A current daemon: it reports `maxLeaseMs`, so pull-ins reach it.
          daemonLeasePolicy: true,
        },
      }),
    ),
  );
  const host = hosts[0]!;
  const other = hosts[1]!;
  const revision = await seedTemplateRevision(db.inspect, {
    data: {
      userId: id,
      sandboxHostId: host.id,
      slug: "base",
      label: "Base",
      incusFingerprint: `sha256:${"a".repeat(64)}`,
    },
  });
  const availability = await db.inspect.sandboxTemplateAvailability.findFirstOrThrow({
    where: { revisionId: revision.id, hostId: host.id },
  });
  const { id: _id, ...data } = availability;
  await db.inspect.sandboxTemplateAvailability.create({ data: { ...data, hostId: other.id } });
  const pool = await db.inspect.sandboxPool.create({
    data: { userId: id, slug: "pool", label: "Pool" },
  });
  for (const h of hosts)
    await db.inspect.sandboxPoolMember.create({
      data: { userId: id, hostOwnerId: id, poolId: pool.id, sandboxHostId: h.id },
    });
  const input = { template: "base", poolId: pool.id, idempotencyKey: randomUUID() };
  return { id, owner, host, other, hosts, revision, pool, input };
}
/** Mints the allowlist key without authenticating it: a concurrent authority
 * change (e.g. a racing pool deletion) correctly fails authentication closed,
 * so race tests about minting must not depend on it. */
export function mintPoolKey(
  f: Awaited<ReturnType<typeof poolFixture>>,
  pools = [f.pool.id],
  hosts = [f.host.id, f.other.id],
) {
  return createSdkKey(f.owner, {
    name: "pool-key",
    resourceMode: "ALLOWLIST",
    hostIds: hosts,
    templateRevisionIds: [f.revision.id],
    poolIds: pools,
    scopes: SERVICE_SCOPES.filter(
      // An allowlist key can hold neither webhooks:write (all-owned only) nor
      // credentials:use without an allowlisted login.
      (scope) => scope !== "webhooks:write" && scope !== "credentials:use",
    ),
  });
}

export async function poolKey(
  _db: PgTestDatabase,
  f: Awaited<ReturnType<typeof poolFixture>>,
  pools = [f.pool.id],
  hosts = [f.host.id, f.other.id],
) {
  const key = await mintPoolKey(f, pools, hosts);
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("Fixture SDK key inactive");
  return { ...key, principal };
}

export async function allOwnedPoolKey(f: Awaited<ReturnType<typeof poolFixture>>) {
  const key = await createSdkKey(f.owner, {
    name: "all-owned-pool-key",
    resourceMode: "ALL_OWNED",
    hostIds: [],
    templateRevisionIds: [],
    poolIds: [],
    scopes: [...SERVICE_SCOPES],
  });
  const principal = await authenticateSdkKeySecret(key.secret);
  if (!principal) throw new Error("Fixture SDK key inactive");
  return { ...key, principal };
}
