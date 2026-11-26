/** Apply committed migrations through the relocated production runner, preserving domain invariants. */
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, expect, it } from "vitest";
import { pgTestDatabase } from "./testing/pg";

const db = await pgTestDatabase();
const root = resolve(import.meta.dirname, "../../..");
const dir = mkdtempSync(join(tmpdir(), "wssp-schema-migrations-"));
afterAll(async () => {
  await db.close();
  rmSync(dir, { recursive: true, force: true });
});
type PgResult = { rows: Record<string, unknown>[]; rowCount: number | null };
type PgClient = {
  connect(): Promise<void>;
  query(text: string, values?: unknown[]): Promise<PgResult>;
  end(): Promise<void>;
};
type PgError = Error & { code?: string; constraint?: string };
const { Client } = createRequire(import.meta.url)("pg") as {
  Client: new (options: { connectionString: string }) => PgClient;
};
const { canonicalApplyFixture } = (await import(
  new URL("../../../scripts/lib/disposable-postgres.mjs", import.meta.url).href
)) as {
  canonicalApplyFixture(
    root: string,
    temporary: string,
    databaseUrl: string,
  ): { apply(): void; prismaCwd: string };
};
/** The committed migration folders, sorted as Prisma applies them. */
function committedMigrations(): string[] {
  return readdirSync(join(root, "packages/db/prisma/migrations"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
}
const HEX = "a".repeat(64);
const FP = `sha256:${HEX}`;
function buildRow(id: string, over: Record<string, string> = {}) {
  const row: Record<string, string> = {
    id: `'${id}'`,
    userId: "'owner'",
    templateId: "'tpl'",
    tag: "'latest'",
    principalKind: "'session'",
    idempotencyKey: `'${id}'`,
    requestBodyHash: "'hash'",
    recipe: `'{"v":1}'`,
    recipeDigest: `'${HEX}'`,
    buildDigest: `'${"b".repeat(64)}'`,
    sourceFormat: "'RECIPE'",
    baseRevisionId: "'rev'",
    baseFingerprint: `'${FP}'`,
    poolId: "'pool'",
    targetKey: "'pool'",
    principalKey: "'s'",
    cpuCount: "2",
    memoryMiB: "2048",
    diskGiB: "32",
    defaultDiskGiB: "32",
    timeoutMinutes: "60",
    reservedMinutes: "60",
    chargeMonth: "'2026-11-01'",
    state: "'QUEUED'",
    updatedAt: "now()",
    ...over,
  };
  const columns = Object.keys(row);
  return `INSERT INTO sandbox_template_build (${columns.map((c) => `"${c}"`).join(",")}) VALUES (${columns.map((c) => row[c]).join(",")})`;
}

it("fresh committed migration, repeat no-op and current domain invariants", async () => {
  const database = `${db.name}_fresh`;
  // The harness owns this disposable database and cleans it up after this file.
  await db.inspect.$executeRawUnsafe(`CREATE DATABASE ${database}`);
  const url = new URL(db.url);
  url.pathname = `/${database}`;
  const connectionString = url.toString();
  const inspector = new Client({ connectionString });
  await inspector.connect();
  try {
    const migration = canonicalApplyFixture(root, dir, connectionString);
    migration.apply();
    const history = (
      await inspector.query(
        "SELECT id, migration_name, checksum, started_at, finished_at, applied_steps_count FROM _prisma_migrations ORDER BY migration_name",
      )
    ).rows;
    // The release baseline comes first; every committed migration (per-PR ones
    // until the next release squash folds them in) applied once, in order.
    const committed = committedMigrations();
    expect(committed[0]).toBe("0_init");
    expect(history.map((row) => row.migration_name)).toEqual(committed);
    for (const row of history) expect(row).toMatchObject({ applied_steps_count: 1 });
    for (const row of history) expect(row.finished_at).toBeInstanceOf(Date);
    await inspector.query(
      `INSERT INTO "user" (id,name,email) VALUES ('repeat-probe','Probe','repeat@example.test')`,
    );
    migration.apply();
    expect(
      (
        await inspector.query(
          "SELECT id, migration_name, checksum, started_at, finished_at, applied_steps_count FROM _prisma_migrations ORDER BY migration_name",
        )
      ).rows,
    ).toEqual(history);
    expect((await inspector.query(`SELECT id FROM "user" WHERE id = 'repeat-probe'`)).rows).toEqual(
      [{ id: "repeat-probe" }],
    );
    expect(
      (await inspector.query("SELECT to_regclass('wssp_control.schema_releases') AS legacy")).rows,
    ).toEqual([{ legacy: null }]);
    await inspector.query(`INSERT INTO "user" (id,name,email) VALUES ('owner','Owner','owner@example.test'), ('other','Other','other@example.test');
      INSERT INTO sandbox_host (id,"userId",slug,label) VALUES ('host','owner','host','Host');
      INSERT INTO sandbox_logical_template (id,"userId",slug,label,"updatedAt") VALUES ('tpl','owner','tpl','Tpl',now());
      INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest") VALUES ('rev','owner','tpl',1,'${FP}','x86_64','${HEX}');
      INSERT INTO sandbox_pool (id,"userId",slug,label) VALUES ('pool','owner','pool','Pool');
      INSERT INTO sdk_key (id,"userId",name,"secretDigest","lookupPrefix",scopes,"updatedAt") VALUES ('key1','owner','Key','hash1','key1',ARRAY[]::text[],now()), ('key2','owner','Key2','hash2','key2',ARRAY[]::text[],now());
      INSERT INTO account_image_policy ("userId","updatedAt") VALUES ('owner',now());
      INSERT INTO sandbox_instance (id,"userId","templateId","templateRevisionId","originalSelector","updatedAt") VALUES ('sbx','owner','tpl','rev','tpl',now());`);
    const refused = async (sql: string, constraint: RegExp | string) => {
      await inspector.query("SAVEPOINT invalid_row");
      try {
        const error = await inspector.query(sql).then(
          () => undefined,
          (cause: unknown) => cause as PgError,
        );
        expect(error?.code).toBe(typeof constraint === "string" ? constraint : "23514");
        if (constraint instanceof RegExp) expect(error?.constraint).toMatch(constraint);
      } finally {
        await inspector.query("ROLLBACK TO SAVEPOINT invalid_row");
      }
    };
    await inspector.query("BEGIN");
    try {
      const set = (data: string) => `UPDATE sandbox_instance SET ${data} WHERE id = 'sbx'`;
      await refused(set(`"guestSudo" = true`), /sandbox_instance_guest_sudo/);
      await refused(set(`"guestSudo" = true, "guestRoot" = true`), /sandbox_instance_guest_sudo/);
      await refused(set(`"guestSudoReason" = 'NODE_POLICY'`), /sandbox_instance_guest_sudo_reason/);
      await inspector.query(
        set(`"guestSudo" = true, "guestRoot" = true, "guestSudoRequested" = true`),
      );
      await refused(set(`purpose = 'CREDENTIAL_LOGIN'`), /sandbox_instance_guest_sudo/);
      await refused(
        set(`"guestSudoReason" = 'HOST_UNSUPPORTED'`),
        /sandbox_instance_guest_sudo_reason/,
      );
      await inspector.query(set(`"guestSudo" = false, "guestSudoRequested" = false`));
      await refused(
        `UPDATE sandbox_template_revision SET "builtWithWsspRecipe" = true WHERE id = 'rev'`,
        /sandbox_revision_wssp_recipe/,
      );
      await inspector.query(
        `INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest","sourceKind","buildId","recipeDigest","builtWithRoot") VALUES ('root','owner','tpl',2,'${FP}','x86_64','${HEX}','BUILD','root-build','${HEX}',true)`,
      );
      await inspector.query(
        `UPDATE sandbox_template_revision SET "builtWithWsspRecipe" = true WHERE id = 'root'`,
      );
      await refused(
        `UPDATE sandbox_template_revision SET "builtOnForeignHost" = true WHERE id = 'root'`,
        /sandbox_revision_wssp_recipe/,
      );
      await refused(
        `UPDATE sandbox_template_revision SET "capturedWithGuestRoot" = true WHERE id = 'root'`,
        /sandbox_revision_wssp_recipe/,
      );
      for (const name of ["", "Upper", "a_b", "-dash", "dash-", "x".repeat(64)])
        await refused(set(`name = '${name}'`), /sandbox_instance_name/);
      await refused(
        set(`state = 'WAITING_FOR_CAPACITY', "liveResourcesHeld" = true`),
        /sandbox_instance_waiting/,
      );
      await refused(
        set(`state = 'WAITING_FOR_CAPACITY', "leaseExpiresAt" = now()`),
        /sandbox_instance_waiting/,
      );
      await refused(
        set(`state = 'WAITING_FOR_CAPACITY', "sandboxHostId" = 'host', "hostOwnerId" = 'owner'`),
        /sandbox_instance_waiting/,
      );
      await refused(set(`"currentPlacementId" = 'missing'`), /sandbox_instance_origin_host/);
      await refused(
        `INSERT INTO sandbox_image_artifact (id,"userId",fingerprint,architecture,"sizeBytes","storeKind",state,"updatedAt") VALUES ('bad','owner','${FP}','x86_64',1024,'PEER','STORED',now())`,
        /sandbox_image_artifact_stored/,
      );
      await refused(
        `INSERT INTO sandbox_pool_member (id,"userId","poolId","sandboxHostId","hostOwnerId") VALUES ('member','owner','pool','host','other')`,
        /sandbox_member_identity/,
      );
      await refused(
        `INSERT INTO sdk_key_pool_allowlist (id,"userId","sdkKeyId","poolId","poolOwnerId") VALUES ('grant','owner','key1','pool','other')`,
        /sdk_pool_grant_identity/,
      );

      await inspector.query(`INSERT INTO sandbox_mutation_operation (id,"userId","sandboxId",generation,kind,state,"idempotencyKey","requestBodyHash","requestDigestScheme","requestDigestKeyId","digestContext","updatedAt") VALUES ('attach-op','owner','sbx',1,'CREDENTIAL_ATTACH','QUEUED','attach','hash','hmac-sha256-v1','${"c".repeat(32)}','{"version":1,"domain":"wssp-request-v1","hostId":"host","hostOwnerId":"owner","generation":1,"configId":null,"usagePoolId":null,"usageMemberId":null}',now());
        INSERT INTO credential_definition (id,"userId",slug,version,document,digest,"displayName") VALUES ('def','owner','cli',1,'{}','${HEX}','CLI');
        INSERT INTO credential (id,"userId",name,"definitionId","definitionDigest",mode,delivery,"copyBack","updatedAt") VALUES ('login','owner','cli','def','${HEX}','EXCLUSIVE','GUEST',true,now());
        INSERT INTO credential_account (id,"userId","credentialId",ordinal,"updatedAt") VALUES ('acct','owner','login',1,now());
        INSERT INTO credential_instance (id,"userId","credentialId","accountId","accountOrdinal",ordinal,capacity,state,"currentSeq","nextStorageSeq","updatedAt") VALUES ('inst','owner','login','acct',1,1,1,'READY',1,2,now());
        INSERT INTO credential_lease (id,"userId","credentialId","accountId","instanceId","sandboxId","operationId",kind,exclusive,state,"updatedAt") VALUES ('lease','owner','login','acct','inst','sbx','attach-op','WORKLOAD',true,'ACTIVE',now());`);
      await refused(
        `INSERT INTO credential_lease (id,"userId","credentialId","accountId","instanceId","sandboxId","operationId",kind,exclusive,state,"updatedAt") VALUES ('lease2','owner','login','acct','inst','sbx','attach-op','WORKLOAD',true,'RESERVED',now())`,
        "23505",
      );
      await refused(
        `INSERT INTO credential (id,"userId",name,"definitionId","definitionDigest",mode,delivery,"copyBack","updatedAt") VALUES ('proxy','owner','proxy','def','${HEX}','EXCLUSIVE','PROXY',true,now())`,
        /credential_proxy_copy_back/,
      );
      await refused(
        `INSERT INTO credential_operation_spec ("operationId",digest,bytes) VALUES ('attach-op',decode(repeat('00',32),'hex'),decode(repeat('00',1179649),'hex'))`,
        /credential_operation_spec_size/,
      );
      await refused(
        `INSERT INTO sandbox_capacity_wait (id,"userId","sandboxId","operationId","poolId","poolOwnerId","templateRevisionId","cpuCount","memoryMiB","diskGiB","chargedMemoryMiB","rootChargeGiB","leaseTimeoutMs","leaseExpireAction",intent,state,"endedAt","updatedAt") VALUES ('wait','owner','sbx','attach-op','pool','owner','rev',1,1024,32,1280,33,300000,'DESTROY','{}','TIMED_OUT',now(),now())`,
        /sandbox_capacity_wait_intent/,
      );
      await inspector.query(buildRow("b-session"));
      await inspector.query(
        buildRow("b-key", {
          principalKind: "'sdkKey'",
          authorizingKeyId: "'key1'",
          principalKey: "'k:key1'",
        }),
      );
      await inspector.query(
        buildRow("b-system", {
          principalKind: "'system'",
          triggeredByRevisionId: "'rev'",
          principalKey: "'sys'",
        }),
      );

      await refused(buildRow("x1", { authorizingKeyId: "'key1'" }), /template_build_principal/);
      await refused(
        buildRow("x2", {
          principalKind: "'sdkKey'",
          authorizingKeyId: "'key1'",
          principalKey: "'s'",
        }),
        /template_build_principal/,
      );
      await refused(buildRow("x3", { triggeredByRevisionId: "'rev'" }), /template_build_principal/);

      await refused(buildRow("x4", { requestedHostId: "'host'" }), /template_build_target/);
      await refused(buildRow("x5", { targetKey: "'other'" }), /template_build_target/);

      await refused(buildRow("x6", { chargedMinutes: "61" }), /template_build_minutes/);
      await refused(buildRow("x7", { minutesSettled: "true" }), /template_build_minutes/);
      await refused(buildRow("x8", { chargeMonth: "'2026-11-02'" }), /template_build_minutes/);
      await refused(
        buildRow("x9", { recipe: `'${JSON.stringify({ s: "x".repeat(70000) })}'` }),
        /template_build_recipe/,
      );
      await refused(buildRow("x10", { sourceFormat: "'DOCKERFILE'" }), /template_build_recipe/);
      await refused(buildRow("x11", { contextSha256: `'${HEX}'` }), /template_build_context/);
      await refused(
        buildRow("x12", { state: "'SUCCEEDED'", completedAt: "now()" }),
        /template_build_outcome/,
      );
      await refused(buildRow("x13", { state: "'FAILED'" }), /template_build_outcome/);
      await refused(buildRow("x14", { errorCode: "'nope'" }), /template_build_error_code/);
      await refused(
        buildRow("x15", { cleanupState: "'DONE'", cleanupDoneAt: "now()" }),
        /template_build_outcome/,
      );

      await refused(buildRow("d1"), "23505");
      await inspector.query(buildRow("d2", { noCache: "true" }));
      await inspector.query(
        buildRow("d3", {
          principalKind: "'sdkKey'",
          authorizingKeyId: "'key2'",
          principalKey: "'k:key2'",
        }),
      );
      await inspector.query(
        buildRow("d4", { poolId: "NULL", requestedHostId: "'host'", targetKey: "'host'" }),
      );
      await inspector.query(
        `UPDATE sandbox_template_build SET state = 'FAILED', "errorCode" = 'build_internal', "completedAt" = now() WHERE id = 'b-session'`,
      );
      await inspector.query(buildRow("d5"));

      const sandbox = (id: string, purpose: string, buildId: string) =>
        `INSERT INTO sandbox_instance (id,"userId","templateId","templateRevisionId","originalSelector",purpose,"buildId","updatedAt") VALUES ('${id}','owner','tpl','rev','tpl','${purpose}',${buildId},now())`;
      await inspector.query(sandbox("vm", "TEMPLATE_BUILD", "'d5'"));
      await refused(sandbox("vm2", "TEMPLATE_BUILD", "NULL"), /sandbox_instance_build/);
      await refused(sandbox("vm3", "WORKLOAD", "'d2'"), /sandbox_instance_build/);

      const revision = (id: string, n: number, source: string, extra = "") =>
        `INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest","sourceKind","buildId","recipeDigest"${extra ? ',"readyTimeoutMs"' : ""}) VALUES ('${id}','owner','tpl',${n},'${FP}','x86_64','${HEX}','${source}',${source === "BUILD" ? `'${id}-b'` : "NULL"},${source === "BUILD" ? `'${HEX}'` : "NULL"}${extra ? `,${extra}` : ""})`;
      await inspector.query(revision("built", 3, "BUILD"));
      await refused(
        `INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest","sourceKind") VALUES ('nobuild','owner','tpl',3,'${FP}','x86_64','${HEX}','BUILD')`,
        /sandbox_revision_template_build/,
      );
      await refused(revision("slow", 4, "BUILD", "999"), /sandbox_revision_template_build/);

      const context = (id: string, build: string, over = "") =>
        `INSERT INTO sandbox_build_context (id,"buildId","userId","totalBytes","expectedSha256","idleExpiresAt","expiresAt","updatedAt"${over ? ",state" : ""}) VALUES ('${id}','${build}','owner',4096,'${HEX}',now(),now(),now()${over ? `,${over}` : ""})`;
      await inspector.query(context("ctx", "d5"));
      await inspector.query(
        `INSERT INTO sandbox_build_context_chunk ("contextId","offset",length,digest) VALUES ('ctx',0,4096,'${HEX}')`,
      );
      await refused(context("ctx2", "d2", "'ADOPTED'"), /sandbox_build_context_shape/);
      await refused(context("ctx3", "d3", "'SEALED'"), /sandbox_build_context_shape/);
      await refused(
        `INSERT INTO sandbox_build_context (id,"buildId","userId","totalBytes","expectedSha256","idleExpiresAt","expiresAt","updatedAt") VALUES ('ctx4','d4','other',1,'${HEX}',now(),now(),now())`,
        "23503",
      );
      await refused(
        `INSERT INTO sandbox_build_context_chunk ("contextId","offset",length,digest) VALUES ('ctx',-1,1,'x')`,
        /sandbox_build_context_chunk_shape/,
      );

      await refused(
        `UPDATE account_image_policy SET "adminConcurrentBuildsMax" = -1`,
        /account_image_policy_admin/,
      );
      await refused(
        `INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest","sourceKind","parentRevisionId") VALUES ('up','owner','tpl',10,'${FP}','x86_64','${HEX}','UPSTREAM','rev')`,
        /sandbox_revision_upstream/,
      );
      await refused(
        `INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest","sourceKind","captureTag") VALUES ('up','owner','tpl',10,'${FP}','x86_64','${HEX}','UPSTREAM','latest')`,
        /sandbox_revision_upstream/,
      );
      await inspector.query(
        `INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest","sourceKind") VALUES ('up','owner','tpl',10,'${FP}','x86_64','${HEX}','UPSTREAM')`,
      );
      const upstream = (meta: number, disk: number) =>
        `INSERT INTO sandbox_upstream_image (id,"userId","templateId","revisionId",source,product,version,fingerprint,architecture,"metaPath","metaSha256","metaSize","diskPath","diskSha256","diskSize") VALUES ('ui','owner','tpl','up','ubuntu-26.04','ubuntu:resolute:amd64:cloud','20261105','${FP}','x86_64','images/x/incus.tar.xz','${HEX}',${meta},'images/x/disk.qcow2','${HEX}',${disk})`;
      await refused(upstream(2000000, 1000), /sandbox_upstream_image_bounds/);
      await refused(upstream(1208, 5 * 1024 ** 3), /sandbox_upstream_image_bounds/);
      await inspector.query(upstream(1208, 496000000));
      await refused(
        `UPDATE sandbox_template_build SET "verifyDeadlineAt" = now() WHERE id = 'd5'`,
        /template_build_verify/,
      );
      await refused(
        `UPDATE sandbox_template_build SET "verifyRequired" = true WHERE id = 'd5'`,
        /template_build_verify/,
      );
      await refused(
        `UPDATE sandbox_template_build SET origin = 'COMMUNITY_PREP' WHERE id = 'd5'`,
        /template_build_origin/,
      );
      await refused(
        `UPDATE sandbox_template_build SET origin = 'COMMUNITY_PREP', "verifyRequired" = true, "noCache" = true WHERE id = 'd5'`,
        /template_build_origin/,
      );
      await refused(set(`purpose = 'TEMPLATE_VERIFY'`), /sandbox_instance_verify/);
      await refused(set(`"verifyBuildId" = 'd5'`), /sandbox_instance_verify/);
      await refused(
        `UPDATE sandbox_template_revision SET "retiredReason" = 'bogus' WHERE id = 'rev'`,
        /sandbox_revision_retired_reason/,
      );
      // Managed build VMs and their operations never emit workload webhooks.
      await inspector.query(`INSERT INTO webhook_endpoint (id,"userId",url,events,"operationKinds","secretCiphertext","secretNonce","secretKeyId","secretVersion","updatedAt") VALUES ('endpoint','owner','https://hooks.example.test/events',ARRAY['sandbox.ready','operation.completed'],ARRAY[]::text[],decode('00','hex'),decode(repeat('00',12),'hex'),'${"0".repeat(16)}',1,now());
        INSERT INTO sandbox_mutation_operation (id,"userId","sandboxId",generation,kind,state,"idempotencyKey","requestBodyHash","requestDigestScheme","requestDigestKeyId","digestContext","updatedAt") VALUES ('build-op','owner','vm',1,'CREATE_SANDBOX','RUNNING','build-op','hash','hmac-sha256-v1','${"c".repeat(32)}','{"version":1,"domain":"wssp-request-v1","hostId":"host","hostOwnerId":"owner","generation":1,"configId":null,"usagePoolId":null,"usageMemberId":null}',now());
        UPDATE sandbox_instance SET state = 'READY' WHERE id IN ('vm','sbx');
        UPDATE sandbox_mutation_operation SET state = 'SUCCEEDED' WHERE id IN ('build-op','attach-op');`);
      expect(
        (
          await inspector.query(
            `SELECT "sandboxId" AS sandbox, type FROM webhook_event ORDER BY type, "sandboxId"`,
          )
        ).rows,
      ).toEqual([
        { sandbox: "sbx", type: "operation.completed" },
        { sandbox: "sbx", type: "sandbox.ready" },
      ]);
    } finally {
      await inspector.query("ROLLBACK");
    }
  } finally {
    await inspector.end();
  }
}, 180000);

it("community prep builds accept only the current prep recipe digest", async () => {
  const CURRENT = "28ddd19b6c16efce199908628d342179eb933ccead39625b640d567fd22a98be";
  const database = `${db.name}_community_digest`;
  // The harness owns this disposable database and cleans it up after this file.
  await db.inspect.$executeRawUnsafe(`CREATE DATABASE ${database}`);
  const url = new URL(db.url);
  url.pathname = `/${database}`;
  const scratch = mkdtempSync(join(tmpdir(), "wssp-schema-migrations-digest-"));
  const inspector = new Client({ connectionString: url.toString() });
  await inspector.connect();
  try {
    canonicalApplyFixture(root, scratch, url.toString()).apply();
    const prep = (id: string, digest: string) =>
      buildRow(id, {
        origin: "'COMMUNITY_PREP'",
        verifyRequired: "true",
        noCache: "true",
        recipeDigest: `'${digest}'`,
      });
    await inspector.query(`INSERT INTO "user" (id,name,email) VALUES ('owner','Owner','owner@example.test');
      INSERT INTO sandbox_logical_template (id,"userId",slug,label,"updatedAt") VALUES ('tpl','owner','tpl','Tpl',now());
      INSERT INTO sandbox_template_revision (id,"userId","templateId",revision,"incusFingerprint",architecture,"manifestDigest") VALUES ('rev','owner','tpl',1,'${FP}','x86_64','${HEX}');
      INSERT INTO sandbox_pool (id,"userId",slug,label) VALUES ('pool','owner','pool','Pool');`);
    await inspector.query(prep("current", CURRENT));
    const live = await inspector.query(
      `SELECT conname, convalidated FROM pg_constraint WHERE conname LIKE 'template_build_origin_%'`,
    );
    expect(live.rows).toHaveLength(1);
    expect(live.rows[0]).toMatchObject({ convalidated: true });
    // Any other digest is refused, including the prep recipe's earlier ones.
    for (const [id, digest] of [
      ["other", HEX],
      ["before-rsync", "76e4e99b8c48671d3f2ea5ba282479e413f91fb15d0f736e6481cec5b9e7af9b"],
      ["before-sftp", "eb8a190977a1665adb2f14dcbe7f60eede39ea3ef72f8646652f4919d6802c59"],
    ] as const) {
      const refused = await inspector.query(prep(id, digest)).then(
        () => undefined,
        (cause: unknown) => cause as PgError,
      );
      expect(refused?.code).toBe("23514");
      expect(refused?.constraint).toBe(live.rows[0]?.conname);
    }
    // A user build may carry any digest.
    await inspector.query(buildRow("user-build", { recipeDigest: `'${HEX}'` }));
    expect(
      (await inspector.query(`SELECT id FROM sandbox_template_build ORDER BY id`)).rows,
    ).toEqual([{ id: "current" }, { id: "user-build" }]);
  } finally {
    await inspector.end();
    rmSync(scratch, { recursive: true, force: true });
  }
}, 180000);
