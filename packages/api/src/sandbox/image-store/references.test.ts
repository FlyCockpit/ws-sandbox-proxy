import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

const { artifactReferencedSql, liveRevisionSql } = await import("./references");
const { Prisma } = await import("@wssp/db/client");

const ROOT = resolve(import.meta.dirname, "../../../../..");
const read = (path: string) => readFileSync(resolve(ROOT, path), "utf8");
/** The body of the exported function `name` in `source` (up to the next export). */
const body = (source: string, name: string) => {
  const start = source.indexOf(`export async function ${name}(`);
  expect(start, `${name} is exported`).toBeGreaterThanOrEqual(0);
  const end = source.indexOf("\nexport ", start + 1);
  return source.slice(start, end < 0 ? undefined : end);
};

/**
 * The churn loop came from two queries each spelling out "live revision":
 * GC checked retired and archived, the publish backfill only retired. Every
 * image-lifecycle query now uses the shared fragments, and none spells out
 * the template's archived check itself.
 */
describe("one definition of a referenced image", () => {
  const callers = {
    gc: "packages/api/src/sandbox/image-store/jobs.ts",
    backfill: "apps/server/src/sandbox-image-relay/scheduler.ts",
    access: "packages/api/src/sandbox/image-store/access.ts",
  };

  it("a live revision is unretired and of an unarchived template", () => {
    expect(liveRevisionSql().sql).toBe('r."retiredAt" IS NULL AND t."archivedAt" IS NULL');
    const referenced = artifactReferencedSql(Prisma.sql`${"o"}`, Prisma.sql`${"f"}`).sql;
    expect(referenced).toContain('r."retiredAt" IS NULL AND t."archivedAt" IS NULL');
  });

  it("GC deletes by artifactReferenced; the backfill uploads only under artifactReferencedSql and liveRevisionSql", () => {
    const gc = body(read(callers.gc), "gcImageArtifacts");
    expect(gc.match(/artifactReferenced\(/g)).toHaveLength(2);
    const backfill = body(read(callers.backfill), "publishBackfill");
    expect(backfill).toMatch(/\$\{liveRevisionSql\(\)\}/);
    expect(backfill).toMatch(
      /\$\{artifactReferencedSql\(Prisma\.raw\('a\."userId"'\), Prisma\.raw\('a\."localFingerprint"'\)\)\}/,
    );
    expect(read(callers.access)).toMatch(/\$\{liveRevisionSql\(\)\}/);
  });

  it.each(Object.entries(callers))(
    "%s spells out no archived or retired revision check of its own",
    (_, path) => {
      const source = read(path);
      expect(source).not.toMatch(/t\."archivedAt" IS NULL/);
      expect(source).not.toMatch(/r\."retiredAt" IS NULL/);
    },
  );
});
