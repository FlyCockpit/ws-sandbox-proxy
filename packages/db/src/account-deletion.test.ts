import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  userRelationInventory,
  userRelationKey,
  userRelationsFromSchema,
  userRelationsFromSource,
} from "./testing/user-relations";

const db = vi.hoisted(() => ({
  user: { update: vi.fn(), deleteMany: vi.fn(), findUnique: vi.fn(), findFirst: vi.fn() },
  session: { deleteMany: vi.fn() },
  sandboxHost: { count: vi.fn(), deleteMany: vi.fn() },
  sandboxTemplate: { count: vi.fn(), deleteMany: vi.fn() },
  sandbox: { count: vi.fn(), deleteMany: vi.fn(), updateMany: vi.fn() },
  sandboxPlacement: { deleteMany: vi.fn() },
  sandboxPool: { deleteMany: vi.fn() },
  sandboxPoolMember: { deleteMany: vi.fn() },
  sandboxCapacityWait: { deleteMany: vi.fn() },
  sandboxDiskCopy: { count: vi.fn(), deleteMany: vi.fn() },
  sandboxTransfer: { count: vi.fn(), deleteMany: vi.fn() },
  sandboxImageTransfer: { deleteMany: vi.fn() },
  sandboxTemplateBuild: { deleteMany: vi.fn() },
  sandboxOperation: { count: vi.fn(), deleteMany: vi.fn() },
  outboxEvent: { count: vi.fn(), deleteMany: vi.fn() },
  webhookEndpoint: { deleteMany: vi.fn() },
  webhookEvent: { deleteMany: vi.fn() },
  $transaction: vi.fn(),
  $queryRaw: vi.fn(),
  $executeRaw: vi.fn(),
}));
vi.mock("./index", () => ({ default: db }));
const { ACCOUNT_DELETION_CLASSIFICATION, AccountDeletionConflictError, requestAccountDeletion } =
  await import("./account-deletion");

beforeEach(() => {
  vi.resetAllMocks();
  db.$transaction.mockImplementation(async (work: (tx: typeof db) => Promise<unknown>) => work(db));
  db.$queryRaw.mockResolvedValue([]);
  db.$executeRaw.mockResolvedValue(0);
  db.sandboxCapacityWait.deleteMany.mockResolvedValue({ count: 0 });
  db.user.findUnique.mockResolvedValue({ id: "owner", deletionRequestedAt: null });
  db.user.findFirst.mockResolvedValue({ id: "owner", deletionRequestedAt: new Date() });
  for (const relation of [
    db.sandboxHost,
    db.sandboxTemplate,
    db.sandbox,
    db.sandboxOperation,
    db.sandboxTransfer,
    db.outboxEvent,
    db.sandboxDiskCopy,
  ]) {
    relation.count.mockResolvedValue(0);
    relation.deleteMany.mockResolvedValue({ count: 0 });
  }
  db.sandbox.updateMany.mockResolvedValue({ count: 0 });
  db.sandboxPlacement.deleteMany.mockResolvedValue({ count: 0 });
  db.sandboxPool.deleteMany.mockResolvedValue({ count: 0 });
  db.sandboxPoolMember.deleteMany.mockResolvedValue({ count: 0 });
  db.sandboxImageTransfer.deleteMany.mockResolvedValue({ count: 0 });
  db.sandboxTemplateBuild.deleteMany.mockResolvedValue({ count: 0 });
  db.webhookEndpoint.deleteMany.mockResolvedValue({ count: 0 });
  db.webhookEvent.deleteMany.mockResolvedValue({ count: 0 });
  db.user.deleteMany.mockResolvedValue({ count: 1 });
  db.user.update.mockResolvedValue({});
  db.session.deleteMany.mockResolvedValue({ count: 0 });
});

describe("account deletion — unit (mocked Prisma; real-DB races: account-deletion.pg.test.ts)", () => {
  it.each([
    ["hosts", db.sandboxHost],
    ["sandboxes", db.sandbox],
    ["operations", db.sandboxOperation],
    ["outbox", db.outboxEvent],
    ["transfers", db.sandboxTransfer],
    // A detached disk copy still holding a host's root reservation (offload S10).
    ["sandboxes", db.sandboxDiskCopy],
  ] as const)("refuses with CONFLICT when %s remain", async (kind, relation) => {
    relation.count.mockResolvedValue(1);
    await expect(requestAccountDeletion("owner")).rejects.toBeInstanceOf(
      AccountDeletionConflictError,
    );
    await expect(requestAccountDeletion("owner")).rejects.toMatchObject({
      kinds: expect.arrayContaining([kind]),
    });
    expect(db.user.update).not.toHaveBeenCalled();
    expect(db.user.deleteMany).not.toHaveBeenCalled();
  });

  it("refuses with CONFLICT while image jobs are open (real-DB: account-deletion.pg.test.ts)", async () => {
    db.$queryRaw.mockImplementation(async (parts: TemplateStringsArray) =>
      parts.join("?").includes("sandbox_image_transfer") ? [{ live: true }] : [],
    );
    await expect(requestAccountDeletion("owner")).rejects.toMatchObject({
      kinds: ["image_jobs"],
    });
    expect(db.user.deleteMany).not.toHaveBeenCalled();
  });

  it("never counts templates as blockers: all templates are receipts deleted with the account", async () => {
    db.sandboxTemplate.count.mockResolvedValue(1);
    expect(await requestAccountDeletion("owner")).toBe(true);
    expect(db.sandboxTemplate.count).not.toHaveBeenCalled();
    expect(db.sandboxTemplate.deleteMany).toHaveBeenCalledWith({ where: { userId: "owner" } });
    expect(db.sandboxTemplate.deleteMany.mock.invocationCallOrder[0]).toBeLessThan(
      db.user.deleteMany.mock.invocationCallOrder[0]!,
    );
  });

  it("finalizes an empty account in one transaction", async () => {
    expect(await requestAccountDeletion("owner")).toBe(true);
    expect(db.user.update).toHaveBeenCalled();
    expect(db.sandbox.deleteMany).toHaveBeenCalled();
    expect(db.user.deleteMany).toHaveBeenCalled();
    expect(db.user.update.mock.invocationCallOrder[0]).toBeLessThan(
      db.user.deleteMany.mock.invocationCallOrder[0]!,
    );
  });

  it("deletes webhook endpoints before their FK-free events, by owner (real-DB: webhook-lock-order.pg.test.ts)", async () => {
    expect(await requestAccountDeletion("owner")).toBe(true);
    expect(db.webhookEndpoint.deleteMany).toHaveBeenCalledWith({ where: { userId: "owner" } });
    expect(db.webhookEvent.deleteMany).toHaveBeenCalledWith({ where: { userId: "owner" } });
    expect(db.webhookEndpoint.deleteMany.mock.invocationCallOrder[0]).toBeLessThan(
      db.webhookEvent.deleteMany.mock.invocationCallOrder[0]!,
    );
  });

  it("C21-ACCTDEL-RACE a concurrent child insert (P2003) during finalization is CONFLICT naming blockers", async () => {
    // Zero blockers under the lock, then a host committed by a racing admission
    // makes the FK-checked user delete fail; the refusal names the new blocker.
    db.sandboxHost.count.mockResolvedValueOnce(0).mockResolvedValue(1);
    db.user.deleteMany.mockRejectedValue(
      Object.assign(new Error("foreign key violation"), { code: "P2003" }),
    );
    const refusal = await requestAccountDeletion("owner").catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(AccountDeletionConflictError);
    expect(refusal).toMatchObject({ kinds: ["hosts"] });
    expect((refusal as Error).message).toContain("hosts");
  });

  it("C21-ACCTDEL-RACE a P2003 whose blocker is gone again says the blocker set changed (no empty-kinds 'in progress')", async () => {
    db.user.deleteMany.mockRejectedValue(
      Object.assign(new Error("foreign key violation"), { code: "P2003" }),
    );
    const refusal = await requestAccountDeletion("owner").catch((error: unknown) => error);
    expect(refusal).toBeInstanceOf(AccountDeletionConflictError);
    expect(refusal).toMatchObject({ kinds: [] });
    expect((refusal as Error).message).toMatch(/resources changed while it was being deleted/);
    expect((refusal as Error).message).not.toMatch(/in progress/);
    // The re-read ran in a fresh transaction under the owner FOR UPDATE lock.
    expect(db.$transaction).toHaveBeenCalledTimes(2);
    const locks = db.$queryRaw.mock.calls.filter(([parts]) =>
      (parts as string[]).join("?").includes('FROM "user" WHERE id = ? FOR UPDATE'),
    );
    expect(locks).toHaveLength(2);
  });

  it("C21-ACCTDEL-RACE finalization takes the owner row FOR UPDATE before counting blockers", async () => {
    expect(await requestAccountDeletion("owner")).toBe(true);
    const lock = db.$queryRaw.mock.calls.findIndex(([parts]) =>
      (parts as string[]).join("?").includes('FROM "user" WHERE id = ? FOR UPDATE'),
    );
    expect(lock).toBeGreaterThanOrEqual(0);
    expect(db.$queryRaw.mock.invocationCallOrder[lock]).toBeLessThan(
      db.sandboxHost.count.mock.invocationCallOrder[0]!,
    );
  });
});

describe("account deletion inventory — every User-related model is classified (DECISIONS: Account-deletion blockers)", () => {
  const schema = userRelationsFromSchema();
  const classified = new Map(
    ACCOUNT_DELETION_CLASSIFICATION.map((entry) => [
      userRelationKey(entry.model, entry.column),
      entry,
    ]),
  );

  it("the schema parser finds the known owner relations (guards against a silently empty scan)", () => {
    expect(schema.get("Sandbox.userId")).toEqual({
      model: "Sandbox",
      table: "sandbox_instance",
      column: "userId",
      onDelete: "Restrict",
    });
    expect(schema.get("Session.userId")).toEqual({
      model: "Session",
      table: "session",
      column: "userId",
      onDelete: "Cascade",
    });
    expect(schema.size).toBeGreaterThanOrEqual(13);
  });

  it("C21b-c2-D the schema parser reads multi-line relation attributes, comments and @@map(name:)", () => {
    const fixture = [
      "model Widget {",
      '  id    String @id // a "quoted" // comment',
      "  owner User   @relation(",
      '    "WidgetOwner",',
      "    fields: [ownerId],",
      "    references: [id],",
      "    onDelete: Cascade",
      "  )",
      "  // audit   User   @relation(fields: [auditId], references: [id])  (commented out)",
      "  ownerId String",
      "  reviewer   User?  @relation(",
      '    "WidgetReviewer", fields: [reviewerId], references: [id]',
      "  )",
      "  reviewerId String?",
      "  backref    User[]",
      '  @@map(name: "widget_table")',
      "}",
      "model Gadget {",
      "  keeper User @relation(fields: [keeperId],",
      "                        references: [id])",
      "  keeperId String",
      "}",
    ].join("\r\n");
    expect(userRelationsFromSource(fixture)).toEqual([
      { model: "Widget", table: "widget_table", column: "ownerId", onDelete: "Cascade" },
      // Prisma's default for an optional relation with no onDelete.
      { model: "Widget", table: "widget_table", column: "reviewerId", onDelete: "SetNull" },
      // … and for a required one.
      { model: "Gadget", table: "Gadget", column: "keeperId", onDelete: "Restrict" },
    ]);
  });

  it("C21c-cf-2 a model with two FKs to User keeps both inventory entries, keyed by (model, FK column)", () => {
    const fixture = [
      "model Review {",
      "  id         String @id",
      '  author     User   @relation("ReviewAuthor", fields: [authorId], references: [id], onDelete: Cascade)',
      "  authorId   String",
      '  approver   User?  @relation("ReviewApprover", fields: [approverId], references: [id], onDelete: Restrict)',
      '  approverId String? @map("approved_by")',
      "}",
    ].join("\n");
    const inventory = userRelationInventory(userRelationsFromSource(fixture));
    expect(Object.fromEntries(inventory)).toEqual({
      "Review.authorId": {
        model: "Review",
        table: "Review",
        column: "authorId",
        onDelete: "Cascade",
      },
      "Review.approved_by": {
        model: "Review",
        table: "Review",
        column: "approved_by",
        onDelete: "Restrict",
      },
    });
    // A repeated key is refused, never collapsed into one entry.
    expect(() =>
      userRelationInventory([
        ...userRelationsFromSource(fixture),
        ...userRelationsFromSource(fixture),
      ]),
    ).toThrow(/duplicate FK to User: Review\.authorId/);
  });

  it("classifies exactly the models with a relation to User — an unclassified model fails", () => {
    const unclassified = [...schema.keys()].filter((model) => !classified.has(model));
    const stale = [...classified.keys()].filter((model) => !schema.has(model));
    expect({ unclassified, stale }).toEqual({ unclassified: [], stale: [] });
    expect(ACCOUNT_DELETION_CLASSIFICATION).toHaveLength(classified.size);
  });

  it.each(
    ACCOUNT_DELETION_CLASSIFICATION.map(
      (entry) => [userRelationKey(entry.model, entry.column), entry] as const,
    ),
  )("%s: its classification matches its FK to User", (model, entry) => {
    const relation = schema.get(model);
    expect(relation?.table).toBe(entry.table);
    if (entry.class === "blocker") {
      // The user delete must never silently remove or orphan live state.
      expect(relation?.onDelete).toBe("Restrict");
      expect(typeof entry.hasLive).toBe("function");
      expect(typeof entry.finalize).toBe("function");
    } else if (entry.class === "receipt" && entry.removedBy === "cascade") {
      expect(relation?.onDelete).toBe("Cascade");
    } else if (entry.class === "receipt") {
      // Explicitly deleted in the finalizing transaction (any FK action).
      expect(typeof entry.finalize).toBe("function");
    } else {
      throw new Error(`unexpected classification class for ${model}`);
    }
  });

  it("templates are receipts, never blockers", () => {
    expect(classified.get("SandboxTemplate.userId")).toMatchObject({
      class: "receipt",
      removedBy: "finalize",
    });
  });
});
