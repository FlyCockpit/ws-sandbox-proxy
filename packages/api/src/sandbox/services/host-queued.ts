import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import {
  HOST_QUEUED_COMMAND_STATES,
  queueHostCommandBodySchema,
  resourceIdSchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { cursorPage, cursorPageInput, pageTake, withCursor } from "../../lib/pagination";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import { hostAccessError, hostCredentialId } from "../host-access";
import { hostCommandProgram, hostSubjectHmac } from "../host-audit";
import { queuedHostCommandWrapper } from "../host-queued-wrapper";
import { readHostTerminalPolicy } from "../host-terminal-policy";

const queueView = (row: {
  id: string;
  state: (typeof HOST_QUEUED_COMMAND_STATES)[number];
  expiresAt: Date;
}) => ({ id: row.id, state: row.state, expiresAt: row.expiresAt.toISOString() });
const publicSelect = {
  id: true,
  state: true,
  expiresAt: true,
} satisfies Prisma.HostQueuedCommandSelect;
type QueueInput = {
  hostId: string;
  command: string;
  reason: string;
  expiresInHours?: number;
  idempotencyKey?: string;
};
export const queueHostCommand = serviceProcedure(
  {
    action: "hostCommands.queue",
    target: (input: QueueInput) => ({ sandboxHostId: input.hostId }),
  },
  async (principal: Principal, input: QueueInput) => {
    const sdkKeyId = hostCredentialId(principal);
    const parsed = queueHostCommandBodySchema.safeParse({
      command: input.command,
      reason: input.reason,
      expiresInHours: input.expiresInHours,
    });
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    await consumeSandboxWriteBudget(principal.ownerId, "ordinary");
    return prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, principal.ownerId);
      await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify(["host-queued-command", principal.ownerId])}, 0))`;
      const host = await tx.sandboxHost.findFirst({
        where: { id: input.hostId, userId: principal.ownerId, deletionRequestedAt: null },
        select: { id: true },
      });
      if (!host) throw hostAccessError("host.not_owned");
      const id = input.idempotencyKey
        ? hostSubjectHmac(
            JSON.stringify([sdkKeyId, input.hostId, "queue", input.idempotencyKey]),
          ).slice(12, 44)
        : undefined;
      if (id) {
        const existing = await tx.hostQueuedCommand.findFirst({
          where: { id, userId: principal.ownerId, sdkKeyId: sdkKeyId },
          select: { ...publicSelect, command: true, reason: true },
        });
        if (existing) {
          if (existing.command !== input.command || existing.reason !== input.reason)
            throw new ORPCError("CONFLICT", { data: { code: "idempotency_conflict" } });
          return queueView(existing);
        }
      }
      const now = new Date();
      await tx.hostQueuedCommand.updateMany({
        where: { userId: principal.ownerId, state: "QUEUED", expiresAt: { lte: now } },
        data: { state: "EXPIRED", decidedAt: now },
      });
      const queued = await tx.hostQueuedCommand.count({
        where: { userId: principal.ownerId, state: "QUEUED" },
      });
      if (queued >= 50) throw hostAccessError("host_queue.limit");
      const row = await tx.hostQueuedCommand.create({
        data: {
          ...(id ? { id } : {}),
          userId: principal.ownerId,
          sandboxHostId: input.hostId,
          sdkKeyId: sdkKeyId,
          command: parsed.data.command,
          reason: parsed.data.reason,
          expiresAt: new Date(now.getTime() + (input.expiresInHours ?? 24) * 3600000),
        },
        select: publicSelect,
      });
      await tx.hostAuditEvent.create({
        data: {
          userId: principal.ownerId,
          sandboxHostId: input.hostId,
          sdkKeyId: sdkKeyId,
          actor: "AGENT",
          kind: "COMMAND_QUEUED",
          program: hostCommandProgram({ script: input.command }),
          subjectHmac: hostSubjectHmac(input.command),
        },
        select: { id: true },
      });
      return queueView(row);
    });
  },
);
export const getQueuedHostCommand = serviceProcedure(
  {
    action: "hostCommands.queue",
    target: (input: { hostId: string; id: string }) => ({ sandboxHostId: input.hostId }),
  },
  async (principal: Principal, input: { hostId: string; id: string }) => {
    const sdkKeyId = hostCredentialId(principal);
    const now = new Date();
    await prisma.hostQueuedCommand.updateMany({
      where: {
        id: input.id,
        sandboxHostId: input.hostId,
        userId: principal.ownerId,
        sdkKeyId: sdkKeyId,
        state: "QUEUED",
        expiresAt: { lte: now },
      },
      data: { state: "EXPIRED", decidedAt: now },
    });
    const row = await prisma.hostQueuedCommand.findFirst({
      where: {
        id: input.id,
        sandboxHostId: input.hostId,
        userId: principal.ownerId,
        sdkKeyId: sdkKeyId,
      },
      select: publicSelect,
    });
    if (!row) throw hostAccessError("host.command_not_found");
    return queueView(row);
  },
);
export const listQueuedHostCommandsInput = cursorPageInput.extend({
  hostId: resourceIdSchema.optional(),
  state: z.enum(HOST_QUEUED_COMMAND_STATES).optional(),
});
export const queuedHostCommandIdInput = z.strictObject({ id: resourceIdSchema });
export const listQueuedHostCommands = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: z.output<typeof listQueuedHostCommandsInput>) => {
    const now = new Date();
    await prisma.hostQueuedCommand.updateMany({
      where: { userId: principal.ownerId, state: "QUEUED", expiresAt: { lte: now } },
      data: { state: "EXPIRED", decidedAt: now },
    });
    const rows = await prisma.hostQueuedCommand.findMany({
      where: withCursor(
        {
          userId: principal.ownerId,
          Host: { userId: principal.ownerId },
          ...(input.hostId ? { sandboxHostId: input.hostId } : {}),
          ...(input.state ? { state: input.state } : {}),
        },
        "createdAt",
        input.cursor,
        "desc",
      ),
      orderBy: [{ createdAt: "desc" }, { id: "desc" }],
      take: pageTake(input.limit),
      select: {
        ...publicSelect,
        sandboxHostId: true,
        command: true,
        reason: true,
        createdAt: true,
        decidedAt: true,
        SdkKey: { select: { name: true } },
      },
    });
    return cursorPage(
      rows.map(({ SdkKey, ...row }) => ({ ...row, credentialName: SdkKey?.name ?? null })),
      input.limit,
      "createdAt",
    );
  },
);
async function decide(principal: Principal, id: string, state: "RUN" | "DISMISSED") {
  await consumeSandboxWriteBudget(principal.ownerId, "ordinary");
  return prisma.$transaction(async (tx) => {
    await lockOwnerForAdmission(tx, principal.ownerId);
    await tx.$queryRaw`SELECT 1 AS locked FROM pg_advisory_xact_lock(hashtextextended(${JSON.stringify(["host-queued-command", principal.ownerId])}, 0))`;
    const row = await tx.hostQueuedCommand.findFirst({
      where: {
        id,
        userId: principal.ownerId,
        Host: { userId: principal.ownerId, deletionRequestedAt: null },
      },
      select: { ...publicSelect, command: true, sandboxHostId: true, sdkKeyId: true },
    });
    if (!row) throw new ORPCError("NOT_FOUND");
    const now = new Date();
    const changed = await tx.hostQueuedCommand.updateMany({
      where: { id, userId: principal.ownerId, state: "QUEUED", expiresAt: { gt: now } },
      data: { state, decidedAt: now, decidedBy: principal.ownerId },
    });
    if (!changed.count) throw new ORPCError("CONFLICT");
    await tx.hostAuditEvent.create({
      data: {
        userId: principal.ownerId,
        sandboxHostId: row.sandboxHostId,
        actor: "PERSON",
        kind: state === "RUN" ? "QUEUED_RUN" : "QUEUED_DISMISSED",
        program: hostCommandProgram({ script: row.command }),
        subjectHmac: hostSubjectHmac(row.command),
      },
      select: { id: true },
    });
    const host = await tx.sandboxHost.findFirst({
      where: { id: row.sandboxHostId, userId: principal.ownerId },
      select: { hostTerminalVetoedAt: true },
    });
    return {
      id,
      state,
      typedCommand: queuedHostCommandWrapper(row.command),
      hostTerminalAvailable:
        !host?.hostTerminalVetoedAt &&
        readHostTerminalPolicy(row.sandboxHostId, principal.ownerId)?.hostTerminal === true,
    };
  });
}
export const runQueuedHostCommand = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: { id: string }) => decide(principal, input.id, "RUN"),
);
export const dismissQueuedHostCommand = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: { id: string }) => {
    const row = await decide(principal, input.id, "DISMISSED");
    return { id: row.id, state: row.state };
  },
);
