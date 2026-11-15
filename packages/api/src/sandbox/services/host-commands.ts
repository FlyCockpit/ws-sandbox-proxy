import { randomBytes } from "node:crypto";
import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import {
  type HostCommandInput,
  type HostCommandStatus,
  hostCommandBodySchema,
  hostCommandIdSchema,
  hostCommandStdinBodySchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { isPrismaUniqueViolation } from "../../lib/prisma-errors";
import { createProcedureBudget } from "../../lib/procedure-budget";
import { authorizeServiceAction, serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import {
  type HostCommandPoll,
  hostAccess,
  hostAccessError,
  hostCredentialId,
} from "../host-access";
import { hostCommandProgram, hostSubjectHmac, recordHostCommandStatus } from "../host-audit";

type HostInput = { hostId: string; idempotencyKey?: string };
const target = (input: HostInput) => ({ sandboxHostId: input.hostId });
const startBudget = createProcedureBudget({
  keyPrefix: "host-command-start",
  points: 30,
  durationSeconds: 60,
  failClosed: true,
  redactErrors: true,
  overBudgetMessage: (seconds) => `Retry in ${seconds} seconds.`,
  unavailableMessage: "Host command budget unavailable.",
  unavailableLog: "Host command budget unavailable",
});

const pollInputSchema = z.object({
  commandId: hostCommandIdSchema,
  stdoutOffset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),
  stderrOffset: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER).default(0),
  maxBytes: z.number().int().min(1).max(65536).default(65536),
  waitMs: z.number().int().min(0).max(60000).default(0),
});
async function ownedCommand(principal: Principal, input: HostInput & { commandId: string }) {
  const row = await prisma.hostAuditEvent.findFirst({
    where: {
      sandboxHostId: input.hostId,
      userId: principal.ownerId,
      sdkKeyId: hostCredentialId(principal),
      commandId: input.commandId,
      kind: "COMMAND",
    },
    select: { state: true, exitCode: true, startedAt: true, finishedAt: true },
  });
  if (!row) throw hostAccessError("host.command_not_found");
  return row;
}
function emptyStatus(
  commandId: string,
  row: {
    state: string | null;
    exitCode: number | null;
    startedAt: Date | null;
    finishedAt: Date | null;
  },
): HostCommandStatus {
  return {
    commandId,
    state:
      row.state === "refused"
        ? "failed"
        : ["succeeded", "failed", "cancelled", "timed_out", "interrupted", "unknown"].includes(
              row.state ?? "",
            )
          ? (row.state as HostCommandStatus["state"])
          : "unknown",
    ...(row.exitCode === null ? {} : { exitCode: row.exitCode }),
    ...(row.startedAt ? { startedAt: row.startedAt.getTime() } : {}),
    ...(row.finishedAt ? { finishedAt: row.finishedAt.getTime() } : {}),
    stdout: { offset: 0, data: "", dropped: false },
    stderr: { offset: 0, data: "", dropped: false },
    stdoutBytes: 0,
    stderrBytes: 0,
  };
}
function isAgentAccessOff(error: unknown): boolean {
  return (
    error instanceof ORPCError &&
    (error.data as { code?: unknown } | undefined)?.code === "host.agent_access_off"
  );
}

async function pollUntil(
  principal: Principal,
  input: HostInput & HostCommandPoll & { waitMs?: number },
): Promise<HostCommandStatus> {
  const deadline = Date.now() + (input.waitMs ?? 0);
  for (;;) {
    await authorizeServiceAction(principal, "hostCommands.get", target(input));
    const row = await ownedCommand(principal, input);
    if (row.state === "refused") return emptyStatus(input.commandId, row);
    if (row.state === "interrupted") throw hostAccessError("host.node_offline");
    let polled: HostCommandStatus;
    try {
      polled = await hostAccess().poll(principal, input.hostId, input);
    } catch (error) {
      // A dashboard veto stops all traffic to the node, polls included. A
      // command that already ended (lowering marks running ones cancelled)
      // still reports its recorded state, without output, so the caller
      // learns it was cancelled instead of retrying forever.
      if (
        isAgentAccessOff(error) ||
        (error instanceof ORPCError && error.data?.code === "host.node_offline")
      ) {
        const latest = await ownedCommand(principal, input);
        if (latest.state !== "running") return emptyStatus(input.commandId, latest);
      }
      throw error;
    }
    const status = row.state === "cancelled" ? { ...polled, state: "cancelled" as const } : polled;
    await recordHostCommandStatus(input.hostId, principal.ownerId, status);
    if (status.state !== "running" || Date.now() >= deadline) return status;
    await new Promise<void>((resolve) =>
      setTimeout(resolve, Math.min(250, Math.max(1, deadline - Date.now()))),
    );
  }
}
export const runHostCommand = serviceProcedure(
  { action: "hostCommands.run", target },
  async (principal: Principal, input: HostInput & HostCommandInput) => {
    const parsed = hostCommandBodySchema.safeParse(
      (({ hostId: _h, idempotencyKey: _k, ...body }) => body)(input),
    );
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    const sdkKeyId = hostCredentialId(principal);
    await startBudget(sdkKeyId);
    await consumeSandboxWriteBudget(principal.ownerId, "ordinary");
    const commandId = input.idempotencyKey
      ? Buffer.from(
          hostSubjectHmac(JSON.stringify([sdkKeyId, input.hostId, input.idempotencyKey])).slice(12),
          "hex",
        )
          .subarray(0, 16)
          .toString("base64url")
      : randomBytes(16).toString("base64url");
    // Persist acceptance before dispatch. A retry can poll, never start it twice.
    const subjectHmac = hostSubjectHmac(JSON.stringify(parsed.data));
    const row = await prisma.hostAuditEvent
      .upsert({
        where: { commandId },
        create: {
          userId: principal.ownerId,
          sandboxHostId: input.hostId,
          sdkKeyId,
          actor: "AGENT",
          kind: "COMMAND",
          commandId,
          state: "running",
          program: hostCommandProgram(parsed.data),
          subjectHmac,
        },
        update: {},
        select: { id: true, subjectHmac: true, createdAt: true },
      })
      .catch(async (error: unknown) => {
        if (isPrismaUniqueViolation(error))
          return prisma.hostAuditEvent.findUniqueOrThrow({
            where: { commandId },
            select: { id: true, subjectHmac: true, createdAt: true },
          });
        throw error;
      });
    if (row.subjectHmac !== subjectHmac)
      throw new ORPCError("CONFLICT", { data: { code: "idempotency_conflict" } });
    // Only the insert winner may send start (the in-process gate also covers simultaneous retries).
    return startOnce(row.id, async () => {
      const existing = await prisma.hostAuditEvent.findFirst({
        where: { id: row.id },
        select: { startedAt: true, state: true },
      });
      if (existing?.startedAt || existing?.state !== "running")
        return pollUntil(principal, {
          ...input,
          commandId,
          stdoutOffset: 0,
          stderrOffset: 0,
          maxBytes: 65536,
        });
      // Claim once durably; a crash after this point is an unknown outcome, never a repeat effect.
      const claim = await prisma.hostAuditEvent.updateMany({
        where: { id: row.id, startedAt: null, state: "running" },
        data: { startedAt: new Date() },
      });
      if (!claim.count)
        return pollUntil(principal, {
          ...input,
          commandId,
          stdoutOffset: 0,
          stderrOffset: 0,
          maxBytes: 65536,
        });
      try {
        await authorizeServiceAction(principal, "hostCommands.run", target(input));
        const status = await hostAccess().start(principal, input.hostId, {
          ...parsed.data,
          commandId,
        });
        await prisma.hostAuditEvent.updateMany({
          where: { id: row.id, state: "running" },
          data: { startedAt: new Date(status.startedAt ?? Date.now()) },
        });
        if (input.waitMs)
          return pollUntil(principal, {
            ...input,
            commandId,
            stdoutOffset: 0,
            stderrOffset: 0,
            maxBytes: 65536,
          });
        return status;
      } catch (error) {
        const data = error instanceof ORPCError ? error.data : undefined;
        const reason =
          data && typeof data === "object" && "reason" in data && typeof data.reason === "string"
            ? data.reason
            : "dispatch_failed";
        await prisma.hostAuditEvent.updateMany({
          where: { id: row.id, state: "running" },
          data: {
            state:
              reason === "dispatch_failed" &&
              data &&
              typeof data === "object" &&
              "code" in data &&
              data.code === "host.node_offline"
                ? "unknown"
                : "refused",
            reason,
            finishedAt: new Date(),
          },
        });
        throw error;
      }
    });
  },
);
const starting = new Map<string, Promise<HostCommandStatus>>();
async function startOnce(id: string, run: () => Promise<HostCommandStatus>) {
  const existing = starting.get(id);
  if (existing) return existing;
  const work = run();
  starting.set(id, work);
  try {
    return await work;
  } finally {
    starting.delete(id);
  }
}
export const getHostCommand = serviceProcedure(
  { action: "hostCommands.get", target },
  async (
    principal: Principal,
    input: HostInput & {
      commandId: string;
      stdoutOffset?: number;
      stderrOffset?: number;
      maxBytes?: number;
      waitMs?: number;
    },
  ) => {
    const parsed = pollInputSchema.safeParse(input);
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    return pollUntil(principal, { hostId: input.hostId, ...parsed.data });
  },
);
export const writeHostCommandStdin = serviceProcedure(
  { action: "hostCommands.writeStdin", target },
  async (
    principal: Principal,
    input: HostInput & { commandId: string; data: string; eof: boolean },
  ) => {
    const parsed = hostCommandStdinBodySchema.safeParse({ data: input.data, eof: input.eof });
    if (!parsed.success || !hostCommandIdSchema.safeParse(input.commandId).success)
      throw new ORPCError("BAD_REQUEST");
    const row = await ownedCommand(principal, input);
    await consumeSandboxWriteBudget(principal.ownerId, "stdin");
    if (row.state !== "running")
      return { commandId: input.commandId, accepted: false, reason: "not_running" };
    return hostAccess().stdin(principal, input.hostId, {
      ...parsed.data,
      commandId: input.commandId,
    });
  },
);
export const cancelHostCommand = serviceProcedure(
  { action: "hostCommands.cancel", target },
  async (principal: Principal, input: HostInput & { commandId: string }) => {
    const row = await ownedCommand(principal, input);
    await consumeSandboxWriteBudget(principal.ownerId, "termination");
    if (row.state !== "running") return emptyStatus(input.commandId, row);
    const status = await hostAccess().cancel(principal, input.hostId, input.commandId);
    await recordHostCommandStatus(input.hostId, principal.ownerId, status);
    return status;
  },
);
