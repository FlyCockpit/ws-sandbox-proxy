import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import { lockOwnerForAdmission } from "@wssp/db/account-deletion";
import { withAuthorityChange } from "@wssp/db/authority";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import { type HostNodeOffWitness, hostAccess, hostAccessError } from "../host-access";

async function lower(
  principal: Principal,
  input: { id: string },
  target: "hostCommands" | "hostTerminal",
) {
  await consumeSandboxWriteBudget(principal.ownerId, "ordinary");
  await withAuthorityChange({ ownerId: principal.ownerId, hostId: input.id }, () =>
    prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, principal.ownerId);
      const changed = await tx.sandboxHost.updateMany({
        where: { id: input.id, userId: principal.ownerId, deletionRequestedAt: null },
        data:
          target === "hostCommands"
            ? { agentHostCommandsVetoedAt: new Date() }
            : { hostTerminalVetoedAt: new Date() },
      });
      if (!changed.count) throw new ORPCError("NOT_FOUND");
      if (target === "hostCommands")
        await tx.hostAuditEvent.updateMany({
          where: {
            userId: principal.ownerId,
            sandboxHostId: input.id,
            kind: "COMMAND",
            state: "running",
          },
          data: { state: "cancelled", reason: "policy_lowered", finishedAt: new Date() },
        });
      await tx.hostAuditEvent.create({
        data: {
          userId: principal.ownerId,
          sandboxHostId: input.id,
          actor: "PERSON",
          kind: "POLICY_LOWER",
          reason: target === "hostCommands" ? "host_commands" : "host_terminal",
        },
        select: { id: true },
      });
    }),
  );
  // Durable veto denies access immediately, including while disconnected.
  try {
    await hostAccess().lower(input.id, principal.ownerId, target);
  } catch {
    /* Hello resends the committed lowering. */
  }
  return { ok: true as const, vetoed: true as const };
}
export const lowerAgentHostCommands = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: { id: string }) => lower(principal, input, "hostCommands"),
);
export const lowerHostTerminal = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: { id: string }) => lower(principal, input, "hostTerminal"),
);

/** Only a person can lift the server veto. No frame enables the node setting. */
async function lift(
  principal: Principal,
  input: { id: string },
  target: "hostCommands" | "hostTerminal",
) {
  await consumeSandboxWriteBudget(principal.ownerId, "ordinary");
  // Sample authenticated live state before our own authority-change fence.
  let witness: HostNodeOffWitness | null = null;
  try {
    witness = hostAccess().offWitness?.(input.id, principal.ownerId, target) ?? null;
  } catch {
    /* No bridge means no live off proof. */
  }
  await withAuthorityChange({ ownerId: principal.ownerId, hostId: input.id }, () =>
    prisma.$transaction(async (tx) => {
      await lockOwnerForAdmission(tx, principal.ownerId);
      const host = await tx.sandboxHost.findFirst({
        where: { id: input.id, userId: principal.ownerId, deletionRequestedAt: null },
        select: { connectionEpoch: true },
      });
      if (!host) throw new ORPCError("NOT_FOUND");
      const requireNodeOff = () => {
        if (!witness || witness.epoch !== host.connectionEpoch || !witness.isOff())
          throw hostAccessError("host.node_not_off");
      };
      requireNodeOff();
      const changed = await tx.sandboxHost.updateMany({
        where: { id: input.id, userId: principal.ownerId, deletionRequestedAt: null },
        data:
          target === "hostCommands"
            ? { agentHostCommandsVetoedAt: null }
            : { hostTerminalVetoedAt: null },
      });
      if (!changed.count) throw new ORPCError("NOT_FOUND");
      await tx.hostAuditEvent.create({
        data: {
          userId: principal.ownerId,
          sandboxHostId: input.id,
          actor: "PERSON",
          kind: "POLICY_VETO_LIFT",
          reason: target === "hostCommands" ? "host_commands" : "host_terminal",
        },
        select: { id: true },
      });
      // A disconnect, reconnect or on report during DB IO must roll back the lift.
      requireNodeOff();
    }),
  );
  // Clear only the local veto cache; preserve the actual node-reported policy.
  try {
    hostAccess().lift?.(input.id, principal.ownerId, target);
  } catch {
    /* Offline is safe. */
  }
  return { ok: true as const };
}
export const liftAgentHostCommandsVeto = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: { id: string }) => lift(principal, input, "hostCommands"),
);
export const liftHostTerminalVeto = serviceProcedure(
  { sessionOnly: true },
  async (principal: Principal, input: { id: string }) => lift(principal, input, "hostTerminal"),
);
