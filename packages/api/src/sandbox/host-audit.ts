import { basename } from "node:path";
import prisma from "@wssp/db";
import { hmacDigestForProductPurpose } from "@wssp/db/credential-security";
import type { HostCommandStatus } from "@wssp/sandbox-contracts";
export function hostSubjectHmac(value: string): string {
  return `hmac-sha256:${hmacDigestForProductPurpose({ purpose: "hostCommandAudit", value })}`;
}
export function hostCommandProgram(input: { argv?: string[]; script?: string }): string {
  const words = input.script?.trim().split(/\s+/) ?? [];
  while (words[0] && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[0])) words.shift();
  const program = basename(input.argv?.[0] ?? words[0] ?? "?");
  return /^[A-Za-z0-9._+-]{1,64}$/.test(program) ? program : "?";
}
/** End-state CAS: a late daemon result must never undo dashboard cancellation. */
export async function recordHostCommandStatus(
  hostId: string,
  ownerId: string,
  status: HostCommandStatus,
) {
  if (status.state === "running") return;
  await prisma.hostAuditEvent.updateMany({
    where: {
      sandboxHostId: hostId,
      userId: ownerId,
      kind: "COMMAND",
      commandId: status.commandId,
      state: { in: ["running", "unknown"] },
    },
    data: {
      state: status.state,
      exitCode: status.exitCode,
      finishedAt: new Date(status.finishedAt ?? Date.now()),
    },
  });
}
export async function interruptHostCommands(hostId: string, ownerId: string) {
  const disconnectedAt = new Date();
  await prisma.hostAuditEvent.updateMany({
    where: {
      sandboxHostId: hostId,
      userId: ownerId,
      kind: "COMMAND",
      state: "running",
      createdAt: { lte: disconnectedAt },
    },
    data: { state: "interrupted", reason: "disconnected", finishedAt: new Date() },
  });
}
