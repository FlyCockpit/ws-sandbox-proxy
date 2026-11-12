import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import type { SandboxOffloadPinDto } from "@wssp/sandbox-contracts";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal, SetSandboxOffloadPinInput } from "../contracts";
import { sandboxStateConflict } from "../errors";
import { budgetSubjectOf } from "../principal-kinds";

/**
 * The owner's restore pin: `OWN_HOSTS` excludes other
 * users' hosts from every later restore of this sandbox's stored disk. A
 * dashboard (owner session) setting only, like the creator-allowlist
 * override; managed sandboxes are never offloaded and refuse it
 * (`sandbox.state_conflict`). It narrows or widens only where a FUTURE restore may
 * run: a restore already admitted keeps its host, and the sandbox's login
 * history (`credentialFilesEver`) keeps it on own hosts whatever the pin says.
 */
export const setSandboxOffloadPin = serviceProcedure(
  { sessionOnly: true },
  async (
    owner: Principal,
    input: SetSandboxOffloadPinInput,
  ): Promise<{ id: string; offloadPin: SandboxOffloadPinDto }> => {
    const budgetOwner = budgetSubjectOf(owner)?.ownerId;
    if (budgetOwner) await consumeSandboxWriteBudget(budgetOwner, "ordinary");
    return prisma.$transaction(async (tx) => {
      const [row] = await tx.$queryRaw<{ id: string }[]>`
        SELECT id FROM sandbox_instance
        WHERE id = ${input.id} AND "userId" = ${owner.ownerId}
        FOR NO KEY UPDATE`;
      const sandbox = row
        ? await tx.sandbox.findFirst({
            where: { id: row.id, userId: owner.ownerId },
            select: { state: true, purpose: true } satisfies Prisma.SandboxSelect,
          })
        : null;
      if (!sandbox) throw new ORPCError("NOT_FOUND", { message: "Sandbox not found" });
      if (sandbox.purpose !== "WORKLOAD")
        throw sandboxStateConflict("Managed sandboxes are never offloaded.");
      if (sandbox.state === "DELETED") throw sandboxStateConflict("Sandbox is deleted.");
      return tx.sandbox.update({
        where: { id: input.id, userId: owner.ownerId },
        data: { offloadPin: input.offloadPin },
        select: { id: true, offloadPin: true } satisfies Prisma.SandboxSelect,
      });
    });
  },
);
