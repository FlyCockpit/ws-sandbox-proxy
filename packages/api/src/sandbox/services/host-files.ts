import { ORPCError } from "@orpc/server";
import prisma from "@wssp/db";
import {
  hostFileEditBodySchema,
  hostFileEditSchema,
  hostFileListBodySchema,
  hostFileListSchema,
  hostFileReadBodySchema,
  hostFileReadSchema,
  hostFileWriteBodySchema,
  hostFileWriteSchema,
} from "@wssp/sandbox-contracts";
import type { z } from "zod";
import { serviceProcedure } from "../../lib/sdk-key-access";
import { consumeSandboxWriteBudget } from "../budgets";
import type { Principal } from "../contracts";
import { hostAccess, hostCredentialId } from "../host-access";
import { hostSubjectHmac } from "../host-audit";

type HostInput = { hostId: string; idempotencyKey?: string };
const target = (input: HostInput) => ({ sandboxHostId: input.hostId });
async function audit(
  principal: Principal,
  hostId: string,
  path: string,
  kind: "FILE_READ" | "FILE_LIST" | "FILE_WRITE" | "FILE_EDIT",
) {
  const sdkKeyId = hostCredentialId(principal);
  await consumeSandboxWriteBudget(principal.ownerId, "ordinary");
  await prisma.hostAuditEvent.create({
    data: {
      userId: principal.ownerId,
      sandboxHostId: hostId,
      sdkKeyId,
      actor: "AGENT",
      kind,
      subjectHmac: hostSubjectHmac(path),
    },
    select: { id: true },
  });
}
const body = <T extends HostInput>(input: T) =>
  (({ hostId: _h, idempotencyKey: _k, ...rest }) => rest)(input);
export const readHostFile = serviceProcedure(
  { action: "hostFiles.read", target },
  async (principal: Principal, input: HostInput & z.output<typeof hostFileReadBodySchema>) => {
    const parsed = hostFileReadBodySchema.safeParse(body(input));
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    await audit(principal, input.hostId, parsed.data.path, "FILE_READ");
    return hostFileReadSchema.parse(
      await hostAccess().file(principal, input.hostId, { op: "read", ...parsed.data }),
    );
  },
);
export const listHostDir = serviceProcedure(
  { action: "hostFiles.list", target },
  async (principal: Principal, input: HostInput & z.output<typeof hostFileListBodySchema>) => {
    const parsed = hostFileListBodySchema.safeParse(body(input));
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    await audit(principal, input.hostId, parsed.data.path, "FILE_LIST");
    return hostFileListSchema.parse(
      await hostAccess().file(principal, input.hostId, { op: "list", ...parsed.data }),
    );
  },
);
export const writeHostFile = serviceProcedure(
  { action: "hostFiles.write", target },
  async (principal: Principal, input: HostInput & z.output<typeof hostFileWriteBodySchema>) => {
    const parsed = hostFileWriteBodySchema.safeParse(body(input));
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    await audit(principal, input.hostId, parsed.data.path, "FILE_WRITE");
    return hostFileWriteSchema.parse(
      await hostAccess().file(principal, input.hostId, { op: "write", ...parsed.data }),
    );
  },
);
export const editHostFile = serviceProcedure(
  { action: "hostFiles.edit", target },
  async (principal: Principal, input: HostInput & z.output<typeof hostFileEditBodySchema>) => {
    const parsed = hostFileEditBodySchema.safeParse(body(input));
    if (!parsed.success) throw new ORPCError("BAD_REQUEST");
    // Rust's wire bound includes all edit text in one 256 KiB budget.
    if (
      parsed.data.edits.reduce(
        (n, edit) => n + Buffer.byteLength(edit.oldText) + Buffer.byteLength(edit.newText),
        0,
      ) > 262144
    )
      throw new ORPCError("UNPROCESSABLE_CONTENT", {
        data: { code: "host.file_error", reason: "too_large" },
      });
    await audit(principal, input.hostId, parsed.data.path, "FILE_EDIT");
    return hostFileEditSchema.parse(
      await hostAccess().file(principal, input.hostId, { op: "edit", ...parsed.data }),
    );
  },
);
