/** Strict mirror of crates/sandbox-protocol/src/host_access.rs. */

import {
  HOST_FILE_ERROR_REASONS,
  hostCommandBodySchema,
  hostCommandIdSchema,
  hostCommandStatusSchema,
  hostCommandStdinBodySchema,
  hostCommandStdinResultSchema,
  hostFileEditBodySchema,
  hostFileEditSchema,
  hostFileListBodySchema,
  hostFileListSchema,
  hostFileReadBodySchema,
  hostFileReadSchema,
  hostFileWriteBodySchema,
  hostFileWriteSchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";

const safe = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const id = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_.:-]+$/);
const epoch = z.number().int().min(1).max(2147483647);
export const agentPolicyFields = {
  hostCommands: z.boolean().optional(),
  hostFiles: z.boolean().optional(),
  hostCommandMaxMs: z.number().int().min(1000).max(86400000).optional(),
  agentPolicyRevision: safe.optional(),
};
export function validAgentPolicy(value: {
  hostCommands?: boolean;
  hostFiles?: boolean;
  hostCommandMaxMs?: number;
}) {
  return (
    (!value.hostFiles || value.hostCommands === true) &&
    (value.hostCommands === true
      ? value.hostCommandMaxMs !== undefined
      : value.hostCommandMaxMs === undefined)
  );
}
const hostAgentPolicySchema = z
  .strictObject({
    type: z.literal("host.agent-policy"),
    connectionEpoch: epoch,
    sequence: safe.min(1),
    ...agentPolicyFields,
    hostCommands: z.boolean(),
    hostFiles: z.boolean(),
    agentPolicyRevision: safe,
  })
  .refine(validAgentPolicy);
const request = { connectionEpoch: epoch, requestId: id };
const command = { ...request, commandId: hostCommandIdSchema };
const hostServerSchemas = [
  z.strictObject({
    type: z.literal("host.policy.lower"),
    ...request,
    target: z.enum(["hostCommands", "hostTerminal"]),
  }),
  z
    .strictObject({
      type: z.literal("host.exec.start"),
      ...command,
      ownerId: id,
      agentPolicyRevision: safe,
      ...hostCommandBodySchema.shape,
      waitMs: z.never().optional(),
      timeoutMs: safe.min(1),
      stdin: z.boolean(),
    })
    .refine(
      (value) =>
        hostCommandBodySchema.safeParse({
          argv: value.argv,
          script: value.script,
          cwd: value.cwd,
          timeoutMs: Math.min(value.timeoutMs, 86400000),
          stdin: value.stdin,
        }).success,
    ),
  z.strictObject({
    type: z.literal("host.exec.poll"),
    ...command,
    stdoutOffset: safe,
    stderrOffset: safe,
    maxBytes: z.number().int().min(0).max(65536),
  }),
  z.strictObject({
    type: z.literal("host.exec.stdin"),
    ...command,
    ...hostCommandStdinBodySchema.shape,
  }),
  z.strictObject({ type: z.literal("host.exec.cancel"), ...command }),
  ...(
    [
      ["read", hostFileReadBodySchema],
      ["list", hostFileListBodySchema],
      ["write", hostFileWriteBodySchema],
      ["edit", hostFileEditBodySchema],
    ] as const
  ).map(([op, schema]) =>
    z.strictObject({
      type: z.literal("host.file.request"),
      ...request,
      ownerId: id,
      agentPolicyRevision: safe,
      op: z.literal(op),
      ...schema.shape,
    }),
  ),
] as const;
export const hostServerMessageSchema = z.union(hostServerSchemas);
export type HostServerMessage = z.infer<typeof hostServerMessageSchema>;
export const hostDaemonSchemas = [
  hostAgentPolicySchema,
  z.strictObject({ type: z.literal("host.policy.lower.result"), requestId: id, ok: z.boolean() }),
  z
    .strictObject({
      type: z.literal("host.exec.started"),
      requestId: id,
      commandId: hostCommandIdSchema,
      startedAt: safe,
      endsBy: safe,
    })
    .refine((v) => v.startedAt <= v.endsBy),
  z.strictObject({
    type: z.literal("host.exec.rejected"),
    requestId: id,
    commandId: hostCommandIdSchema,
    reason: z.enum([
      "host_commands_off",
      "policy_changed",
      "owner_mismatch",
      "bad_command",
      "bad_cwd",
      "limit",
      "duplicate",
      "spawn_failed",
    ]),
  }),
  hostCommandStatusSchema.extend({ type: z.literal("host.exec.status"), requestId: id.optional() }),
  hostCommandStdinResultSchema.extend({ type: z.literal("host.exec.stdin.result"), requestId: id }),
  z.strictObject({
    type: z.literal("host.file.result"),
    requestId: id,
    ok: z.literal(true),
    result: z.union([
      hostFileReadSchema,
      hostFileListSchema,
      hostFileWriteSchema,
      hostFileEditSchema,
    ]),
  }),
  z.strictObject({
    type: z.literal("host.file.result"),
    requestId: id,
    ok: z.literal(false),
    error: z.enum(HOST_FILE_ERROR_REASONS),
  }),
] as const;
export type HostDaemonMessage = z.infer<typeof hostDaemonMessageSchema>;
const hostDaemonMessageSchema = z.union(hostDaemonSchemas);
export const HOST_CONTROL_MAX_BYTES = 2 * 1024 * 1024;
