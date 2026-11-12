import { z } from "zod";
import resultLimits from "../../config/src/sandbox-result-limits.json";
import {
  cursorSchema,
  isoDateTimeSchema,
  OPERATION_STATES,
  type OperationFailure,
  type OperationStateDto,
  resourceIdSchema,
} from "./dto";

/** Reject malformed UTF-16 before UTF-8 encoding can replace it with U+FFFD. */
export function utf8String(maxBytes: number) {
  return z
    .string()
    .refine((value) => value.isWellFormed() && new TextEncoder().encode(value).length <= maxBytes);
}
/** Observed paths are canonical: no empty, `.` or `..` component (except `/`). */
export const observedGuestPathSchema = utf8String(4096).refine(
  (value) =>
    value.startsWith("/") &&
    !value.includes("\0") &&
    (value === "/" ||
      value
        .slice(1)
        .split("/")
        .every((part) => part !== "" && part !== "." && part !== "..")),
);
export const processRefSchema = z
  .object({
    sandboxId: resourceIdSchema,
    generation: z.number().int().positive().max(2_147_483_647),
    processId: resourceIdSchema,
    attempt: z.number().int().positive().max(2_147_483_647),
    pid: z.number().int().min(2).max(2_147_483_647),
  })
  .strict();
export type ProcessRef = z.infer<typeof processRefSchema>;
const processArgumentSchema = utf8String(2048)
  .max(512)
  .refine((value) => value.length <= 512 && !value.includes("\0"));
export const processInfoSchema = z
  .object({
    process: processRefSchema,
    operationId: resourceIdSchema,
    kind: z.literal("command"),
    cmd: processArgumentSchema,
    args: z
      .array(processArgumentSchema)
      .max(256)
      .refine((args) => new TextEncoder().encode(JSON.stringify(args)).length <= 4096),
    argsTruncated: z.boolean(),
    cwd: observedGuestPathSchema,
    startedAt: isoDateTimeSchema,
    observedAt: isoDateTimeSchema,
  })
  .strict()
  .refine(
    ({ cmd, args, argsTruncated, cwd }) =>
      new TextEncoder().encode(JSON.stringify({ cmd, args, argsTruncated, cwd })).length <=
      resultLimits.descriptionMaxBytes,
  );
export type ProcessInfo = z.infer<typeof processInfoSchema>;
export const processConnectionSchema = z
  .object({
    info: processInfoSchema,
    state: z.enum(OPERATION_STATES),
    exitCode: z.number().int().min(-2_147_483_648).max(2_147_483_647).nullable(),
    outputOperationId: resourceIdSchema,
    attempt: z.number().int().positive().max(2_147_483_647),
    attachmentCursor: cursorSchema,
  })
  .strict()
  .refine(
    (value) =>
      value.info.operationId === value.outputOperationId &&
      value.info.process.attempt === value.attempt,
  );
export type ProcessConnection = z.infer<typeof processConnectionSchema>;
export const processSignalSchema = z.enum(["SIGTERM", "SIGINT", "SIGHUP", "SIGKILL"]);

/** Staged qualified controls; existing naked-PID routes are cut over in 6C. */
export const processQualifiersSchema = processRefSchema.omit({ sandboxId: true, pid: true });
export const qualifiedProcessSignalSchema = processQualifiersSchema
  .extend({ signal: processSignalSchema })
  .strict();

/** Explicit multi-parameter native routes; never use the single-id mutation helper. */
export const processParamsSchema = z
  .object({
    id: resourceIdSchema,
    pid: z
      .string()
      .regex(/^[1-9][0-9]{0,9}$/)
      .transform(Number)
      .pipe(processRefSchema.shape.pid),
  })
  .strict();
const positiveQuery = z
  .string()
  .regex(/^[1-9][0-9]{0,9}$/)
  .transform(Number)
  .pipe(z.number().int().positive().max(2_147_483_647));
export const processConnectQuerySchema = z
  .object({
    generation: positiveQuery,
    processId: resourceIdSchema,
    attempt: positiveQuery,
  })
  .strict();

/** Classify the command observed after canonical cancellation, never the action receipt.
 * A failed command needs known effect evidence to prove it has finished.
 */
export function classifyKillOutcome(target: {
  state: OperationStateDto;
  failure?: OperationFailure | null;
}): "killed" | "alreadyExited" | "unknown" {
  if (target.state === "CANCELLED") return "killed";
  if (target.state === "SUCCEEDED") return "alreadyExited";
  if (target.state === "FAILED" && target.failure && target.failure.effect !== "unknown")
    return "alreadyExited";
  return "unknown";
}
