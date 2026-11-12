import {
  CAPTURE_EXTRA_SCRUB_PATHS_MAX,
  COMMAND_PAYLOAD_MAX_BYTES,
  isSafeMapText,
  resourceIdSchema,
  validScrubPath,
  vmSizeOverridesSchema,
} from "@wssp/sandbox-contracts";
import { z } from "zod";
import { RECIPE_EGRESS_PRESETS_MAX } from "./egress";

/** Recipe bounds. Command and env limits are the sandbox ones. */
export const RECIPE_LIMITS = Object.freeze({
  /** Canonical JSON bytes. */
  recipeBytes: 65536,
  /** Dockerfile source bytes (UTF-8). */
  dockerfileBytes: 65536,
  steps: 256,
  /** Merged command payload of one run step (script + cwd + effective envs). */
  stepPayloadBytes: COMMAND_PAYLOAD_MAX_BYTES,
  /** Same as the capture body's extra scrub paths. */
  scrubPaths: CAPTURE_EXTRA_SCRUB_PATHS_MAX,
  egressPresets: RECIPE_EGRESS_PRESETS_MAX,
  copySources: 64,
  /** Bytes of one substitutable path or value before substitution. */
  textBytes: 4096,
  /**
   * Total expanded output (UTF-16 code units) of every substitution in one
   * planning pass; each expanded value is also capped at `textBytes`.
   */
  expansionBytes: 1048576,
  startCommandBytes: 4096,
  readyTimeoutMsMin: 1000,
  readyTimeoutMsMax: 600000,
});

const encoder = new TextEncoder();
const boundedText = (maxBytes: number) =>
  z
    .string()
    .min(1)
    .refine((value) => isSafeMapText(value) && encoder.encode(value).byteLength <= maxBytes, {
      message: `Text must be valid Unicode without NUL, at most ${maxBytes} UTF-8 bytes.`,
    });
const valueText = z
  .string()
  .refine(
    (value) => isSafeMapText(value) && encoder.encode(value).byteLength <= RECIPE_LIMITS.textBytes,
    { message: "Value must be valid Unicode without NUL, at most 4096 UTF-8 bytes." },
  );

/** POSIX env name; ARG and ENV share it. */
export const RECIPE_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const nameSchema = z.string().max(128).regex(RECIPE_NAME_PATTERN);
/** Names stored defaults reserve for guest identity and PTYs. */
export const RESERVED_ENV_NAMES: readonly string[] = Object.freeze(["HOME", "SHELL", "TERM"]);

/** Same syntax as the template selector's slug and the capture tag. */
export const TEMPLATE_SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
export const TEMPLATE_TAG_PATTERN = /^[a-z0-9][a-z0-9._-]{0,62}$/;

export const recipeUserSchema = z.enum(["root", "user"]);
export type RecipeUser = z.infer<typeof recipeUserSchema>;

const fromSchema = z.union([
  z.strictObject({
    template: z.string().max(63).regex(TEMPLATE_SLUG_PATTERN),
    tag: z.string().regex(TEMPLATE_TAG_PATTERN).optional(),
  }),
  z.strictObject({ revisionId: resourceIdSchema }),
]);

const envMap = z
  .record(nameSchema, valueText)
  .refine((values) => Object.keys(values).length > 0, { message: "ENV needs a value." });

export const recipeStepSchema = z.discriminatedUnion("type", [
  z.strictObject({
    type: z.literal("run"),
    script: boundedText(RECIPE_LIMITS.stepPayloadBytes),
    user: recipeUserSchema.optional(),
  }),
  z.strictObject({ type: z.literal("env"), values: envMap }),
  z.strictObject({ type: z.literal("workdir"), path: boundedText(RECIPE_LIMITS.textBytes) }),
  z.strictObject({ type: z.literal("user"), user: recipeUserSchema }),
  z.strictObject({ type: z.literal("arg"), name: nameSchema, default: valueText.optional() }),
  z.strictObject({
    type: z.literal("copy"),
    src: z.array(boundedText(RECIPE_LIMITS.textBytes)).min(1).max(RECIPE_LIMITS.copySources),
    dest: boundedText(RECIPE_LIMITS.textBytes),
    owner: recipeUserSchema.optional(),
    /** Octal permission bits applied to copied files, e.g. "0644". */
    mode: z
      .string()
      .regex(/^0?[0-7]{3}$/)
      .nullable()
      .optional(),
  }),
]);
export type RecipeStep = z.infer<typeof recipeStepSchema>;

export const recipeEgressSchema = z.strictObject({
  mode: z.enum(["open", "allowlist"]).optional(),
  presets: z.array(z.string().max(64)).max(RECIPE_LIMITS.egressPresets).optional(),
  domains: z.array(z.string().max(253)).max(128).optional(),
  cidrs: z.array(z.string().max(64)).max(128).optional(),
});
export type RecipeEgress = z.infer<typeof recipeEgressSchema>;

export const recipeSchema = z.strictObject({
  version: z.literal(1),
  from: fromSchema,
  /** Values for declared ARGs (each key must be declared by an `arg` step). */
  args: z.record(nameSchema, valueText).optional(),
  steps: z.array(recipeStepSchema).max(RECIPE_LIMITS.steps),
  /** Run at every boot of a sandbox from the built revision, as the guest
   * user; READY waits for `ready` to exit 0 within `readyTimeoutMs` (B9). */
  start: z
    .strictObject({
      command: boundedText(RECIPE_LIMITS.startCommandBytes),
      ready: boundedText(RECIPE_LIMITS.startCommandBytes).optional(),
      readyTimeoutMs: z
        .number()
        .int()
        .min(RECIPE_LIMITS.readyTimeoutMsMin)
        .max(RECIPE_LIMITS.readyTimeoutMsMax)
        .optional(),
    })
    .optional(),
  resources: vmSizeOverridesSchema.optional(),
  egress: recipeEgressSchema.optional(),
  scrubPaths: z
    .array(z.string().refine(validScrubPath, "invalid scrub path"))
    .max(RECIPE_LIMITS.scrubPaths)
    .optional(),
});
export type Recipe = z.infer<typeof recipeSchema>;
export type RecipeFrom = Recipe["from"];

/** The `/v1` template selector string for the recipe's base. */
export function recipeFromSelector(from: RecipeFrom): string {
  if ("revisionId" in from) return `revision/${from.revisionId}`;
  return from.tag === undefined ? from.template : `${from.template}:${from.tag}`;
}
