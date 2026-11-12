import { z } from "zod";
import { isStringMapShape } from "./map-primitives";

// Shape/Unicode checks run before record parsing can discard prototype keys
// or invoke accessors. Numeric bounds are composed in env.ts.
export const envShapeSchema = z.preprocess(
  (value, ctx) => {
    if (!isStringMapShape(value)) {
      ctx.addIssue({ code: "custom", message: "sandbox.env_invalid" });
      return z.NEVER;
    }
    return value;
  },
  z.record(z.string().regex(/^[A-Za-z_][A-Za-z0-9_]*$/, "sandbox.env_invalid"), z.string()),
) as z.ZodType<Record<string, string>, Record<string, string>>;
// Preprocess does not coerce: advertise the accepted map type to typed callers
// instead of its default `unknown` input. safeParse still checks unknown values.

// Stored template/sandbox defaults reserve guest identity and PTY TERM.
// Command-level TERM retains its piped-command behavior.
export const defaultEnvShapeSchema = envShapeSchema.refine(
  (value) => !["HOME", "SHELL", "TERM"].some((key) => Object.hasOwn(value, key)),
  "sandbox.env_invalid",
);
