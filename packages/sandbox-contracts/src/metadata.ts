import { z } from "zod";
import { isSafeMapName, isSafeMapText, isStringMapShape } from "./map-primitives";
export const METADATA_MAX_BYTES = 8192;
export const METADATA_MAX_KEYS = 32;

// Zod preprocess exposes unknown input; the guarded public map deliberately
// advertises string values to typed SDK and oRPC callers as well as at runtime.
/** String-only labels; limits retain the existing UTF-16 unit and JSON UTF-8 byte bounds. */
export const metadataSchema = z.preprocess(
  (value, ctx) => {
    if (!isStringMapShape(value)) {
      ctx.addIssue({ code: "custom", message: "sandbox.metadata_invalid" });
      return z.NEVER;
    }
    return value;
  },
  z
    .record(
      // Zod 4.6 measures string bounds in code points; this contract uses UTF-16 units.
      z
        .string()
        .min(1)
        .max(64)
        .refine((value) => value.length <= 64 && isSafeMapName(value), "sandbox.metadata_invalid"),
      z
        .string()
        .max(1024)
        .refine(
          (value) => value.length <= 1024 && isSafeMapText(value),
          "sandbox.metadata_invalid",
        ),
    )
    .superRefine((value, ctx) => {
      if (
        Object.keys(value).length > METADATA_MAX_KEYS ||
        new TextEncoder().encode(JSON.stringify(value)).byteLength > METADATA_MAX_BYTES
      ) {
        ctx.addIssue({ code: "custom", message: "sandbox.metadata_invalid" });
      }
    })
    .meta({
      maxProperties: METADATA_MAX_KEYS,
      "x-wssp-maxSerializedBytes": METADATA_MAX_BYTES,
      description:
        "String metadata; keys use 1–64 UTF-16 units, values at most 1024; canonical JSON at most 8192 UTF-8 bytes. NUL, malformed Unicode and prototype-related keys are refused.",
    }),
) as z.ZodType<Record<string, string>, Record<string, string>>;
