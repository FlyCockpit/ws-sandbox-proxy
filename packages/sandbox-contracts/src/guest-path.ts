import { z } from "zod";

/**
 * Guest paths: one rule for the server and the SDK (TQ-N2, E-28). Paths name
 * files in the VM only and are never interpolated into a server path.
 *
 * `guestPathSchema` mirrors the host's `validate_guest_path`
 * (crates/sandbox-runtime/src/incus/client.rs): absolute, at most 4096 UTF-8
 * bytes, no NUL and no `..` component. It also refuses unpaired UTF-16
 * surrogates (they cannot be sent as UTF-8) and leading or trailing
 * whitespace: a path is never trimmed, because `/data/report ` and
 * `/data/report` are different files (G4R1-1). Every file operation uses it.
 *
 * `guestEntryPathSchema` also requires at least one name, so `/` is refused
 * where the host refuses it (mkdir, move, remove: G4R1-2).
 *
 * `guestFilePathSchema` adds the guest file helper's rules for moving file
 * bytes (crates/sandbox-runtime/src/incus/file-helper.py): no `.` component and
 * at least one name. It also keeps the transfer rule against control
 * characters. Uploads and downloads use it, so a path the
 * guest would refuse is refused with 400 before any slot or disk is reserved.
 */
export const GUEST_PATH_MAX_BYTES = 4096;
const encoder = new TextEncoder();
const components = (path: string) => path.split("/");
export const guestPathSchema = z
  .string()
  .refine((path) => !path.includes("\0"), { message: "Path must not contain NUL." })
  // A Unicode iterator combines valid pairs; a remaining surrogate is lone.
  .refine(
    (path) =>
      Array.from(path).every((char) => {
        const point = char.codePointAt(0)!;
        return point < 0xd800 || point > 0xdfff;
      }),
    { message: "Path must not contain unpaired UTF-16 surrogates." },
  )
  .refine((path) => path === path.trim(), {
    message: "Path must not start or end with whitespace.",
  })
  .min(1)
  .max(GUEST_PATH_MAX_BYTES)
  .regex(/^\//)
  .refine((path) => encoder.encode(path).byteLength <= GUEST_PATH_MAX_BYTES, {
    message: `Path must be at most ${GUEST_PATH_MAX_BYTES} UTF-8 bytes.`,
  })
  .refine((path) => path.startsWith("/") && !components(path).includes(".."), {
    message: "Path must be an absolute guest path without `..`.",
  });
export const guestEntryPathSchema = guestPathSchema.refine(
  (path) => components(path).some(Boolean),
  { message: "Path must name an entry, not `/`." },
);
export const guestFilePathSchema = guestEntryPathSchema
  .refine((path) => !components(path).includes("."), {
    message: "File path must not contain a `.` component.",
  })
  .refine(
    (path) => [...path].every((char) => char.charCodeAt(0) >= 32 && char.charCodeAt(0) !== 127),
    { message: "File path must not contain control characters." },
  );

/** Metadata intents validate before lexical normalization. Transfer inputs
 * retain their stricter existing rules. Never trim or URL-decode JSON paths. */
export const metadataGuestPathSchema = guestPathSchema.transform((path) => {
  const parts = path.split("/").filter((part) => part !== "" && part !== ".");
  return parts.length ? `/${parts.join("/")}` : "/";
});
export const metadataGuestEntryPathSchema = metadataGuestPathSchema.refine((path) => path !== "/");
