import { z } from "zod";

/** Longest sandbox name: one DNS label. */
export const SANDBOX_NAME_MAX = 63;

const SANDBOX_NAME_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const UUID_SHAPED = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/**
 * Whether `value` is an acceptable sandbox name: a lowercase DNS label
 * (1-63 characters of `a-z`, `0-9` and inner hyphens), not shaped like a
 * UUID (ids are UUIDs) and without the reserved `wssp-` prefix (Incus
 * instances are `wssp-sbx-<id>`). Names are never transformed: an invalid
 * name is refused, not normalized.
 */
export function isValidSandboxName(value: string): boolean {
  return (
    value.length <= SANDBOX_NAME_MAX &&
    SANDBOX_NAME_PATTERN.test(value) &&
    !UUID_SHAPED.test(value) &&
    !value.startsWith("wssp-")
  );
}

export const sandboxNameSchema = z
  .string()
  .min(1)
  .max(SANDBOX_NAME_MAX)
  .refine(isValidSandboxName, "Use 1-63 lowercase letters, digits and inner hyphens.")
  .meta({
    description:
      "Sandbox name: a lowercase DNS label (1-63 characters of a-z, 0-9 and inner hyphens), unique among the owner's live sandboxes. Not UUID-shaped and not starting with `wssp-`.",
    example: "quiet-otter",
  });
