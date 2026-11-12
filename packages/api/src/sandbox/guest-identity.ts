import { z } from "zod";
import limits from "../../../config/src/sandbox-receipt-limits.json";

const DEFAULT_GUEST_UID = 1000;
const DEFAULT_GUEST_GID = 1000;
const DEFAULT_GUEST_HOME = "/home/user";
const DEFAULT_GUEST_SHELL = "/bin/bash";

const guestPathSchema = z
  .string()
  .min(2)
  .refine((value) => new TextEncoder().encode(value).length <= limits.guestPathBytes)
  .refine(
    (value) =>
      value.startsWith("/") &&
      Array.from(value).every((char) => {
        const code = char.codePointAt(0) ?? 0;
        return code >= 32 && (code < 127 || code > 159) && (code < 0xd800 || code > 0xdfff);
      }) &&
      value
        .split("/")
        .slice(1)
        .every((part) => part !== "" && part !== "." && part !== ".."),
    "Guest paths must be absolute and normalized",
  );
const guestShellSchema = guestPathSchema;

export const guestIdentityInput = z.object({
  guestUid: z.number().int().min(1).max(limits.guestIdMax).default(DEFAULT_GUEST_UID),
  guestGid: z.number().int().min(1).max(limits.guestIdMax).default(DEFAULT_GUEST_GID),
  guestHome: guestPathSchema.default(DEFAULT_GUEST_HOME),
  guestShell: guestShellSchema.default(DEFAULT_GUEST_SHELL),
});

export type GuestIdentityInput = z.infer<typeof guestIdentityInput>;

export type GuestIdentity = {
  guestUid: number;
  guestGid: number;
  guestHome: string;
  guestShell: string;
};

export function normalizeGuestIdentity(input: GuestIdentityInput): GuestIdentity {
  return guestIdentityInput.parse(input);
}
