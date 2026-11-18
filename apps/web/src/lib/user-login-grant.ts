import {
  USER_LOGIN_DEFAULT_EXPIRY_DAYS,
  USER_LOGIN_DEFAULT_NAME,
  type UserLoginGrant,
  userLoginGrantSchema,
} from "@wssp/config/user-device-login";

/**
 * The `wssp login` approval form's draft. Inputs keep their raw text (the
 * live-sandbox limit and expiry are strings); `userLoginGrantFromDraft` turns
 * the draft into exactly the grant the approve endpoint accepts.
 */
export type UserLoginDraft = {
  name: string;
  access: UserLoginGrant["access"];
  poolMode: UserLoginGrant["poolMode"];
  poolIds: string[];
  ownSandboxesOnly: boolean;
  /** Empty means no limit. */
  maxLiveSandboxes: string;
  expiresInDays: string;
};

export const DEFAULT_USER_LOGIN_DRAFT: UserLoginDraft = {
  name: USER_LOGIN_DEFAULT_NAME,
  access: "read",
  poolMode: "ALL_USABLE",
  poolIds: [],
  ownSandboxesOnly: false,
  maxLiveSandboxes: "",
  expiresInDays: String(USER_LOGIN_DEFAULT_EXPIRY_DAYS),
};

/** A whole positive decimal number, or `undefined` for anything else. */
function wholeNumber(text: string): number | undefined {
  const trimmed = text.trim();
  return /^\d+$/.test(trimmed) ? Number(trimmed) : undefined;
}

/** `null` for an empty limit, `undefined` for one that is not a whole number. */
export function draftMaxLiveSandboxes(text: string): number | null | undefined {
  return text.trim() === "" ? null : wholeNumber(text);
}

/**
 * The grant a draft asks for, or `null` when it would not parse. Pools are sent
 * only for SELECTED (a hidden selection never leaks into an all-pools grant).
 */
export function userLoginGrantFromDraft(draft: UserLoginDraft): UserLoginGrant | null {
  const maxLiveSandboxes = draftMaxLiveSandboxes(draft.maxLiveSandboxes);
  if (maxLiveSandboxes === undefined) return null;
  const parsed = userLoginGrantSchema.safeParse({
    access: draft.access,
    poolMode: draft.poolMode,
    poolIds: draft.poolMode === "SELECTED" ? draft.poolIds : [],
    ownSandboxesOnly: draft.ownSandboxesOnly,
    maxLiveSandboxes,
    expiresInDays: wholeNumber(draft.expiresInDays),
    name: draft.name,
  });
  return parsed.success ? parsed.data : null;
}
