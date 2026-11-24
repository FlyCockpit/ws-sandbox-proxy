import { createHash } from "node:crypto";
import prisma from "@wssp/db";
import { SIGNUP_ENABLED } from "@wssp/env/server";
import { isEmailConfigured } from "@wssp/mailer";
import { z } from "zod";

export const SIGNUP_SETTING_KEY = "signupEnabled";

export async function getSignupEnabled(): Promise<boolean> {
  const row = await prisma.appSetting.findUnique({
    where: { key: SIGNUP_SETTING_KEY },
    select: { value: true },
  });
  // The env default is refused at startup without SMTP; an override is not, so
  // one stored before mail was removed must not re-enable unverifiable signup.
  return row ? row.value === "true" && isEmailConfigured() : SIGNUP_ENABLED;
}

// The token is request memory only. Preflight never consumes or grants a Share.
const poolSignupBody = z.object({
  email: z.email().max(320),
  poolInviteToken: z.string().regex(/^wssp_inv_[A-Za-z0-9_-]{43}$/),
});
export async function poolInviteSignup(body: unknown) {
  const input = poolSignupBody.safeParse(body);
  if (!input.success) return null;
  const email = input.data.email.trim().toLowerCase();
  const tokenDigest = createHash("sha256").update(input.data.poolInviteToken).digest("hex");
  const [clock] = await prisma.$queryRaw<
    { now: Date }[]
  >`SELECT clock_timestamp() AT TIME ZONE 'UTC' AS now`;
  const invite = await prisma.shareInvite.findFirst({
    where: {
      tokenDigest,
      email,
      signupAllowed: true,
      pendingKey: { not: null },
      expiresAt: { gt: clock!.now },
      Pool: {
        deletedAt: null,
        User: {
          deletionRequestedAt: null,
          OR: [{ banned: { not: true } }, { banned: null }, { banExpires: { lte: clock!.now } }],
        },
      },
    },
    select: { id: true, ownerUserId: true },
  });
  return invite;
}

// The closed-signup inputs of one request: the invitation preflight, then the
// setting. The user.create hook decides with them; the sign-up after-hook runs
// the same reads for a request that created nothing, so a registered address
// costs exactly what a free one does (signup-response.ts).
export async function signupAdmission(path: string | undefined, body: unknown) {
  const invitation = path === "/sign-up/email" ? await poolInviteSignup(body) : null;
  return { invitation, signupEnabled: await getSignupEnabled() };
}
