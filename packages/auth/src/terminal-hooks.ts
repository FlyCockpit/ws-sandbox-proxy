/** TOTP oracle guard and auth→host watermark. Shared by HTTP and auth.api dispatch. */
import prisma from "@wssp/db";
import type { TerminalFactor } from "@wssp/db/terminal-proof";
import {
  advanceTerminalWatermark,
  HOST_PROOF_FRESH_MS,
  lockTerminalFactor,
  lockTerminalProofUser,
  terminalDatabaseTime,
} from "@wssp/db/terminal-proof";
import { APIError, createAuthMiddleware } from "better-auth/api";
import { isUserBanned } from "./ban";
import { hasSessionCookies, matchedTotpSteps } from "./terminal-proof";

type Identity = { user: { id: string }; session: { id: string } };
type ResolveSession = (headers: Headers, disableCache: boolean) => Promise<Identity | null>;
type Evidence = { userId: string; factor: TerminalFactor; startedAt: number; code: string };
const sensitivePath = (path: string) =>
  path === "/two-factor/verify-totp" || path === "/two-factor/get-totp-uri";
const refused = () => new APIError("UNAUTHORIZED", { message: "TOTP verification unavailable" });
export function createTerminalAuthHooks(resolveSession: ResolveSession) {
  // Dispatch preserves ctx.context identity across the before/after middleware.
  const evidence = new WeakMap<object, Evidence>();
  const before = createAuthMiddleware(async (ctx) => {
    if (!sensitivePath(ctx.path)) return;
    const startedAt = Date.now();
    const headers = new Headers(ctx.headers ?? ctx.request?.headers);
    let cached: Identity | null, durable: Identity | null;
    try {
      // Separate dispatches, original headers, no shared context.session/cookie mutations.
      [cached, durable] = await Promise.all([
        resolveSession(new Headers(headers), false),
        resolveSession(new Headers(headers), true),
      ]);
    } catch {
      throw refused();
    }
    let userId: string;
    if (cached || durable || hasSessionCookies(headers)) {
      if (
        !cached ||
        !durable ||
        cached.user.id !== durable.user.id ||
        cached.session.id !== durable.session.id
      )
        throw refused();
      userId = durable.user.id;
      const pending = await prisma.$transaction(async (tx) => {
        const user = await lockTerminalProofUser(tx, userId);
        await tx.$queryRaw`SELECT id FROM session WHERE id = ${durable.session.id} FOR SHARE`;
        const session = await tx.session.findFirst({
          where: {
            id: durable.session.id,
            userId,
            expiresAt: { gt: new Date() },
            impersonatedBy: null,
          },
          select: { id: true },
        });
        const factor = await lockTerminalFactor(tx, userId);
        return Boolean(
          user?.emailVerified &&
            !user.deletionRequestedAt &&
            !isUserBanned(user, new Date()) &&
            session &&
            factor?.verified === false,
        );
      });
      if (!pending) throw refused();
    } else {
      if (ctx.path !== "/two-factor/verify-totp") throw refused();
      // Validate signed challenge without consuming it or its attempt budget.
      const cookie = ctx.context.createAuthCookie("two_factor");
      const signed = await ctx.getSignedCookie(cookie.name, ctx.context.secret);
      if (!signed) throw refused();
      const challenge = await ctx.context.internalAdapter.findVerificationValue(signed);
      if (!challenge || new Date(challenge.expiresAt).getTime() <= startedAt) throw refused();
      userId = challenge.value;
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          emailVerified: true,
          banned: true,
          banExpires: true,
          deletionRequestedAt: true,
        },
      });
      if (!user?.emailVerified || user.deletionRequestedAt || isUserBanned(user, new Date()))
        throw refused();
    }
    if (ctx.path !== "/two-factor/verify-totp") return;
    const factor = await prisma.twoFactor.findUnique({ where: { userId } });
    if (!factor || typeof ctx.body?.code !== "string") throw refused();
    evidence.set(ctx.context, { userId, factor, startedAt, code: ctx.body.code });
  });
  const after = createAuthMiddleware(async (ctx) => {
    if (ctx.path !== "/two-factor/verify-totp") return;
    const saved = evidence.get(ctx.context);
    evidence.delete(ctx.context);
    const returned: unknown = ctx.context.returned;
    // Errors and failed verification advance nothing.
    if (
      returned instanceof APIError ||
      !returned ||
      typeof returned !== "object" ||
      !("token" in returned) ||
      !("user" in returned)
    )
      return;
    try {
      if (!saved || Date.now() - saved.startedAt > HOST_PROOF_FRESH_MS) throw refused();
      const resultUser = returned.user;
      if (
        !resultUser ||
        typeof resultUser !== "object" ||
        !("id" in resultUser) ||
        resultUser.id !== saved.userId ||
        (ctx.context.newSession && ctx.context.newSession.user.id !== saved.userId)
      )
        throw refused();
      const endedAt = Date.now();
      const steps = [
        ...new Set([
          ...(await matchedTotpSteps(
            saved.factor,
            saved.code,
            ctx.context.secretConfig,
            saved.startedAt,
          )),
          ...(await matchedTotpSteps(saved.factor, saved.code, ctx.context.secretConfig, endedAt)),
        ]),
      ];
      if (!steps.length) throw refused();
      const accepted = await prisma.$transaction(async (tx) => {
        const user = await lockTerminalProofUser(tx, saved.userId);
        const factor = await lockTerminalFactor(tx, saved.userId);
        const now = await terminalDatabaseTime(tx);
        if (
          !user?.emailVerified ||
          user.deletionRequestedAt ||
          isUserBanned(user, now) ||
          !factor?.verified ||
          factor.id !== saved.factor.id ||
          factor.secret !== saved.factor.secret ||
          now.getTime() - saved.startedAt > HOST_PROOF_FRESH_MS
        )
          return false;
        await advanceTerminalWatermark(tx, user, steps);
        return true;
      });
      if (!accepted) throw refused();
    } catch {
      // Dispatch accumulates handler cookies separately: throwing alone leaks success.
      ctx.context.responseHeaders?.delete("set-cookie");
      ctx.context.responseHeaders?.delete("authorization");
      ctx.responseHeaders?.delete("set-cookie");
      const created = ctx.context.newSession;
      if (created)
        await prisma.session.deleteMany({
          where: {
            id: created.session.id,
            userId: created.user.id,
          },
        });
      ctx.context.newSession = null;
      throw refused();
    }
  });
  return { before, after };
}
