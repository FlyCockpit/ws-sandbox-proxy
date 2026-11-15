import { ORPCError } from "@orpc/server";
import { agentTokenExpiryRejection } from "@wssp/config/agent-token-limits";
import { env } from "@wssp/env/server";
import { z } from "zod";
import { serviceProcedure } from "../../lib/sdk-key-access";
import type { Principal } from "../contracts";
import {
  createSdkKeyInput,
  listCredentialKeys,
  listSdkKeysInput,
  mintCredentialKey,
  revokeCredentialKey,
  revokeSdkKeyInput,
} from "./sdk-keys";

export const createAgentTokenInput = createSdkKeyInput.safeExtend({
  ownSandboxesOnly: z.boolean().default(true),
  expiresAt: z
    .union([z.date(), z.iso.datetime({ offset: true }).transform((value) => new Date(value))])
    .nullable(),
});
export const listAgentTokensInput = listSdkKeysInput;
export const revokeAgentTokenInput = revokeSdkKeyInput;
export const createAgentToken = serviceProcedure(
  { sessionOnly: true },
  async (owner: Principal, input: z.input<typeof createAgentTokenInput>) => {
    const parsed = createAgentTokenInput.safeParse(input);
    if (!parsed.success)
      throw new ORPCError("BAD_REQUEST", { message: "Invalid agent token input." });
    const rejection = agentTokenExpiryRejection(parsed.data.expiresAt, Date.now(), {
      allowNoExpiry: env.WSSP_AGENT_TOKEN_ALLOW_NO_EXPIRY,
      maxLifetimeDays: env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS,
    });
    if (rejection) {
      const message =
        rejection === "no_expiry_disabled"
          ? "Agent tokens without expiry are disabled by this deployment."
          : rejection === "past"
            ? "Agent token expiry must be in the future."
            : `Agent token expiry must be within ${env.WSSP_AGENT_TOKEN_MAX_LIFETIME_DAYS} days.`;
      throw new ORPCError("BAD_REQUEST", { message, data: { code: "agent_token.expiry_policy" } });
    }
    return mintCredentialKey(owner, parsed.data, "AGENT_TOKEN");
  },
);
export const listAgentTokens = serviceProcedure(
  { sessionOnly: true },
  (owner: Principal, input: z.infer<typeof listAgentTokensInput>) =>
    listCredentialKeys(owner, input, "AGENT_TOKEN"),
);
export const revokeAgentToken = serviceProcedure(
  { sessionOnly: true },
  (owner: Principal, input: z.infer<typeof revokeAgentTokenInput>) =>
    revokeCredentialKey(owner, input, "AGENT_TOKEN"),
);
