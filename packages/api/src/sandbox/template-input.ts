import { defaultEnvSchema, vmSizeOverridesSchema } from "@wssp/sandbox-contracts";
import { z } from "zod";
import { cursorPageInput } from "../lib/pagination";
import { entityId, resourceSlugSchema, shortText } from "../lib/schemas";
import { guestIdentityInput } from "./guest-identity";
import { isIncusImageRef } from "./incus-image";

/**
 * Template procedure inputs. Pure (zod only): the server procedures and the
 * web registration form parse with these same schemas, so the browser can
 * never accept a draft the server would refuse on shape alone.
 */

export const TEMPLATE_LABEL_MAX = 160;
export const TEMPLATE_GUEST_VERSION_MAX = 64;

/**
 * Architectures the dashboard offers (Incus `uname -m` names). The server
 * accepts any short name and the node daemon verifies it against the image.
 */
export const TEMPLATE_ARCHITECTURES = ["x86_64", "aarch64"] as const;

const templateDefinitionInput = z
  .object({
    hostId: entityId.optional(),
    poolId: entityId.optional(),
    memberId: entityId.optional(),
    ...vmSizeOverridesSchema.shape,
    envs: defaultEnvSchema.optional(),
    slug: resourceSlugSchema,
    label: shortText.max(TEMPLATE_LABEL_MAX),
    imageRef: z
      .string()
      .min(2)
      .max(128)
      .refine(
        (value) => isIncusImageRef(value) || /^sha256:[a-f0-9]{64}$/.test(value),
        "imageRef must be an Incus alias or exact fingerprint.",
      ),
    architecture: z.string().trim().min(1).max(32).default("x86_64"),
    guestVersion: z.string().trim().max(TEMPLATE_GUEST_VERSION_MAX).optional(),
  })
  .merge(guestIdentityInput)
  .strict();
function validVerificationTarget(input: { hostId?: string; poolId?: string; memberId?: string }) {
  return input.hostId ? !input.poolId && !input.memberId : Boolean(input.poolId && input.memberId);
}
const imageValidationShape = z.object({ imageRef: z.string(), poolId: entityId.optional() });
function validTargetImage(input: { imageRef: string; poolId?: string }) {
  return input.poolId
    ? /^sha256:[a-f0-9]{64}$/.test(input.imageRef)
    : isIncusImageRef(input.imageRef);
}
const imageValidationOptions = {
  path: ["imageRef"],
  message: "Use an owned host alias or a pool member exact fingerprint.",
  // Other draft errors must not suppress this independent field's verdict.
  when: (payload: { value: unknown }) => imageValidationShape.safeParse(payload.value).success,
};
export const createTemplateInput = templateDefinitionInput
  .refine(validVerificationTarget, "Choose one image verification target.")
  .refine(validTargetImage, imageValidationOptions);
export type CreateTemplateInput = z.infer<typeof createTemplateInput>;

/**
 * Logical status: active means unarchived; exact per-host availability and
 * revision retirement are separate. `all` includes retained logical history.
 */
export const TEMPLATE_LIST_STATUSES = ["active", "retired", "all"] as const;
export type TemplateListStatus = (typeof TEMPLATE_LIST_STATUSES)[number];

export const listTemplatesInput = cursorPageInput.extend({
  status: z.enum(TEMPLATE_LIST_STATUSES).default("all"),
});
/** Services also take plain page input (the /v1 read passes no status: `all`). */
export type ListTemplatesInput = z.infer<typeof cursorPageInput> & { status?: TemplateListStatus };

export const templateIdInput = z.object({ id: entityId });
export type TemplateIdInput = z.infer<typeof templateIdInput>;

export const appendRevisionInput = templateDefinitionInput
  .omit({ slug: true, label: true })
  .extend({ templateId: entityId })
  .refine(validVerificationTarget, "Choose one image verification target.")
  .refine(validTargetImage, imageValidationOptions);
export type AppendRevisionInput = z.infer<typeof appendRevisionInput>;
export const listRevisionsInput = cursorPageInput.extend({ templateId: entityId });
export const listAvailabilityInput = cursorPageInput.extend({
  templateId: entityId,
  revisionId: entityId,
});
export const associateAvailabilityInput = z
  .object({
    templateId: entityId,
    revisionId: entityId,
    hostId: entityId.optional(),
    poolId: entityId.optional(),
    memberId: entityId.optional(),
  })
  .strict()
  .refine(validVerificationTarget, "Choose one image verification target.");
export const setTemplateTagInput = z
  .object({
    templateId: entityId,
    revisionId: entityId,
    tag: z
      .string()
      .min(1)
      .max(64)
      .regex(/^[A-Za-z0-9][A-Za-z0-9_.-]*$/),
  })
  .strict();
export const revisionChoicesInput = cursorPageInput.extend({
  hostIds: z.array(entityId).max(200),
  poolId: entityId.optional(),
  includePending: z.boolean().default(true),
});
