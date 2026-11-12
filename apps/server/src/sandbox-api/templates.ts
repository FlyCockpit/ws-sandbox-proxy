import { createTemplateInput } from "@wssp/api/sandbox/contracts";
import {
  appendRevisionReceipt,
  associateAvailabilityReceipt,
  registerTemplateReceipt,
} from "@wssp/api/sandbox/sdk-mutations";
import { appendRevisionInput, associateAvailabilityInput } from "@wssp/api/sandbox/template-input";
import type { RouteHandlers } from "./reads.js";

export const templateMutationHandlers = {
  appendTemplateRevision: (owner, { params, body, idempotencyKey }) =>
    appendRevisionReceipt(owner, {
      ...appendRevisionInput.parse({ ...body, templateId: params.id }),
      idempotencyKey,
    }),
  associateTemplateAvailability: (owner, { params, body, idempotencyKey }) =>
    associateAvailabilityReceipt(owner, {
      ...associateAvailabilityInput.parse({ ...body, templateId: params.id }),
      idempotencyKey,
    }),
  registerTemplate: (owner, { body, idempotencyKey }) =>
    registerTemplateReceipt(owner, { ...createTemplateInput.parse(body), idempotencyKey }),
} satisfies Pick<
  RouteHandlers,
  "registerTemplate" | "appendTemplateRevision" | "associateTemplateAvailability"
>;
