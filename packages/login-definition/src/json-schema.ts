import { z } from "zod";
import { isExtensibleObjectSchema, loginDefinitionSchema } from "./definition";

export const LOGIN_DEFINITION_SCHEMA_ID = "urn:wssp:login-definition:v1";

/**
 * JSON Schema (draft 2020-12) for login definition v1, committed as
 * `schema/login-definition.v1.schema.json`. It documents the shape for
 * editors; cross-field rules (path overlap, proxy-only definitions, byte
 * bounds) are enforced by `parseLoginDefinition` and the Rust crate.
 */
export function buildLoginDefinitionJsonSchema(): Record<string, unknown> {
  const schema = z.toJSONSchema(loginDefinitionSchema, {
    target: "draft-2020-12",
    io: "input",
    override: (ctx) => {
      if (isExtensibleObjectSchema(ctx.zodSchema)) {
        ctx.jsonSchema.patternProperties = { "^x-.": {} };
        ctx.jsonSchema.additionalProperties = false;
      }
    },
  }) as Record<string, unknown>;
  const { $schema, ...rest } = schema;
  return { $schema, $id: LOGIN_DEFINITION_SCHEMA_ID, title: "wssp login definition v1", ...rest };
}

export function renderLoginDefinitionJsonSchema(): string {
  return `${JSON.stringify(buildLoginDefinitionJsonSchema(), null, 2)}\n`;
}
