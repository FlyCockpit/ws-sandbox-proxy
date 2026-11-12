import { z } from "zod";
import { isSafeMapText } from "./map-primitives";

// Pure syntax only. A bare name can be either a slug or logical ID; the later
// owner-scoped resolver must reject ambiguity and resolve latest exactly once.
const id = z.string().min(1).max(64).refine(isSafeMapText, "Invalid template selector.");
export const templateSelectorSchema = z
  .string()
  .min(1)
  .max(192)
  .refine((value) => isSafeMapText(value) && !/\s/.test(value), "Invalid template selector.");

type TemplateSelector =
  | { kind: "template" | "revision"; id: string }
  | { kind: "tag"; slug: string; tag: string }
  | { kind: "name"; name: string };

/** Parse the bounded public selector syntax before resource lookup. */
export function parseTemplateSelector(value: unknown): TemplateSelector {
  const text = templateSelectorSchema.parse(value);
  if (text.startsWith("template/") || text.startsWith("revision/")) {
    const [kind, identifier] = text.split("/");
    if (text.split("/").length === 2 && !identifier?.includes(":")) {
      return { kind: kind === "template" ? "template" : "revision", id: id.parse(identifier) };
    }
  } else if (!text.includes("/")) {
    const [name, tag, extra] = text.split(":");
    if (name && extra === undefined) {
      if (tag !== undefined) {
        // Reuse the existing lowercase, hyphen-separated resource-slug syntax.
        const slug = z
          .string()
          .min(1)
          .max(63)
          .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
          .parse(name);
        return { kind: "tag", slug, tag: z.string().min(1).parse(tag) };
      }
      return { kind: "name", name: id.parse(name) };
    }
  }
  throw new Error("Invalid template selector.");
}
