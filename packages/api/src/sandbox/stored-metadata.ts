import { metadataSchema } from "@wssp/sandbox-contracts";

/** Stored metadata obeys the same validation as accepted input. */
export function storedMetadata(_sandboxId: string, value: unknown): Record<string, string> {
  return metadataSchema.parse(value);
}
