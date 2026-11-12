import {
  type DefinitionIssue,
  type LoginDefinition,
  parseLoginDefinition,
  parseLoginDefinitionText,
} from "@wssp/api/credentials/definition-rules";

/**
 * Pure rules for the Logins pages. The browser parses definitions with the
 * shared parser only to explain problems early; the server re-parses every
 * create and is the authority. Values are write-only: nothing here reads one
 * back, and uploads leave the browser only as the write request body.
 */
export type { DefinitionIssue, LoginDefinition };

export type DefinitionCheck =
  | { state: "empty" }
  | { state: "valid"; definition: LoginDefinition; warnings: string[] }
  | { state: "invalid"; code: string; issues: DefinitionIssue[] };

/** Live check of pasted definition text, with the server's parser. */
export function checkDefinitionText(text: string): DefinitionCheck {
  if (!text.trim()) return { state: "empty" };
  const result = parseLoginDefinitionText(text);
  if (result.success)
    return { state: "valid", definition: result.definition, warnings: [...result.warnings] };
  return { state: "invalid", code: result.error.code, issues: result.error.issues.slice(0, 20) };
}

/** A stored definition document, parsed for display (`null` when it no longer parses). */
export function readDefinition(document: unknown): LoginDefinition | null {
  const result = parseLoginDefinition(document);
  return result.success ? result.definition : null;
}

/** Declared file paths in upload order: required first, then optional. */
export function definitionFiles(
  definition: LoginDefinition,
): { path: string; required: boolean }[] {
  const files = definition.credentials.files;
  return [
    ...(files?.required ?? []).map((path) => ({ path, required: true })),
    ...(files?.optional ?? []).map((path) => ({ path, required: false })),
  ];
}

/** Proxy-capable: every env entry proxied and no files (the server's PROXY rule). */
export function definitionProxyCapable(definition: LoginDefinition): boolean {
  const env = definition.credentials.env ?? [];
  return (
    definitionFiles(definition).length === 0 &&
    env.length > 0 &&
    env.every((entry) => entry.proxy !== undefined)
  );
}

/** Shareable logins whose tokens may rotate: concurrent holders can invalidate each other. */
export function shareRotationRisk(definition: LoginDefinition): boolean {
  return definition.credentials.sharing === "shareable" && definition.credentials.rotates !== "no";
}

export type LoginProblem =
  | "notFound"
  | "definitionNotFound"
  | "accountNotFound"
  | "instanceNotFound"
  | "nameTaken"
  | "busy"
  | "repinBlocked"
  | "repinIncompatible"
  | "repinConfirmErase"
  | "valueInvalid"
  | "definitionInvalid"
  | "schemaVersionUnsupported"
  | "definitionCorrupt"
  | "limit"
  | "unavailable"
  | "rateLimited"
  | "forbidden"
  | "generic";

const BY_CODE: Record<string, LoginProblem> = {
  "credential.not_found": "notFound",
  "credential.definition_not_found": "definitionNotFound",
  "credential.account_not_found": "accountNotFound",
  "credential.instance_not_found": "instanceNotFound",
  "credential.name_taken": "nameTaken",
  "credential.busy": "busy",
  "credential.repin_blocked": "repinBlocked",
  "credential.repin_confirm_erase": "repinConfirmErase",
  "credential.value_invalid": "valueInvalid",
  "definition.invalid": "definitionInvalid",
  "definition.schema_version_unsupported": "schemaVersionUnsupported",
  "credential.definition_corrupt": "definitionCorrupt",
  "credential.limit_reached": "limit",
  "credential.unavailable": "unavailable",
};

type ErrorShape = { code?: unknown; status?: unknown; data?: unknown };

function errorData(error: unknown): Record<string, unknown> {
  const shape = (error && typeof error === "object" ? error : {}) as ErrorShape;
  return shape.data != null && typeof shape.data === "object"
    ? (shape.data as Record<string, unknown>)
    : {};
}

/** Map a failed login call to the explanation shown next to it. */
export function loginProblem(error: unknown): LoginProblem {
  const shape = (error && typeof error === "object" ? error : {}) as ErrorShape;
  const data = errorData(error);
  const code = data.code;
  if (code === "credential.repin_blocked" && data.reason === "incompatible_definition")
    return "repinIncompatible";
  if (typeof code === "string" && BY_CODE[code]) return BY_CODE[code];
  if (shape.code === "NOT_FOUND" || shape.status === 404) return "notFound";
  if (shape.code === "TOO_MANY_REQUESTS" || shape.status === 429) return "rateLimited";
  if (
    shape.code === "FORBIDDEN" ||
    shape.code === "UNAUTHORIZED" ||
    shape.status === 403 ||
    shape.status === 401
  )
    return "forbidden";
  return "generic";
}

/** Structured definition issues the server attached to a refusal (paths and parser messages). */
export function loginProblemIssues(error: unknown): DefinitionIssue[] {
  const issues = errorData(error).issues;
  if (!Array.isArray(issues)) return [];
  return issues
    .filter(
      (issue): issue is DefinitionIssue =>
        !!issue &&
        typeof issue === "object" &&
        typeof (issue as DefinitionIssue).path === "string" &&
        typeof (issue as DefinitionIssue).message === "string",
    )
    .slice(0, 20);
}

/** The env entry a `credential.value_invalid` refusal names (never a value). */
export function loginProblemEntry(error: unknown): string | null {
  const entry = errorData(error).entry;
  return typeof entry === "string" ? entry : null;
}

/** Standard base64 of file bytes, chunked so large files do not overflow the call stack. */
export async function fileToBase64(file: Blob): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk)
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  return btoa(binary);
}

/** Total decoded size, checked against the definition's `maxBytes` before upload. */
export function totalBytes(files: readonly Blob[]): number {
  return files.reduce((sum, file) => sum + file.size, 0);
}
