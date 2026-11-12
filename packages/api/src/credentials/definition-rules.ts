/**
 * Browser-safe re-export of the shared login-definition parser (pure zod, no
 * IO), so the dashboard validates pasted definitions live with the exact rules
 * the server applies on create. The server stays the authority: it re-parses
 * every create and stores only what it parsed.
 */
export {
  type DefinitionIssue,
  type LoginDefinition,
  parseLoginDefinition,
  parseLoginDefinitionText,
} from "@wssp/login-definition";
