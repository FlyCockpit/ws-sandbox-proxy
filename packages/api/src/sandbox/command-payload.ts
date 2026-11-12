import commandLimits from "../../../config/src/sandbox-command-limits.json";

export const SANDBOX_COMMAND_PAYLOAD_MAX_BYTES = commandLimits.commandPayloadBytes;
export const SANDBOX_JSON_CONTROL_MAX_BYTES = commandLimits.jsonControlMaxBytes;
export const SANDBOX_COMMAND_ARGV_MAX_COUNT = commandLimits.commandArgvMaxCount;
export const SANDBOX_COMMAND_ARGV_MAX_UTF16_UNITS = commandLimits.commandArgvMaxUtf16Units;

export type CommandRunPayloadParts = {
  argv?: string[];
  script?: string;
  cwd?: string;
  env?: Array<[string, string]>;
};

export function serializedCommandPayloadBytes(parts: CommandRunPayloadParts): number {
  return new TextEncoder().encode(
    JSON.stringify({
      argv: parts.argv ?? null,
      script: parts.script ?? null,
      cwd: parts.cwd ?? null,
      env: parts.env ?? [],
    }),
  ).byteLength;
}

export function commandRunMode(parts: CommandRunPayloadParts): "argv" | "script" | "invalid" {
  const hasArgv = parts.argv !== undefined;
  const hasScript = parts.script !== undefined;
  if (hasArgv === hasScript) return "invalid";
  return hasArgv ? "argv" : "script";
}

export function commandPayloadWithinLimit(parts: CommandRunPayloadParts): boolean {
  return serializedCommandPayloadBytes(parts) <= SANDBOX_COMMAND_PAYLOAD_MAX_BYTES;
}
