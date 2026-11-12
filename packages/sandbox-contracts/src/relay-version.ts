/** Sole integrated relay contract (capacity + sharing + typed terminals).
 * Deploy same-commit peers; the version string alone cannot prove shape parity.
 * Old stored versions remain ineligible and must never be rewritten as current.
 */
export const SANDBOX_RELAY_PROTOCOL_VERSION = "1.0";
export type RelayProtocolVersion = typeof SANDBOX_RELAY_PROTOCOL_VERSION;
export function knownRelayProtocolVersion(version: unknown): version is RelayProtocolVersion {
  return version === SANDBOX_RELAY_PROTOCOL_VERSION;
}
