/** The relay contract version (capacity, sharing and typed terminals).
 * Deploy same-commit peers; the version string alone cannot prove shape parity.
 * A stored version other than this one is ineligible and is never rewritten as
 * current.
 */
export const SANDBOX_RELAY_PROTOCOL_VERSION = "1.0";
export type RelayProtocolVersion = typeof SANDBOX_RELAY_PROTOCOL_VERSION;
export function knownRelayProtocolVersion(version: unknown): version is RelayProtocolVersion {
  return version === SANDBOX_RELAY_PROTOCOL_VERSION;
}
