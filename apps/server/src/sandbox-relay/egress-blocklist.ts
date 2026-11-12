/**
 * Deployment-wide egress blocklist (default-open egress E6, §2.0.4, D-f).
 *
 * `SANDBOX_EGRESS_BLOCKLIST` holds IPv4 CIDRs and domain names separated by
 * commas or whitespace. The relay validates it once, at boot, with the
 * guard's grammar and limits (`crates/sandbox-runtime/src/guard/sources.rs`,
 * shared cases in `crates/sandbox-protocol/fixtures/egress_blocklist_cases.json`)
 * and sends the result as `egress.blocklist` after every egress-capable
 * hello. The node daemon relays it to its guard as the `deployment` source.
 *
 * Boot never fails on it. An invalid list is logged (position and reason of
 * the first bad entry, never the list) and sent as `invalid:true`: it never
 * becomes an empty list (M13). Daemons keep the last list they received; a
 * daemon without one refuses new sandboxes until the list is fixed.
 */
import { createHash } from "node:crypto";
import { env } from "@wssp/env/server";
import type { EgressBlocklistV11 } from "@wssp/sandbox-contracts";
import { SANDBOX_JSON_CONTROL_MAX_BYTES } from "./protocol.js";

const MAX_CIDRS = 4096;
const MAX_DOMAINS = 2048;
/** Rendered `local=/<d>/\n` lines (the guard's 63 KiB domain budget). */
const MAX_DOMAIN_RENDER_BYTES = 63 * 1024;

export type DeploymentBlocklist =
  | { state: "not_configured"; entries: []; digest: string }
  | { state: "valid"; entries: string[]; digest: string }
  | { state: "invalid"; entry?: number; reason: string; digest: string };

export function blocklistDigest(entries: readonly string[]): string {
  return `sha256:${createHash("sha256").update(JSON.stringify(entries)).digest("hex")}`;
}

/** Rust `Ipv4Addr::from_str`: four decimal octets, no leading zeros. */
function parseIpv4(text: string): number | undefined {
  const parts = text.split(".");
  if (parts.length !== 4) return undefined;
  let value = 0;
  for (const part of parts) {
    if (!/^(0|[1-9][0-9]{0,2})$/.test(part)) return undefined;
    const octet = Number(part);
    if (octet > 255) return undefined;
    value = value * 256 + octet;
  }
  return value;
}

function validDomainName(domain: string): boolean {
  if (domain.length === 0 || domain.length > 253 || parseIpv4(domain) !== undefined) return false;
  const labels = domain.split(".");
  return (
    labels.length >= 2 &&
    labels.every(
      (label) =>
        label.length >= 1 &&
        label.length <= 63 &&
        /^[a-z0-9-]+$/.test(label) &&
        !label.startsWith("-") &&
        !label.endsWith("-"),
    )
  );
}

type Entry = { kind: "cidr" | "domain"; value: string };

/** One token, exactly as the guard's `parse_entry` reads one line. */
function parseEntry(token: string): Entry | string {
  if (token.includes("#")) return "comments are not allowed";
  if (token.includes(":")) return "IPv6 entries are not supported";
  if (token.includes("/") || parseIpv4(token) !== undefined) {
    const [address = "", prefixText, ...rest] = token.split("/");
    if (rest.length > 0) return "invalid IPv4 address";
    const ip = parseIpv4(address);
    if (ip === undefined) return "invalid IPv4 address";
    if (prefixText === undefined) return { kind: "cidr", value: `${address}/32` };
    if (!/^(0|[1-9][0-9]*)$/.test(prefixText)) return "invalid prefix length";
    const prefix = Number(prefixText);
    if (prefix > 32) return "invalid prefix length";
    const hostBits = prefix === 32 ? 0 : 2 ** (32 - prefix);
    if (hostBits > 0 && ip % hostBits !== 0) return "CIDR has host bits set";
    return { kind: "cidr", value: `${address}/${prefix}` };
  }
  const lower = token.toLowerCase();
  const domain = lower.endsWith(".") ? lower.slice(0, -1) : lower;
  return validDomainName(domain)
    ? { kind: "domain", value: domain }
    : "not an IPv4 CIDR or a domain name";
}

export function parseDeploymentBlocklist(raw: string | undefined): DeploymentBlocklist {
  const tokens = (raw ?? "").split(/[\s,]+/).filter((token) => token.length > 0);
  if (tokens.length === 0)
    return { state: "not_configured", entries: [], digest: blocklistDigest([]) };
  const invalid = (reason: string, entry?: number): DeploymentBlocklist => ({
    state: "invalid",
    reason,
    ...(entry !== undefined ? { entry } : {}),
    digest: blocklistDigest([]),
  });
  const cidrs = new Set<string>();
  const domains = new Set<string>();
  for (const [index, token] of tokens.entries()) {
    const entry = parseEntry(token);
    if (typeof entry === "string") return invalid(entry, index + 1);
    (entry.kind === "cidr" ? cidrs : domains).add(entry.value);
    if (cidrs.size > MAX_CIDRS) return invalid(`more than ${MAX_CIDRS} CIDRs`, index + 1);
    if (domains.size > MAX_DOMAINS) return invalid(`more than ${MAX_DOMAINS} domains`, index + 1);
  }
  let rendered = 0;
  for (const domain of domains) rendered += "local=//\n".length + domain.length;
  if (rendered > MAX_DOMAIN_RENDER_BYTES) return invalid("rendered domain list exceeds 63 KiB");
  const entries = [...cidrs, ...domains].sort();
  const digest = blocklistDigest(entries);
  const frame: EgressBlocklistV11 = { type: "egress.blocklist", configured: true, entries, digest };
  if (Buffer.byteLength(JSON.stringify(frame)) > SANDBOX_JSON_CONTROL_MAX_BYTES)
    return invalid("the list does not fit one relay control frame (64 KiB)");
  return { state: "valid", entries, digest };
}

/** The `egress.blocklist` frame for a parsed list. */
export function egressBlocklistFrame(list: DeploymentBlocklist): EgressBlocklistV11 {
  switch (list.state) {
    case "not_configured":
      return { type: "egress.blocklist", configured: false, entries: [], digest: list.digest };
    case "valid":
      return {
        type: "egress.blocklist",
        configured: true,
        entries: list.entries,
        digest: list.digest,
      };
    case "invalid":
      return {
        type: "egress.blocklist",
        configured: true,
        entries: [],
        digest: list.digest,
        invalid: true,
      };
  }
}

let current: DeploymentBlocklist | undefined;

/**
 * The deployment list from the environment, parsed once. The first call
 * (at boot) logs an invalid list; it never throws.
 */
export function deploymentEgressBlocklist(): DeploymentBlocklist {
  if (current) return current;
  current = parseDeploymentBlocklist(env.SANDBOX_EGRESS_BLOCKLIST);
  if (current.state === "invalid")
    console.error(
      `[sandbox-relay] SANDBOX_EGRESS_BLOCKLIST is invalid${
        current.entry !== undefined ? ` at entry ${current.entry}` : ""
      } (${current.reason}); hosts keep their last list, and hosts without one refuse new sandboxes until it is fixed`,
    );
  return current;
}
