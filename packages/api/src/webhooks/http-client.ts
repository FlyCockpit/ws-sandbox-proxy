import { Resolver } from "node:dns/promises";
import http from "node:http";
import net from "node:net";
import type { Duplex } from "node:stream";
import tls from "node:tls";
import {
  formatIpv6,
  type ParsedCidr,
  parseIpAddress,
  WEBHOOK_BODY_MAX_BYTES,
  type WebhookErrorClass,
} from "@wssp/sandbox-contracts";
import {
  checkAddresses,
  type ParsedDestination,
  parseDestination,
  type WebhookAllowlist,
} from "./destination-policy";

/**
 * The SSRF-safe webhook transport. One attempt:
 *
 * 1. Resolve the hostname ONCE (c-ares `Resolver`, A and AAAA in parallel, at
 *    most 16 addresses). IP literals skip DNS.
 * 2. Validate EVERY address; any refusal refuses the attempt.
 * 3. Connect to the validated IPs in order (at most 2 tries), never by name.
 *    TLS runs over that raw socket with SNI and certificate identity bound to
 *    the original hostname, TLS ≥ 1.2, default CA store.
 * 4. Send with `http.request({ createConnection })` and NO `daemon` option.
 *    `daemon: false` would make Node build a fresh Daemon that ignores
 *    `createConnection` and re-resolves the name (review B1); an unset daemon
 *    plus `createConnection` uses exactly the pinned socket, bypasses pooled
 *    sockets and env-proxy daemons, and never calls `lookup`.
 * 5. Total deadline 10 s; the response is read up to 64 KiB, then the socket is
 *    destroyed. Redirects are never followed.
 */

export const ATTEMPT_DEADLINE_MS = 10_000;
export const CONNECT_TIMEOUT_MS = 5_000;
/**
 * An answer set larger than this is refused outright. Below it, EVERY address
 * is validated before any is used; only connection attempts are capped
 * (MAX_CONNECT_TRIES), never validation.
 */
export const MAX_RESOLVED_ADDRESSES = 64;
export const MAX_CONNECT_TRIES = 2;
export const RESPONSE_READ_LIMIT_BYTES = 64 * 1024;
export const RESPONSE_EXCERPT_BYTES = 512;

export type ResolveAddresses = (hostname: string) => Promise<string[]>;
/** Opens a raw byte stream to exactly `address:port`. Production: `net.connect`. */
export type ConnectRaw = (target: {
  address: string;
  family: 4 | 6;
  port: number;
  signal: AbortSignal;
}) => Promise<Duplex & { remoteAddress?: string }>;

export type AttemptResult = {
  statusCode: number | null;
  errorClass: WebhookErrorClass | null;
  resolvedAddress: string | null;
  responseExcerpt: string | null;
  /** Parsed Retry-After seconds on 429/503, uncapped. */
  retryAfterSeconds: number | null;
  durationMs: number;
};

export type DeliveryRequest = {
  url: string;
  headers: Record<string, string>;
  body: string;
  allowlist: WebhookAllowlist;
  ownerMayUsePrivate: boolean;
  resolve?: ResolveAddresses;
  connect?: ConnectRaw;
  /** Test seam: extra trust roots. Production uses Node's default CA store. */
  ca?: string | Buffer | Array<string | Buffer>;
  deadlineMs?: number;
  connectTimeoutMs?: number;
  now?: () => number;
};

class AttemptFailure extends Error {
  constructor(
    readonly errorClass: WebhookErrorClass,
    readonly resolvedAddress: string | null = null,
  ) {
    super(errorClass);
    this.name = "AttemptFailure";
  }
}

/** c-ares resolver: reads resolv.conf (so tailnet MagicDNS works), not /etc/hosts. */
export const resolveWithCares: ResolveAddresses = async (hostname) => {
  const resolver = new Resolver({ timeout: 2000, tries: 2 });
  const [a, aaaa] = await Promise.allSettled([
    resolver.resolve4(hostname),
    resolver.resolve6(hostname),
  ]);
  const out = [
    ...(a.status === "fulfilled" ? a.value : []),
    ...(aaaa.status === "fulfilled" ? aaaa.value : []),
  ];
  if (out.length === 0) throw new AttemptFailure("dns_failed");
  return out;
};

export const connectWithNet: ConnectRaw = ({ address, family, port, signal }) =>
  new Promise((resolve, reject) => {
    const socket = net.connect({ host: address, port, family, noDelay: true });
    const abort = () => {
      socket.destroy();
      reject(new AttemptFailure("connect_timeout", address));
    };
    if (signal.aborted) return abort();
    signal.addEventListener("abort", abort, { once: true });
    socket.once("connect", () => {
      signal.removeEventListener("abort", abort);
      resolve(socket);
    });
    socket.once("error", () => {
      signal.removeEventListener("abort", abort);
      socket.destroy();
      reject(new AttemptFailure("connect_failed", address));
    });
  });

/**
 * Parse a full DNS answer set. Nothing is dropped: an oversized set is refused
 * (`destination_blocked`) rather than truncated, so "any blocked address
 * refuses" sees every answer.
 */
export function parseResolvedAddresses(
  names: readonly string[],
): { ok: true; addresses: ParsedCidr[] } | { ok: false; errorClass: WebhookErrorClass } {
  if (names.length === 0) return { ok: false, errorClass: "dns_failed" };
  if (names.length > MAX_RESOLVED_ADDRESSES)
    return { ok: false, errorClass: "destination_blocked" };
  const addresses: ParsedCidr[] = [];
  for (const name of names) {
    const parsed = parseIpAddress(name);
    if (!parsed) return { ok: false, errorClass: "dns_failed" };
    addresses.push(parsed);
  }
  return { ok: true, addresses };
}

function canonical(address: ParsedCidr): string {
  if (address.family === 4) {
    const [hi, lo] = address.groups as [number, number];
    return `${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return formatIpv6(address.groups);
}

function tlsErrorClass(error: unknown): WebhookErrorClass {
  return error instanceof AttemptFailure ? error.errorClass : "tls_error";
}

/** Abort-aware wait for an event, cleaning up listeners either way. */
function once(emitter: Duplex, event: string, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const onEvent = () => {
      cleanup();
      resolve();
    };
    const onError = (error: unknown) => {
      cleanup();
      reject(error);
    };
    const onAbort = () => {
      cleanup();
      reject(new AttemptFailure("connect_timeout"));
    };
    const cleanup = () => {
      emitter.off(event, onEvent);
      emitter.off("error", onError);
      signal.removeEventListener("abort", onAbort);
    };
    if (signal.aborted) return onAbort();
    emitter.once(event, onEvent);
    emitter.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function openPinned(
  destination: ParsedDestination,
  address: ParsedCidr,
  options: DeliveryRequest,
  attemptSignal: AbortSignal,
): Promise<Duplex> {
  const connect = options.connect ?? connectWithNet;
  const target = canonical(address);
  const signal = AbortSignal.any([
    attemptSignal,
    AbortSignal.timeout(options.connectTimeoutMs ?? CONNECT_TIMEOUT_MS),
  ]);
  const raw = await connect({
    address: target,
    family: address.family,
    port: destination.port,
    signal,
  });
  const remote = raw.remoteAddress
    ? parseIpAddress(raw.remoteAddress.replace(/^::ffff:(?=\d+\.)/, ""))
    : null;
  if (!remote || canonical(remote) !== target) {
    raw.destroy();
    throw new AttemptFailure("connect_failed", target);
  }
  if (destination.scheme === "http") return raw;
  const secure = tls.connect({
    socket: raw,
    servername: destination.literal ? undefined : destination.hostname,
    ALPNProtocols: ["http/1.1"],
    minVersion: "TLSv1.2",
    rejectUnauthorized: true,
    ...(options.ca ? { ca: options.ca } : {}),
    checkServerIdentity: (_host, cert) => tls.checkServerIdentity(destination.hostname, cert),
  });
  try {
    await once(secure, "secureConnect", signal);
  } catch (error) {
    secure.destroy();
    raw.destroy();
    throw new AttemptFailure(tlsErrorClass(error), target);
  }
  return secure;
}

function parseRetryAfter(value: string | undefined, now: number): number | null {
  if (!value) return null;
  if (/^\d{1,9}$/.test(value.trim())) return Number(value.trim());
  const at = Date.parse(value);
  return Number.isNaN(at) ? null : Math.max(0, Math.ceil((at - now) / 1000));
}

function excerptOf(bytes: Buffer): string | null {
  if (bytes.byteLength === 0) return null;
  return new TextDecoder("utf-8", { fatal: false }).decode(
    bytes.subarray(0, RESPONSE_EXCERPT_BYTES),
  );
}

function send(
  socket: Duplex,
  destination: ParsedDestination,
  options: DeliveryRequest,
  signal: AbortSignal,
  now: number,
): Promise<Omit<AttemptResult, "durationMs" | "resolvedAddress">> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (
      value: Omit<AttemptResult, "durationMs" | "resolvedAddress"> | AttemptFailure,
    ) => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", onAbort);
      socket.destroy();
      if (value instanceof AttemptFailure) reject(value);
      else resolve(value);
    };
    const onAbort = () => finish(new AttemptFailure("timeout"));
    const request = http.request({
      method: "POST",
      host: destination.hostname,
      port: destination.port,
      path: `${destination.url.pathname}${destination.url.search}`,
      headers: {
        ...options.headers,
        host: destination.authority,
        connection: "close",
        "content-length": String(Buffer.byteLength(options.body)),
      },
      // No `daemon`: see the module comment. `createConnection` hands Node the
      // already-validated socket; `lookup` must never run.
      createConnection: () => socket as net.Socket,
      lookup: () => {
        throw new Error("webhook transport never resolves names");
      },
      setHost: false,
      insecureHTTPParser: false,
    });
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) return onAbort();
    request.on("error", (error: NodeJS.ErrnoException) => {
      finish(
        new AttemptFailure(
          error.code === "HPE_HEADER_OVERFLOW" ? "response_too_large" : "protocol_error",
        ),
      );
    });
    request.on("response", (response) => {
      const statusCode = response.statusCode ?? 0;
      const chunks: Buffer[] = [];
      let bytes = 0;
      const done = () => {
        const body = Buffer.concat(chunks);
        if (statusCode >= 300 && statusCode < 400) {
          let host = "invalid";
          try {
            host = new URL(response.headers.location ?? "", destination.url).hostname || "invalid";
          } catch {
            // Keep "invalid": only the redirect target's host is ever stored.
          }
          return finish({
            statusCode,
            errorClass: "redirect_not_followed",
            responseExcerpt: `redirect host: ${host}`.slice(0, RESPONSE_EXCERPT_BYTES),
            retryAfterSeconds: null,
          });
        }
        finish({
          statusCode,
          errorClass: statusCode >= 200 && statusCode < 300 ? null : "http_status",
          responseExcerpt: excerptOf(body),
          retryAfterSeconds:
            statusCode === 429 || statusCode === 503
              ? parseRetryAfter(
                  Array.isArray(response.headers["retry-after"])
                    ? response.headers["retry-after"][0]
                    : response.headers["retry-after"],
                  now,
                )
              : null,
        });
      };
      response.on("data", (chunk: Buffer) => {
        if (bytes >= RESPONSE_READ_LIMIT_BYTES) return;
        const room = RESPONSE_READ_LIMIT_BYTES - bytes;
        chunks.push(chunk.byteLength > room ? chunk.subarray(0, room) : chunk);
        bytes += Math.min(room, chunk.byteLength);
        // Cap reached: stop reading and answer with what we have.
        if (bytes >= RESPONSE_READ_LIMIT_BYTES) done();
      });
      response.on("end", done);
      response.on("aborted", done);
      response.on("error", done);
    });
    request.end(options.body);
  });
}

/** One delivery attempt. Never throws: every outcome is an `AttemptResult`. */
export async function deliverOnce(options: DeliveryRequest): Promise<AttemptResult> {
  const clock = options.now ?? Date.now;
  const started = clock();
  const signal = AbortSignal.timeout(options.deadlineMs ?? ATTEMPT_DEADLINE_MS);
  let resolvedAddress: string | null = null;
  const result = (
    partial: Omit<AttemptResult, "durationMs" | "resolvedAddress">,
  ): AttemptResult => ({
    ...partial,
    resolvedAddress,
    durationMs: Math.max(0, Math.round(clock() - started)),
  });
  const failure = (errorClass: WebhookErrorClass) =>
    result({ statusCode: null, errorClass, responseExcerpt: null, retryAfterSeconds: null });
  try {
    if (Buffer.byteLength(options.body) > WEBHOOK_BODY_MAX_BYTES) return failure("protocol_error");
    const destination = parseDestination(options.url, options.allowlist);
    if (!destination.ok) return failure("destination_blocked");
    let addresses: ParsedCidr[];
    if (destination.literal) addresses = [destination.literal];
    else {
      const resolve = options.resolve ?? resolveWithCares;
      let names: string[];
      try {
        names = await Promise.race([
          resolve(destination.hostname),
          new Promise<never>((_, reject) =>
            signal.addEventListener("abort", () => reject(new AttemptFailure("timeout")), {
              once: true,
            }),
          ),
        ]);
      } catch (error) {
        return failure(error instanceof AttemptFailure ? error.errorClass : "dns_failed");
      }
      const parsed = parseResolvedAddresses(names);
      if (!parsed.ok) return failure(parsed.errorClass);
      addresses = parsed.addresses;
    }
    const verdict = checkAddresses({
      destination,
      addresses,
      allowlist: options.allowlist,
      ownerMayUsePrivate: options.ownerMayUsePrivate,
    });
    if (!verdict.ok) return failure("destination_blocked");
    let socket: Duplex | null = null;
    let lastClass: WebhookErrorClass = "connect_failed";
    for (const address of addresses.slice(0, MAX_CONNECT_TRIES)) {
      resolvedAddress = canonical(address);
      try {
        socket = await openPinned(destination, address, options, signal);
        break;
      } catch (error) {
        lastClass = error instanceof AttemptFailure ? error.errorClass : "connect_failed";
        if (lastClass === "tls_error" || signal.aborted) break;
      }
    }
    if (!socket)
      return failure(signal.aborted && lastClass !== "tls_error" ? "timeout" : lastClass);
    return result(await send(socket, destination, options, signal, clock()));
  } catch (error) {
    return failure(error instanceof AttemptFailure ? error.errorClass : "protocol_error");
  }
}
