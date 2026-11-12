import { execFileSync } from "node:child_process";
import dns from "node:dns";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Duplex, duplexPair } from "node:stream";
import tls from "node:tls";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { EMPTY_ALLOWLIST, parseAllowedCidrs, type WebhookAllowlist } from "./destination-policy";
import { type ConnectRaw, type DeliveryRequest, deliverOnce } from "./http-client";

/**
 * Transport tests over in-memory `duplexPair()` sockets: the TCP guard is never
 * triggered, and TLS runs with the production options (`tls.connect({ socket,
 * servername, checkServerIdentity, minVersion })`) against a throwaway test CA
 * generated with the system `openssl` into a temp dir (no key material in git).
 */

type Pem = { key: string; cert: string };
let dir: string;
let ca: string;
let good: Pem;
let otherName: Pem;
let selfSigned: Pem;

function openssl(args: string[]) {
  execFileSync("openssl", args, { cwd: dir, stdio: "ignore" });
}
function leaf(name: string, san: string): Pem {
  openssl([
    "req",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    `${name}.key`,
    "-out",
    `${name}.csr`,
    "-subj",
    `/CN=${name}`,
  ]);
  writeFileSync(join(dir, `${name}.ext`), `subjectAltName=${san}\nbasicConstraints=CA:FALSE\n`);
  openssl([
    "x509",
    "-req",
    "-in",
    `${name}.csr`,
    "-CA",
    "ca.crt",
    "-CAkey",
    "ca.key",
    "-CAcreateserial",
    "-out",
    `${name}.crt`,
    "-days",
    "30",
    "-extfile",
    `${name}.ext`,
  ]);
  return {
    key: readFileSync(join(dir, `${name}.key`), "utf8"),
    cert: readFileSync(join(dir, `${name}.crt`), "utf8"),
  };
}

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "wssp-webhook-tls-"));
  openssl([
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    "ca.key",
    "-out",
    "ca.crt",
    "-days",
    "30",
    "-subj",
    "/CN=wssp webhook test CA",
    "-addext",
    "basicConstraints=critical,CA:TRUE",
    "-addext",
    "keyUsage=critical,keyCertSign,cRLSign",
  ]);
  ca = readFileSync(join(dir, "ca.crt"), "utf8");
  good = leaf("hooks.example.com", "DNS:hooks.example.com,IP:8.8.8.8");
  otherName = leaf("other.example.com", "DNS:other.example.com");
  openssl([
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-nodes",
    "-keyout",
    "self.key",
    "-out",
    "self.crt",
    "-days",
    "30",
    "-subj",
    "/CN=hooks.example.com",
    "-addext",
    "subjectAltName=DNS:hooks.example.com",
  ]);
  selfSigned = {
    key: readFileSync(join(dir, "self.key"), "utf8"),
    cert: readFileSync(join(dir, "self.crt"), "utf8"),
  };
});
afterAll(() => rmSync(dir, { recursive: true, force: true }));
afterEach(() => vi.unstubAllEnvs());

type Seen = {
  servername: string | false | null;
  requests: { headers: http.IncomingHttpHeaders; body: string; url: string }[];
};

/**
 * A fake receiver behind an injected connect. `handler` answers each request;
 * `tlsOptions` null serves plain HTTP. Every connect is recorded.
 */
function receiver(options: {
  handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void;
  tlsOptions?: tls.TlsOptions | null;
  remoteAddress?: (address: string) => string;
}) {
  const seen: Seen = { servername: null, requests: [] };
  const connects: { address: string; port: number; family: number }[] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.setEncoding("utf8");
    req.on("data", (chunk) => {
      body += chunk;
    });
    req.on("end", () => {
      seen.requests.push({ headers: req.headers, body, url: req.url ?? "" });
      (options.handler ?? ((_q, r) => r.writeHead(204).end()))(req, res);
    });
  });
  const connect: ConnectRaw = async ({ address, port, family }) => {
    connects.push({ address, port, family });
    const [client, serverSide] = duplexPair();
    Object.defineProperty(client, "remoteAddress", {
      value: options.remoteAddress ? options.remoteAddress(address) : address,
    });
    if (options.tlsOptions === null) server.emit("connection", serverSide);
    else {
      const secure = new tls.TLSSocket(serverSide as Duplex, {
        isServer: true,
        ...good,
        ...options.tlsOptions,
      });
      secure.on("secure", () => {
        seen.servername =
          (secure as tls.TLSSocket & { servername?: string | false }).servername ?? false;
      });
      secure.on("error", () => {});
      server.emit("connection", secure);
    }
    return client as Duplex & { remoteAddress?: string };
  };
  return { seen, connects, connect };
}

function request(
  overrides: Partial<DeliveryRequest> & Pick<DeliveryRequest, "connect">,
): DeliveryRequest {
  return {
    url: "https://hooks.example.com/wssp?x=1",
    headers: { "content-type": "application/json", "webhook-id": "evt_x" },
    body: '{"ok":true}',
    allowlist: EMPTY_ALLOWLIST,
    ownerMayUsePrivate: false,
    resolve: async () => ["8.8.8.8"],
    ca,
    deadlineMs: 2_000,
    ...overrides,
  };
}

describe("pinned transport (review B1)", () => {
  it("uses the injected socket via createConnection, resolves once, never calls lookup", async () => {
    const lookup = vi.spyOn(dns, "lookup");
    const resolve = vi.fn(async () => ["8.8.8.8"]);
    const fake = receiver({});
    const result = await deliverOnce(request({ connect: fake.connect, resolve }));
    expect(result).toMatchObject({ statusCode: 204, errorClass: null, resolvedAddress: "8.8.8.8" });
    expect(resolve).toHaveBeenCalledTimes(1);
    expect(fake.connects).toEqual([{ address: "8.8.8.8", port: 443, family: 4 }]);
    expect(fake.seen.requests).toHaveLength(1);
    expect(fake.seen.requests[0]?.headers.host).toBe("hooks.example.com");
    expect(fake.seen.requests[0]?.url).toBe("/wssp?x=1");
    expect(fake.seen.requests[0]?.body).toBe('{"ok":true}');
    expect(lookup).not.toHaveBeenCalled();
    lookup.mockRestore();
  });

  it("ignores env proxy settings: the request still rides the pinned socket", async () => {
    vi.stubEnv("HTTPS_PROXY", "http://proxy.invalid:3128");
    vi.stubEnv("HTTP_PROXY", "http://proxy.invalid:3128");
    vi.stubEnv("NODE_USE_ENV_PROXY", "1");
    const fake = receiver({});
    const result = await deliverOnce(request({ connect: fake.connect }));
    expect(result.errorClass).toBeNull();
    expect(fake.connects.map((c) => c.address)).toEqual(["8.8.8.8"]);
  });

  it("DNS rebinding: a second, private answer is never consulted", async () => {
    let calls = 0;
    const resolve = async () => (calls++ === 0 ? ["8.8.8.8"] : ["169.254.169.254"]);
    const fake = receiver({});
    expect((await deliverOnce(request({ connect: fake.connect, resolve }))).errorClass).toBeNull();
    expect(calls).toBe(1);
    expect(fake.connects.map((c) => c.address)).toEqual(["8.8.8.8"]);
  });

  it("refuses a mixed public/private answer set before connecting", async () => {
    const fake = receiver({});
    const result = await deliverOnce(
      request({ connect: fake.connect, resolve: async () => ["8.8.8.8", "10.0.0.7"] }),
    );
    expect(result.errorClass).toBe("destination_blocked");
    expect(fake.connects).toEqual([]);
  });

  it("validates every answer: 16 public addresses plus one metadata address is refused (review finding 3)", async () => {
    const fake = receiver({});
    const publicAnswers = Array.from({ length: 16 }, (_, i) => `8.8.4.${i + 1}`);
    const result = await deliverOnce(
      request({
        connect: fake.connect,
        resolve: async () => [...publicAnswers, "169.254.169.254"],
      }),
    );
    expect(result.errorClass).toBe("destination_blocked");
    expect(fake.connects).toEqual([]);
    // An answer set too large to validate is refused, never truncated.
    const flood = await deliverOnce(
      request({
        connect: fake.connect,
        resolve: async () => Array.from({ length: 65 }, (_, i) => `8.8.${i >> 8}.${i & 255}`),
      }),
    );
    expect(flood.errorClass).toBe("destination_blocked");
    expect(fake.connects).toEqual([]);
  });

  it("validates every IPv6 answer too", async () => {
    const fake = receiver({});
    const result = await deliverOnce(
      request({ connect: fake.connect, resolve: async () => ["2606:4700::1111", "fd00:ec2::254"] }),
    );
    expect(result.errorClass).toBe("destination_blocked");
    expect(fake.connects).toEqual([]);
  });

  it("aborts when the socket's remote address is not the pinned IP", async () => {
    const fake = receiver({ remoteAddress: () => "10.9.9.9" });
    const result = await deliverOnce(request({ connect: fake.connect }));
    expect(result.errorClass).toBe("connect_failed");
    expect(fake.seen.requests).toEqual([]);
  });

  it("maps a DNS failure to dns_failed", async () => {
    const fake = receiver({});
    const result = await deliverOnce(
      request({
        connect: fake.connect,
        resolve: async () => {
          throw new Error("ENOTFOUND");
        },
      }),
    );
    expect(result.errorClass).toBe("dns_failed");
  });

  it("re-checks the URL policy per attempt (a private literal is refused)", async () => {
    const fake = receiver({});
    const result = await deliverOnce(request({ connect: fake.connect, url: "https://10.0.0.1/" }));
    expect(result.errorClass).toBe("destination_blocked");
  });
});

describe("TLS over duplexPair", () => {
  it("sends SNI equal to the hostname", async () => {
    const fake = receiver({});
    await deliverOnce(request({ connect: fake.connect }));
    expect(fake.seen.servername).toBe("hooks.example.com");
  });

  it("refuses a certificate for a different name", async () => {
    const fake = receiver({ tlsOptions: otherName });
    const result = await deliverOnce(request({ connect: fake.connect }));
    expect(result.errorClass).toBe("tls_error");
    expect(fake.seen.requests).toEqual([]);
  });

  it("refuses a self-signed certificate", async () => {
    const fake = receiver({ tlsOptions: selfSigned });
    expect((await deliverOnce(request({ connect: fake.connect }))).errorClass).toBe("tls_error");
  });

  it("refuses TLS 1.1", async () => {
    const fake = receiver({ tlsOptions: { maxVersion: "TLSv1.1", minVersion: "TLSv1" } });
    expect((await deliverOnce(request({ connect: fake.connect }))).errorClass).toBe("tls_error");
  });

  it("sends no SNI to an IP literal and skips DNS", async () => {
    const resolve = vi.fn(async () => ["8.8.8.8"]);
    const fake = receiver({});
    const result = await deliverOnce(
      request({ connect: fake.connect, resolve, url: "https://8.8.8.8/h" }),
    );
    expect(result.errorClass).toBeNull();
    expect(resolve).not.toHaveBeenCalled();
    expect(fake.seen.servername).toBe(false);
  });
});

describe("limits, redirects and Retry-After", () => {
  it("times out a receiver that never answers", async () => {
    const fake = receiver({ handler: () => {} });
    const result = await deliverOnce(request({ connect: fake.connect, deadlineMs: 150 }));
    expect(result.errorClass).toBe("timeout");
  });

  it("cuts a large body at the read limit and keeps a 512-byte excerpt", async () => {
    const fake = receiver({
      handler: (_req, res) => {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("x".repeat(200 * 1024));
      },
    });
    const result = await deliverOnce(request({ connect: fake.connect }));
    expect(result.statusCode).toBe(500);
    expect(result.errorClass).toBe("http_status");
    expect(result.responseExcerpt).toHaveLength(512);
  });

  it("records a redirect without following it, keeping only the target host", async () => {
    const fake = receiver({
      handler: (_req, res) => {
        res.writeHead(302, { location: "https://evil.example/steal?token=1" }).end();
      },
    });
    const result = await deliverOnce(request({ connect: fake.connect }));
    expect(result).toMatchObject({ statusCode: 302, errorClass: "redirect_not_followed" });
    expect(result.responseExcerpt).toBe("redirect host: evil.example");
    expect(fake.connects).toHaveLength(1);
  });

  it("parses Retry-After on 429 and 503 only", async () => {
    for (const [status, expected] of [
      [429, 120],
      [503, 120],
      [500, null],
    ] as const) {
      const fake = receiver({
        handler: (_req, res) => {
          res.writeHead(status, { "retry-after": "120" }).end();
        },
      });
      expect((await deliverOnce(request({ connect: fake.connect }))).retryAfterSeconds).toBe(
        expected,
      );
    }
  });

  it("treats only 2xx as success", async () => {
    for (const status of [200, 201, 299, 304, 400, 404]) {
      const fake = receiver({ handler: (_req, res) => res.writeHead(status).end() });
      const result = await deliverOnce(request({ connect: fake.connect }));
      expect(result.errorClass === null, String(status)).toBe(status >= 200 && status < 300);
    }
  });
});

describe("plaintext to an allowlisted private destination", () => {
  const allowlist: WebhookAllowlist = {
    cidrs: parseAllowedCidrs("192.168.1.0/24", true),
    hosts: new Set(),
    allowPlaintext: true,
    allowLoopback: false,
  };

  it("connects over plain TCP only when flag, allowlist and eligibility all hold", async () => {
    const fake = receiver({ tlsOptions: null });
    const ok = await deliverOnce(
      request({
        connect: fake.connect,
        url: "http://192.168.1.20:8080/h",
        allowlist,
        ownerMayUsePrivate: true,
      }),
    );
    expect(ok).toMatchObject({
      statusCode: 204,
      errorClass: null,
      resolvedAddress: "192.168.1.20",
    });
    const ineligible = await deliverOnce(
      request({
        connect: fake.connect,
        url: "http://192.168.1.20:8080/h",
        allowlist,
        ownerMayUsePrivate: false,
      }),
    );
    expect(ineligible.errorClass).toBe("destination_blocked");
    expect(fake.connects).toHaveLength(1);
  });
});
