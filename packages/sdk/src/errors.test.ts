import { describe, expect, it } from "vitest";
import { isWsspError, redact, redactCause, WsspError } from "./errors";
import { createWsspTransport, type FetchLike } from "./transport";

// Obviously fake fixture key (matches the wssp_sdk_ shape the constructor
// requires); the tests assert this exact string never leaks.
const KEY = "wssp_sdk_test_canary";
const BASE = "https://api.example.test";

/** Every string an Error can be coerced to, including serialized fields and causes. */
function surfaceOf(error: unknown): string {
  const seen = new Set<unknown>();
  const parts: string[] = [];
  const walk = (value: unknown) => {
    if (value === null || value === undefined || seen.has(value)) return;
    if (typeof value === "object") {
      seen.add(value);
      if (value instanceof Error) {
        parts.push(value.name, value.message, String(value));
        try {
          parts.push(JSON.stringify(value));
        } catch {
          // non-serializable
        }
        walk(value.cause);
        return;
      }
      for (const nested of Object.values(value)) walk(nested);
      return;
    }
    parts.push(String(value));
  };
  walk(error);
  return parts.join("\n");
}

async function failureOf(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => {
      throw new Error("expected a rejection");
    },
    (e: unknown) => e,
  );
}

function transportWith(fetch: FetchLike, apiKey = KEY) {
  return createWsspTransport({ baseUrl: BASE, apiKey, fetch });
}

describe("secret redaction", () => {
  it("redacts a rejected fetch whose message and cause embed the key", async () => {
    const cause = new TypeError(`connect failed for Authorization: Bearer ${KEY}`);
    cause.cause = new Error(`tls ${KEY} down`);
    const error = await failureOf(
      transportWith(async () => {
        throw cause;
      }).request("getSandbox", { params: { id: "sbx_1" } }),
    );
    expect(isWsspError(error)).toBe(true);
    const surface = surfaceOf(error);
    expect(surface).not.toContain(KEY);
    expect(surface).toContain("[REDACTED]");
  });

  it("redacts the key from a mutation failure with an unknown outcome", async () => {
    const error = await failureOf(
      transportWith(async () => {
        throw new Error(`socket hung up on ${KEY}`);
      }).request("stopSandbox", { params: { id: "sbx_1" }, idempotencyKey: "stop-1" }),
    );
    expect(isWsspError(error, "unknown")).toBe(true);
    expect(surfaceOf(error)).not.toContain(KEY);
    expect((error as WsspError).idempotencyKey).toBe("stop-1");
  });

  it("redacts credential-shaped strings other than the configured key", async () => {
    const other = "wssp_sdk_AnotherKey_999";
    const error = await failureOf(
      transportWith(async () => {
        throw new Error(`upstream sent Bearer ${other} and wssp_host_xyz`);
      }).request("getSandbox", { params: { id: "sbx_1" } }),
    );
    const surface = surfaceOf(error);
    expect(surface).not.toContain(other);
    expect(surface).not.toContain("wssp_host_xyz");
  });

  it("never stores the key on the transport or its serialization", async () => {
    const transport = transportWith(async () => new Response("{}"));
    expect(surfaceOf(transport)).not.toContain(KEY);
    expect(surfaceOf(transport)).toContain(BASE);
  });

  it("redacts a string `code` carried by a cause", async () => {
    const error = await failureOf(
      transportWith(async () => {
        const cause = new Error("boom");
        Object.defineProperty(cause, "code", { value: KEY });
        throw cause;
      }).request("getSandbox", { params: { id: "sbx_1" } }),
    );
    expect(surfaceOf(error)).not.toContain(KEY);
  });

  it("drops error text the server returned inside an error envelope", async () => {
    const error = await failureOf(
      transportWith(async () =>
        Response.json(
          {
            error: {
              code: "NOT_FOUND",
              message: `internal: ${KEY} row missing`,
              requestId: crypto.randomUUID(),
            },
          },
          { status: 404 },
        ),
      ).request("getSandbox", { params: { id: "sbx_1" } }),
    );
    const surface = surfaceOf(error);
    expect(surface).not.toContain(KEY);
    expect(surface).not.toContain("internal:");
    expect(surface).toContain("Resource not found.");
  });
});

describe("redact", () => {
  it("replaces the exact secret and credential patterns", () => {
    expect(redact(`a ${KEY} b`, KEY)).toBe("a [REDACTED] b");
    expect(redact(`Bearer ${KEY}`, KEY)).toBe("Bearer [REDACTED]");
    expect(redact("wssp_device_zz", KEY)).toBe("[REDACTED]");
    expect(redact("plain text", KEY)).toBe("plain text");
  });

  it("replaces a secret that is not credential-shaped", () => {
    expect(redact("the code hunter2 here", "hunter2")).toBe("the code [REDACTED] here");
  });

  it("replaces an opaque bearer token", () => {
    expect(redact("Authorization: Bearer opaqueToken123", KEY)).toBe(
      "Authorization: Bearer [REDACTED]",
    );
  });
});

describe("redactCause", () => {
  it("bounds the chain depth and message length", () => {
    let root: Error = new Error("x".repeat(2000));
    for (let i = 0; i < 10; i++) root = new Error(`level ${i}`, { cause: root });
    const copy = redactCause(root, KEY);
    expect(copy).toBeInstanceOf(Error);
    expect(copy?.message.length).toBeLessThanOrEqual(512);
    let depth = 0;
    let cursor = copy;
    while (cursor?.cause instanceof Error) {
      depth += 1;
      cursor = cursor.cause;
    }
    expect(depth).toBeLessThan(4);
  });

  it("returns undefined for non-errors beyond a message", () => {
    expect(redactCause(undefined, KEY)).toBeUndefined();
    expect(redactCause("oops", KEY)?.message).toBe("oops");
  });

  it("redacts before truncating: a key straddling the cut leaves no fragment", () => {
    // Position the key so truncation alone would keep ALL BUT ONE of its
    // characters: exact-key replacement would fail on the sliced text, and
    // the credential regex finds no word boundary in the "xwssp_sdk_…"
    // fragment. Redaction must run on the COMPLETE contents first.
    const fragment = KEY.slice(0, KEY.length - 1);
    const straddle = (limit: number, pad: string) => pad.repeat(limit - KEY.length + 1) + KEY;
    const root = new Error(straddle(512, "x"));
    Object.defineProperty(root, "name", { value: straddle(64, "n") });
    Object.defineProperty(root, "code", { value: straddle(64, "c") });
    const copy = redactCause(root, KEY);
    expect(copy?.message.length).toBeLessThanOrEqual(512);
    expect(copy?.name.length).toBeLessThanOrEqual(64);
    expect(copy?.message).not.toContain(KEY);
    expect(copy?.message).not.toContain(fragment);
    expect(copy?.name).not.toContain(KEY);
    expect(copy?.name).not.toContain(fragment);
    const code = (copy as unknown as { code?: string }).code;
    expect(code).not.toContain(KEY);
    expect(code).not.toContain(fragment);
    expect(copy?.stack).not.toContain(KEY);
    expect(surfaceOf(copy)).not.toContain(fragment);
    // Truncation still bounds the redacted text (the depth-bounded test's
    // long message sits below the chain cutoff and never exercises this).
    expect(redactCause(new Error("y".repeat(2000)), KEY)?.message).toBe("y".repeat(512));
    expect(redactCause(new Error("ok"), KEY)?.message).toBe("ok");
  });
});

describe("isWsspError", () => {
  it("narrows by kind", () => {
    const error = new WsspError({ kind: "not_found", message: "gone" });
    expect(isWsspError(error)).toBe(true);
    expect(isWsspError(error, "not_found")).toBe(true);
    expect(isWsspError(error, "gone")).toBe(false);
    expect(isWsspError(new Error("gone"))).toBe(false);
  });

  it("serializes without the cause", () => {
    const error = new WsspError({
      kind: "unknown",
      message: "x",
      cause: redactCause(new Error(KEY), KEY),
    });
    const json = JSON.stringify(error);
    expect(json).not.toContain(KEY);
    expect(json).not.toContain("cause");
  });
});
