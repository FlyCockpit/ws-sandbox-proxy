import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { encodeHmacContext } from "./hmac-context";

describe("staged length-prefixed HMAC contexts", () => {
  it("uses UTF-8 byte lengths, including empty fields and non-ASCII text", () => {
    expect(encodeHmacContext(["", "é", "😀"]).toString("hex")).toBe(
      "0000000000000002c3a900000004f09f9880",
    );
    expect(encodeHmacContext([])).toEqual(Buffer.alloc(0));
    expect(encodeHmacContext(["ab", "c"])).not.toEqual(encodeHmacContext(["a", "bc"]));
    expect(encodeHmacContext(["a", "", "b"])).not.toEqual(encodeHmacContext(["a", "b", ""]));
  });

  it("separates domain/version, key ID, binding, principal and canonical payload", () => {
    // Public test fixture only. No runtime secrets or env values are read/logged.
    const master = Buffer.from("0123456789abcdef".repeat(4), "hex");
    const mac = (fields: readonly string[]) =>
      createHmac("sha256", master).update(encodeHmacContext(fields)).digest("hex");
    const fields = [
      "wssp-request-v1",
      "key-id",
      "server",
      "owner",
      "host",
      "session",
      '{"envs":{"A":"fixture"}}',
    ];
    expect(mac(fields)).toBe(mac([...fields]));
    for (let i = 0; i < fields.length; i++) {
      const changed = [...fields];
      changed[i] = `${changed[i]}-changed`;
      expect(mac(changed)).not.toBe(mac(fields));
    }
    expect(mac(["wssp-key-id-v1"])).not.toBe(mac(["wssp-host-journal-key-v1"]));
    expect(mac(["ab", "c"])).not.toBe(mac(["a", "bc"]));
  });
});
