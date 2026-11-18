import { describe, expect, it, vi } from "vitest";

vi.mock("@wssp/db", () => ({ default: {} }));

import { dataRootKey, deriveSubkey } from "../../crypto/data-key";
import {
  normalizeTunnelApiUrl,
  openCredential,
  sealCredential,
  TUNNEL_CREDENTIAL_PURPOSE,
  TunnelCredentialUnavailable,
  validServiceCredential,
} from "./config";

const key = deriveSubkey(dataRootKey("a".repeat(64)), TUNNEL_CREDENTIAL_PURPOSE);
const other = deriveSubkey(dataRootKey("b".repeat(64)), TUNNEL_CREDENTIAL_PURPOSE);
const credential = `tnsvc_${"x".repeat(43)}`;

describe("tunnel server config", () => {
  it("accepts only bare https origins", () => {
    expect(normalizeTunnelApiUrl("https://Tunnel.Example.com/")).toBe("https://tunnel.example.com");
    expect(normalizeTunnelApiUrl("https://tunnel.example.com:8443")).toBe(
      "https://tunnel.example.com:8443",
    );
    for (const bad of [
      "http://tunnel.example.com",
      "https://tunnel.example.com/api",
      "https://user:pw@tunnel.example.com",
      "https://tunnel.example.com?x=1",
      "https://tunnel.example.com#a",
      "tunnel.example.com",
      // The relay frame's server pattern refuses these host names.
      "https://my_tunnel.example.com",
      "https://-tunnel.example.com",
    ])
      expect(normalizeTunnelApiUrl(bad), bad).toBeNull();
  });

  it("accepts only service credentials", () => {
    expect(validServiceCredential(credential)).toBe(true);
    expect(validServiceCredential(`tncli_${"x".repeat(43)}`)).toBe(false);
    expect(validServiceCredential("tnsvc_short")).toBe(false);
  });

  it("seals the credential bound to its URL and key", () => {
    const sealed = sealCredential(credential, "https://tunnel.example.com", key);
    expect(sealed.ciphertext.toString("utf8")).not.toContain("tnsvc_");
    expect(openCredential(sealed, "https://tunnel.example.com", [key])).toBe(credential);
    // Moved to another URL, or opened with another key: refused, never a crash.
    expect(() => openCredential(sealed, "https://evil.example.com", [key])).toThrow(
      TunnelCredentialUnavailable,
    );
    expect(() =>
      openCredential({ ...sealed, keyId: other.rootKeyId }, "https://tunnel.example.com", [other]),
    ).toThrow(TunnelCredentialUnavailable);
  });
});
