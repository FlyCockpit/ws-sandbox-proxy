import enErrors from "@wssp/locales/src/en-US/errors.json";
import esErrors from "@wssp/locales/src/es-MX/errors.json";
import { describe, expect, it } from "vitest";
import {
  CREDENTIAL_ERROR_CODES,
  credentialErrorCode,
  credentialErrorKey,
} from "./credential-errors";

describe("credential error copy", () => {
  it("has en-US and es-MX copy for every known credential code", () => {
    for (const code of CREDENTIAL_ERROR_CODES) {
      expect((enErrors.credential as Record<string, string>)[code]).toEqual(expect.any(String));
      expect((esErrors.credential as Record<string, string>)[code]).toEqual(expect.any(String));
    }
  });

  it("maps only known credential.* codes", () => {
    expect(credentialErrorCode({ data: { code: "credential.env_conflict" } })).toBe("env_conflict");
    expect(credentialErrorKey({ data: { code: "credential.login_needs_consent" } })).toBe(
      "errors:credential.login_needs_consent",
    );
    expect(credentialErrorCode({ data: { code: "credential.future" } })).toBeNull();
    expect(credentialErrorCode({ data: { code: "sandbox.not_found" } })).toBeNull();
    expect(credentialErrorCode(new Error("x"))).toBeNull();
  });
});
