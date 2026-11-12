import { describe, expect, it } from "vitest";
import {
  checkDefinitionText,
  definitionFiles,
  definitionProxyCapable,
  fileToBase64,
  loginProblem,
  loginProblemEntry,
  loginProblemIssues,
  readDefinition,
  shareRotationRisk,
} from "./login-rules";

const minimal = {
  schemaVersion: 1,
  id: "a",
  displayName: "Minimal",
  login: { command: "true", method: "paste" },
  credentials: { env: [{ name: "EXAMPLE_TOKEN", required: true }] },
};

describe("checkDefinitionText", () => {
  it("is empty for blank text and valid for a minimal definition", () => {
    expect(checkDefinitionText("  ").state).toBe("empty");
    const check = checkDefinitionText(JSON.stringify(minimal));
    expect(check.state).toBe("valid");
  });

  it("reports unparseable JSON, unknown keys and the typed schemaVersion refusal", () => {
    expect(checkDefinitionText("{").state).toBe("invalid");
    const unknown = checkDefinitionText(JSON.stringify({ ...minimal, surprise: 1 }));
    expect(unknown.state === "invalid" && unknown.issues.length > 0).toBe(true);
    const future = checkDefinitionText(JSON.stringify({ ...minimal, schemaVersion: 2 }));
    expect(future.state === "invalid" && future.code).toBe("definition.schema_version_unsupported");
  });
});

describe("definition helpers", () => {
  it("lists files required-first and detects proxy capability and rotation risk", () => {
    const files = readDefinition({
      ...minimal,
      credentials: {
        files: { required: [".tool/creds.json"], optional: [".tool/extra"] },
        sharing: "shareable",
      },
    });
    expect(files && definitionFiles(files)).toEqual([
      { path: ".tool/creds.json", required: true },
      { path: ".tool/extra", required: false },
    ]);
    expect(files && definitionProxyCapable(files)).toBe(false);
    // rotates defaults to "unknown": shareable + unknown warns.
    expect(files && shareRotationRisk(files)).toBe(true);
    const env = readDefinition(minimal);
    expect(env && shareRotationRisk(env)).toBe(false);
    expect(readDefinition({ nope: true })).toBeNull();
  });
});

describe("loginProblem", () => {
  it("maps domain codes, the incompatible re-pin reason and transport statuses", () => {
    expect(loginProblem({ data: { code: "credential.busy" } })).toBe("busy");
    expect(loginProblem({ data: { code: "credential.repin_blocked" } })).toBe("repinBlocked");
    expect(
      loginProblem({
        data: { code: "credential.repin_blocked", reason: "incompatible_definition" },
      }),
    ).toBe("repinIncompatible");
    expect(loginProblem({ code: "TOO_MANY_REQUESTS" })).toBe("rateLimited");
    expect(loginProblem({ code: "UNAUTHORIZED" })).toBe("forbidden");
    expect(loginProblem(new Error("x"))).toBe("generic");
  });

  it("extracts issues and the named entry, never anything else", () => {
    const error = {
      data: {
        code: "credential.value_invalid",
        entry: "EXAMPLE_TOKEN",
        issues: [{ path: "a", message: "b" }, { bogus: true }],
      },
    };
    expect(loginProblemEntry(error)).toBe("EXAMPLE_TOKEN");
    expect(loginProblemIssues(error)).toEqual([{ path: "a", message: "b" }]);
  });
});

describe("fileToBase64", () => {
  it("encodes bytes with the standard alphabet", async () => {
    const blob = new Blob([new Uint8Array([0, 1, 2, 250, 251, 252])]);
    expect(await fileToBase64(blob)).toBe("AAEC+vv8");
  });
});
