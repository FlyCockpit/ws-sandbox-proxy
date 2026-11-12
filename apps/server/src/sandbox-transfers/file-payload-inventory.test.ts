import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * C30 full-scan inventory: file bytes move only through the transfer store
 * (C27–C30). No SQL byte column, whole-file base64 field, RPC/HTTP file-content
 * adapter or in-memory whole-file buffer may reappear. Each allowlist entry is
 * an exhaustive, reviewed site; a new one fails here until it is classified.
 */
const ROOT = join(import.meta.dirname, "../../../..");
const read = (path: string) => readFileSync(join(ROOT, path), "utf8");
function sources(dir: string, extension: string): string[] {
  const out: string[] = [];
  const walk = (at: string) => {
    for (const entry of readdirSync(join(ROOT, at))) {
      const path = join(at, entry);
      if (["node_modules", "dist", "generated", "target"].includes(entry)) continue;
      if (statSync(join(ROOT, path)).isDirectory()) walk(path);
      else if (
        path.endsWith(extension) &&
        !/\.(test|pg\.test)\.ts$|\.gen\.ts$|-harness\.ts$|-fixtures\.ts$/.test(path)
      )
        out.push(relative(ROOT, join(ROOT, path)));
    }
  };
  walk(dir);
  return out;
}
const TS_ROOTS = [
  "apps/server/src",
  "apps/worker/src",
  "apps/web/src",
  "packages/api/src",
  "packages/db/src",
  "packages/sandbox-contracts/src",
];

describe("file payload inventory", () => {
  it("allows SQL byte columns only for bounded command output", () => {
    const schemaDir = "packages/db/prisma/schema";
    const columns: string[] = [];
    for (const file of readdirSync(join(ROOT, schemaDir))) {
      let model = "";
      for (const line of read(join(schemaDir, file)).split("\n")) {
        const header = /^model (\w+)/.exec(line);
        if (header) model = header[1]!;
        const field = /^\s+(\w+)\s+Bytes\b/.exec(line);
        if (field) columns.push(`${model}.${field[1]}`);
      }
    }
    // C26 retained output (1 MiB aggregate cap per operation); never file content.
    // Webhook signing secrets: AES-256-GCM ciphertext (48 bytes) and 12-byte nonces.
    expect(columns.sort()).toEqual([
      // CLI logins (never guest file content): 32-byte digests and keys, wrap
      // salts/nonces, the encrypted vault value (bounded by the definition's
      // maxBytes), the wrapped return private key, and the non-secret dispatch
      // spec (CHECK-bounded to specMaxBytes).
      "CredentialCapture.envelopeDigest",
      "CredentialCaptureRejection.envelopeDigest",
      "CredentialOperationSpec.bytes",
      "CredentialOperationSpec.digest",
      "CredentialReturnKey.publicKey",
      "CredentialReturnKey.rwrapSalt",
      "CredentialReturnKey.wrapNonce",
      "CredentialReturnKey.wrappedPrivate",
      "CredentialSecretVersion.ciphertext",
      "CredentialSecretVersion.nonce",
      "CredentialSecretVersion.wrapNonce",
      "CredentialSecretVersion.wrapSalt",
      "CredentialSecretVersion.wrappedDek",
      "SandboxCommandOutputSegment.bytes",
      "SandboxCommandOutputSegment.stderrMask",
      // Disk offload: a 48-byte wrapped disk DEK, its 32-byte
      // HKDF salt and 12-byte nonce; never content.
      "SandboxDiskOffload.wrapNonce",
      "SandboxDiskOffload.wrapSalt",
      "SandboxDiskOffload.wrappedKey",
      // A 48-byte wrapped image data key and its 12-byte nonce; never content.
      "SandboxImageArtifact.wrappedKey",
      "SandboxImageArtifact.wrappedKeyNonce",
      "SandboxImageUploadSession.wrapSalt",
      "SandboxImageUploadSession.wrappedKey",
      "SandboxImageUploadSession.wrappedKeyNonce",
      // Bounded command output, the C26 class: a failed build step's output
      // tail, copied from its command output so it outlives the 24 h output
      // retention (template builds §3.3). Never file content; its 8 KiB bound
      // is a CHECK, pinned below.
      "SandboxTemplateBuild.failureTail",
      "WebhookEndpoint.previousSecretCiphertext",
      "WebhookEndpoint.previousSecretNonce",
      "WebhookEndpoint.secretCiphertext",
      "WebhookEndpoint.secretNonce",
    ]);
    // The build failure tail is command output only while it stays bounded.
    expect(read(join(schemaDir, "build.prisma"))).toContain(
      `("failureTail" IS NULL OR octet_length("failureTail") <= 8192)`,
    );
  });

  it("finds no legacy whole-file identifiers in any TypeScript source", () => {
    const files = TS_ROOTS.flatMap((dir) => [...sources(dir, ".ts"), ...sources(dir, ".tsx")]);
    expect(files.length).toBeGreaterThan(100);
    const banned =
      /\bpayloadBytes\b|\bgetFileContent\b|\bwriteFileInput\b|\bWriteFileInput\b|\bSANDBOX_FILE_MAX_BYTES\b|\bdecodeFileBase64\b|\bsandboxes\.writeFile\b|\bfile-buffers\b/;
    const hits = files.filter((file) => banned.test(read(file)));
    expect(hits).toEqual([]);
  });

  it("decodes base64 only for bounded stdin chunks", () => {
    const decodes: string[] = [];
    for (const file of TS_ROOTS.flatMap((dir) => sources(dir, ".ts"))) {
      read(file)
        .split("\n")
        .forEach((line, index) => {
          if (/,\s*"base64"\s*\)/.test(line) && /Buffer\.from\(/.test(line))
            decodes.push(`${file}:${index + 1}`);
        });
    }
    const sites = decodes.map((site) => site.replace(/:\d+$/, ""));
    expect(sites.sort()).toEqual([
      // Relay dispatch of writeStdin chunks and runCommand initial stdin (outbox payload).
      "apps/server/src/sandbox-relay/outbox-processor.ts",
      "apps/server/src/sandbox-relay/outbox-processor.ts",
      // CLI-login value upload: credential files go straight into the vault
      // bundle (bounded by the definition's maxBytes), never to a guest path.
      "packages/api/src/credentials/service.ts",
      // The 32-byte image store master key (IMAGE_STORE_ENCRYPTION_KEY); never content.
      "packages/api/src/sandbox/image-store/s3.ts",
      // Atomic control and initial-command length checks, each ≤ 32 KiB.
      "packages/api/src/sandbox/process-controls.ts",
      "packages/api/src/sandbox/services/sandboxes.ts",
    ]);
  });

  it("keeps Rust file payloads disk-backed, never in-memory byte vectors", () => {
    const traits = read("crates/sandbox-runtime/src/trait.rs");
    const fileStructs = [...traits.matchAll(/pub struct (\w*File\w*) \{([^}]*)\}/g)];
    expect(fileStructs.map((m) => m[1]).sort()).toEqual([
      "ReadFileRequest",
      "ReadFileResponse",
      "RecoverFilePutRequest",
      "WriteFileRequest",
      "WriteFileResponse",
    ]);
    for (const [, name, body] of fileStructs) {
      expect(body, name).not.toMatch(/Vec<u8>|String,\s*\/\/\s*bytes/);
      if (/bytes:/.test(body!)) expect(body, name).toMatch(/bytes: crate::FileContent/);
    }
    // The only byte vector is one bounded chunk read (at most FILE_CHUNK_BYTES).
    const staging = read("crates/sandbox-runtime/src/files.rs").split("#[cfg(test)]")[0]!;
    expect(staging.match(/Vec<u8>/g)).toHaveLength(1);
    expect(staging).toMatch(
      /pub fn read_chunk\(&self, offset: u64, size: usize\) -> Result<Vec<u8>, RuntimeError> \{\s*if size > FILE_CHUNK_BYTES/,
    );
    expect(read("apps/cli/src/sandbox_relay/files.rs")).not.toMatch(/Vec<u8>/);
    expect(read("crates/sandbox-protocol/src/frame.rs")).not.toMatch(/SANDBOX_FILE_MAX_BYTES/);
  });

  it("pins one 1 GiB transfer cap across contracts, env schema, relay and host", async () => {
    const { TRANSFER_MAX_BYTES } = await import("@wssp/sandbox-contracts");
    expect(TRANSFER_MAX_BYTES).toBe(1024 ** 3);
    expect(read("crates/sandbox-runtime/src/files.rs")).toContain(
      "pub const FILE_MAX_BYTES: u64 = 1024 * 1024 * 1024;",
    );
    const envVars = read("packages/env/src/vars/server.ts");
    const transferMax = /TRANSFER_MAX_BYTES: z\.coerce([\s\S]*?)\.default\(([^)]*)\)/.exec(envVars);
    expect(transferMax?.[1]).toContain(".max(1024 ** 3)");
    expect(transferMax?.[2]).toBe("1024 ** 3");
    expect(read("apps/server/src/sandbox-relay/session-manager.ts")).toMatch(
      /input\.fileUpload\.size > TRANSFER_MAX_BYTES/,
    );
  });
});
