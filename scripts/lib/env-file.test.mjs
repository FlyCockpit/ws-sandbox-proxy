import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { upsertEnvContents, upsertEnvFile } from "./env-file.mjs";

describe("upsertEnvContents", () => {
  it("replaces in place, keeps comments and other lines, appends missing keys", () => {
    const input = "# header\nA=1\n# B=commented\nexport B=old\nC=keep\n";
    const out = upsertEnvContents(input, { B: "new", D: "x/y:z" });
    assert.equal(out.contents, "# header\nA=1\n# B=commented\nB=new\nC=keep\nD=x/y:z\n");
    assert.deepEqual(out.replaced, ["B"]);
    assert.deepEqual(out.appended, ["D"]);
  });

  it("adds a newline before appending to a file without one", () => {
    assert.equal(upsertEnvContents("A=1", { B: "2" }).contents, "A=1\nB=2\n");
    assert.equal(upsertEnvContents("", { B: "2" }).contents, "B=2\n");
  });

  it("removes later duplicates and whole multi-line quoted values", () => {
    const input = 'K="line1\nline2"\nOTHER=1\nK=dup\n';
    assert.equal(upsertEnvContents(input, { K: "v" }).contents, "K=v\nOTHER=1\n");
  });

  it("quotes non-plain values and refuses newline-bearing ones without echoing them", () => {
    assert.equal(upsertEnvContents("", { K: "a b" }).contents, "K='a b'\n");
    assert.throws(
      () => upsertEnvContents("", { K: "s3cr3t\nv4lue" }),
      (error) => {
        assert.doesNotMatch(String(error), /s3cr3t|v4lue/);
        return true;
      },
    );
    assert.throws(() => upsertEnvContents("", { "bad-key": "v" }));
  });

  it("is idempotent", () => {
    const once = upsertEnvContents("A=1\n", { B: "2" }).contents;
    assert.equal(upsertEnvContents(once, { B: "2" }).contents, once);
  });
});

describe("upsertEnvFile", () => {
  it("writes mode 0600 and refuses a symlink", () => {
    const dir = mkdtempSync(join(tmpdir(), "wssp-env-file-"));
    try {
      const file = join(dir, ".env");
      writeFileSync(file, "A=1\n", { mode: 0o644 });
      upsertEnvFile(file, { B: "2" });
      assert.equal(readFileSync(file, "utf8"), "A=1\nB=2\n");
      assert.equal(statSync(file).mode & 0o777, 0o600);
      const link = join(dir, "link.env");
      symlinkSync(file, link);
      assert.throws(() => upsertEnvFile(link, { C: "3" }));
      assert.equal(readFileSync(file, "utf8"), "A=1\nB=2\n");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
