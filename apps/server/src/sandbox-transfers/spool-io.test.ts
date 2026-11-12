import * as fs from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ImportSourceError, openImportSource } from "./spool-io.js";

vi.mock("@wssp/env/server", () => ({ env: {} }));

/** Source validation for `TransferStore.importSealed` (template-builds §3.7
 * step 2): the transfer store's own file checks applied to a sibling root. */
describe("openImportSource", () => {
  let base: string;
  let root: string;
  beforeEach(async () => {
    base = await fs.mkdtemp(join(tmpdir(), "wssp-spool-io-"));
    root = join(base, "spool.build-context");
    await fs.mkdir(root, { mode: 0o700 });
  });
  afterEach(() => fs.rm(base, { recursive: true, force: true }));
  const reason = (promise: Promise<unknown>) =>
    promise.then(
      () => "accepted",
      (error: unknown) => (error instanceof ImportSourceError ? error.reason : String(error)),
    );
  const staged = async (name = "a1.context", bytes = Buffer.from("context"), mode = 0o600) => {
    await fs.writeFile(join(root, name), bytes, { mode });
    return name;
  };

  it("opens our private regular file of exactly the declared size", async () => {
    const name = await staged();
    const { file, stat } = await openImportSource(root, name, 7);
    expect(stat.nlink).toBe(1);
    await file.close();
  });

  it("refuses a symlink, even to a valid file", async () => {
    const target = await staged("real.context");
    await fs.symlink(join(root, target), join(root, "link.context"));
    expect(await reason(openImportSource(root, "link.context", 7))).toBe("invalid");
  });

  it("refuses a second name as transient (nlink 2), and accepts once it is gone", async () => {
    const name = await staged();
    await fs.link(join(root, name), join(base, "other-name"));
    expect(await reason(openImportSource(root, name, 7))).toBe("linked");
    await fs.unlink(join(base, "other-name"));
    expect(await reason(openImportSource(root, name, 7))).toBe("accepted");
  });

  it("refuses a size other than the declared total, in both directions", async () => {
    const name = await staged();
    expect(await reason(openImportSource(root, name, 6))).toBe("invalid");
    expect(await reason(openImportSource(root, name, 8))).toBe("invalid");
  });

  it("refuses group/other permission bits, directories and missing names", async () => {
    const name = await staged("open.context", Buffer.from("context"), 0o644);
    await fs.chmod(join(root, name), 0o644);
    expect(await reason(openImportSource(root, name, 7))).toBe("invalid");
    await fs.mkdir(join(root, "dir.context"));
    expect(await reason(openImportSource(root, "dir.context", 0))).toBe("invalid");
    expect(await reason(openImportSource(root, "absent.context", 7))).toBe("missing");
  });

  it("refuses names that are not one plain component", async () => {
    await staged();
    for (const name of [
      "../spool.build-context/a1.context",
      "a/b",
      ".",
      "..",
      "",
      ".hidden",
      "a..b",
    ])
      expect([name, await reason(openImportSource(root, name, 7))]).toEqual([name, "invalid"]);
  });

  it("refuses a root that is a symlink or not private", async () => {
    const name = await staged();
    await fs.symlink(root, join(base, "alias"));
    expect(await reason(openImportSource(join(base, "alias"), name, 7))).toBe("invalid");
    await fs.chmod(root, 0o755);
    expect(await reason(openImportSource(root, name, 7))).toBe("invalid");
  });
});
