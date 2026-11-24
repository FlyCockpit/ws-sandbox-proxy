import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findRepoRoot, resolveRepoRoot } from "./root-env.js";

const repoRoot = path.resolve(import.meta.dirname, "../../..");
const scratch: string[] = [];

afterEach(() => {
  for (const dir of scratch.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe("repository root", () => {
  it("is the workspace root from inside packages/env, past the package's own turbo.json", () => {
    const envPackage = path.join(repoRoot, "packages/env");
    expect(fs.existsSync(path.join(envPackage, "turbo.json"))).toBe(true);
    expect(findRepoRoot(envPackage)).toBe(repoRoot);
    expect(findRepoRoot(import.meta.dirname)).toBe(repoRoot);
    expect(resolveRepoRoot()).toBe(repoRoot);
  });

  it("needs pnpm-workspace.yaml: a turbo.json alone never marks the root", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "wssp-root-env-"));
    scratch.push(root);
    const nested = path.join(root, "packages/env/src");
    fs.mkdirSync(nested, { recursive: true });
    fs.writeFileSync(path.join(root, "packages/env/turbo.json"), "{}\n");
    fs.writeFileSync(path.join(root, "turbo.json"), "{}\n");
    // No workspace file anywhere above: the walk reaches / without a root
    // (unless the machine's tmpdir itself sits in a workspace).
    const outside = findRepoRoot(nested);
    expect(outside === null || !outside.startsWith(root)).toBe(true);
    fs.writeFileSync(path.join(root, "pnpm-workspace.yaml"), "packages: []\n");
    expect(findRepoRoot(nested)).toBe(root);
  });
});
