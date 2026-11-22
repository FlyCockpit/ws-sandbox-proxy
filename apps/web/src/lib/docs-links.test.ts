import { describe, expect, it } from "vitest";

import { DOC_PAGES, docsRepoPath, docsUrl } from "./docs-links";

describe("docs links", () => {
  it("no docs base means no link, only the repository path", () => {
    expect(docsUrl(undefined, "templates")).toBeNull();
    expect(docsUrl("", "templates")).toBeNull();
    expect(docsRepoPath("templates")).toBe("docs/operations/templates.md");
  });

  it("joins the configured base and the page without doubled slashes", () => {
    expect(docsUrl("https://docs.example.test/wssp", "templates")).toBe(
      "https://docs.example.test/wssp/operations/templates.md",
    );
    expect(docsUrl("https://docs.example.test/wssp//", "templates")).toBe(
      "https://docs.example.test/wssp/operations/templates.md",
    );
  });

  it("every referenced doc page exists in the repository", async () => {
    const { existsSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { readFileSync } = await import("node:fs");
    // GitHub-style heading anchors: lower case, punctuation dropped, spaces to hyphens.
    const slug = (heading: string) =>
      heading
        .trim()
        .toLowerCase()
        .replace(/[^\p{L}\p{N}\s-]/gu, "")
        .replace(/\s/g, "-");
    for (const page of Object.keys(DOC_PAGES) as (keyof typeof DOC_PAGES)[]) {
      const [file, anchor] = docsRepoPath(page).split("#");
      const path = fileURLToPath(new URL(`../../../../${file}`, import.meta.url));
      expect(existsSync(path), path).toBe(true);
      if (anchor) {
        const anchors = readFileSync(path, "utf8")
          .split("\n")
          .filter((line) => /^#{1,6} /.test(line))
          .map((line) => slug(line.replace(/^#+ /, "")));
        expect(anchors, `${file}#${anchor}`).toContain(anchor);
      }
    }
  });

  it("the local docker stack configures a docs base, so its docs references are links (M7-S10)", async () => {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const defaults = readFileSync(
      fileURLToPath(new URL("../../../../.env.docker.defaults", import.meta.url)),
      "utf8",
    );
    const base = /^VITE_DOCS_URL=(\S+)$/m.exec(defaults)?.[1];
    expect(base).toMatch(/^https:\/\//);
    // The repository's default branch is `main`.
    expect(base).toBe("https://github.com/FlyCockpit/ws-sandbox-proxy/blob/main/docs");
    expect(docsUrl(base, "templates")).toBe(`${base}/operations/templates.md`);
  });
});
