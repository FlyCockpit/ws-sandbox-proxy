import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  EXCHANGE_DEVICE_CODE_ERROR_ROWS,
  EXCHANGE_DEVICE_CODE_THROW_SITE_IDS,
  EXCHANGE_DEVICE_CODE_THROW_SITE_ROWS,
} from "./exchange-device-code-contract";

const contractPath = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../docs/design/device-flow-contract.md",
);

type ParsedRow = {
  http: number;
  orpcCode: string;
  deviceFlowError: string | null;
  retry: boolean;
};

function parseErrorTable(markdown: string): ParsedRow[] {
  const section = markdown.split("## Error responses")[1]?.split("## ")[0] ?? "";
  const lines = section.split("\n").filter((line) => line.startsWith("|") && !line.includes("---"));
  const dataLines = lines.filter((line) => !line.includes("`json.code`"));
  return dataLines.map((line) => {
    const cells = line
      .split("|")
      .map((cell) => cell.trim())
      .filter(Boolean);
    const http = Number(cells[0]);
    const orpcCode = cells[1]?.replace(/`/g, "") ?? "";
    const flowCell = cells[2] ?? "";
    const deviceFlowError =
      flowCell.includes("absent") || flowCell === "(absent)"
        ? null
        : flowCell.replace(/`/g, "").trim() || null;
    const retryCell = cells[3]?.toLowerCase() ?? "";
    const retry = retryCell.startsWith("yes");
    return { http, orpcCode, deviceFlowError, retry };
  });
}

describe("exchange device code contract", () => {
  it("matches docs/design/device-flow-contract.md error table rows", () => {
    const markdown = readFileSync(contractPath, "utf8");
    const fromDoc = parseErrorTable(markdown);
    const fromCode = EXCHANGE_DEVICE_CODE_ERROR_ROWS.map((row) => ({
      http: row.http,
      orpcCode: row.orpcCode,
      deviceFlowError: row.deviceFlowError,
      retry: row.retry,
    }));
    expect(fromDoc).toEqual(fromCode);
  });

  it("maps every throw site to documented contract rows", () => {
    const rowIds = new Set(EXCHANGE_DEVICE_CODE_ERROR_ROWS.map((row) => row.id));
    for (const site of EXCHANGE_DEVICE_CODE_THROW_SITE_IDS) {
      const mapped = EXCHANGE_DEVICE_CODE_THROW_SITE_ROWS[site];
      if (site === "csrf_mismatch") {
        expect(mapped).toEqual([]);
        continue;
      }
      expect(mapped.length).toBeGreaterThan(0);
      for (const id of mapped) expect(rowIds.has(id)).toBe(true);
    }
    const covered = new Set(
      EXCHANGE_DEVICE_CODE_THROW_SITE_IDS.flatMap(
        (site) => EXCHANGE_DEVICE_CODE_THROW_SITE_ROWS[site],
      ),
    );
    for (const row of EXCHANGE_DEVICE_CODE_ERROR_ROWS) {
      expect(covered.has(row.id)).toBe(true);
    }
  });

  it("documents a terminal catch-all for unlisted responses and only the tagged rows retry", () => {
    const markdown = readFileSync(contractPath, "utf8");
    expect(markdown).toMatch(
      /Any response not listed in the error table[\s\S]*treat as \*\*terminal\*\*/,
    );
    const retryable = EXCHANGE_DEVICE_CODE_ERROR_ROWS.filter((row) => row.retry);
    for (const row of retryable) {
      expect(
        row.deviceFlowError === "authorization_pending" ||
          row.deviceFlowError === "slow_down" ||
          row.http === 429,
      ).toBe(true);
    }
  });
});
