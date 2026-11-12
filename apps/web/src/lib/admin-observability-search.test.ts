import { describe, expect, it } from "vitest";

import {
  DEFAULT_OBSERVABILITY_SEARCH,
  hostListInput,
  invalidObservabilityFilters,
  observabilityFilterKey,
  operationListInput,
  parseObservabilitySearch,
  sandboxListInput,
} from "./admin-observability-search";

describe("admin observability search contract", () => {
  it("falls back to defaults for unknown tabs and enum values and bounds id text", () => {
    const parsed = parseObservabilitySearch({
      tab: "secrets",
      hostStatus: "ONLINE",
      sandboxState: 7,
      operationState: "DONE",
      owner: `  ${"x".repeat(80)}  `,
      host: 12345,
    });
    expect(parsed).toEqual({
      ...DEFAULT_OBSERVABILITY_SEARCH,
      owner: "x".repeat(64),
      host: "12345",
    });
  });

  it("flags only the active tab's ids that no row could have", () => {
    const search = parseObservabilitySearch({
      tab: "sandboxes",
      owner: "ok_1",
      host: "no/pe",
      sandbox: "x y",
    });
    expect(invalidObservabilityFilters(search)).toEqual(["host"]);
    expect(invalidObservabilityFilters({ ...search, tab: "operations" })).toEqual(["sandbox"]);
    expect(invalidObservabilityFilters({ ...search, tab: "maintenance" })).toEqual([]);
  });

  it("sends each list only its own exact filters and omits empty ones", () => {
    const search = parseObservabilitySearch({
      owner: "u-1",
      hostStatus: "STALE",
      host: "h-1",
      sandboxState: "READY",
      sandbox: "s-1",
      operationState: "FAILED",
    });
    expect(hostListInput(search, "c")).toEqual({
      limit: 25,
      cursor: "c",
      ownerId: "u-1",
      status: "STALE",
    });
    expect(sandboxListInput(search, undefined)).toEqual({
      limit: 25,
      cursor: undefined,
      ownerId: "u-1",
      hostId: "h-1",
      state: "READY",
    });
    expect(operationListInput({ ...search, owner: "" }, undefined)).toEqual({
      limit: 25,
      cursor: undefined,
      ownerId: undefined,
      sandboxId: "s-1",
      state: "FAILED",
    });
  });

  it("changes the paging key when the tab or an applicable filter changes, not otherwise", () => {
    const base = DEFAULT_OBSERVABILITY_SEARCH;
    expect(observabilityFilterKey({ ...base, tab: "sandboxes" })).not.toBe(
      observabilityFilterKey(base),
    );
    expect(observabilityFilterKey({ ...base, owner: "u" })).not.toBe(observabilityFilterKey(base));
    // A sandbox-tab filter does not reset host paging.
    expect(observabilityFilterKey({ ...base, sandboxState: "READY" })).toBe(
      observabilityFilterKey(base),
    );
  });
});
