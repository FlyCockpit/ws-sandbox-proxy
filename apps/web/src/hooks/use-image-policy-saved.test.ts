// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook } from "@testing-library/react";
import { createElement, type ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

vi.mock("@/utils/orpc", () => ({
  orpc: {
    settings: { imagePolicy: { key: () => ["settings", "imagePolicy"] } },
    templateBuilds: { usage: { key: () => ["templateBuilds", "usage"] } },
    sandboxPools: { hostPolicy: { key: () => ["sandboxPools", "hostPolicy"] } },
  },
}));

const { useImagePolicySaved } = await import("./use-image-policy-saved");

describe("useImagePolicySaved", () => {
  it("refetches the pool host policy with the image policy readers", () => {
    const client = new QueryClient();
    const invalidate = vi.spyOn(client, "invalidateQueries").mockResolvedValue();
    const wrapper = ({ children }: { children: ReactNode }) =>
      createElement(QueryClientProvider, { client }, children);
    const { result } = renderHook(() => useImagePolicySaved(), { wrapper });
    result.current();
    expect(invalidate.mock.calls.map(([filters]) => filters?.queryKey)).toEqual([
      ["settings", "imagePolicy"],
      ["templateBuilds", "usage"],
      ["sandboxPools", "hostPolicy"],
    ]);
  });
});
