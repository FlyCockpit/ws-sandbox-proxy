// @vitest-environment jsdom
import { renderHook } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { getAuthSessionState } from "@/lib/auth-session-state";
import { useSensitiveAccessUnavailable } from "./use-sensitive-access-unavailable";

const atom = vi.hoisted(() => ({
  data: null as { session: { impersonatedBy?: string | null } } | null,
  error: null as unknown,
}));
vi.mock("./use-auth-session", () => ({
  useAuthSession: () =>
    getAuthSessionState({
      data: atom.data,
      error: atom.error,
      isPending: false,
      isRefetching: false,
      isOnline: true,
      refetch: vi.fn(),
      confirmedAnonymous: false,
    }),
}));
it("uses the authenticated impersonatedBy snapshot, independently of gate errors", () => {
  atom.data = { session: { impersonatedBy: "admin" } };
  atom.error = null;
  const { result, rerender } = renderHook(() => useSensitiveAccessUnavailable());
  expect(result.current).toBe(true);
  atom.data = { session: { impersonatedBy: null } };
  rerender();
  expect(result.current).toBe(false);
  atom.data = { session: {} };
  rerender();
  expect(result.current).toBe(false);
  atom.data = null;
  atom.error = { status: 401 };
  rerender();
  expect(result.current).toBe(false);
});
