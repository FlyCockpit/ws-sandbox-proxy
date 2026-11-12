import { expect, it } from "vitest";
import { notifyAuthSessionsRevoked, onAuthSessionsRevoked } from "./session-revocation";

it("delivers after the caller's turn, isolates a throwing listener, and unsubscribes", async () => {
  const seen: unknown[] = [];
  const offBroken = onAuthSessionsRevoked(() => {
    throw new Error("broken listener");
  });
  const off = onAuthSessionsRevoked((revocation) => seen.push(revocation));
  notifyAuthSessionsRevoked({ userId: "u1" });
  expect(seen).toEqual([]);
  await Promise.resolve();
  expect(seen).toEqual([{ userId: "u1" }]);
  off();
  offBroken();
  notifyAuthSessionsRevoked({});
  await Promise.resolve();
  expect(seen).toEqual([{ userId: "u1" }]);
});
