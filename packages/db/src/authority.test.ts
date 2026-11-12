import { describe, expect, it } from "vitest";
import {
  authorityTicket,
  onAuthorityCommitted,
  trackedAuthorityKeyCount,
  withAuthorityChange,
  withGlobalAuthorityChange,
} from "./authority";

describe("revocation linearization", () => {
  it("invalidates stale reads before IO, denies reads during IO, and recovers after commit", async () => {
    const stale = authorityTicket({ credentialId: "key" });
    const during = await withAuthorityChange({ credentialId: "key" }, async () => {
      expect(stale()).toBe(false);
      const ticket = authorityTicket({ credentialId: "key" });
      expect(ticket()).toBe(false);
      return ticket;
    });
    expect(during()).toBe(false);
    expect(stale()).toBe(false);
    expect(authorityTicket({ credentialId: "key" })()).toBe(true);
  });

  it("recovers on rollback without reviving old tickets", async () => {
    const stale = authorityTicket({ ownerId: "owner" });
    await expect(
      withAuthorityChange({ ownerId: "owner" }, async () => {
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(stale()).toBe(false);
    expect(authorityTicket({ ownerId: "owner" })()).toBe(true);
  });
});

it("scopes revocation to matching identities while account changes invalidate all their credentials", async () => {
  const own = authorityTicket({ ownerId: "a", hostId: "h", credentialId: "key-a" });
  const other = authorityTicket({ ownerId: "b", hostId: "h2", credentialId: "key-b" });
  const foreign = authorityTicket({ ownerId: "b", hostId: "h", credentialId: "key-a" });
  await withAuthorityChange({ ownerId: "a", credentialId: "key-a" }, async () => {
    expect(own()).toBe(false);
    expect(other()).toBe(true);
    expect(foreign()).toBe(true);
  });
  const sibling = authorityTicket({ ownerId: "a", credentialId: "sibling" });
  await withAuthorityChange({ ownerId: "a" }, async () => {
    expect(sibling()).toBe(false);
    expect(other()).toBe(true);
  });
  await withAuthorityChange({ ownerId: "a", hostId: "h" }, async () => {
    expect(foreign()).toBe(true);
  });
  await withAuthorityChange({ credentialId: "key-a" }, async () => {
    expect(foreign()).toBe(false);
  });
});

describe("committed listener semantics", () => {
  it("delivers committed scope after the change window closes and tickets sampled inside succeed", async () => {
    let listenerTicketValid = false;
    const stop = onAuthorityCommitted((scope) => {
      expect(scope).toEqual({ kind: "scoped", ownerId: "owner-a", credentialId: "key-a" });
      listenerTicketValid = authorityTicket({
        ownerId: "owner-a",
        credentialId: "key-a",
      })();
    });
    await withAuthorityChange({ ownerId: "owner-a", credentialId: "key-a" }, async () => undefined);
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(listenerTicketValid).toBe(true);
    stop();
  });

  it("invalidates scoped tickets when global policy changes", async () => {
    const ticket = authorityTicket({ ownerId: "owner-a", credentialId: "key-a" });
    await withGlobalAuthorityChange(async () => undefined);
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(ticket()).toBe(false);
    expect(authorityTicket({ ownerId: "owner-a", credentialId: "key-a" })()).toBe(true);
  });

  it("leaves another owner's initial-auth ticket valid after one owner's change", async () => {
    const otherInitial = authorityTicket({
      ownerId: "owner-b",
      hostId: "host-b",
      credentialId: "token-b",
    });
    await withAuthorityChange({ ownerId: "owner-a", credentialId: "key-a" }, async () => undefined);
    await new Promise<void>((resolve) => queueMicrotask(resolve));
    expect(otherInitial()).toBe(true);
  });
});

it("a change naming both a host and a credential invalidates tickets scoped to either", async () => {
  const hostTicket = authorityTicket({ ownerId: "o", hostId: "h" });
  const credentialTicket = authorityTicket({ ownerId: "o", credentialId: "c" });
  await withAuthorityChange({ ownerId: "o", hostId: "h", credentialId: "c" }, async () => {});
  expect(hostTicket()).toBe(false);
  expect(credentialTicket()).toBe(false);
});

it("tickets for ids no change ever named allocate nothing, yet still observe a later change", async () => {
  const before = trackedAuthorityKeyCount();
  for (let i = 0; i < 1_000; i += 1) {
    expect(authorityTicket({ ownerId: "probe-owner", hostId: `missing-${i}` })()).toBe(true);
  }
  expect(trackedAuthorityKeyCount()).toBe(before);

  const unseen = authorityTicket({ ownerId: "fresh-owner", hostId: "fresh-host" });
  const unseenCredential = authorityTicket({ credentialId: "fresh-key" });
  await withAuthorityChange({ ownerId: "fresh-owner", hostId: "fresh-host" }, async () => {
    expect(unseen()).toBe(false);
  });
  await withAuthorityChange({ credentialId: "fresh-key" }, async () => {
    expect(unseenCredential()).toBe(false);
  });
  expect(unseen()).toBe(false);
  expect(unseenCredential()).toBe(false);
  expect(authorityTicket({ ownerId: "fresh-owner", hostId: "fresh-host" })()).toBe(true);
});

it("rolled-back terminal host change releases its hold without a committed lifecycle hint", async () => {
  const { holdAuthorityChange } = await import("./authority");
  const seen: unknown[] = [],
    off = onAuthorityCommitted((scope) => seen.push(scope));
  const hold = holdAuthorityChange({ ownerId: "rollback-owner", hostId: "rollback-host" });
  expect(authorityTicket({ ownerId: "rollback-owner", hostId: "rollback-host" })()).toBe(false);
  hold.settle(false);
  await new Promise<void>((resolve) => queueMicrotask(resolve));
  expect(seen).toEqual([]);
  expect(authorityTicket({ ownerId: "rollback-owner", hostId: "rollback-host" })()).toBe(true);
  off();
});
