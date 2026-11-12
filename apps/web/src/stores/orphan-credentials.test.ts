import { beforeEach, describe, expect, it } from "vitest";

import { ORPHAN_QUEUE_MAX, useOrphanCredentials } from "./orphan-credentials";

const store = () => useOrphanCredentials.getState();
const epoch = () => store().epoch;

beforeEach(() => useOrphanCredentials.setState({ entries: [], ownerId: undefined, epoch: 0 }));

describe("orphan credential queue", () => {
  it("keeps nonsecret copies, once per credential, bounded per owner and scope", () => {
    const entry = { ownerId: "o1", scope: "sdkKey" as const, id: "k1", label: "ci" };
    store().add(entry, epoch());
    store().add(entry, epoch());
    expect(store().entries).toEqual([entry]);
    expect(store().entries[0]).not.toBe(entry);
    for (let i = 0; i < ORPHAN_QUEUE_MAX + 5; i++)
      store().add({ ownerId: "o1", scope: "hostToken", id: `t${i}`, label: "x" }, epoch());
    expect(store().entries.filter((item) => item.scope === "hostToken")).toHaveLength(
      ORPHAN_QUEUE_MAX,
    );
  });

  it("an owner change drops other owners' entries; signing out drops all", () => {
    store().add({ ownerId: "o1", scope: "sdkKey", id: "k1", label: "a" }, epoch());
    store().add({ ownerId: "o2", scope: "sdkKey", id: "k2", label: "b" }, epoch());
    store().syncOwner("o2");
    expect(store().entries.map((item) => item.id)).toEqual(["k2"]);
    store().syncOwner(null);
    expect(store().entries).toEqual([]);
  });

  it("removes a revoked orphan by scope and ID", () => {
    store().add({ ownerId: "o1", scope: "sdkKey", id: "same", label: "a" }, epoch());
    store().add({ ownerId: "o1", scope: "hostToken", id: "same", label: "b" }, epoch());
    store().remove("sdkKey", "same");
    expect(store().entries.map((item) => item.scope)).toEqual(["hostToken"]);
  });

  it("learning the first owner keeps pending cleanups valid", () => {
    const started = epoch();
    store().syncOwner("o1");
    store().add({ ownerId: "o1", scope: "sdkKey", id: "k1", label: "a" }, started);
    expect(store().entries.map((item) => item.id)).toEqual(["k1"]);
  });

  it.each([
    ["sign-out", () => store().clear()],
    ["sign-out reported by the session", () => store().syncOwner(null)],
    ["an owner change", () => store().syncOwner("o2")],
    [
      "sign-out then the same owner signing back in",
      () => {
        store().clear();
        store().syncOwner("o1");
      },
    ],
  ])("a cleanup started before %s cannot re-add its entry", (_name, invalidate) => {
    store().syncOwner("o1");
    const started = epoch();
    invalidate();
    store().add({ ownerId: "o1", scope: "sdkKey", id: "k1", label: "a" }, started);
    expect(store().entries).toEqual([]);
  });

  it("never queues an entry for an owner other than the signed-in one", () => {
    store().syncOwner("o2");
    store().add({ ownerId: "o1", scope: "sdkKey", id: "k1", label: "a" }, epoch());
    expect(store().entries).toEqual([]);
  });
});
