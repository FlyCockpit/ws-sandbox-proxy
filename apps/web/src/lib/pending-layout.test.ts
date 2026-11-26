import { describe, expect, it } from "vitest";

import { resolvePendingLayout } from "./pending-layout";

const ROOT = { routeId: "__root__" };
const LANG = { routeId: "/$lang" };
const APP = { routeId: "/$lang/_app" };
const AUTH = { routeId: "/$lang/_app/_auth", staticData: { pendingFrame: "dashboard" as const } };
const DASHBOARD = { routeId: "/$lang/_app/_auth/dashboard", staticData: {} };
const SANDBOX = {
  routeId: "/$lang/_app/_auth/dashboard/sandboxes/$sandboxId",
  staticData: { pendingShape: "detail" as const },
};
const NEW_SANDBOX = {
  routeId: "/$lang/_app/_auth/dashboard/sandboxes/new",
  staticData: { pendingShape: "form" as const },
};
const ADMIN = { routeId: "/$lang/_app/admin", staticData: {} };
const ADMIN_USERS = {
  routeId: "/$lang/_app/admin/users",
  staticData: { pendingShape: "list" as const },
};
const DEVICE = {
  routeId: "/$lang/_app/device",
  staticData: { pendingShape: "form" as const, pendingWidth: "narrow" as const },
};

describe("resolvePendingLayout", () => {
  it("draws the dashboard frame below the pending boundary and the leaf's shape", () => {
    expect(resolvePendingLayout([ROOT, LANG, APP, AUTH, DASHBOARD, SANDBOX], APP.routeId)).toEqual({
      shape: "detail",
      width: "default",
      frames: ["dashboard"],
      insideFrame: false,
    });
  });

  it("leaves out frames that are already on screen above the boundary", () => {
    expect(
      resolvePendingLayout([ROOT, LANG, APP, AUTH, DASHBOARD, NEW_SANDBOX], DASHBOARD.routeId),
    ).toEqual({ shape: "form", width: "default", frames: [], insideFrame: true });
  });

  it("draws an unframed page at its own width", () => {
    expect(resolvePendingLayout([ROOT, LANG, APP, DEVICE], APP.routeId)).toEqual({
      shape: "form",
      width: "narrow",
      frames: [],
      insideFrame: false,
    });
  });

  it("gives /admin the same first frame as a route that declares nothing", () => {
    const admin = resolvePendingLayout([ROOT, LANG, APP, ADMIN, ADMIN_USERS], APP.routeId);
    expect(admin).toEqual(resolvePendingLayout([ROOT, LANG, APP], APP.routeId));
    expect(admin).toEqual({ shape: "list", width: "default", frames: [], insideFrame: false });
  });

  it("reads from the top when the boundary is unknown", () => {
    expect(resolvePendingLayout([ROOT, AUTH, SANDBOX], undefined).frames).toEqual(["dashboard"]);
    expect(resolvePendingLayout([ROOT, AUTH, SANDBOX], "/nowhere").frames).toEqual(["dashboard"]);
  });
});
