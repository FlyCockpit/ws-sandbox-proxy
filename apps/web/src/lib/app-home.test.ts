import { describe, expect, it } from "vitest";

import { safeRedirectTo } from "@/utils/safe-redirect";

import { APP_HOME, appHomeHref } from "./app-home";

describe("APP_HOME", () => {
  it("is the Sandboxes list", () => {
    expect(APP_HOME).toBe("/$lang/dashboard/sandboxes");
    expect(appHomeHref("es-MX")).toBe("/es-MX/dashboard/sandboxes");
  });

  it("is where sign-in lands without a usable redirect", () => {
    for (const value of [undefined, "https://evil.example/", "/en-US/login", "/en-US/signup"]) {
      expect(safeRedirectTo(value, "en-US")).toBe("/en-US/dashboard/sandboxes");
    }
    expect(safeRedirectTo("/en-US/dashboard/templates", "en-US")).toBe(
      "/en-US/dashboard/templates",
    );
  });
});
