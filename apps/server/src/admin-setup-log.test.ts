import { describe, expect, it, vi } from "vitest";

import { logAdminSetupHint } from "./admin-setup-log";

describe("logAdminSetupHint (M7-S14 operator hint)", () => {
  it("stays silent once an active administrator exists", async () => {
    const warn = vi.fn();
    await logAdminSetupHint({
      hasActiveAdministrator: async () => true,
      adminEmailsConfigured: false,
      setupKeyConfigured: false,
      warn,
    });
    expect(warn).not.toHaveBeenCalled();
  });

  it("names ADMIN_EMAILS in the server log when no administrator exists", async () => {
    const warn = vi.fn();
    await logAdminSetupHint({
      hasActiveAdministrator: async () => false,
      adminEmailsConfigured: false,
      setupKeyConfigured: false,
      warn,
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toMatch(/ADMIN_EMAILS is empty.*restart/);
    expect(warn.mock.calls[0]?.[0]).toContain("Set SETUP_KEY and run `pnpm deploy:generate-admin`");

    warn.mockClear();
    await logAdminSetupHint({
      hasActiveAdministrator: async () => false,
      adminEmailsConfigured: true,
      setupKeyConfigured: false,
      warn,
    });
    expect(warn.mock.calls[0]?.[0]).toMatch(/address listed in ADMIN_EMAILS/);
  });

  it("points at deploy:generate-admin while SETUP_KEY is set and no administrator exists", async () => {
    const warn = vi.fn();
    await logAdminSetupHint({
      hasActiveAdministrator: async () => false,
      adminEmailsConfigured: true,
      setupKeyConfigured: true,
      warn,
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toMatch(/SETUP_KEY is set: run `pnpm deploy:generate-admin`/);
  });

  it("reminds the operator to remove SETUP_KEY once an administrator exists", async () => {
    const warn = vi.fn();
    await logAdminSetupHint({
      hasActiveAdministrator: async () => true,
      adminEmailsConfigured: false,
      setupKeyConfigured: true,
      warn,
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn.mock.calls[0]?.[0]).toMatch(/SETUP_KEY is still set.*remove it/);
  });

  it("never fails startup when the check itself fails", async () => {
    const warn = vi.fn();
    await expect(
      logAdminSetupHint({
        hasActiveAdministrator: async () => {
          throw new Error("database unavailable");
        },
        adminEmailsConfigured: true,
        setupKeyConfigured: true,
        warn,
      }),
    ).resolves.toBeUndefined();
    expect(warn.mock.calls[0]?.[0]).toContain("database unavailable");
  });
});
