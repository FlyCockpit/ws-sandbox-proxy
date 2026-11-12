import { beforeEach, describe, expect, it, vi } from "vitest";

const redisSet = vi.fn();
const redisEval = vi.fn();
const sendEmail = vi.fn();
const isEmailConfigured = vi.fn(() => true);

vi.mock("@wssp/db", async () => {
  const { mockDeep } = await import("vitest-mock-extended");
  return { default: mockDeep() };
});
// Importing the real `@wssp/queue` opens IORedis sockets at import time.
vi.mock("@wssp/queue", () => ({
  createRedisConnection: () => ({ set: redisSet, eval: redisEval, disconnect: () => {} }),
}));
vi.mock("@wssp/mailer", async () => ({
  renderDataDeleted: (await import("../../../packages/mailer/src/templates/data-deleted.js"))
    .renderDataDeleted,
  isEmailConfigured: () => isEmailConfigured(),
  sendEmail: (args: unknown) => sendEmail(args),
}));

const { default: prisma } = await import("@wssp/db");
const { sendOperationalAlert, sendDataDeletedAlert } = await import("./operational-alerts.js");

const db = prisma as unknown as { user: { findMany: ReturnType<typeof vi.fn> } };

const alert = {
  source: "worker",
  message: "boom",
  subject: "[worker] background job failed",
  html: "<p>boom</p>",
};

describe("sendOperationalAlert", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isEmailConfigured.mockReturnValue(true);
    sendEmail.mockReset().mockResolvedValue(undefined);
    redisEval.mockReset().mockResolvedValue(1);
    vi.spyOn(console, "error").mockImplementation(() => {});
    db.user.findMany.mockResolvedValue([{ id: "u1", email: "admin@example.com", role: "admin" }]);
  });

  it("emails admins when it wins the cooldown slot", async () => {
    redisSet.mockResolvedValue("OK");

    await sendOperationalAlert(alert);

    expect(sendEmail).toHaveBeenCalledWith(
      expect.objectContaining({ to: "admin@example.com", subject: alert.subject }),
    );
  });

  it("stays quiet while the cooldown is held", async () => {
    redisSet.mockResolvedValue(null);

    await sendOperationalAlert(alert);

    expect(sendEmail).not.toHaveBeenCalled();
  });

  // Redis is what turns a failure repeating every minute into ONE email an
  // hour. If it is unreachable, sending anyway would mail every admin every
  // minute for the length of the outage — so skip instead.
  it("skips the alert when Redis errors instead of mailing every admin", async () => {
    redisSet.mockRejectedValue(new Error("private-cooldown-sentinel"));

    await sendOperationalAlert(alert);

    expect(sendEmail).not.toHaveBeenCalled();
    expect(JSON.stringify(vi.mocked(console.error).mock.calls)).not.toContain(
      "private-cooldown-sentinel",
    );
    expect(console.error).toHaveBeenCalledWith(expect.any(String), {
      code: "operational_alert_cooldown_failed",
      errorClass: "Error",
    });
  });

  it("skips the alert when the Redis reservation never settles", async () => {
    vi.useFakeTimers();
    redisSet.mockReturnValue(new Promise(() => {}));

    const pending = sendOperationalAlert(alert);
    await vi.advanceTimersByTimeAsync(5_000);
    await pending;

    expect(sendEmail).not.toHaveBeenCalled();
    vi.useRealTimers();
  });
});

const deletion = {
  name: "20261101000000_drop_field",
  effects: "column match.legacy",
  deletedAt: new Date("2026-11-11T12:00:00Z"),
  backup: "pre-drop-20261111.dump",
  note: null,
};

describe("delivered-only alerts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    isEmailConfigured.mockReturnValue(true);
    redisSet.mockReset().mockResolvedValue("OK");
    redisEval.mockReset().mockResolvedValue(1);
    sendEmail.mockReset().mockResolvedValue(undefined);
    db.user.findMany
      .mockReset()
      .mockResolvedValue([{ id: "a", email: "a@example.com", role: "admin", locale: "es-MX" }]);
  });

  it("rejects a deletion while SMTP is absent or the cooldown is held", async () => {
    isEmailConfigured.mockReturnValue(false);
    await expect(sendDataDeletedAlert(deletion)).resolves.toBe(0);
    expect(redisSet).not.toHaveBeenCalled();
    isEmailConfigured.mockReturnValue(true);
    redisSet.mockResolvedValue(null);
    await expect(sendDataDeletedAlert(deletion)).resolves.toBe(0);
    expect(sendEmail).not.toHaveBeenCalled();
  });

  it.each([
    { recipients: [] },
    { recipients: [{ id: "u", email: "u@example.com", role: "user", locale: "en-US" }] },
  ])(
    "keeps the cooldown when the recipient scan returns $recipients without an eligible admin",
    async ({ recipients }) => {
      db.user.findMany.mockResolvedValueOnce(recipients);
      redisSet.mockResolvedValueOnce("OK").mockResolvedValueOnce(null);
      await expect(sendOperationalAlert(alert)).resolves.toBe(0);
      await expect(sendOperationalAlert(alert)).resolves.toBe(0);
      expect(db.user.findMany).toHaveBeenCalledOnce();
      expect(sendEmail).not.toHaveBeenCalled();
      expect(redisEval).not.toHaveBeenCalled();
    },
  );

  it("releases the reservation when sends were attempted and every send failed", async () => {
    sendEmail.mockRejectedValue(new Error("SMTP refused"));
    await expect(sendDataDeletedAlert(deletion)).resolves.toBe(0);
    expect(redisEval).toHaveBeenCalledOnce();
    await expect(sendDataDeletedAlert(deletion)).resolves.toBe(0);
    expect(redisEval).toHaveBeenCalledTimes(2);
    expect(redisEval.mock.calls[0]?.slice(2)).toEqual(redisSet.mock.calls[0]?.slice(0, 2));
    expect(redisEval.mock.calls[0]?.[0]).toContain("== ARGV[1]");
  });

  it("keeps the cooldown when the recipient query fails before any sends", async () => {
    db.user.findMany.mockRejectedValueOnce(new Error("DB down"));
    await expect(sendDataDeletedAlert(deletion)).rejects.toMatchObject({ message: "DB down" });
    expect(redisEval).not.toHaveBeenCalled();
  });

  it("counts partial success and renders in each verified opted-in admin's locale", async () => {
    db.user.findMany.mockResolvedValueOnce([
      { id: "a", email: "a@example.com", role: "admin", locale: "es-MX" },
      { id: "b", email: "b@example.com", role: "user, admin ", locale: "en-US" },
      { id: "c", email: "c@example.com", role: "superadmin", locale: "en-US" },
    ]);
    sendEmail.mockRejectedValueOnce(new Error("one failure"));
    await expect(sendDataDeletedAlert(deletion)).resolves.toBe(1);
    expect(sendEmail).toHaveBeenCalledTimes(2);
    expect(sendEmail.mock.calls[0]?.[0].subject).toBe(
      "Se completó la eliminación programada de datos",
    );
    expect(sendEmail.mock.calls[1]?.[0].subject).toBe("Planned data deletion completed");
    expect(redisEval).not.toHaveBeenCalled();
    expect(db.user.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: { emailVerified: true, operationalAlerts: true },
        select: { id: true, email: true, role: true, locale: true },
        take: 50,
      }),
    );
  });

  it("uses each exact migration identity while failure alerts still mask changing numbers", async () => {
    await sendDataDeletedAlert(deletion);
    await sendDataDeletedAlert({ ...deletion, name: "20261102000000_drop_field" });
    expect(redisSet.mock.calls[0]?.[0]).not.toBe(redisSet.mock.calls[1]?.[0]);
    await sendOperationalAlert({ ...alert, message: "error 123" });
    await sendOperationalAlert({ ...alert, message: "error 456" });
    expect(redisSet.mock.calls[2]?.[0]).toBe(redisSet.mock.calls[3]?.[0]);
  });

  it("returns actual successful delivery counts and retries a zero-delivery alert", async () => {
    sendEmail.mockRejectedValueOnce(new Error("SMTP down"));
    await expect(sendOperationalAlert(alert)).resolves.toBe(0);
    await expect(sendOperationalAlert(alert)).resolves.toBe(1);
    expect(redisEval).toHaveBeenCalledOnce();
  });
});

it("cannot release a replacement sender's cooldown token after expiry", async () => {
  redisSet.mockResolvedValue("OK");
  isEmailConfigured.mockReturnValue(true);
  db.user.findMany.mockResolvedValue([
    { id: "a", email: "a@example.com", role: "admin", locale: "en-US" },
  ]);
  let rejectSend!: (error: Error) => void;
  sendEmail.mockImplementationOnce(
    () =>
      new Promise<void>((_resolve, reject) => {
        rejectSend = reject;
      }),
  );
  let currentToken = "replacement-token";
  redisEval.mockImplementation(
    async (script: string, _count: number, _key: string, token: string) => {
      expect(script).toContain("== ARGV[1]");
      if (currentToken === token) currentToken = "";
      return 0;
    },
  );
  const pending = sendOperationalAlert(alert);
  await vi.waitFor(() => expect(rejectSend).toBeTypeOf("function"));
  rejectSend(new Error("wssp_sdk_private-smtp-error"));
  await expect(pending).resolves.toBe(0);
  expect(currentToken).toBe("replacement-token");
  expect(redisEval.mock.lastCall?.slice(2)).toEqual(redisSet.mock.lastCall?.slice(0, 2));
});

it("bounds and advances the admin scan and counts successful sends across pages", async () => {
  isEmailConfigured.mockReturnValue(true);
  redisSet.mockResolvedValue("OK");
  sendEmail.mockReset().mockResolvedValue(undefined);
  const page = Array.from({ length: 50 }, (_, i) => ({
    id: `u${String(i).padStart(2, "0")}`,
    email: `u${i}@example.com`,
    role: "user",
    locale: "en-US",
  }));
  db.user.findMany
    .mockReset()
    .mockResolvedValueOnce(page)
    .mockResolvedValueOnce([
      { id: "u50", email: "admin@example.com", role: " user, admin ", locale: "unknown" },
    ]);
  await expect(sendDataDeletedAlert(deletion)).resolves.toBe(1);
  expect(db.user.findMany.mock.calls[1]?.[0]).toMatchObject({
    where: { emailVerified: true, operationalAlerts: true, id: { gt: "u49" } },
    take: 50,
    select: { id: true, email: true, role: true, locale: true },
  });
  expect(sendEmail).toHaveBeenCalledExactlyOnceWith(
    expect.objectContaining({
      subject: "Planned data deletion completed",
      html: expect.stringContaining('<html lang="en-US">'),
    }),
  );
});
