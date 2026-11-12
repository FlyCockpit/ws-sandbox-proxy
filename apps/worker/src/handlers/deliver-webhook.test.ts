import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  run: vi.fn(),
  findUnique: vi.fn(),
  send: vi.fn(),
  configured: true,
}));
vi.mock("@wssp/api/webhooks/deliver", () => ({ runDeliveryJob: state.run }));
vi.mock("@wssp/queue", async () => await import("@wssp/queue/jobs"));
vi.mock("@wssp/db", () => ({ default: { user: { findUnique: state.findUnique } } }));
vi.mock("@wssp/mailer", () => ({
  isEmailConfigured: () => state.configured,
  sendEmail: state.send,
  // The real template is covered in packages/mailer; host-only input is what matters here.
  renderWebhookEndpointDisabled: (args: { host: string; consecutiveFailures: number }) => ({
    subject: "Webhook endpoint disabled",
    html: `<p>${args.host} ${args.consecutiveFailures}</p>`,
  }),
}));

const { createDeliverWebhookHandler, notifyWebhookEndpointDisabled } = await import(
  "./deliver-webhook"
);

beforeEach(() => {
  vi.clearAllMocks();
  state.configured = true;
});

describe("webhook delivery handler (unit; ledger paths: webhook-ledger.pg.test.ts)", () => {
  it("validates ids-only job data and delegates to the ledger runner", async () => {
    state.run.mockResolvedValue({ outcome: "SUCCEEDED", errorClass: null, statusCode: 204 });
    const enqueue = vi.fn();
    const handler = createDeliverWebhookHandler({ config: null, enqueue });
    await expect(handler({ data: { deliveryId: "d1", attempt: 1, seq: 2 } })).resolves.toEqual({
      outcome: "SUCCEEDED",
      errorClass: null,
      statusCode: 204,
    });
    expect(state.run).toHaveBeenCalledWith(
      { deliveryId: "d1", attempt: 1, seq: 2 },
      expect.objectContaining({ config: null, enqueue }),
    );
    await expect(
      handler({ data: { deliveryId: "d1", attempt: 1, seq: 2, url: "https://x" } as never }),
    ).resolves.toBeDefined();
    await expect(handler({ data: { deliveryId: "bad id", attempt: 0, seq: 0 } })).rejects.toThrow();
  });

  it("emails the owner the destination host only, and only when email is configured", async () => {
    state.findUnique.mockResolvedValue({
      email: "o@example.test",
      locale: "es-MX",
      emailVerified: true,
    });
    await notifyWebhookEndpointDisabled({
      userId: "u1",
      host: "hooks.example.com",
      consecutiveFailures: 20,
    });
    expect(state.send).toHaveBeenCalledOnce();
    const mail = state.send.mock.calls[0]?.[0] as { to: string; html: string };
    expect(mail.to).toBe("o@example.test");
    expect(mail.html).toContain("hooks.example.com");
    state.configured = false;
    await notifyWebhookEndpointDisabled({ userId: "u1", host: "h", consecutiveFailures: 20 });
    expect(state.send).toHaveBeenCalledOnce();
  });
});
