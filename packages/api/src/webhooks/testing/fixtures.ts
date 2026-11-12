import { randomUUID } from "node:crypto";
import type { Prisma, SandboxState } from "@wssp/db";
import { WEBHOOK_EVENT_TYPES } from "@wssp/sandbox-contracts";

/** Test-only rows for the webhook pg tests. Never used by application IO. */
type Client = Prisma.TransactionClient;

export async function seedOwner(
  client: Client,
  overrides: Partial<Prisma.UserUncheckedCreateInput> = {},
) {
  const id = `user-${randomUUID()}`;
  await client.user.create({
    data: {
      id,
      name: "Owner",
      email: `${id}@example.test`,
      emailVerified: true,
      twoFactorEnabled: true,
      ...overrides,
    },
  });
  return id;
}

async function seedRevision(client: Client, userId: string) {
  const template = await client.sandboxTemplate.create({
    data: { userId, slug: `base-${randomUUID().slice(0, 8)}`, label: "Base" },
  });
  return client.sandboxTemplateRevision.create({
    data: {
      userId,
      templateId: template.id,
      revision: 1,
      incusFingerprint: `sha256:${"b".repeat(64)}`,
      architecture: "x86_64",
      manifestDigest: "b".repeat(64),
    },
    select: { id: true, templateId: true },
  });
}

export async function seedSandbox(
  client: Client,
  userId: string,
  state: SandboxState,
  extra: Partial<Prisma.SandboxUncheckedCreateInput> = {},
) {
  const revision = await seedRevision(client, userId);
  return client.sandbox.create({
    data: {
      userId,
      templateId: revision.templateId,
      templateRevisionId: revision.id,
      originalSelector: `revision/${revision.id}`,
      // A waiting sandbox is hostless (sandbox_instance_waiting check).
      originHostId: state === "WAITING_FOR_CAPACITY" ? null : "host-none",
      state,
      ...extra,
    },
    select: { id: true, templateId: true, templateRevisionId: true },
  });
}

export async function seedEndpoint(
  client: Client,
  userId: string,
  extra: Partial<Prisma.WebhookEndpointUncheckedCreateInput> = {},
) {
  return client.webhookEndpoint.create({
    data: {
      userId,
      url: "https://hooks.example.com/wssp",
      events: [...WEBHOOK_EVENT_TYPES],
      operationKinds: [],
      secretCiphertext: new Uint8Array(32),
      secretNonce: new Uint8Array(12),
      secretKeyId: "0".repeat(16),
      ...extra,
    },
    select: { id: true, createdAt: true },
  });
}
