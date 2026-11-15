import { expect, it, vi } from "vitest";

const calls = vi.hoisted(
  () =>
    [] as {
      keyPrefix: string;
      points: number;
      durationSeconds: number;
      failClosed: boolean;
      redactErrors: boolean;
    }[],
);
vi.mock("@wssp/api/lib/procedure-budget", () => ({
  createProcedureBudget: (options: (typeof calls)[number]) => {
    calls.push(options);
    return vi.fn();
  },
}));

import {
  consumeMcpCreateQuota,
  consumeMcpCredentialQuota,
  consumeMcpHostCommandQuota,
  consumeMcpIpQuota,
} from "./mcp-rate-limit";

it("uses separate replica-wide fail-closed IP, credential and spend budgets", () => {
  expect([
    consumeMcpIpQuota,
    consumeMcpCredentialQuota,
    consumeMcpCreateQuota,
    consumeMcpHostCommandQuota,
  ]).toHaveLength(4);
  expect(calls).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ keyPrefix: "mcp:ip", points: 300 }),
      expect.objectContaining({ keyPrefix: "mcp:credential", points: 120 }),
      expect.objectContaining({ keyPrefix: "mcp:create", points: 30 }),
      expect.objectContaining({ keyPrefix: "mcp:host-command", points: 30 }),
    ]),
  );
  for (const options of calls)
    expect(options).toMatchObject({ durationSeconds: 60, failClosed: true, redactErrors: true });
});
