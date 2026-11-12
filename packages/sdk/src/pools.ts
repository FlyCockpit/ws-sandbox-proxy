import { cursorSchema, PAGE_SIZE_MAX } from "@wssp/sandbox-contracts";
import { z } from "zod";
import { WsspError } from "./errors";
import { type WaitOptions, waitTimeout } from "./polling";
import type { RouteResponse, WsspTransport } from "./transport";

const page = z
  .object({
    limit: z.number().int().min(1).max(PAGE_SIZE_MAX).optional(),
    cursor: cursorSchema.optional(),
  })
  .strict();
export type PoolPageOptions = z.input<typeof page>;
function wire(input: PoolPageOptions = {}) {
  const parsed = page.safeParse(input);
  if (!parsed.success)
    throw new WsspError({ kind: "invalid_request", message: "Invalid pool page options." });
  return { ...parsed.data, limit: parsed.data.limit?.toString() };
}
export type PoolsApi = {
  list(query?: PoolPageOptions, options?: WaitOptions): Promise<RouteResponse<"listPools">>;
  get(id: string, options?: WaitOptions): Promise<RouteResponse<"getPool">>;
  members(
    id: string,
    query?: PoolPageOptions,
    options?: WaitOptions,
  ): Promise<RouteResponse<"listPoolMembers">>;
  /**
   * What this caller could place now: schedulable aggregates (pool-usable,
   * member-capped), how many of a template/size fit, lease limits and the
   * queue. `hosts` lists only your OWN member hosts (needs hosts:read).
   */
  capacity(
    id: string,
    query?: PoolCapacityQuery,
    options?: WaitOptions,
  ): Promise<RouteResponse<"getPoolCapacity">>;
};
export type PoolCapacityQuery = {
  template?: string;
  cpuCount?: number;
  memoryMiB?: number;
  diskGiB?: number;
};
function capacityWire(query: PoolCapacityQuery = {}) {
  const out: Record<string, string> = {};
  if (query.template !== undefined) out.template = query.template;
  for (const field of ["cpuCount", "memoryMiB", "diskGiB"] as const) {
    const value = query[field];
    if (value === undefined) continue;
    if (!Number.isSafeInteger(value) || value < 1)
      throw new WsspError({ kind: "invalid_request", message: `Invalid capacity ${field}.` });
    out[field] = String(value);
  }
  return out;
}
export function createPoolsApi(transport: WsspTransport): PoolsApi {
  return {
    list: (query, options) =>
      transport.request("listPools", {
        query: wire(query),
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
    get: (id, options) =>
      transport.request("getPool", {
        params: { id },
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
    members: (id, query, options) =>
      transport.request("listPoolMembers", {
        params: { id },
        query: wire(query),
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
    capacity: (id, query, options) =>
      transport.request("getPoolCapacity", {
        params: { id },
        query: capacityWire(query),
        signal: options?.signal,
        timeoutMs: waitTimeout(options),
      }),
  };
}
