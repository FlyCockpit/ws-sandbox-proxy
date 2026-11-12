import { skipToken, useQuery } from "@tanstack/react-query";
import { orpc } from "@/utils/orpc";

/** Closed UI classifications: never render arbitrary server error text. */
export function observationProblem(error: unknown) {
  const shape =
    error && typeof error === "object"
      ? (error as {
          code?: unknown;
          status?: unknown;
          data?: { code?: unknown };
        })
      : {};
  const code = shape.data?.code ?? shape.code;
  if (
    shape.status === 410 ||
    code === "OPERATION_RESULT_EXPIRED" ||
    code === "COMMAND_OUTPUT_EXPIRED" ||
    code === "OUTPUT_EXPIRED"
  )
    return "expired";
  if (code === "OPERATION_RESULT_NOT_READY") return "pending";
  if (
    code === "UNAUTHORIZED" ||
    code === "FORBIDDEN" ||
    shape.status === 401 ||
    shape.status === 403
  )
    return "unavailable";
  if (code === "UNSUPPORTED_CAPABILITY" || code === "unsupported_capability") return "unsupported";
  if (code === "signal_unsupported_on_guest") return "signalUnsupported";
  if (code === "sandbox.process_exited" || code === "process_exited") return "processExited";
  if (code === "sandbox.process_cancel_pending" || code === "process_cancel_pending")
    return "cancelPending";
  if (code === "sandbox.process_not_started" || code === "process_not_started")
    return "processNotStarted";
  if (code === "sandbox.process_unavailable") return "processUnavailable";
  if (code === "sandbox.process_not_found" || code === "process_not_found") return "processMissing";
  if (
    code === "sandbox.process_stale" ||
    code === "process_stale" ||
    code === "RESULT_CURSOR_STALE"
  )
    return "stale";
  if (code === "sandbox.process_unknown_outcome" || code === "unknown_outcome") return "unknown";
  if (code === "TOO_MANY_REQUESTS" || shape.status === 429) return "rateLimited";
  return "failed";
}

/** Poll only this accepted observation. A next page/refresh is an explicit new action. */
export function useSandboxObservation(operationId: string | null) {
  return useQuery({
    ...orpc.sandboxes.getOperationResult.queryOptions({
      input: operationId ? { operationId } : skipToken,
    }),
    retry: false,
    gcTime: 0,
    staleTime: 0,
    refetchOnWindowFocus: false,
    refetchInterval: (query) => {
      if (query.state.status === "error")
        return observationProblem(query.state.error) === "pending" ? 2_000 : false;
      return query.state.data?.outcome === "pending" || !query.state.data ? 2_000 : false;
    },
    meta: { skipGlobalErrorToast: true },
  });
}
