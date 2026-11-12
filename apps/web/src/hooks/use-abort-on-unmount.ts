import { useCallback, useEffect, useRef } from "react";

/**
 * Hands out AbortControllers that are aborted when the component unmounts,
 * so a long browser transfer never keeps running (and holding a server
 * transfer slot) after the user navigates away. `next()` also aborts the
 * previous controller: one transfer per owner of the hook.
 */
export function useAbortOnUnmount() {
  const current = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      current.current?.abort();
    },
    [],
  );
  return useCallback(() => {
    current.current?.abort();
    current.current = new AbortController();
    return current.current;
  }, []);
}
