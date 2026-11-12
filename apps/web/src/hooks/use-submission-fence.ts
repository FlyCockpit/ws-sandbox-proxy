import { useCallback, useEffect, useRef } from "react";

/**
 * Generation fence for a submit handler that awaits before it acts. `begin()`
 * starts a submission and returns its `isCurrent` check; a later `begin()`,
 * `cancel()` (the user closed the form) or unmount makes every earlier check
 * false, so a continuation that resumes afterwards does nothing.
 */
export function useSubmissionFence() {
  const generation = useRef(0);
  useEffect(
    () => () => {
      generation.current += 1;
    },
    [],
  );
  const begin = useCallback(() => {
    generation.current += 1;
    const mine = generation.current;
    return () => generation.current === mine;
  }, []);
  const cancel = useCallback(() => {
    generation.current += 1;
  }, []);
  return { begin, cancel };
}
