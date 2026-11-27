import { useEffect, useRef } from "react";

/** Reveal a request failure only after its form controls are enabled again. */
export function useRevealSettledProblem(problem: unknown, pending: boolean, reveal: () => void) {
  const latest = useRef(reveal);
  latest.current = reveal;
  useEffect(() => {
    if (problem && !pending) latest.current();
  }, [problem, pending]);
}
