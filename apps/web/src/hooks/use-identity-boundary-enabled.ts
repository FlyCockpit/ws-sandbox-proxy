import { useRouterState } from "@tanstack/react-router";
import { useEffect, useState } from "react";

/** Start session observation only on account-aware pages, then retain it across public navigation. */
export function useIdentityBoundaryEnabled(): boolean {
  const accountAware = useRouterState({
    select: (state) => state.matches.some((match) => match.routeId.startsWith("/$lang/_app")),
  });
  const [started, setStarted] = useState(accountAware);
  useEffect(() => {
    if (accountAware) setStarted(true);
  }, [accountAware]);
  return started || accountAware;
}
