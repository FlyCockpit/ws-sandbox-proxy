import { useRouterState } from "@tanstack/react-router";
import { useEffect, useState } from "react";

/** An account-aware (`/$lang/_app`) page is showing, not a public one. */
export function useAccountAwarePage(): boolean {
  return useRouterState({
    select: (state) => state.matches.some((match) => match.routeId.startsWith("/$lang/_app")),
  });
}

/** Start session observation only on account-aware pages, then retain it across public navigation. */
export function useIdentityBoundaryEnabled(): boolean {
  const accountAware = useAccountAwarePage();
  const [started, setStarted] = useState(accountAware);
  useEffect(() => {
    if (accountAware) setStarted(true);
  }, [accountAware]);
  return started || accountAware;
}
