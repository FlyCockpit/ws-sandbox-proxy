import { useAuthSession } from "./use-auth-session";

/** UI hint only. Durable server gates remain authoritative on every IO boundary. */
export function useSensitiveAccessUnavailable(): boolean {
  const { state } = useAuthSession();
  return state.status === "authenticated" && state.session.session.impersonatedBy != null;
}
