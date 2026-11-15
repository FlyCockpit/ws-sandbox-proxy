import { useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { markExplicitSignOut } from "@/hooks/use-reload-on-identity-change";
import { authClient } from "@/lib/auth-client";
import { useOrphanCredentials } from "@/stores/orphan-credentials";

/** A revoked OAuth generation requires a new session, not another Continue. */
export function useMcpReauthenticate(lang: string) {
  const client = useQueryClient();
  const flight = useRef(false);
  const [status, setStatus] = useState<"idle" | "pending" | "failed">("idle");
  async function reauthenticate() {
    if (flight.current) return;
    flight.current = true;
    setStatus("pending");
    const back = `/${lang}/mcp-login${window.location.search}`;
    const undo = markExplicitSignOut();
    try {
      // Keep the signed transaction in redirectTo and suppress OAuth's signout redirect.
      const result = await authClient.signOut({ disableRedirect: true });
      if (result.error) throw result.error;
      client.clear();
      useOrphanCredentials.getState().clear();
      window.location.assign(`/${lang}/login?redirectTo=${encodeURIComponent(back)}`);
    } catch {
      undo();
      setStatus("failed");
    } finally {
      flight.current = false;
    }
  }
  return { status, reauthenticate };
}
