import { useRef, useState } from "react";
import { signOutAndLeave } from "@/lib/explicit-sign-out";

/** A revoked OAuth generation requires a new session, not another Continue. */
export function useMcpReauthenticate(lang: string) {
  const flight = useRef(false);
  const [status, setStatus] = useState<"idle" | "pending" | "failed">("idle");
  async function reauthenticate() {
    if (flight.current) return;
    flight.current = true;
    setStatus("pending");
    const back = `/${lang}/mcp-login${window.location.search}`;
    try {
      // Keep the signed transaction in redirectTo and suppress OAuth's signout
      // redirect; success full-loads login as a quarantined new document.
      const result = await signOutAndLeave(
        `/${lang}/login?redirectTo=${encodeURIComponent(back)}`,
        { disableRedirect: true },
      );
      if (!result.ok) setStatus("failed");
    } finally {
      flight.current = false;
    }
  }
  return { status, reauthenticate };
}
