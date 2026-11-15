import { useEffect, useRef, useState } from "react";
import { authClient } from "@/lib/auth-client";
import type { sdkKeyMintInput } from "@/lib/credential-rules";
import { oauthRedirect } from "@/lib/mcp-oauth";

type ConsentInput = ReturnType<typeof sdkKeyMintInput>;
export function useMcpSubmit() {
  const live = useRef(false);
  const pending = useRef(false);
  const [phase, setPhase] = useState<"review" | "pending" | "failed" | "denied">("review");
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  async function submit(accept: boolean, input?: ConsentInput, offline = false) {
    if (pending.current) return;
    pending.current = true;
    setPhase("pending");
    try {
      // The client plugin adds the original signed oauth_query, including repeated ba_param keys.
      const body =
        accept && input
          ? {
              accept,
              ...input,
              scope: [...input.scopes, ...(offline ? ["offline_access"] : [])].join(" "),
            }
          : { accept };
      const result = await authClient.oauth2.consent(body);
      if (!live.current) return;
      const url = result.error ? null : oauthRedirect(result.data);
      if (url) {
        window.location.assign(url);
        return;
      }
      setPhase(!result.error && !accept ? "denied" : "failed");
    } catch {
      if (live.current) setPhase("failed");
    } finally {
      pending.current = false;
    }
  }
  return { phase, submit };
}
