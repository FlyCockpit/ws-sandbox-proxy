import { useEffect, useRef, useState } from "react";
import { authClient } from "@/lib/auth-client";
import { oauthRedirect } from "@/lib/mcp-oauth";
export function useMcpContinue() {
  const live = useRef(false);
  const pending = useRef(false);
  const [status, setStatus] = useState<"idle" | "pending" | "failed">("idle");
  useEffect(() => {
    live.current = true;
    return () => {
      live.current = false;
    };
  }, []);
  async function proceed() {
    if (pending.current) return;
    pending.current = true;
    setStatus("pending");
    try {
      const result = await authClient.oauth2.continue({ postLogin: true });
      if (!live.current) return;
      const url = result.error ? null : oauthRedirect(result.data);
      if (url) window.location.assign(url);
      else setStatus("failed");
    } catch {
      if (live.current) setStatus("failed");
    } finally {
      pending.current = false;
    }
  }
  return { status, proceed };
}
