import { useEffect, useRef, useState } from "react";

/** A durable loss deadline clearing is the server's restoration signal, never an IO grant. */
export function useSharingRestoration(sandboxId: string, deadline: Date | string | null) {
  const previous = useRef<{ id: string; lost: boolean } | null>(null);
  const [restoredId, setRestoredId] = useState<string | null>(null);
  const lost = deadline != null;
  useEffect(() => {
    if (previous.current?.id === sandboxId && previous.current.lost && !lost)
      setRestoredId(sandboxId);
    else if (lost) setRestoredId(null);
    previous.current = { id: sandboxId, lost };
  }, [sandboxId, lost]);
  return !lost && restoredId === sandboxId;
}
