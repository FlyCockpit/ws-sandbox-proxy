import { useQueryClient } from "@tanstack/react-query";
import { orpc } from "@/utils/orpc";

/**
 * Everything that reads the account image policy, refetched after a save
 * from either settings card. `sandboxPools.hostPolicy` carries the member's
 * own "Run my builds on other people's builder hosts", and the build
 * pre-flight disables Build on it, so a stale copy would keep a now-valid
 * build blocked (e2e5-fups Codex r1).
 */
export function useImagePolicySaved(): () => void {
  const queryClient = useQueryClient();
  return () => {
    for (const queryKey of [
      orpc.settings.imagePolicy.key(),
      orpc.templateBuilds.usage.key(),
      orpc.sandboxPools.hostPolicy.key(),
    ])
      void queryClient.invalidateQueries({ queryKey });
  };
}
