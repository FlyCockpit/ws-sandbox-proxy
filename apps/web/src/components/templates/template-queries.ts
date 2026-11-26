import type { QueryClient } from "@tanstack/react-query";
import { orpc } from "@/utils/orpc";

/** Every template read a register, archive or version change can alter. */
export function invalidateTemplates(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listTemplates.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisions.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listAvailability.key() });
  void queryClient.invalidateQueries({ queryKey: orpc.sandboxTemplates.listRevisionChoices.key() });
}
