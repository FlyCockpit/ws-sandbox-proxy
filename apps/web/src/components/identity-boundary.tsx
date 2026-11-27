import { useAccountAwarePage } from "@/hooks/use-identity-boundary-enabled";
import { useReloadOnIdentityChange } from "@/hooks/use-reload-on-identity-change";

/** Kept mounted by the hosted root after the first account-aware page. */
export default function IdentityBoundary() {
  useReloadOnIdentityChange({ showsAccount: useAccountAwarePage() });
  return null;
}
