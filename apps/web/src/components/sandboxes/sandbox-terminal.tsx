import { useTranslation } from "react-i18next";
import { TerminalPanel } from "@/components/terminal-panel";
import type { PhotoTarget } from "@/components/terminal-utilities";
import { useSensitiveAccessUnavailable } from "@/hooks/use-sensitive-access-unavailable";

type SandboxTerminalProps = {
  sandboxId: string;
  lang: string;
  available: boolean;
  /** The login page's "Type it for me" text. */
  typeCommand?: string;
  /** Where Utilities › Photo uploads (sandboxes whose files may be written). */
  photo?: PhotoTarget;
};
/** Thin creator-only guest wrapper. Loading xterm still requires explicit attach. */
export function SandboxTerminal(props: SandboxTerminalProps) {
  const unavailable = useSensitiveAccessUnavailable();
  const { t } = useTranslation("sandboxes");
  return unavailable ? (
    <p role="status" data-sensitive-unavailable="">
      {t("sandboxes:sensitiveAccessUnavailable")}
    </p>
  ) : (
    <TerminalPanel {...props} />
  );
}
