import { CopyField } from "@wssp/ui/components/copy-field";
import { cn } from "@wssp/ui/lib/utils";
import { useTranslation } from "react-i18next";

const SHA256 = /^(sha256:)?([0-9a-f]{64})$/i;

/**
 * The short form of an opaque identifier: `sha256:` plus 12 hex for digests
 * and fingerprints, 8 characters plus "…" for anything longer than 12.
 */
export function shortId(value: string): string {
  const digest = SHA256.exec(value);
  if (digest) return `${digest[1] ?? ""}${digest[2]!.slice(0, 12)}…`;
  return value.length > 12 ? `${value.slice(0, 8)}…` : value;
}

/**
 * An opaque ID (UUID, cuid, digest) shown short, with the full value in the
 * tooltip and on the clipboard. `label` names what is copied ("Sandbox ID"),
 * already translated; the 44px copy button reads "Copy <label>".
 */
export function CopyableId({
  value,
  label,
  className,
}: {
  value: string;
  label: string;
  className?: string;
}) {
  const { t } = useTranslation("common");
  return (
    <CopyField
      data-copyable-id=""
      value={value}
      displayValue={shortId(value)}
      copyLabel={t("copyableId.copy", { label })}
      className={cn("w-fit max-w-full", className)}
    />
  );
}
