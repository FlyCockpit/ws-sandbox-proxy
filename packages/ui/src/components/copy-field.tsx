import { Button } from "@wssp/ui/components/button";
import { useCopyToClipboard } from "@wssp/ui/hooks/use-copy-to-clipboard";
import { edgeAttributes, useScrollEdges } from "@wssp/ui/hooks/use-scroll-edges";
import { cn } from "@wssp/ui/lib/utils";
import { Check, Copy } from "lucide-react";
import * as React from "react";

type CopyFieldProps = React.ComponentProps<"div"> & {
  /** The text placed on the clipboard (and rendered, single-line). */
  value: string;
  /** Rendered instead of `value` (e.g. a shortened ID); the full `value` is still copied. */
  displayValue?: string;
  /**
   * aria-label for the copy button. The default is accessibility text (the
   * allowed hardcoded-string exception) — pass a translated string where the
   * call site has one.
   */
  copyLabel?: string;
  /** Fired after a successful copy — wire toasts at the call site. */
  onCopied?: () => void;
  /** Fired when both the async clipboard API and the fallback fail. */
  onCopyError?: () => void;
};

/**
 * Single-line copyable value (shell command, API key, URL) with a copy
 * button in its own 44px column beside (never over) it. The layout contract
 * is baked in: the value region scrolls itself horizontally
 * (`min-w-0 overflow-x-auto`), never the page, so it is safe inside
 * `DialogContent` by default; a long value fades out at the edge that has
 * more to scroll (`edge-fade-x`). The border sits on the outer box, not on
 * the masked scroller, so the fade dims text and never the outline. Code text
 * is `font-mono text-xs leading-5`, the same as `CodeSnippet`
 * (docs/design/shell-rules.md).
 */
function CopyField({
  value,
  displayValue,
  copyLabel = "Copy value",
  onCopied,
  onCopyError,
  className,
  ...props
}: CopyFieldProps) {
  const { copied, copy } = useCopyToClipboard();
  const valueRef = React.useRef<HTMLElement>(null);
  const shown = displayValue ?? value;
  const edges = useScrollEdges(valueRef, shown);

  return (
    <div
      data-slot="copy-field"
      className={cn(
        "flex min-w-0 max-w-full items-center gap-2 rounded-lg border bg-muted/50 p-1",
        className,
      )}
      {...props}
    >
      <code
        ref={valueRef}
        data-slot="copy-field-value"
        {...edgeAttributes(edges)}
        className="min-w-0 flex-1 overflow-x-auto overscroll-x-contain no-scrollbar edge-fade-x px-2.5 py-1.5 font-mono text-xs leading-5 whitespace-nowrap"
        title={displayValue !== undefined && displayValue !== value ? value : undefined}
      >
        {shown}
      </code>
      <Button
        type="button"
        variant="ghost"
        size="icon-sm"
        className="min-h-[44px] min-w-[44px] shrink-0"
        aria-label={copyLabel}
        disabled={!value}
        onClick={async () => {
          if (await copy(value)) onCopied?.();
          else onCopyError?.();
        }}
      >
        {copied ? (
          <Check aria-hidden="true" className="size-4" />
        ) : (
          <Copy aria-hidden="true" className="size-4" />
        )}
      </Button>
    </div>
  );
}

export { CopyField };
