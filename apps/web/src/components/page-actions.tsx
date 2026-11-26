import { Button } from "@wssp/ui/components/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@wssp/ui/components/dropdown-menu";
import type { LucideIcon } from "lucide-react";
import { MoreHorizontal } from "lucide-react";
import type { ReactNode } from "react";
import { useTranslation } from "react-i18next";

export type OverflowAction = {
  id: string;
  label: string;
  onSelect: () => void;
  icon?: LucideIcon;
  disabled?: boolean;
  /** Destructive actions sit in their own section at the end of the menu. */
  destructive?: boolean;
};

/**
 * The page-header action rule: at most one primary and one secondary action
 * are visible; everything else goes in a "More actions" menu, with
 * destructive actions separated at the end. Wraps as one row group so a long
 * title keeps its own row on narrow and zoomed screens.
 */
export function PageActions({
  primary,
  secondary,
  overflow = [],
  overflowLabel,
}: {
  primary?: ReactNode;
  secondary?: ReactNode;
  overflow?: readonly OverflowAction[];
  /** Accessible name of the menu trigger; defaults to "More actions". */
  overflowLabel?: string;
}) {
  const { t } = useTranslation("common");
  const regular = overflow.filter((action) => !action.destructive);
  const destructive = overflow.filter((action) => action.destructive);
  const label = overflowLabel ?? t("actions.more");
  return (
    <div data-page-actions="" className="flex min-w-0 shrink-0 flex-wrap items-center gap-2">
      {primary}
      {secondary}
      {overflow.length > 0 ? (
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                type="button"
                variant="outline"
                size="icon-touch"
                aria-label={label}
                title={label}
              />
            }
          >
            <MoreHorizontal aria-hidden="true" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-56 bg-card">
            {regular.length > 0 ? (
              <DropdownMenuGroup>
                {regular.map((action) => (
                  <OverflowItem key={action.id} action={action} />
                ))}
              </DropdownMenuGroup>
            ) : null}
            {regular.length > 0 && destructive.length > 0 ? <DropdownMenuSeparator /> : null}
            {destructive.length > 0 ? (
              <DropdownMenuGroup>
                {destructive.map((action) => (
                  <OverflowItem key={action.id} action={action} />
                ))}
              </DropdownMenuGroup>
            ) : null}
          </DropdownMenuContent>
        </DropdownMenu>
      ) : null}
    </div>
  );
}

function OverflowItem({ action }: { action: OverflowAction }) {
  const Icon = action.icon;
  return (
    <DropdownMenuItem
      variant={action.destructive ? "destructive" : "default"}
      disabled={action.disabled}
      data-overflow-action={action.id}
      onClick={action.onSelect}
    >
      {Icon ? <Icon aria-hidden="true" className="size-4" /> : null}
      {action.label}
    </DropdownMenuItem>
  );
}
