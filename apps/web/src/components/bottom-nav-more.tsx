import { Link } from "@tanstack/react-router";
import { buttonVariants } from "@wssp/ui/components/button";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@wssp/ui/components/sheet";
import { cn } from "@wssp/ui/lib/utils";
import { useTranslation } from "react-i18next";

import { type AppNavId, type AppNavItem, toLangRoute } from "@/lib/nav-items";

/**
 * The phone bottom bar's More sheet: every sidebar section that is not a tab
 * (Hosts, and Admin for admins). Lazy-loaded by `bottom-nav.tsx` on the first
 * press of More so the Base UI overlay chunk stays off the eager bundle.
 */
export default function BottomNavMore({
  open,
  onOpenChange,
  items,
  lang,
  active,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  items: readonly AppNavItem[];
  lang: string;
  active: AppNavId | null;
}) {
  const { t } = useTranslation(["nav", "common"]);
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent
        side="bottom"
        closeLabel={t("common:actions.close")}
        className="max-h-[85dvh] overflow-x-hidden overflow-y-auto"
        style={{ paddingBottom: "var(--safe-area-bottom)" }}
      >
        <SheetHeader>
          <SheetTitle>{t("nav:items.more")}</SheetTitle>
        </SheetHeader>
        <nav aria-label={t("nav:items.more")} className="flex flex-col gap-1 px-4 pb-4">
          {items.map((item) => (
            <Link
              key={item.id}
              to={toLangRoute(item.path)}
              params={{ lang }}
              activeOptions={{ exact: item.exact }}
              data-nav-id={item.id}
              data-active={item.id === active ? "true" : undefined}
              onClick={() => onOpenChange(false)}
              className={cn(
                buttonVariants({ variant: "ghost", size: "touch" }),
                "justify-start gap-3 text-sm",
                item.id === active ? "bg-muted text-foreground" : "text-muted-foreground",
              )}
            >
              <item.icon aria-hidden="true" className="size-4 shrink-0" />
              <span className="min-w-0 truncate">{t(item.labelKey)}</span>
            </Link>
          ))}
        </nav>
      </SheetContent>
    </Sheet>
  );
}
