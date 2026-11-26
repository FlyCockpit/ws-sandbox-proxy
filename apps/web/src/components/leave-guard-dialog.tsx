import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@wssp/ui/components/alert-dialog";
import { useTranslation } from "react-i18next";
import { useLeaveGuard } from "@/hooks/use-leave-guard";

/**
 * While `active`, leaving the page (a link, Back, Cancel, or closing the tab)
 * asks first: "stay" keeps the page as it is, "leave" goes on.
 */
export function LeaveGuardDialog({
  active,
  title,
  description,
  stayLabel,
  leaveLabel,
}: {
  active: boolean;
  title: string;
  description: string;
  stayLabel: string;
  leaveLabel: string;
}) {
  const guard = useLeaveGuard(active);
  return (
    <AlertDialog
      open={guard.blocked}
      onOpenChange={(open) => {
        if (!open) guard.stay();
      }}
    >
      <AlertDialogContent className="max-w-[calc(100%-2rem)]! sm:max-w-md! data-[size=default]:max-w-[calc(100%-2rem)]! data-[size=default]:sm:max-w-md! data-[size=sm]:max-w-[calc(100%-2rem)]!">
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter className="sm:flex-wrap">
          <AlertDialogCancel className="min-h-[44px] w-full sm:w-auto">
            {stayLabel}
          </AlertDialogCancel>
          <AlertDialogAction
            variant="destructive"
            className="min-h-[44px] w-full sm:w-auto"
            onClick={guard.leave}
          >
            {leaveLabel}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** A form page with input not yet submitted asks before that input is thrown away. */
export function UnsavedChangesGuard({ active }: { active: boolean }) {
  const { t } = useTranslation("common");
  return (
    <LeaveGuardDialog
      active={active}
      title={t("form.leave.title")}
      description={t("form.leave.description")}
      stayLabel={t("form.leave.stay")}
      leaveLabel={t("form.leave.leave")}
    />
  );
}
