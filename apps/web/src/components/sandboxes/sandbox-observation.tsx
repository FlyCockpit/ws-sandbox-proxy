import { Skeleton } from "@wssp/ui/components/skeleton";
import { useTranslation } from "react-i18next";
import { SkeletonList } from "@/components/skeleton-list";
import { observationProblem } from "@/hooks/use-sandbox-observation";

export function ObservationNotice({
  state,
  list = false,
}: {
  state: string;
  list?: boolean | "files";
}) {
  const { t } = useTranslation(["sandboxes"]);
  return (
    <div role="status" data-observation-state={state} className="text-sm text-muted-foreground">
      {state === "pending" && list ? (
        list === "files" ? (
          <ul className="mb-2 flex min-w-0 flex-col gap-2" aria-hidden="true">
            {[0, 1].map((row) => (
              <li key={row} className="flex flex-wrap items-center gap-3 rounded-lg border p-3">
                <Skeleton className="h-11 w-40 max-w-full" />
                <Skeleton className="h-5 w-12" />
                <Skeleton className="h-11 w-32" />
              </li>
            ))}
          </ul>
        ) : (
          <SkeletonList count={2} className="mb-2 rounded-lg border" layout="resource" />
        )
      ) : null}
      {t(`sandboxes:observations.${state}`)}
    </div>
  );
}

export function ObservationError({ error }: { error: unknown }) {
  return <ObservationNotice state={observationProblem(error)} />;
}
