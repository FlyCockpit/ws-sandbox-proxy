import { type QueryClient, useQuery } from "@tanstack/react-query";
import type { AppRouterClient } from "@wssp/api/routers/index";
import { useTranslation } from "react-i18next";
import type { DefinitionIssue, LoginProblem } from "@/lib/login-rules";
import { orpc } from "@/utils/orpc";

export type LoginItem = Awaited<ReturnType<AppRouterClient["logins"]["getLogin"]>>;
export type DefinitionItem = Awaited<
  ReturnType<AppRouterClient["logins"]["listDefinitions"]>
>["items"][number];
export type AccountItem = Awaited<
  ReturnType<AppRouterClient["logins"]["listAccounts"]>
>["items"][number];
export type InstanceItem = Awaited<
  ReturnType<AppRouterClient["logins"]["listInstances"]>
>["items"][number];

/** Every logins query shares one key prefix; writes refresh them together. */
export function invalidateLogins(queryClient: QueryClient) {
  void queryClient.invalidateQueries({ queryKey: orpc.logins.key() });
}

export type LoginsAvailability = "pending" | "enabled" | "readOnly" | "unavailable";

/**
 * Feature availability: `enabled` allows writes; `readOnly` is drain mode
 * (switched off with the key still present: reads and deletes work, writes
 * refuse); `unavailable` means the server cannot serve logins at all.
 */
export function useLoginsAvailability(): LoginsAvailability {
  const status = useQuery({
    ...orpc.logins.status.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  if (status.isPending) return "pending";
  if (status.data?.enabled) return "enabled";
  if (status.data?.drain) return "readOnly";
  return "unavailable";
}

export function ProblemText({
  problem,
  entry,
  issues,
}: {
  problem: LoginProblem | null;
  entry?: string | null;
  issues?: readonly DefinitionIssue[];
}) {
  const { t } = useTranslation(["logins"]);
  if (!problem) return null;
  return (
    <div role="alert" className="flex min-w-0 flex-col gap-1 text-sm text-destructive">
      <p>
        {problem === "valueInvalid" && entry
          ? t("logins:problem.valueInvalidEntry", { entry })
          : t(`logins:problem.${problem}`)}
      </p>
      {issues && issues.length > 0 ? <DefinitionIssues issues={issues} /> : null}
    </div>
  );
}

/** Parser issues: a field path and the shared parser's technical message. */
export function DefinitionIssues({ issues }: { issues: readonly DefinitionIssue[] }) {
  const { t } = useTranslation(["logins"]);
  return (
    <ul aria-label={t("logins:definitions.issues")} className="flex min-w-0 flex-col gap-1">
      {issues.map((issue, index) => (
        <li key={`${issue.path}-${index}`} className="break-words font-mono text-xs">
          {issue.path ? `${issue.path}: ` : ""}
          {issue.message}
        </li>
      ))}
    </ul>
  );
}

/** "Account 2" when unnamed. */
export function accountLabel(
  t: (key: string, options?: Record<string, unknown>) => string,
  account: Pick<AccountItem, "name" | "ordinal">,
) {
  return account.name ?? t("logins:accounts.unnamed", { ordinal: account.ordinal });
}

/** "Instance 3" when unnamed. */
export function instanceLabel(
  t: (key: string, options?: Record<string, unknown>) => string,
  instance: Pick<InstanceItem, "name" | "ordinal">,
) {
  return instance.name ?? t("logins:instances.unnamed", { ordinal: instance.ordinal });
}
