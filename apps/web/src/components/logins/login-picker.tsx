import { skipToken, useInfiniteQuery } from "@tanstack/react-query";
import { Button } from "@wssp/ui/components/button";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { X } from "lucide-react";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import { LoadMore } from "@/components/load-more";
import { accountLabel, instanceLabel } from "@/components/logins/logins-shared";
import { translateText } from "@/i18n/translate-text";
import { orpc } from "@/utils/orpc";

/**
 * A login choice: the login, plus an optional account and instance ("Any
 * available" when empty). Naming an account or instance is a one-shot hint
 * for this create or attach only; the server decides availability.
 */
export type LoginChoice = { credentialId: string; accountId: string; instanceId: string };

/** At most this many logins per sandbox (the server's cap). */
const MAX_SANDBOX_LOGINS = 8;

export const EMPTY_LOGIN_CHOICE: LoginChoice = { credentialId: "", accountId: "", instanceId: "" };

/** The request row for a choice (empty account/instance are omitted). */
export function loginRequest(choice: LoginChoice) {
  return {
    credentialId: choice.credentialId,
    ...(choice.accountId ? { accountId: choice.accountId } : {}),
    ...(choice.instanceId ? { instanceId: choice.instanceId } : {}),
  };
}

const PICKER_LIMIT = 100;
const pages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

/** One login with its optional account and instance pickers. */
export function LoginChoiceFields({
  value,
  onChange,
  exclude = [],
  disabled,
}: {
  value: LoginChoice;
  onChange: (next: LoginChoice) => void;
  /** Logins already chosen elsewhere (each login once per sandbox). */
  exclude?: readonly string[];
  disabled?: boolean;
}) {
  const { t } = useTranslation(["logins"]);
  const loginId = useId();
  const accountId = useId();
  const instanceId = useId();
  const logins = useInfiniteQuery({
    ...orpc.logins.listLogins.infiniteOptions({
      ...pages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const accounts = useInfiniteQuery({
    ...orpc.logins.listAccounts.infiniteOptions({
      ...pages,
      input: value.credentialId
        ? (cursor: string | undefined) => ({
            credentialId: value.credentialId,
            limit: PICKER_LIMIT,
            cursor,
          })
        : skipToken,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const instances = useInfiniteQuery({
    ...orpc.logins.listInstances.infiniteOptions({
      ...pages,
      input:
        value.credentialId && value.accountId
          ? (cursor: string | undefined) => ({
              credentialId: value.credentialId,
              accountId: value.accountId,
              limit: PICKER_LIMIT,
              cursor,
            })
          : skipToken,
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const loginRows = (logins.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (login) => login.id === value.credentialId || !exclude.includes(login.id),
  );
  const accountRows = accounts.data?.pages.flatMap((page) => page.items) ?? [];
  const instanceRows = instances.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <div className="flex min-w-0 flex-col gap-2" data-login-choice="">
      <Label htmlFor={loginId}>{t("logins:picker.login")}</Label>
      <FormSelect
        id={loginId}
        autoComplete="off"
        disabled={disabled}
        optionsSettled={logins.isSuccess && !logins.isFetching && !logins.hasNextPage}
        value={value.credentialId}
        onValueChange={(next) => onChange({ credentialId: next, accountId: "", instanceId: "" })}
      >
        <SelectItem value="">{t("logins:picker.chooseLogin")}</SelectItem>
        {loginRows.map((login) => (
          <SelectItem key={login.id} value={login.id}>
            {login.name}
          </SelectItem>
        ))}
      </FormSelect>
      <LoadMore
        hasNextPage={logins.hasNextPage}
        isFetchingNextPage={logins.isFetchingNextPage}
        onLoadMore={() => void logins.fetchNextPage()}
      />
      {value.credentialId ? (
        <>
          <Label htmlFor={accountId}>{t("logins:picker.account")}</Label>
          <FormSelect
            id={accountId}
            autoComplete="off"
            disabled={disabled}
            optionsSettled={accounts.isSuccess && !accounts.isFetching && !accounts.hasNextPage}
            value={value.accountId}
            onValueChange={(next) => onChange({ ...value, accountId: next, instanceId: "" })}
          >
            <SelectItem value="">{t("logins:picker.any")}</SelectItem>
            {accountRows.map((account) => (
              <SelectItem key={account.id} value={account.id}>
                {account.paused
                  ? translateText(t, "logins:picker.paused", { name: accountLabel(t, account) })
                  : accountLabel(t, account)}
              </SelectItem>
            ))}
          </FormSelect>
          <LoadMore
            hasNextPage={accounts.hasNextPage}
            isFetchingNextPage={accounts.isFetchingNextPage}
            onLoadMore={() => void accounts.fetchNextPage()}
          />
        </>
      ) : null}
      {value.accountId ? (
        <>
          <Label htmlFor={instanceId}>{t("logins:picker.instance")}</Label>
          <FormSelect
            id={instanceId}
            autoComplete="off"
            disabled={disabled}
            optionsSettled={instances.isSuccess && !instances.isFetching && !instances.hasNextPage}
            value={value.instanceId}
            onValueChange={(next) => onChange({ ...value, instanceId: next })}
          >
            <SelectItem value="">{t("logins:picker.any")}</SelectItem>
            {instanceRows.map((instance) => (
              <SelectItem key={instance.id} value={instance.id}>
                {translateText(t, "logins:picker.instanceOption", {
                  name: instanceLabel(t, instance),
                  state: t(`logins:instances.state.${instance.state}`),
                })}
              </SelectItem>
            ))}
          </FormSelect>
          <LoadMore
            hasNextPage={instances.hasNextPage}
            isFetchingNextPage={instances.isFetchingNextPage}
            onLoadMore={() => void instances.fetchNextPage()}
          />
        </>
      ) : null}
      {value.accountId || value.instanceId ? (
        <p className="text-xs text-muted-foreground">{t("logins:picker.oneShot")}</p>
      ) : null}
    </div>
  );
}

/** Up to eight login choices for a new sandbox. */
export function LoginsPicker({
  value,
  onChange,
  disabled,
}: {
  value: readonly LoginChoice[];
  onChange: (next: LoginChoice[]) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation(["logins"]);
  const chosen = value.map((choice) => choice.credentialId).filter(Boolean);
  return (
    <fieldset className="flex min-w-0 flex-col gap-3" disabled={disabled} data-logins-picker="">
      <legend className="mb-1 text-sm font-medium">{t("logins:picker.heading")}</legend>
      <p className="text-xs text-muted-foreground">{t("logins:picker.hint")}</p>
      <p className="text-xs text-muted-foreground" data-proxy-note="">
        {t("logins:picker.proxyNote")}
      </p>
      {value.map((choice, index) => (
        <div
          // Rows have no identity until a login is chosen; position is the key.
          key={index}
          className="flex min-w-0 flex-col gap-2 rounded-lg border p-3"
        >
          <LoginChoiceFields
            value={choice}
            exclude={chosen.filter((id) => id !== choice.credentialId)}
            disabled={disabled}
            onChange={(next) => onChange(value.map((row, i) => (i === index ? next : row)))}
          />
          <Button
            type="button"
            size="touch"
            variant="outline"
            className="self-start"
            onClick={() => onChange(value.filter((_, i) => i !== index))}
          >
            <X aria-hidden="true" className="size-4" />
            {t("logins:picker.remove")}
          </Button>
        </div>
      ))}
      {value.length < MAX_SANDBOX_LOGINS ? (
        <Button
          type="button"
          size="touch"
          variant="outline"
          className="self-start"
          onClick={() => onChange([...value, EMPTY_LOGIN_CHOICE])}
        >
          {t("logins:picker.add")}
        </Button>
      ) : (
        <p className="text-xs text-muted-foreground">
          {t("logins:picker.max", { max: MAX_SANDBOX_LOGINS })}
        </p>
      )}
    </fieldset>
  );
}
