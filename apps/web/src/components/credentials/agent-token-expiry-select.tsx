import type { AgentTokenExpiryPolicy } from "@wssp/config/agent-token-limits";
import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { useId } from "react";
import { useTranslation } from "react-i18next";
import { FormSelect } from "@/components/form-select";
import {
  agentTokenExpiryPresets,
  latestAgentTokenCustomDate,
  localDateInputValue,
} from "@/lib/agent-token-expiry";

export function AgentTokenExpirySelect({
  id,
  policy,
  value,
  onChange,
  customDate,
  onCustomDateChange,
  invalid = false,
}: {
  id: string;
  policy: AgentTokenExpiryPolicy;
  value: string;
  onChange: (value: string) => void;
  customDate: string;
  onCustomDateChange: (value: string) => void;
  /** After a failed submit: the choice is not a future date within the policy. */
  invalid?: boolean;
}) {
  const { t } = useTranslation(["agents", "credentials"]);
  const dateId = useId();
  const limitId = useId();
  const errorId = useId();
  const now = new Date();
  return (
    <div className="flex flex-col gap-2">
      <Label htmlFor={id}>{t("credentials:form.expiry")}</Label>
      <FormSelect
        id={id}
        value={value}
        onValueChange={onChange}
        aria-invalid={(invalid && value !== "custom") || undefined}
        aria-describedby={invalid && value !== "custom" ? errorId : undefined}
      >
        {agentTokenExpiryPresets(policy.maxLifetimeDays).map((preset) => (
          <SelectItem key={preset} value={preset}>
            {t(`credentials:expiry.${preset}`)}
          </SelectItem>
        ))}
        <SelectItem value="custom">{t("agents:expiry.custom")}</SelectItem>
        {policy.allowNoExpiry ? (
          <SelectItem value="never">{t("agents:expiry.never")}</SelectItem>
        ) : null}
      </FormSelect>
      {value === "custom" ? (
        <>
          <Label htmlFor={dateId}>{t("agents:expiry.customDate")}</Label>
          <Input
            id={dateId}
            type="date"
            autoComplete="off"
            className="min-h-11"
            value={customDate}
            min={localDateInputValue(now)}
            max={localDateInputValue(latestAgentTokenCustomDate(now, policy.maxLifetimeDays))}
            aria-invalid={invalid || undefined}
            aria-describedby={invalid ? `${errorId} ${limitId}` : limitId}
            onChange={(event) => onCustomDateChange(event.target.value)}
          />
        </>
      ) : null}
      {invalid ? (
        <p id={errorId} role="alert" className="text-sm text-destructive">
          {t("agents:expiry.invalid")}
        </p>
      ) : null}
      {value === "never" ? (
        <p role="note" className="text-sm text-muted-foreground">
          {t("agents:expiry.warning")}
        </p>
      ) : null}
      {value === "never" ? null : (
        <p id={limitId} className="text-xs text-muted-foreground">
          {t("agents:expiry.limit", { days: policy.maxLifetimeDays })}
        </p>
      )}
    </div>
  );
}
