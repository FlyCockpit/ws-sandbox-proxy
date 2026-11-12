import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@wssp/ui/components/select";
import { cn } from "@wssp/ui/lib/utils";
import { Children, type ComponentProps, isValidElement, type ReactNode } from "react";
import { useTranslation } from "react-i18next";

type FormSelectProps = Omit<
  ComponentProps<typeof SelectTrigger>,
  "children" | "value" | "onChange"
> & {
  value: string;
  /** True only after discovery succeeds, finishes fetching, and exhausts its pages. */
  optionsSettled?: boolean;
  /** Shown while nothing is chosen (an empty value with no matching option). */
  placeholder?: string;
  onValueChange: (value: string) => void;
  children: ReactNode;
  name?: string;
  autoComplete?: string;
};

/** A labeled, controlled form select with the same label before its popup first opens. */
export function FormSelect({
  value,
  optionsSettled = true,
  placeholder,
  onValueChange,
  children,
  name,
  autoComplete = "off",
  disabled,
  className,
  ...triggerProps
}: FormSelectProps) {
  const { t } = useTranslation("common");
  const items = Children.toArray(children).flatMap((child) =>
    isValidElement<ComponentProps<typeof SelectItem>>(child) && child.type === SelectItem
      ? [{ value: child.props.value, label: child.props.children }]
      : [],
  );

  return (
    <Select
      value={value}
      onValueChange={(next, details) => {
        // A query refresh can remove an option while the draft still owns its
        // value (including an uncertain create awaiting an exact retry). Native
        // selects never changed React form state here. Cancel Base UI's internal
        // reconciliation only for a missing value. Closed-trigger typeahead uses
        // the same event signature while the current value is still present.
        if (
          details.reason === "none" &&
          details.event.type === "base-ui" &&
          !items.some((item) => item.value === value)
        ) {
          details.cancel();
          return;
        }
        if (next !== null) onValueChange(next);
      }}
      items={items}
      name={name}
      autoComplete={autoComplete}
      disabled={disabled}
    >
      <SelectTrigger
        {...triggerProps}
        disabled={disabled}
        size="touch"
        className={cn("w-full min-w-0 text-sm", className)}
      >
        <SelectValue>
          {items.some((item) => item.value === value)
            ? undefined
            : value === "" && placeholder !== undefined
              ? placeholder
              : t(optionsSettled ? "optionUnavailable" : "selectedOption")}
        </SelectValue>
      </SelectTrigger>
      <SelectContent align="start" alignItemWithTrigger={false}>
        {children}
      </SelectContent>
    </Select>
  );
}
