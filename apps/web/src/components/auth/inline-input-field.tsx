import { Input } from "@wssp/ui/components/input";
import { Label } from "@wssp/ui/components/label";
import { FieldError } from "@wssp/ui/components/text-field";
import type { ComponentProps, ReactNode, Ref } from "react";

type InputProps = Omit<
  ComponentProps<typeof Input>,
  "id" | "ref" | "aria-invalid" | "aria-describedby" | "autoComplete"
> & {
  /** Required, as on `TextField`: autofill and password managers depend on it. */
  autoComplete: NonNullable<ComponentProps<typeof Input>["autoComplete"]>;
};

/**
 * A labelled input for the auth steps that are not TanStack forms (2FA codes,
 * password confirmations). Its error sits right under it (`role="alert"`),
 * wired with `aria-invalid` and `aria-describedby`; callers move focus to it
 * through `inputRef` when a submit fails.
 */
export function InlineInputField({
  id,
  label,
  error,
  description,
  inputRef,
  ...inputProps
}: InputProps & {
  id: string;
  label: string;
  error?: string | null;
  description?: ReactNode;
  inputRef?: Ref<HTMLInputElement>;
}) {
  const errorId = `${id}-error`;
  const descriptionId = `${id}-description`;
  const describedBy =
    [description ? descriptionId : null, error ? errorId : null].filter(Boolean).join(" ") ||
    undefined;
  return (
    <div className="min-w-0 space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        {...inputProps}
        id={id}
        ref={inputRef}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy}
      />
      {description ? (
        <div id={descriptionId} className="text-xs text-muted-foreground">
          {description}
        </div>
      ) : null}
      <FieldError id={errorId} errors={error ? [error] : []} />
    </div>
  );
}
