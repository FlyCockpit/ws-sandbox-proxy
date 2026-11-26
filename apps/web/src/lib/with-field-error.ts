type FieldShape<V> = {
  name: string;
  state: { value: V; meta: { errors: readonly unknown[] } };
  handleBlur: () => void;
  handleChange: (value: V) => void;
};

/**
 * A `TextField`-shaped view of a TanStack field whose errors are one message
 * the page computed itself (a draft rule, a source check), so the field shows
 * it inline with `aria-invalid` and `aria-describedby`. `onChange` replaces
 * the field's own change handler (a derived value, a "was edited" flag).
 */
export function withFieldError<V>(
  field: FieldShape<V>,
  message: string | null,
  onChange?: (value: V) => void,
): FieldShape<V> {
  return {
    name: field.name,
    state: {
      value: field.state.value,
      meta: { errors: message ? [message] : field.state.meta.errors },
    },
    handleBlur: () => field.handleBlur(),
    handleChange: onChange ?? ((value) => field.handleChange(value)),
  };
}
