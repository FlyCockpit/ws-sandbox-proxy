import { Radio as RadioPrimitive } from "@base-ui/react/radio";
import { RadioGroup as RadioGroupPrimitive } from "@base-ui/react/radio-group";
import { cn } from "@wssp/ui/lib/utils";

function RadioGroup<Value>({ className, ...props }: RadioGroupPrimitive.Props<Value>) {
  return (
    <RadioGroupPrimitive
      data-slot="radio-group"
      className={cn("flex min-w-0 flex-col gap-0", className)}
      {...props}
    />
  );
}

function RadioGroupItem<Value>({ className, ...props }: RadioPrimitive.Root.Props<Value>) {
  return (
    <RadioPrimitive.Root
      data-slot="radio-group-item"
      className={cn(
        "relative flex size-4 shrink-0 items-center justify-center rounded-full border border-muted-foreground outline-none transition-colors after:absolute after:-inset-3.5 focus-visible:border-ring focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:ring-offset-background data-checked:border-primary data-disabled:opacity-50 aria-invalid:border-destructive",
        className,
      )}
      {...props}
    >
      <RadioPrimitive.Indicator className="size-2 rounded-full bg-primary" />
    </RadioPrimitive.Root>
  );
}

export { RadioGroup, RadioGroupItem };
