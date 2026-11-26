import { afterEach, describe, expect, it, vi } from "vitest";

const backend = vi.hoisted(() => {
  const method = () => vi.fn((options: { id?: string }) => options.id ?? "sileo-default");
  return {
    show: method(),
    success: method(),
    error: method(),
    info: method(),
    warning: method(),
    dismiss: vi.fn(),
    clear: vi.fn(),
  };
});
vi.mock("sileo", () => ({ sileo: backend, Toaster: () => null }));
vi.mock("sileo/styles.css", () => ({}));

afterEach(() => {
  vi.resetModules();
  for (const fn of Object.values(backend)) fn.mockClear();
});

const LONG = "That code didn't work. Check your authenticator and try again.";

describe("toast facade", () => {
  it("gives every toast its own id so two toasts stack instead of merging", async () => {
    // sileo defaults every toast to id "sileo-default" and replaces it in place.
    const { toast } = await import("@wssp/ui/components/sileo");

    const first = toast.error("That wasn't found.");
    const second = toast.error("That wasn't found.");

    expect(first).not.toBe(second);
    expect(backend.error.mock.calls.map(([options]) => options.id)).toEqual([first, second]);
    expect(first).not.toBe("sileo-default");
  });

  it("keeps a short message as the pill title with no description", async () => {
    const { toast } = await import("@wssp/ui/components/sileo");
    const onClick = vi.fn();
    toast.success("Saved", { duration: 5000, action: { label: "Undo", onClick } });
    expect(backend.success).toHaveBeenCalledWith({
      id: expect.any(String),
      title: "Saved",
      duration: 5000,
      button: { title: "Undo", onClick },
    });
  });

  it("repeats a long message in the description when no short title is set", async () => {
    const { toast } = await import("@wssp/ui/components/sileo");
    toast.error(LONG);
    expect(backend.error).toHaveBeenCalledWith(
      expect.objectContaining({ title: LONG, description: LONG }),
    );
  });

  it("uses the translated short title for a long message and puts it in the description", async () => {
    const { Toaster, toast } = await import("@wssp/ui/components/sileo");
    const { renderToStaticMarkup } = await import("react-dom/server");
    renderToStaticMarkup(
      <Toaster
        titles={{
          message: "Notice",
          success: "Done",
          error: "Something went wrong",
          info: "Info",
          warning: "Warning",
        }}
      />,
    );
    toast.error(LONG);
    expect(backend.error).toHaveBeenCalledWith(
      expect.objectContaining({ title: "Something went wrong", description: LONG }),
    );
  });

  it("decides by the measured width, not the character count", async () => {
    const { titleOverflowsPill, pillTitleBudget } = await import("@wssp/ui/components/sileo");
    // ~8px per glyph at a 16px root: 36 characters fit, 30 wide glyphs don't.
    const at16 = (perChar: number) => (m: string) => ({
      width: m.length * perChar,
      budget: pillTitleBudget(16),
    });
    expect(pillTitleBudget(16)).toBe(292);
    expect(titleOverflowsPill("a".repeat(36), at16(6.5))).toBe(false);
    expect(titleOverflowsPill("W".repeat(30), at16(11))).toBe(true);
    // At a 24px root (large screens) the font grows but sileo's pill does not:
    // a 36-character message that fit at 16px no longer does.
    const at24 = (m: string) => ({ width: m.length * 6.5 * 1.5, budget: pillTitleBudget(24) });
    expect(titleOverflowsPill("We've emailed you a verification code", at24)).toBe(true);
  });

  it("falls back to a length rule when nothing can be measured", async () => {
    const { titleOverflowsPill } = await import("@wssp/ui/components/sileo");
    expect(titleOverflowsPill("Saved", () => null)).toBe(false);
    expect(titleOverflowsPill("x".repeat(41), () => null)).toBe(true);
  });
});
