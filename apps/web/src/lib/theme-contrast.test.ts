import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import postcss from "postcss";
import { describe, expect, it } from "vitest";

/**
 * WCAG 2.x contrast of the theme tokens in packages/ui globals.css. Text
 * colors must reach AA (4.5:1) on the surfaces they are used on, including
 * the translucent tints components put behind them (composited in sRGB, as
 * browsers do).
 */
const css = readFileSync(
  resolve(import.meta.dirname, "../../../../packages/ui/src/styles/globals.css"),
  "utf8",
);

type Rgb = [number, number, number];

function block(selector: string): string {
  const start = css.indexOf(`${selector} {`);
  if (start === -1) throw new Error(`missing ${selector}`);
  return css.slice(start, css.indexOf("\n}", start));
}

function token(scope: string, name: string): Rgb {
  const match = new RegExp(`--${name}:\\s*oklch\\(([\\d.]+) ([\\d.]+) ([\\d.]+)\\)`).exec(
    block(scope),
  );
  if (!match) throw new Error(`--${name} is not an oklch() literal in ${scope}`);
  return oklchToSrgb(Number(match[1]), Number(match[2]), Number(match[3]));
}

function oklchToSrgb(l: number, c: number, hue: number): Rgb {
  const a = c * Math.cos((hue * Math.PI) / 180);
  const b = c * Math.sin((hue * Math.PI) / 180);
  const lms = [
    (l + 0.3963377774 * a + 0.2158037573 * b) ** 3,
    (l - 0.1055613458 * a - 0.0638541728 * b) ** 3,
    (l - 0.0894841775 * a - 1.291485548 * b) ** 3,
  ] as const;
  const linear = [
    4.0767416621 * lms[0] - 3.3077115913 * lms[1] + 0.2309699292 * lms[2],
    -1.2684380046 * lms[0] + 2.6097574011 * lms[1] - 0.3413193965 * lms[2],
    -0.0041960863 * lms[0] - 0.7034186147 * lms[1] + 1.707614701 * lms[2],
  ];
  const encode = (x: number) => {
    const v = Math.min(1, Math.max(0, x));
    return v <= 0.0031308 ? 12.92 * v : 1.055 * v ** (1 / 2.4) - 0.055;
  };
  return [encode(linear[0] ?? 0), encode(linear[1] ?? 0), encode(linear[2] ?? 0)];
}

/** `fg` at `alpha` over `bg`, as `bg-x/NN` composites. */
function over(fg: Rgb, alpha: number, bg: Rgb): Rgb {
  return [0, 1, 2].map((i) => (fg[i] ?? 0) * alpha + (bg[i] ?? 0) * (1 - alpha)) as Rgb;
}

function luminance([r, g, b]: Rgb): number {
  const decode = (v: number) => (v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4);
  return 0.2126 * decode(r) + 0.7152 * decode(g) + 0.0722 * decode(b);
}

function contrast(a: Rgb, b: Rgb): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x) as [number, number];
  return (hi + 0.05) / (lo + 0.05);
}

const AA = 4.5;

const buttonSource = readFileSync(
  resolve(import.meta.dirname, "../../../../packages/ui/src/components/button.tsx"),
  "utf8",
);

/** Alpha of the default button's link hover fill (`[a]:hover:bg-primary/NN`, with an optional dark prefix). */
function linkHoverAlpha(prefix: "" | "dark:"): number {
  const match = new RegExp(`(?:^|[\\s"])${prefix}\\[a\\]:hover:bg-primary/(\\d+)`).exec(
    buttonSource,
  );
  if (!match) throw new Error(`no ${prefix}[a]:hover:bg-primary/NN in button.tsx`);
  return Number(match[1]) / 100;
}

describe("theme token contrast (WCAG AA)", () => {
  it("keeps light-mode destructive text readable on every surface it sits on", () => {
    const destructive = token(":root", "destructive");
    const background = token(":root", "background");
    for (const surface of ["background", "card", "popover", "muted"]) {
      expect(contrast(destructive, token(":root", surface)), surface).toBeGreaterThanOrEqual(AA);
    }
    // The destructive button: `bg-destructive/10 text-destructive`.
    expect(contrast(destructive, over(destructive, 0.1, background))).toBeGreaterThanOrEqual(AA);
  });

  it("keeps dark-mode primary readable as text and under its own foreground", () => {
    const primary = token(".dark", "primary");
    for (const surface of ["background", "card", "popover", "muted"]) {
      expect(contrast(primary, token(".dark", surface)), surface).toBeGreaterThanOrEqual(AA);
    }
    expect(contrast(token(".dark", "primary-foreground"), primary)).toBeGreaterThanOrEqual(AA);
    // Selected options: `bg-primary/10` behind primary text.
    const background = token(".dark", "background");
    expect(contrast(primary, over(primary, 0.1, background))).toBeGreaterThanOrEqual(AA);
  });

  it("keeps the other primary and destructive pairs at AA", () => {
    expect(
      contrast(token(":root", "primary-foreground"), token(":root", "primary")),
    ).toBeGreaterThanOrEqual(AA);
    expect(
      contrast(token(":root", "primary"), token(":root", "background")),
    ).toBeGreaterThanOrEqual(AA);
    const darkDestructive = token(".dark", "destructive");
    const darkBackground = token(".dark", "background");
    expect(contrast(darkDestructive, darkBackground)).toBeGreaterThanOrEqual(AA);
    expect(contrast(darkDestructive, token(".dark", "card"))).toBeGreaterThanOrEqual(AA);
    // Dark destructive button: `dark:bg-destructive/20`.
    expect(
      contrast(darkDestructive, over(darkDestructive, 0.2, darkBackground)),
    ).toBeGreaterThanOrEqual(AA);
  });

  it("keeps the default link-button label readable on its hover fill", () => {
    // `[a]:hover:bg-primary/NN` lets the surface behind the button show through.
    for (const [scope, prefix] of [
      [":root", ""],
      [".dark", "dark:"],
    ] as const) {
      const alpha = linkHoverAlpha(prefix);
      const primary = token(scope, "primary");
      const foreground = token(scope, "primary-foreground");
      for (const surface of ["background", "card", "popover", "muted"]) {
        const fill = over(primary, alpha, token(scope, surface));
        expect(contrast(foreground, fill), `${scope} ${surface}`).toBeGreaterThanOrEqual(AA);
      }
    }
  });

  it("measures the old tokens as failing, so the check discriminates", () => {
    const oldLight = oklchToSrgb(0.577, 0.245, 27.325);
    expect(contrast(oldLight, token(":root", "muted"))).toBeLessThan(AA);
    const oldDark = oklchToSrgb(0.437, 0.078, 188.216);
    expect(contrast(oldDark, token(".dark", "background"))).toBeLessThan(AA);
    // The old 80% link hover fill under the new dark primary.
    const darkPrimary = token(".dark", "primary");
    const darkHover = over(darkPrimary, 0.8, token(".dark", "background"));
    expect(contrast(token(".dark", "primary-foreground"), darkHover)).toBeLessThan(AA);
  });
});

describe("wssp blue and family palette contrast", () => {
  for (const scope of [":root", ".dark"]) {
    it(`${scope} keeps sidebar and muted text at AA`, () => {
      const sidebar = token(scope, "sidebar-primary");
      expect(contrast(sidebar, token(scope, "sidebar-primary-foreground"))).toBeGreaterThanOrEqual(
        4.5,
      );
      for (const surface of ["background", "card", "muted"]) {
        expect(contrast(sidebar, token(scope, surface)), surface).toBeGreaterThanOrEqual(4.5);
        expect(
          contrast(token(scope, "muted-foreground"), token(scope, surface)),
          surface,
        ).toBeGreaterThanOrEqual(4.5);
      }
    });
    it(`${scope} gives every categorical chart mark 3:1 on its card`, () => {
      for (let slot = 1; slot <= 8; slot++) {
        const hex = new RegExp(`--chart-${slot}:\\s*#([0-9a-f]{6})`).exec(block(scope))?.[1];
        if (!hex) throw new Error(`Missing --chart-${slot}`);
        const rgb: Rgb = [
          Number.parseInt(hex.slice(0, 2), 16) / 255,
          Number.parseInt(hex.slice(2, 4), 16) / 255,
          Number.parseInt(hex.slice(4, 6), 16) / 255,
        ];
        expect(contrast(rgb, token(scope, "card")), `chart-${slot}`).toBeGreaterThanOrEqual(3);
      }
    });
  }
});

it("keeps destructive action labels readable on normal and hover tints across surfaces", () => {
  for (const scope of [":root", ".dark"]) {
    const destructive = token(scope, "destructive");
    const alphas = scope === ":root" ? [0.05, 0.1] : [0.05, 0.08];
    for (const alpha of alphas) {
      for (const surface of ["background", "card", "popover", "muted"]) {
        expect(
          contrast(destructive, over(destructive, alpha, token(scope, surface))),
          `${scope} ${surface} ${alpha}`,
        ).toBeGreaterThanOrEqual(4.5);
      }
    }
  }
});

// Field outlines (input, textarea, select, checkbox, the Off switch track) are
// non-text UI (WCAG 1.4.11): what shows where to type. --border is decorative
// (dividers, cards) and is not held to this.
for (const scope of [":root", ".dark"]) {
  it(`${scope} field outlines (--input) reach 3:1 on every surface a field sits on`, () => {
    for (const surface of ["background", "card", "popover", "muted"]) {
      expect(
        contrast(token(scope, "input"), token(scope, surface)),
        `${scope} input on ${surface}`,
      ).toBeGreaterThanOrEqual(3);
    }
    // The dark field fill (`dark:bg-input/30`) keeps placeholder text readable.
    if (scope === ".dark") {
      for (const surface of ["background", "card", "popover"]) {
        const fill = over(token(scope, "input"), 0.3, token(scope, surface));
        expect(
          contrast(token(scope, "muted-foreground"), fill),
          `${scope} placeholder on input fill over ${surface}`,
        ).toBeGreaterThanOrEqual(AA);
      }
    }
  });
}

it("keeps placeholder text readable on every hovered --input fill", () => {
  // Select and combobox triggers hover to a stronger `bg-input/NN` while they
  // still show a muted placeholder; at /50 the dark fill fell to ~3.78:1 on a
  // card. Every `hover:bg-input/NN` in the ui package and the app is checked
  // in the themes it applies to (`dark:` only in .dark).
  const roots = [
    resolve(import.meta.dirname, "../../../../packages/ui/src"),
    resolve(import.meta.dirname, ".."),
  ];
  const fills: string[] = [];
  for (const root of roots) {
    for (const file of readdirSync(root, { recursive: true, encoding: "utf8" })) {
      if (!/\.tsx?$/.test(file) || /\.test\.tsx?$/.test(file)) continue;
      const source = readFileSync(resolve(root, file), "utf8");
      for (const match of source.matchAll(/(?<![\w-])((?:[\w-]+:)*hover:)bg-input\/(\d+)/g)) {
        const variants = match[1] ?? "";
        const alpha = Number(match[2]) / 100;
        fills.push(`${file}: ${match[0]}`);
        const scopes = variants.split(":").includes("dark") ? [".dark"] : [":root", ".dark"];
        for (const scope of scopes) {
          for (const surface of ["background", "card", "popover"]) {
            const fill = over(token(scope, "input"), alpha, token(scope, surface));
            expect(
              contrast(token(scope, "muted-foreground"), fill),
              `${scope} placeholder on ${match[0]} over ${surface} (${file})`,
            ).toBeGreaterThanOrEqual(AA);
          }
        }
      }
    }
  }
  // The scan found the select, button and language-switcher hovers.
  expect(fills.length).toBeGreaterThanOrEqual(3);
});

it("measures the old dark hover fill as failing, so the hover check discriminates", () => {
  const fill = over(token(".dark", "input"), 0.5, token(".dark", "card"));
  expect(contrast(token(".dark", "muted-foreground"), fill)).toBeLessThan(AA);
});

it("fills light-mode fields with no --input tint, which would bury the placeholder", () => {
  // bg-input/30 over white is 3.9:1 for muted-foreground placeholder text with
  // the 3:1 --input; light search fields use bg-muted instead. Disabled fills
  // (disabled:bg-input/50) sit under opacity-50 and are exempt.
  const dir = resolve(import.meta.dirname, "../../../../packages/ui/src/components");
  for (const file of readdirSync(dir).filter((name) => name.endsWith(".tsx"))) {
    const source = readFileSync(resolve(dir, file), "utf8");
    expect(source, file).not.toMatch(/(?<![\w:-])bg-input\/\d+/);
  }
});

it.each(["command.tsx", "async-combobox.tsx", "multi-async-combobox.tsx"])(
  "%s: the search placeholder is muted-foreground on an opaque muted fill (tested at 4.5:1 above)",
  (file) => {
    // Tailwind's default placeholder is the text colour at 50%, and a
    // translucent bg-input fill moves with the --input outline token: the
    // dark pair fell to 4.23:1 when --input reached 3:1.
    const source = readFileSync(
      resolve(import.meta.dirname, "../../../../packages/ui/src/components", file),
      "utf8",
    );
    expect(source).toContain("placeholder:text-muted-foreground");
    // Unprefixed and dark: InputGroup's own `dark:bg-input/30` would
    // otherwise win in the dark theme.
    expect(source).toMatch(/InputGroup className="[^"]*(?<![\w:-])bg-muted[^"]*dark:bg-muted/);
    expect(source).not.toMatch(/InputGroup className="[^"]*bg-input\/\d+/);
  },
);

it("measures the old --input values as failing, so the field check discriminates", () => {
  // Light oklch(0.925 0.005 214.3) was 1.25:1 on white; dark was 15% white.
  expect(contrast(oklchToSrgb(0.925, 0.005, 214.3), token(":root", "background"))).toBeLessThan(3);
  const darkBackground = token(".dark", "background");
  expect(contrast(over([1, 1, 1], 0.15, darkBackground), darkBackground)).toBeLessThan(3);
});

it("fills an Off switch track with the opaque --input, which the 3:1 checks cover", () => {
  // A translucent track (dark:data-unchecked:bg-input/80) composites below
  // the measured colour.
  const source = readFileSync(
    resolve(import.meta.dirname, "../../../../packages/ui/src/components/switch.tsx"),
    "utf8",
  );
  expect(source).toContain("data-unchecked:bg-input ");
  expect(source).not.toMatch(/data-unchecked:bg-input\/\d+/);
});

it("draws dropdown menus on an opaque popover surface", () => {
  // A translucent menu (bg-popover/70 + backdrop blur) let a banner tint it.
  const menu = readFileSync(
    resolve(import.meta.dirname, "../../../../packages/ui/src/components/dropdown-menu.tsx"),
    "utf8",
  );
  expect(menu).toContain(" bg-popover ");
  expect(menu).not.toMatch(/bg-popover\/\d+|backdrop-blur/);
});

// Unchecked radio/checkbox/switch outlines identify the control on these surfaces.
for (const scope of [":root", ".dark"]) {
  it(`${scope} keeps unchecked control borders at 3:1`, () => {
    for (const surface of ["background", "card", "popover", "muted"]) {
      expect(
        contrast(token(scope, "muted-foreground"), token(scope, surface)),
        surface,
      ).toBeGreaterThanOrEqual(3);
    }
  });
}

for (const scope of [":root", ".dark"]) {
  it(`${scope} keeps full-opacity focus rings at 3:1 on adjacent surfaces`, () => {
    for (const name of ["ring", "sidebar-ring"]) {
      for (const surface of ["background", "card", "popover", "muted"]) {
        expect(
          contrast(token(scope, name), token(scope, surface)),
          `${name} on ${surface}`,
        ).toBeGreaterThanOrEqual(3);
      }
    }
  });
}

/** A token that may alias another one (`--state-loading: var(--muted-foreground)`), resolved in its scope. */
function resolved(scope: string, name: string, depth = 0): Rgb {
  const alias = new RegExp(`--${name}:\\s*var\\(--([\\w-]+)\\)`).exec(block(scope))?.[1];
  if (alias && depth < 5) return resolved(scope, alias, depth + 1);
  return token(scope, name);
}

/** The declarations of the one unlayered rule with exactly this selector. */
function declarations(selector: string): Map<string, string> {
  const rule = postcss
    .parse(css)
    .nodes.find((node) => node.type === "rule" && node.selector === selector);
  if (rule?.type !== "rule") throw new Error(`Missing toast rule ${selector}`);
  return new Map(
    rule.nodes.flatMap((node) => (node.type === "decl" ? [[node.prop, node.value] as const] : [])),
  );
}

const aliasOf = (value: string | undefined) => /^var\(--([\w-]+)\)$/.exec(value ?? "")?.[1];

describe("state inks and toasts (docs/design/shell-rules.md rule 3)", () => {
  for (const scope of [":root", ".dark"]) {
    it(`${scope} state inks reach 4.5:1 on background, card and popover`, () => {
      // Badges, alerts and toasts write in these colours.
      for (const ink of ["state-success", "state-warning", "state-info", "state-loading"]) {
        for (const surface of ["background", "card", "popover"]) {
          expect(
            contrast(resolved(scope, ink), token(scope, surface)),
            `${scope} ${ink} on ${surface}`,
          ).toBeGreaterThanOrEqual(AA);
        }
      }
    });

    it(`${scope} toasts are a popover surface with 4.5:1 inks`, () => {
      // sileo's own palette inverts the theme; globals.css repaints it from the
      // tokens. Every state ink it maps and its text colour must hold up on the
      // fill it maps.
      const fill = aliasOf(
        declarations(":root [data-sileo-viewport] :is([data-sileo-pill], [data-sileo-body])").get(
          "fill",
        ),
      );
      expect(fill).toBe("popover");
      const surface = token(scope, "popover");
      const viewport = declarations(":root [data-sileo-viewport]");
      for (const state of ["success", "loading", "error", "warning", "info", "action"]) {
        const ink = aliasOf(viewport.get(`--sileo-state-${state}`));
        expect(ink, `--sileo-state-${state} maps to a token`).toBeDefined();
        expect(
          contrast(resolved(scope, ink ?? ""), surface),
          `${scope} toast ${state} (${ink}) on popover`,
        ).toBeGreaterThanOrEqual(AA);
      }
      // The badge ink sits on the pill itself (contrast above), not on a tint.
      expect(
        declarations(":root [data-sileo-viewport] [data-sileo-badge][data-state]").get(
          "--sileo-tone-bg",
        ),
      ).toBe("transparent");
      for (const selector of [
        ":root [data-sileo-viewport] [data-sileo-title][data-state]",
        ":root [data-sileo-viewport] [data-sileo-description]",
      ]) {
        expect(aliasOf(declarations(selector).get("color")), selector).toBe("popover-foreground");
      }
      expect(contrast(token(scope, "popover-foreground"), surface)).toBeGreaterThanOrEqual(AA);
      // A long title must not outgrow sileo's 350px pill (the badge icon ended
      // up half outside it): the header row is capped and the title ellipsised.
      expect(
        declarations(":root [data-sileo-viewport] [data-sileo-header-inner]").get("max-width"),
      ).toBe("calc(var(--sileo-width) - 1rem - 10px)");
      expect(
        declarations(
          ":root [data-sileo-viewport] [data-sileo-header-inner] [data-sileo-title]",
        ).get("text-overflow"),
      ).toBe("ellipsis");
      // The action button writes --popover-foreground on an 8% (14% on hover)
      // tint of itself over the pill.
      const button = declarations(":root [data-sileo-viewport] [data-sileo-button][data-state]");
      expect(aliasOf(button.get("--sileo-btn-color"))).toBe("popover-foreground");
      for (const key of ["--sileo-btn-bg", "--sileo-btn-bg-hover"]) {
        const mix = /^color-mix\(in oklch, var\(--popover-foreground\) (\d+)%, transparent\)$/.exec(
          button.get(key) ?? "",
        );
        expect(mix, key).not.toBeNull();
        const tint = over(token(scope, "popover-foreground"), Number(mix?.[1]) / 100, surface);
        expect(
          contrast(token(scope, "popover-foreground"), tint),
          `${scope} toast button text on ${key}`,
        ).toBeGreaterThanOrEqual(AA);
      }
    });
  }

  it("gives the Toaster no theme, so sileo cannot invert the page", () => {
    const toaster = readFileSync(
      resolve(import.meta.dirname, "../../../../packages/ui/src/components/sileo.tsx"),
      "utf8",
    );
    expect(toaster).not.toMatch(/\btheme=|useTheme/);
  });
});
