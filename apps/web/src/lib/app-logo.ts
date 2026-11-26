/**
 * The header logo slot (components/app-name-link.tsx): 2rem (32 CSS px at the
 * default root size), with 32/64/128 px sources picked by width descriptors
 * and `sizes`, so a scaled-up root (large screens) or a dense display gets a
 * file at least as large as the drawn box. The files are generated, never drawn
 * by hand: `pnpm --filter web generate-pwa-assets` derives them from the same
 * source image as the favicon and the install icons
 * (apps/web/pwa-assets.config.ts, `assets/logo.png`), and the outputs are
 * copied to `apps/web/public/`. docs/design/shell-rules.md § Logo slot.
 */
export const APP_LOGO = {
  /** CSS px, both sides: the `<img>` reserves this box before the file loads. */
  size: 32,
  src: "/pwa-32x32.png",
  srcSet: "/pwa-32x32.png 32w, /pwa-64x64.png 64w, /pwa-128x128.png 128w",
  /**
   * The largest width the slot is drawn at: 2rem at a root font scaled up to
   * 150% on big screens. A literal, not "2rem": `sizes` resolves `rem`
   * against the browser's initial font size, never the page's scaled root.
   * At 1x this picks the 64px file, a few KB more than the 32px one.
   */
  sizes: "48px",
} as const;
