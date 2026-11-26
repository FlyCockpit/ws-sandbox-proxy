import { defineConfig, minimal2023Preset } from "@vite-pwa/assets-generator/config";

// `assets/logo.png` is the bare artwork on a transparent canvas. The transparent
// icons (favicon and pwa-*) use it as is, so they sit on any page background.
// The maskable icon must be opaque, so its padding uses the FlyCockpit suite
// blue (#4a97fa) instead of the generator's default white. Padding 0.27 is
// tuned for this logo so its farthest opaque pixel stays inside the center
// 80% maskable safe-zone circle: measured radius 198.81 px versus 204.8 px
// at 512px, leaving 5.99 px of margin (messages-mcp's artwork uses 0.27).
//
// The apple touch icon is NOT generated here (`sizes: []`):
// `public/apple-touch-icon-180x180.png` is the owner's Apple-style tile, flattened
// to an opaque full-bleed square (iOS applies its own mask and shows transparency
// as black). Replace it by hand: docs/operations/deployment.md.
//
// The header logo (components/app-name-link.tsx, `APP_LOGO` in
// src/lib/app-logo.ts) is drawn at 32 CSS px, so the transparent set adds 32
// and 128 to the preset's 64: `pwa-32x32.png`, `pwa-64x64.png` and
// `pwa-128x128.png` are its 1×/2×/4× sources. They come from the same source
// image as the favicon and the install icons, so the three never drift.
// docs/design/shell-rules.md § Logo slot.
const background = "#4a97fa";

export default defineConfig({
  headLinkOptions: {
    preset: "2023",
  },
  preset: {
    ...minimal2023Preset,
    transparent: {
      ...minimal2023Preset.transparent,
      sizes: [32, ...minimal2023Preset.transparent.sizes, 128],
    },
    maskable: { ...minimal2023Preset.maskable, padding: 0.27, resizeOptions: { background } },
    apple: { ...minimal2023Preset.apple, sizes: [] },
  },
  images: ["assets/logo.png"],
});
