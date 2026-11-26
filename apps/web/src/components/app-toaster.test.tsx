// @vitest-environment jsdom
import { hideDecorativeSvgs } from "@wssp/ui/components/sileo";
import { expect, it } from "vitest";

it("hides Sileo's decorative SVGs so a toast is named by its own text", () => {
  document.body.innerHTML = `
    <div data-toaster-root>
      <section data-sileo-viewport aria-live="polite">
        <button data-sileo-toast>
          <div data-sileo-canvas><svg data-sileo-svg><title>sileo notification</title></svg></div>
          <div data-sileo-header><div data-sileo-badge><svg><title>X</title></svg></div>
            <span data-sileo-title>That code didn't work.</span></div>
        </button>
      </section>
    </div>
    <svg id="elsewhere"><title>untouched</title></svg>`;
  hideDecorativeSvgs(document);
  const toastSvgs = document.querySelectorAll("[data-sileo-viewport] svg");
  expect(toastSvgs).toHaveLength(2);
  for (const svg of toastSvgs) expect(svg.getAttribute("aria-hidden")).toBe("true");
  expect(document.getElementById("elsewhere")?.hasAttribute("aria-hidden")).toBe(false);
});
