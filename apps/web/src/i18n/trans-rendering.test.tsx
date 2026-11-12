import enAdmin from "@wssp/locales/src/en-US/admin.json";
import enAuth from "@wssp/locales/src/en-US/auth.json";
import { createInstance } from "i18next";
import { renderToStaticMarkup } from "react-dom/server";
import { I18nextProvider, Trans } from "react-i18next";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * Regression tests for the `<Trans>` rendering bugs this app shipped once: the
 * originals passed JSX children whose positional indices did not match the
 * `<N>` tags in the JSON, which produced duplicated phrases and dropped
 * `<code>` content. The fix is the explicit `components` prop, so the JSON
 * value stays the source of truth for both text and tag positions.
 *
 * These cover every `<0>`-carrying key in the shipped bundles. If a future
 * refactor reverts to children-as-source-of-truth, or an edit desyncs a
 * translated value from its `components` array, these snapshots diverge from
 * the JSON and the test fails loudly.
 */
describe("<Trans> components-prop rendering", () => {
  const i18n = createInstance();

  beforeAll(async () => {
    await i18n.init({
      lng: "en-US",
      fallbackLng: "en-US",
      ns: ["admin", "auth"],
      defaultNS: "admin",
      resources: {
        "en-US": { admin: enAdmin, auth: enAuth },
      },
      interpolation: { escapeValue: false },
      react: { useSuspense: false },
    });
  });

  function renderTrans(node: React.ReactElement): string {
    return renderToStaticMarkup(<I18nextProvider i18n={i18n}>{node}</I18nextProvider>);
  }

  it("renders auth device enterCodeDescription with <code> around the query hint", () => {
    const html = renderTrans(
      <Trans
        i18nKey="device.enterCodeDescription"
        ns="auth"
        components={[<code key="0" className="font-mono" />]}
      />,
    );

    expect(html).toContain('<code class="font-mono">?user_code=YOURCODE</code>');
  });
});
