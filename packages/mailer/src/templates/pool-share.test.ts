import { expect, it } from "vitest";
import en from "../locales/en-US/pool-share.json";
import es from "../locales/es-MX/pool-share.json";
import { renderPoolShare } from "./pool-share";

it.each(["en-US", "es-MX", "unknown"])(
  "renders %s with escaped names, fragment-only link, independent permissions and null limits",
  (locale) => {
    const result = renderPoolShare({
      locale,
      inviter: "<script>inviter</script>",
      pool: "<img src=x>",
      url: "https://example.test/en-US/settings/pools/invite#wssp_inv_test",
      invite: {
        canUse: true,
        canContribute: false,
        maxMemoryMiB: null,
        maxVcpu: 2,
        maxDiskGiB: 3,
        expiresAt: new Date(0),
      },
    });
    expect(result.html).not.toContain("<script>");
    expect(result.html).not.toContain("<img");
    expect(result.html).toContain("&lt;script&gt;");
    expect(result.html).toContain(locale === "es-MX" ? "Sí / No" : "Yes / No");
    expect(result.html).toContain("#wssp_inv_test");
    expect(result.html).toContain("incus-admin");
    expect(result.html).toContain("30");
    expect(Object.keys(es).sort()).toEqual(Object.keys(en).sort());
    expect(result.html).not.toMatch(/\{\{/);
    expect(result.html).not.toContain("1970-01-01T00:00:00.000Z");
    expect(result.html).toContain(locale === "es-MX" ? "1 de enero de 1970" : "January 1, 1970");
    expect(result.html).toContain("UTC");
  },
);
