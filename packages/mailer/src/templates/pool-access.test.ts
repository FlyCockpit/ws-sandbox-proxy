import { expect, it } from "vitest";
import en from "../locales/en-US/pool-access.json";
import es from "../locales/es-MX/pool-access.json";
import { renderPoolAccessNotice } from "./pool-access";

it.each(["en-US", "es-MX"])(
  "%s loss/restore notices pin deadlines and escape identifiers",
  (locale) => {
    for (const kind of ["loss", "restore"] as const) {
      const mail = renderPoolAccessNotice({
        locale,
        sandboxId: "<sandbox>",
        kind,
        deadline: new Date(0),
      });
      expect(mail.html).toContain("&lt;sandbox&gt;");
      expect(mail.html).not.toContain("<sandbox>");
      if (kind === "loss") expect(mail.html).toContain(new Date(0).toISOString());
      expect(mail.html).not.toContain("{{");
    }
    expect(Object.keys(es)).toEqual(Object.keys(en));
  },
);
