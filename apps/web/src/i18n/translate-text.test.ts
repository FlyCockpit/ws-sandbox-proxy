import enCredentials from "@wssp/locales/src/en-US/credentials.json";
import enOperations from "@wssp/locales/src/en-US/operations.json";
import enSandboxes from "@wssp/locales/src/en-US/sandboxes.json";
import enSdk from "@wssp/locales/src/en-US/sdkKeys.json";
import enTemplates from "@wssp/locales/src/en-US/templates.json";
import esCredentials from "@wssp/locales/src/es-MX/credentials.json";
import esOperations from "@wssp/locales/src/es-MX/operations.json";
import esSandboxes from "@wssp/locales/src/es-MX/sandboxes.json";
import esSdk from "@wssp/locales/src/es-MX/sdkKeys.json";
import esTemplates from "@wssp/locales/src/es-MX/templates.json";
import { createInstance } from "i18next";
import { describe, expect, it } from "vitest";
import { translateText } from "./translate-text";

describe.each(["en-US", "es-MX"])("opaque display values in %s", (lng) => {
  it.each([
    "<1>fake</1>",
    "<strong>x</strong>",
    "{{slug}}",
    "{{id}}",
    "{{state}}",
    "{{status}}",
    "$t(common:loading)",
  ])("keeps %s literal in multi-value resource translations", async (label) => {
    const i18n = createInstance();
    await i18n.init({
      lng,
      interpolation: { escapeValue: false },
      resources: {
        "en-US": {
          credentials: enCredentials,
          sdkKeys: enSdk,
          sandboxes: enSandboxes,
          templates: enTemplates,
          operations: enOperations,
        },
        "es-MX": {
          credentials: esCredentials,
          sdkKeys: esSdk,
          sandboxes: esSandboxes,
          templates: esTemplates,
          operations: esOperations,
        },
      },
    });
    const t = i18n.t.bind(i18n);
    const values = {
      label,
      host: label,
      slug: "dev-east",
      id: "resource-id",
      state: "Ready",
      status: "Available",
      live: 1,
      max: 4,
      uid: 1000,
      gid: 1000,
      home: label,
      shell: "/bin/sh",
      reason: "no storage",
      owner: "Ada",
    };
    for (const key of [
      "credentials:host.label",
      "sdkKeys:resourceIdentity",
      "sdkKeys:form.association",
      "sandboxes:create.logicalOption",
      "sandboxes:create.hostAvailable",
      "sandboxes:create.hostOffline",
      "sandboxes:create.hostUnavailable",
      "sandboxes:create.hostUnmeasured",
      "sandboxes:create.poolOption",
      "sandboxes:hostLabel",
      "sandboxes:hostOffline",
      "templates:form.hostOption",
      "operations:detail.hostOffline",
      "sandboxes:detail.guestIdentity",
    ]) {
      const baseline = translateText(t, key, {
        ...values,
        label: "LABEL",
        host: "LABEL",
        home: "LABEL",
      });
      expect(baseline).toContain("LABEL");
      expect(translateText(t, key, values)).toBe(baseline.replace("LABEL", label));
    }
  });
});
