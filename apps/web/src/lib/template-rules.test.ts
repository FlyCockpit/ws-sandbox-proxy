import enTemplates from "@wssp/locales/src/en-US/templates.json";
import esTemplates from "@wssp/locales/src/es-MX/templates.json";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_TEMPLATE_DRAFT,
  nextTemplateStateChangeAt,
  parseTemplateDraft,
  registrationHostState,
  type TemplateDraft,
  type TemplateHost,
  templateDraftInput,
  templateDraftProblems,
  templateProblem,
  templateUsability,
} from "./template-rules";

const NOW = Date.parse("2026-09-26T12:00:00Z");

function host(overrides: Partial<TemplateHost> = {}): TemplateHost {
  return {
    id: "h1",
    slug: "alpha",
    label: "Alpha",
    status: "CONNECTED",
    lastConnectedAt: new Date(NOW - 60_000),
    lastHeartbeatAt: new Date(NOW - 1_000),
    deletionRequestedAt: null,
    draining: false,
    ...overrides,
  };
}

const draft = (overrides: Partial<TemplateDraft> = {}): TemplateDraft => ({
  ...DEFAULT_TEMPLATE_DRAFT,
  hostId: "h1",
  slug: "ubuntu-dev",
  label: "Ubuntu dev",
  imageRef: "local:ubuntu-dev",
  ...overrides,
});

describe("registration form schema (the server's createTemplateInput)", () => {
  it("accepts the default guest identity and builds the exact input", () => {
    expect(templateDraftProblems(draft(), [host()], NOW)).toEqual([]);
    expect(parseTemplateDraft(draft({ guestVersion: " 2026-09 " }))).toEqual({
      hostId: "h1",
      envs: {},
      slug: "ubuntu-dev",
      label: "Ubuntu dev",
      imageRef: "local:ubuntu-dev",
      architecture: "x86_64",
      cpuCount: 1,
      memoryMiB: 1024,
      diskGiB: 32,
      guestUid: 1000,
      guestGid: 1000,
      guestHome: "/home/user",
      guestShell: "/bin/bash",
      guestVersion: "2026-09",
    });
    // An empty guest version is omitted, not sent as "".
    expect(templateDraftInput(draft())).not.toHaveProperty("guestVersion");
  });

  it.each([
    [{ cpuCount: "" }, "cpuCount"],
    [{ cpuCount: "0" }, "cpuCount"],
    [{ cpuCount: "33" }, "cpuCount"],
    [{ cpuCount: "1.5" }, "cpuCount"],
    [{ cpuCount: "1e1" }, "cpuCount"],
    [{ memoryMiB: "" }, "memoryMiB"],
    [{ memoryMiB: "511" }, "memoryMiB"],
    [{ memoryMiB: "1025" }, "memoryMiB"],
    [{ memoryMiB: "65792" }, "memoryMiB"],
    [{ slug: "Bad_Slug" }, "slug"],
    [{ slug: "" }, "slug"],
    [{ label: "   " }, "label"],
    [{ label: "x".repeat(161) }, "label"],
    [{ imageRef: `sha256:${"a".repeat(64)}` }, "imageRef"],
    [{ imageRef: "--project=default" }, "imageRef"],
    [{ imageRef: "" }, "imageRef"],
    [{ guestUid: "0" }, "guestUid"],
    [{ guestUid: "65535" }, "guestUid"],
    [{ guestUid: "1e3" }, "guestUid"],
    [{ guestGid: "-1" }, "guestGid"],
    [{ guestHome: "relative" }, "guestHome"],
    [{ guestHome: "/home/../root" }, "guestHome"],
    [{ guestShell: "bash" }, "guestShell"],
    [{ guestVersion: "v".repeat(65) }, "guestVersion"],
  ] as const)("refuses %j as %s", (overrides, problem) => {
    expect(templateDraftProblems(draft(overrides), [host()], NOW)).toEqual([problem]);
  });

  it("needs a known host that can answer the image check now", () => {
    expect(templateDraftProblems(draft({ hostId: "" }), [host()], NOW)).toEqual(["noHost"]);
    expect(templateDraftProblems(draft({ hostId: "gone" }), [host()], NOW)).toEqual([
      "unknownHost",
    ]);
    expect(
      templateDraftProblems(draft(), [host({ deletionRequestedAt: new Date(NOW) })], NOW),
    ).toEqual(["unknownHost"]);
    expect(templateDraftProblems(draft(), [host({ status: "DISCONNECTED" })], NOW)).toEqual([
      "hostUnavailable",
    ]);
    expect(
      templateDraftProblems(draft(), [host({ lastHeartbeatAt: new Date(NOW - 60_000) })], NOW),
    ).toEqual(["hostUnavailable"]);
    expect(templateDraftProblems(draft(), [host({ draining: true })], NOW)).toEqual([
      "hostDraining",
    ]);
    expect(registrationHostState(host(), NOW)).toBe("ready");
  });

  it("every draft problem has copy in both locales", () => {
    for (const problem of [
      "noHost",
      "unknownHost",
      "hostUnavailable",
      "hostDraining",
      "slug",
      "label",
      "imageRef",
      "architecture",
      "guestUid",
      "guestGid",
      "guestHome",
      "guestShell",
      "guestVersion",
    ] as const) {
      expect(enTemplates.draft[problem]).toBeTruthy();
      expect(esTemplates.draft[problem]).toBeTruthy();
    }
  });
});

describe("a template is shown usable only on an active, reachable, admitting host", () => {
  it.each([
    [{ retiredAt: new Date(NOW), host: null }, "archived"],
    [{ retiredAt: null, host: null }, "archived"],
    [{ retiredAt: null, host: host() }, "usable"],
    [{ retiredAt: null, host: host({ draining: true }) }, "hostDraining"],
    [{ retiredAt: null, host: host({ deletionRequestedAt: new Date(NOW) }) }, "hostDeleting"],
    [{ retiredAt: null, host: host({ status: "REVOKED" }) }, "hostRevoked"],
    [{ retiredAt: null, host: host({ status: "STALE" }) }, "hostStale"],
    [{ retiredAt: null, host: host({ lastHeartbeatAt: new Date(NOW - 31_000) }) }, "hostStale"],
    [{ retiredAt: null, host: host({ status: "DISCONNECTED" }) }, "hostOffline"],
    [
      { retiredAt: null, host: host({ status: "DISCONNECTED", lastConnectedAt: null }) },
      "hostOffline",
    ],
  ] as const)("%j → %s", (template, expected) => {
    expect(templateUsability(template, NOW)).toBe(expected);
  });

  it("a silent host turns the template unusable when its heartbeat goes stale", () => {
    const template = { retiredAt: null, host: host({ lastHeartbeatAt: new Date(NOW) }) };
    const at = nextTemplateStateChangeAt([template], NOW);
    expect(at).toBe(NOW + 30_001);
    expect(templateUsability(template, (at as number) - 1)).toBe("usable");
    expect(templateUsability(template, at as number)).toBe("hostStale");
    expect(nextTemplateStateChangeAt([{ host: null }], NOW)).toBeNull();
  });
});

describe("server refusals", () => {
  it.each([
    ["sandbox.template_image_rejected", "BAD_REQUEST", "imageRejected"],
    ["sandbox.host_unavailable", "CONFLICT", "hostUnavailable"],
    ["sandbox.host_draining", "CONFLICT", "hostDraining"],
    ["sandbox.host_delete_conflict", "CONFLICT", "hostDeleting"],
    ["sandbox.template_revision_exists", "CONFLICT", "revisionExists"],
    ["sandbox.template_in_use", "CONFLICT", "inUse"],
    ["sandbox.template_not_found", "NOT_FOUND", "notFound"],
    ["sandbox.host_not_found", "NOT_FOUND", "notFound"],
  ] as const)("%s maps to %s", (code, orpc, expected) => {
    expect(templateProblem({ code: orpc, data: { code } })).toBe(expected);
    expect(enTemplates.problem[expected]).toBeTruthy();
    expect(esTemplates.problem[expected]).toBeTruthy();
  });

  it("falls back on the transport code", () => {
    expect(templateProblem({ code: "CONFLICT" })).toBe("changed");
    expect(templateProblem({ code: "BAD_REQUEST" })).toBe("invalid");
    expect(templateProblem({ status: 403 })).toBe("forbidden");
    expect(templateProblem(new Error("offline"))).toBe("generic");
  });
});

it("maps exact image absence to the missing-image explanation", () => {
  expect(
    templateProblem({ code: "CONFLICT", data: { code: "sandbox.template_image_missing" } }),
  ).toBe("imageMissing");
});
