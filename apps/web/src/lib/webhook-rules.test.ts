import { describe, expect, it } from "vitest";
import { webhookDraftProblems, webhookHost, webhookProblem } from "./webhook-rules";

describe("webhook draft rules", () => {
  it("requires a URL and an event, and bounds the description", () => {
    expect(
      webhookDraftProblems({ url: "", description: "", events: [], kinds: "default" }),
    ).toEqual(["urlRequired", "eventsRequired"]);
    expect(
      webhookDraftProblems({
        url: "ftp://x",
        description: "d".repeat(201),
        events: ["sandbox.ready"],
        kinds: "all",
      }),
    ).toEqual(["destinationInvalid", "descriptionTooLong"]);
    expect(
      webhookDraftProblems({
        url: "https://hooks.example.com/x",
        description: "",
        events: ["sandbox.ready"],
        kinds: "default",
      }),
    ).toEqual([]);
  });

  it("shows only the host and maps server refusals", () => {
    expect(webhookHost("https://hooks.example.com:8443/secret/path?q=1")).toBe(
      "hooks.example.com:8443",
    );
    expect(
      webhookProblem({ code: "BAD_REQUEST", data: { code: "webhook.destination_blocked" } }),
    ).toBe("destinationBlocked");
    expect(webhookProblem({ code: "CONFLICT", data: { code: "webhook.endpoint_limit" } })).toBe(
      "limit",
    );
    expect(webhookProblem({ code: "BAD_REQUEST", data: { code: "UNSUPPORTED_CAPABILITY" } })).toBe(
      "notConfigured",
    );
    expect(webhookProblem({ status: 429 })).toBe("rateLimited");
    expect(webhookProblem(new Error("x"))).toBe("generic");
  });
});
