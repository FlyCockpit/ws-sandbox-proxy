import { describe, expect, it } from "vitest";

import { renderInviteUser } from "./invite-user";

describe("renderInviteUser", () => {
  const baseArgs = {
    name: "Jane Doe",
    email: "jane@example.com",
    tempPassword: "hunter2hunter2",
    acceptUrl: "https://example.com/login",
    expiresInDays: 7,
  };

  it("returns the en-US bundle for locale='en-US'", () => {
    const { subject, html } = renderInviteUser({ ...baseArgs, locale: "en-US" });

    expect(subject).toBe("You've been invited");
    expect(html).toContain('<html lang="en-US">');
    expect(html).toContain("You've been invited");
    expect(html).toContain("Jane Doe");
    expect(html).toContain("jane@example.com");
    expect(html).toContain("hunter2hunter2");
    expect(html).toContain("https://example.com/login");
    expect(html).toContain("Email"); // label
    expect(html).toContain("Temporary password"); // label
    expect(html).toContain("Accept invitation"); // CTA
    // What the link does, how long it works, and the next step once it expired.
    expect(html).toContain("it confirms this email address");
    expect(html).toContain("works for 7 days");
    expect(html).toContain("sign in with the temporary password anyway");
  });

  it("returns the Spanish bundle for locale='es-MX'", () => {
    const { subject, html } = renderInviteUser({ ...baseArgs, locale: "es-MX" });

    expect(subject).not.toBe("");
    expect(html).toContain('<html lang="es-MX">');
    // The user-supplied data passes through the body regardless of locale.
    expect(html).toContain("Jane Doe");
    expect(html).toContain("jane@example.com");
    expect(html).toContain("hunter2hunter2");
    expect(html).toContain("https://example.com/login");
    // The en-US CTA literal should not survive (would indicate fallback to
    // en-US per-key, i.e. unpopulated bundle).
    expect(html).not.toContain("Accept invitation");
    expect(html).toContain("durante 7 días");
    expect(html).toContain("con la contraseña temporal");
  });

  it("falls back to en-US for an unsupported locale", () => {
    const { subject, html } = renderInviteUser({ ...baseArgs, locale: "fr-FR" });

    expect(subject).toBe("You've been invited");
    expect(html).toContain('<html lang="en-US">');
    expect(html).toContain("Accept invitation");
  });

  it("HTML-escapes user-provided values to defeat injection", () => {
    const { html } = renderInviteUser({
      ...baseArgs,
      name: '<script>alert("xss")</script>',
      email: 'evil"@example.com',
      tempPassword: "</p><script>x</script>",
      locale: "en-US",
    });

    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain("&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;");
    expect(html).toContain("evil&quot;@example.com");
    expect(html).toContain("&lt;/p&gt;&lt;script&gt;x&lt;/script&gt;");
  });

  it("escapes sign-in href attribute values", () => {
    const { html } = renderInviteUser({
      ...baseArgs,
      acceptUrl: "https://example.com/login?email=jane%40example.com&next=%2Fadmin",
      locale: "en-US",
    });

    expect(html).toContain(
      'href="https://example.com/login?email=jane%40example.com&amp;next=%2Fadmin"',
    );
  });

  it("rejects non-http sign-in URLs", () => {
    expect(() =>
      renderInviteUser({
        ...baseArgs,
        acceptUrl: "data:text/html,<script>alert(1)</script>",
        locale: "en-US",
      }),
    ).toThrow("Email link must use HTTP or HTTPS.");
  });
});
