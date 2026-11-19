import { describe, expect, it, vi } from "vitest";
import {
  createTunnel,
  deleteTunnel,
  mintAccessLink,
  previewUrls,
  revokeAccessLink,
  rotateTunnelToken,
  TunServerError,
  tunnelsByLabel,
  tunnelsWithLabelPrefix,
} from "./tun-client";

const server = { apiUrl: "https://tunnel.example.com", credential: `tnsvc_${"s".repeat(43)}` };
const token = `tntun_${"t".repeat(43)}`;

function respond(status: number, body?: unknown) {
  return vi.fn(async (_url: string | URL | Request, _init?: RequestInit) =>
    body === undefined
      ? new Response(null, { status })
      : new Response(JSON.stringify(body), {
          status,
          headers: { "content-type": "application/json" },
        }),
  );
}

describe("tunnel server client", () => {
  it("revokes an access link by its id; a link the server no longer has is not an error", async () => {
    const fetch = respond(204);
    await expect(revokeAccessLink(server, "al_0123456789abcdef", fetch)).resolves.toBe(true);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("https://tunnel.example.com/v1/access-links/al_0123456789abcdef");
    expect(init?.method).toBe("DELETE");
    expect(init?.redirect).toBe("manual");
    await expect(
      revokeAccessLink(server, "al_0123456789abcdef", respond(404, { error: "not_found" })),
    ).resolves.toBe(false);
    await expect(
      revokeAccessLink(server, "al_0123456789abcdef", respond(500)),
    ).rejects.toBeInstanceOf(TunServerError);
    // Never a path built from anything but a link id.
    const never = respond(204);
    for (const id of ["../tunnels/abc", "al_x/y", "abc123", "al_"])
      await expect(revokeAccessLink(server, id, never)).rejects.toBeInstanceOf(TunServerError);
    expect(never).not.toHaveBeenCalled();
  });

  it("creates a link-mode tunnel without ICE and never follows redirects", async () => {
    const fetch = respond(201, {
      id: "abc123def4",
      tunnel_token: token,
      host_template: "{port}-abc123def4.tunnel.example.com",
      expires_at: 1,
    });
    const created = await createTunnel(server, { label: "wssp:sbx", maxPorts: 2 }, fetch);
    expect(created).toEqual({
      id: "abc123def4",
      token,
      hostTemplate: "{port}-abc123def4.tunnel.example.com",
    });
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("https://tunnel.example.com/v1/tunnels");
    expect(init?.redirect).toBe("manual");
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${server.credential}`);
    expect(JSON.parse(String(init?.body))).toMatchObject({
      label: "wssp:sbx",
      max_ports: 2,
      inject_ice: false,
      access: { mode: "link" },
    });
  });

  it("refuses malformed answers", async () => {
    await expect(
      createTunnel(
        server,
        { label: "x", maxPorts: 1 },
        respond(201, { id: "a/b", tunnel_token: token, host_template: "{port}-a.x" }),
      ),
    ).rejects.toBeInstanceOf(TunServerError);
    await expect(
      rotateTunnelToken(server, "abc123", respond(200, { tunnel_token: "tncli_nope" })),
    ).rejects.toBeInstanceOf(TunServerError);
    // A redirect is an error, not a hop.
    await expect(rotateTunnelToken(server, "abc123", respond(302))).rejects.toMatchObject({
      status: 302,
    });
  });

  it("maps quota and not-found answers", async () => {
    const quota = await createTunnel(
      server,
      { label: "x", maxPorts: 1 },
      respond(429, { error: { code: "tunnel_quota", message: "" } }),
    ).catch((error) => error);
    expect(quota).toBeInstanceOf(TunServerError);
    expect((quota as TunServerError).quota).toBe(true);
    expect((quota as TunServerError).code).toBe("tunnel_quota");
    // Deleting a deleted tunnel is fine.
    await expect(deleteTunnel(server, "abc123", respond(404))).resolves.toBeUndefined();
    await expect(deleteTunnel(server, "abc123", respond(500))).rejects.toBeInstanceOf(
      TunServerError,
    );
  });

  it("mints https links only", async () => {
    const link = await mintAccessLink(
      server,
      "abc123",
      { port: 3000, ttlSeconds: 60, singleUse: true, sessionTtlSeconds: 3600 },
      respond(201, {
        id: "al_0123456789abcdef",
        url: "https://tunnel.example.com/__access/3000-abc123/tnacc_x",
        expires_at: 1_700_000_000,
      }),
    );
    expect(link.id).toBe("al_0123456789abcdef");
    expect(link.expiresAt.toISOString()).toBe("2023-11-14T22:13:20.000Z");
    await expect(
      mintAccessLink(
        server,
        "abc123",
        { port: 3000, ttlSeconds: 60, singleUse: true, sessionTtlSeconds: 3600 },
        respond(201, { id: "al_0123", url: "http://x.example/a", expires_at: 1 }),
      ),
    ).rejects.toBeInstanceOf(TunServerError);
  });

  it("builds preview origins from the host template", () => {
    expect(previewUrls("{port}-abc.tunnel.example.com", [3000, 5173])).toEqual([
      { port: 3000, url: "https://3000-abc.tunnel.example.com" },
      { port: 5173, url: "https://5173-abc.tunnel.example.com" },
    ]);
    expect(previewUrls(null, [3000])).toEqual([]);
  });

  it("lists a label strictly and follows next_cursor", async () => {
    const pages = [
      { tunnels: [{ id: "a1", label: "wssp:s" }], next_cursor: "c1" },
      { tunnels: [{ id: "b2", label: "wssp:s" }], next_cursor: null },
    ];
    const fetch = vi.fn(async () => new Response(JSON.stringify(pages.shift()), { status: 200 }));
    await expect(tunnelsByLabel(server, "wssp:s", fetch)).resolves.toEqual(["a1", "b2"]);
    expect(String(fetch.mock.calls[1]?.[0])).toContain("cursor=c1");
    // A missing list or another label is an error, never "nothing there".
    await expect(tunnelsByLabel(server, "wssp:s", respond(200, {}))).rejects.toBeInstanceOf(
      TunServerError,
    );
    await expect(
      tunnelsByLabel(server, "wssp:s", respond(200, { tunnels: [{ id: "x1", label: "other" }] })),
    ).rejects.toBeInstanceOf(TunServerError);
  });

  it("checks the caller's deadline before every page request", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({ tunnels: [{ id: "a1", label: "wssp:s" }], next_cursor: "c1" }),
        ),
      );
    let pages = 0;
    const late = new Error("late");
    await expect(
      tunnelsByLabel(server, "wssp:s", fetch, () => {
        pages += 1;
        if (pages === 2) throw late;
      }),
    ).rejects.toBe(late);
    // The second page was never requested.
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("lists every tunnel with a label prefix and keeps only those", async () => {
    const pages = [
      {
        tunnels: [
          { id: "a1", label: "wssp:s1" },
          { id: "z9", label: "squadron:x" },
        ],
        next_cursor: "c1",
      },
      { tunnels: [{ id: "b2", label: "wssp:s2" }], next_cursor: "" },
    ];
    const fetch = vi.fn(async () => new Response(JSON.stringify(pages.shift()), { status: 200 }));
    await expect(tunnelsWithLabelPrefix(server, "wssp:", null, fetch)).resolves.toEqual({
      ids: ["a1", "b2"],
      next: null,
    });
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("label=");
    await expect(
      tunnelsWithLabelPrefix(server, "wssp:", null, respond(200, {})),
    ).rejects.toBeInstanceOf(TunServerError);
    // A long listing ends a run after 20 pages with where to continue.
    const endless = vi.fn(
      async () =>
        new Response(
          JSON.stringify({ tunnels: [{ id: "q1", label: "other" }], next_cursor: "n" }),
          {
            status: 200,
          },
        ),
    );
    await expect(tunnelsWithLabelPrefix(server, "wssp:", "c7", endless)).resolves.toEqual({
      ids: [],
      next: "n",
    });
    expect(String(endless.mock.calls[0]?.[0])).toContain("cursor=c7");
    expect(endless).toHaveBeenCalledTimes(20);
  });
});
