// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import enCommon from "@wssp/locales/src/en-US/common.json";
import enHosts from "@wssp/locales/src/en-US/hosts.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, expect, it, vi } from "vitest";

const FP_OWNED = `sha256:${"7c".repeat(32)}`;
const FP_LOOSE = `sha256:${"5a".repeat(32)}`;

vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirectOnError: () => {} }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxHosts: {
      imageCache: {
        infiniteOptions: (options: { initialPageParam: undefined }) => ({
          queryKey: ["imageCache"],
          initialPageParam: options.initialPageParam,
          getNextPageParam: () => undefined,
          queryFn: async () => ({
            summary: {
              enabled: true,
              current: true,
              capBytes: String(2 ** 34),
              usedBytes: String(2 ** 30),
              foreignBytes: "0",
              acceptForeign: false,
              builder: false,
              acceptForeignBuilds: false,
            },
            items: [
              {
                id: "c1",
                fingerprint: FP_OWNED,
                compressedBytes: String(339 * 2 ** 20),
                unpackedBytes: null,
                origin: "fetched",
                pinned: false,
                reportedAt: new Date(),
                revision: { slug: "r3b-dns", revision: 2 },
              },
              {
                id: "c2",
                fingerprint: FP_LOOSE,
                compressedBytes: String(2 ** 20),
                unpackedBytes: null,
                origin: "captured",
                pinned: true,
                reportedAt: new Date(),
                revision: null,
              },
            ],
            nextCursor: null,
          }),
        }),
      },
    },
  },
}));

import { HostImageCacheCard } from "./host-image-cache-card";

afterEach(cleanup);

it("names owned images slug vN · size, keeps the fingerprint short and copyable", async () => {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    fallbackLng: false,
    ns: ["hosts", "common"],
    defaultNS: "hosts",
    resources: { "en-US": { hosts: enHosts, common: enCommon } },
    interpolation: { escapeValue: false },
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <I18nextProvider i18n={i18n}>
        <HostImageCacheCard hostId="host-1" lang="en-US" />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  expect(await screen.findByText("r3b-dns v2 · 339 MiB")).toBeTruthy();
  expect(screen.getByText(enHosts.imageCache.unnamed.replace("{{size}}", "1 MiB"))).toBeTruthy();
  expect(screen.getByText("sha256:7c7c7c7c7c7c…")).toBeTruthy();
  expect(document.body.textContent).not.toContain(FP_OWNED);
  expect(
    screen.getAllByRole("button", { name: `Copy ${enHosts.imageCache.fingerprint}` }),
  ).toHaveLength(2);
});
