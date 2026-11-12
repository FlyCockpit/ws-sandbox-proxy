// @vitest-environment jsdom
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import commonEn from "@wssp/locales/src/en-US/common.json";
import en from "@wssp/locales/src/en-US/sandboxes.json";
import commonEs from "@wssp/locales/src/es-MX/common.json";
import es from "@wssp/locales/src/es-MX/sandboxes.json";
import { createInstance } from "i18next";
import { I18nextProvider } from "react-i18next";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

const server = vi.hoisted(() => ({
  captures: [] as Record<string, unknown>[],
  captureError: null as unknown,
  views: 0,
}));
vi.mock("@/hooks/use-two-factor-redirect", () => ({ useTwoFactorRedirect: () => () => false }));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    sandboxes: {
      key: () => ["sandboxes"],
      captureSandbox: {
        mutationOptions: () => ({
          mutationFn: async (input: Record<string, unknown>) => {
            server.captures.push(input);
            const error = server.captureError;
            server.captureError = null;
            if (error) throw error;
            return { operationId: "op-1" };
          },
        }),
      },
      getOperationView: {
        queryOptions: ({ input }: { input: { operationId: string } }) => ({
          queryKey: ["op", input.operationId],
          queryFn: async () => {
            server.views += 1;
            return server.views === 1
              ? {
                  state: "RUNNING",
                  progress: { phase: "scrubbing", bytesDone: null, bytesTotal: null },
                  errorMessage: null,
                }
              : { state: "SUCCEEDED", progress: null, errorMessage: null };
          },
        }),
      },
    },
    sandboxTemplates: {
      listTemplates: {
        queryOptions: () => ({
          queryKey: ["templates"],
          queryFn: async () => ({
            items: [{ id: "tpl-1", label: "Base" }],
            nextCursor: null,
          }),
        }),
      },
    },
  },
}));

import { PROGRESS_REFETCH_MS, SaveAsTemplateDialog } from "./save-as-template-dialog";

beforeEach(() => {
  server.captures = [];
  server.captureError = null;
  server.views = 0;
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
});

async function mount(lang: string) {
  const i18n = createInstance();
  await i18n.init({
    lng: lang,
    resources: {
      "en-US": { sandboxes: en, common: commonEn },
      "es-MX": { sandboxes: es, common: commonEs },
    },
  });
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  const onClose = vi.fn();
  render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <SaveAsTemplateDialog
          sandbox={{ id: "sbx-1", template: { id: "tpl-1", label: "Base" } }}
          lang={lang}
          onClose={onClose}
        />
      </I18nextProvider>
    </QueryClientProvider>,
  );
  return { onClose };
}

it("translates the enabled close button for the real Spanish capture dialog", async () => {
  await mount("es-MX");
  expect(screen.getByRole("button", { name: commonEs.actions.close })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Close" })).toBeNull();
});

it.each([
  ["en-US", en],
  ["es-MX", es],
])("%s captures with a warning, then follows the phases to success", async (lang, copy) => {
  // The progress poll runs on fake time instead of a real 2 s wait.
  vi.useFakeTimers({ shouldAdvanceTime: true });
  await mount(lang);
  expect(screen.getByText(copy.capture.warning)).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: copy.capture.submit }));
  await waitFor(() => expect(server.captures).toHaveLength(1));
  expect(server.captures[0]).toMatchObject({
    id: "sbx-1",
    templateId: "tpl-1",
    tag: "latest",
    scrubPaths: [],
  });
  expect(typeof server.captures[0]?.idempotencyKey).toBe("string");
  expect(await screen.findByText(copy.capture.phase.scrubbing)).toBeTruthy();
  expect(screen.queryByText(copy.capture.succeeded)).toBeNull();
  await act(async () => {
    await vi.advanceTimersByTimeAsync(PROGRESS_REFETCH_MS);
  });
  expect(await screen.findByText(copy.capture.succeeded)).toBeTruthy();
});

it("rejects an invalid tag or a relative path without sending anything", async () => {
  await mount("en-US");
  const tag = screen.getByLabelText(en.capture.tag);
  await userEvent.clear(tag);
  await userEvent.type(tag, "Not Valid");
  await userEvent.type(screen.getByLabelText(en.capture.scrubPaths), "relative/path");
  await userEvent.click(screen.getByRole("button", { name: en.capture.submit }));
  expect(await screen.findByText(en.capture.invalidTag)).toBeTruthy();
  expect(screen.getByText(en.capture.invalidPaths)).toBeTruthy();
  expect(server.captures).toHaveLength(0);
});

it("explains a busy refusal and a retry is a new intent", async () => {
  server.captureError = { data: { code: "sandbox.capture_busy" } };
  await mount("en-US");
  await userEvent.click(screen.getByRole("button", { name: en.capture.submit }));
  expect(await screen.findByText(en.capture.problem.busy)).toBeTruthy();
  await userEvent.click(screen.getByRole("button", { name: en.capture.submit }));
  await waitFor(() => expect(server.captures).toHaveLength(2));
  expect(server.captures[1]?.idempotencyKey).not.toBe(server.captures[0]?.idempotencyKey);
});

it("explains that an offloaded disk must be restored before a capture", async () => {
  server.captureError = { data: { code: "sandbox.disk_offloaded" } };
  await mount("en-US");
  await userEvent.click(screen.getByRole("button", { name: en.capture.submit }));
  expect(await screen.findByText(en.capture.problem.offloaded)).toBeTruthy();
});
