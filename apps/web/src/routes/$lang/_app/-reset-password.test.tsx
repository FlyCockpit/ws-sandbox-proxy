// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import en from "../../../../../../packages/locales/src/en-US/auth.json";
import es from "../../../../../../packages/locales/src/es-MX/auth.json";

const fx = vi.hoisted(() => ({
  reset: vi.fn(),
  navigate: vi.fn(),
  lang: "en-US",
  messages: {} as Record<string, unknown>,
}));
vi.mock("@tanstack/react-router", async (importOriginal) => ({
  lazyRouteComponent: (await importOriginal<typeof import("@tanstack/react-router")>())
    .lazyRouteComponent,
  createFileRoute: () => (options: Record<string, unknown>) => ({
    options,
    useParams: () => ({ lang: fx.lang }),
    useSearch: () => ({ token: "valid-link" }),
  }),
  Link: ({ children }: { children: ReactNode }) => <a>{children}</a>,
  redirect: vi.fn(),
  useNavigate: () => fx.navigate,
}));
vi.mock("@tanstack/react-query", () => ({
  useQuery: () => ({ isPending: false, isError: false }),
  useMutation: () => ({ mutateAsync: vi.fn() }),
}));
vi.mock("@/utils/orpc", () => ({
  orpc: {
    appConfig: { queryOptions: () => ({}) },
    setup: { claimFirstAdmin: { mutationOptions: () => ({}) } },
  },
}));
vi.mock("@/lib/auth-client", () => ({ authClient: { resetPassword: fx.reset } }));
vi.mock("@/lib/route-session", () => ({ resolveRouteSession: vi.fn() }));
vi.mock("@wssp/ui/components/sileo", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/utils/friendly-error", () => ({ friendly: () => "Retry", isRateLimit: () => false }));
vi.mock("react-i18next", () => ({
  useTranslation: () => ({
    t: (key: string) => {
      const parts = key.replace(/^auth:/, "").split(".");
      let value: unknown = fx.messages;
      for (const part of parts) value = (value as Record<string, unknown>)?.[part];
      return typeof value === "string" ? value : key;
    },
  }),
}));
const { Route } = await import("./reset-password");
const Page = Route.options.component as (() => ReactNode) & { preload?: () => Promise<void> };
await Page.preload?.();
beforeEach(() => {
  vi.clearAllMocks();
  fx.reset.mockReset();
});
afterEach(cleanup);

function submit(messages: typeof en) {
  fireEvent.change(screen.getByLabelText(messages.resetPassword.newPasswordLabel), {
    target: { value: "replacement-password" },
  });
  fireEvent.change(screen.getByLabelText(messages.resetPassword.confirmPasswordLabel), {
    target: { value: "replacement-password" },
  });
  fireEvent.click(screen.getByRole("button", { name: messages.resetPassword.submit }));
}

describe.each([
  ["en-US", en],
  ["es-MX", es],
] as const)("reset page %s", (lang, messages) => {
  beforeEach(() => {
    fx.lang = lang;
    fx.messages = messages;
  });
  it("keeps both passwords on a pre-sweep 503 and retries the same link", async () => {
    fx.reset
      .mockResolvedValueOnce({ error: { status: 503, code: "SERVICE_UNAVAILABLE" } })
      .mockResolvedValueOnce({ error: null });
    render(<Page />);
    submit(messages);
    const alert = await screen.findByRole("alert");
    expect(alert.textContent).toBe(messages.resetPassword.retryable);
    expect(screen.queryByText(messages.resetPassword.invalidTitle)).toBeNull();
    for (const label of [
      messages.resetPassword.newPasswordLabel,
      messages.resetPassword.confirmPasswordLabel,
    ]) {
      expect((screen.getByLabelText(label) as HTMLInputElement).value).toBe("replacement-password");
    }
    fireEvent.click(screen.getByRole("button", { name: messages.resetPassword.retry }));
    await waitFor(() => expect(fx.navigate).toHaveBeenCalledOnce());
    expect(fx.reset).toHaveBeenCalledTimes(2);
    expect(fx.reset.mock.calls[1]).toEqual([
      { token: "valid-link", newPassword: "replacement-password" },
    ]);
  });
  it("shows the invalid-link card only for an invalid or expired token", async () => {
    fx.reset.mockResolvedValueOnce({ error: { status: 400, code: "INVALID_TOKEN" } });
    render(<Page />);
    submit(messages);
    expect(await screen.findByText(messages.resetPassword.invalidTitle)).toBeTruthy();
    expect(screen.queryByLabelText(messages.resetPassword.newPasswordLabel)).toBeNull();
  });
  it("keeps the form for errors other than invalid tokens", async () => {
    fx.reset.mockResolvedValueOnce({ error: { status: 400, code: "PASSWORD_TOO_SHORT" } });
    render(<Page />);
    submit(messages);
    expect(await screen.findByRole("alert")).toBeTruthy();
    expect(screen.queryByText(messages.resetPassword.invalidTitle)).toBeNull();
    expect(screen.getByLabelText(messages.resetPassword.newPasswordLabel)).toBeTruthy();
  });
});
