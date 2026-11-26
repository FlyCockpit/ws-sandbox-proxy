import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { createFileRoute, Outlet } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { AppShellFrame, AppShellPending } from "@/components/app-shell";
import BottomNav from "@/components/bottom-nav";
import Header from "@/components/header";
import { OfflineBanner } from "@/components/offline-banner";
import { useDocumentLang } from "@/hooks/use-document-lang";
import { useMobileKeyboard } from "@/hooks/use-mobile-keyboard";
import { useUserLocaleSync } from "@/hooks/use-user-locale-sync";

export const Route = createFileRoute("/$lang/_app")({
  // App/auth/admin surfaces depend on browser-only auth, PWA, viewport, and
  // navigation side effects. Keep this branch client-rendered while public
  // pages remain SSR-capable under `/$lang/_public`.
  ssr: false,
  // What the server sends for this client-only branch, and the first frame of
  // a hard refresh: the shell itself (header, sidebar, bottom nav) with only
  // the page body as a skeleton, never a bare skeleton list.
  pendingComponent: AppShellPending,
  component: AppShellLayout,
});

function AppShellLayout() {
  // Service-worker registration (useAppUpdate) lives in __root so public
  // pages get it too — don't re-add it here.
  useDocumentLang();
  useUserLocaleSync();
  const mobileKeyboardOpen = useMobileKeyboard();

  return (
    <>
      <AppShellFrame
        mobileKeyboardOpen={mobileKeyboardOpen}
        header={
          <>
            <Header />
            <OfflineBanner />
          </>
        }
        bottomNav={<BottomNav hidden={mobileKeyboardOpen} />}
      >
        <Outlet />
      </AppShellFrame>
      {import.meta.env.DEV && (
        <>
          <TanStackRouterDevtools position="bottom-left" />
          <ReactQueryDevtools position="bottom" buttonPosition="bottom-right" />
        </>
      )}
    </>
  );
}
