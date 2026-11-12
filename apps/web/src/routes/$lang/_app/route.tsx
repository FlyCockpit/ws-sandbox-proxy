import { ReactQueryDevtools } from "@tanstack/react-query-devtools";
import { createFileRoute, Outlet } from "@tanstack/react-router";
import { TanStackRouterDevtools } from "@tanstack/react-router-devtools";
import { cn } from "@wssp/ui/lib/utils";
import BottomNav from "@/components/bottom-nav";
import Header from "@/components/header";
import { SkipToContent } from "@/components/skip-to-content";
import { useDocumentLang } from "@/hooks/use-document-lang";
import { useMobileKeyboard } from "@/hooks/use-mobile-keyboard";
import { useUserLocaleSync } from "@/hooks/use-user-locale-sync";
import { MAIN_SCROLLER_ID } from "@/lib/main-scroller";

export const Route = createFileRoute("/$lang/_app")({
  // App/auth/admin surfaces depend on browser-only auth, PWA, viewport, and
  // navigation side effects. Keep this branch client-rendered while public
  // pages remain SSR-capable under `/$lang/_public`.
  ssr: false,
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
      <SkipToContent />
      <div
        className={cn(
          "grid h-svh min-w-0 grid-rows-[auto_1fr_auto] md:grid-rows-[auto_1fr] md:pb-[var(--safe-area-bottom)]",
          !mobileKeyboardOpen && "pb-[calc(3.5rem_+_var(--safe-area-bottom))]",
        )}
        style={{
          paddingTop: "var(--safe-area-top)",
          paddingLeft: "var(--safe-area-left)",
          paddingRight: "var(--safe-area-right)",
        }}
      >
        <div>
          <Header />
        </div>
        <main
          id="main-content"
          tabIndex={-1}
          data-scroll-restoration-id={MAIN_SCROLLER_ID}
          className="relative [container-type:size] min-h-0 min-w-0 overflow-y-auto overflow-x-clip overscroll-contain [scrollbar-gutter:stable]"
        >
          <Outlet />
        </main>
        <BottomNav hidden={mobileKeyboardOpen} />
      </div>
      {import.meta.env.DEV && (
        <>
          <TanStackRouterDevtools position="bottom-left" />
          <ReactQueryDevtools position="bottom" buttonPosition="bottom-right" />
        </>
      )}
    </>
  );
}
