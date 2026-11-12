import { createFileRoute } from "@tanstack/react-router";
import { LoginDetailPage } from "@/components/logins/login-detail-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins/$loginId")({
  component: LoginRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function LoginRoute() {
  const { lang, loginId } = Route.useParams();
  return <LoginDetailPage lang={lang} loginId={loginId} />;
}
