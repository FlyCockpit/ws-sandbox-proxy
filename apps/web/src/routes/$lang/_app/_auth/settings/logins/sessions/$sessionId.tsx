import { createFileRoute } from "@tanstack/react-router";
import { LoginSessionPage } from "@/components/logins/login-session-page";
import { SkeletonList } from "@/components/skeleton-list";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins/sessions/$sessionId")({
  component: LoginSessionRoute,
  pendingComponent: () => <SkeletonList count={3} />,
});
function LoginSessionRoute() {
  const { lang, sessionId } = Route.useParams();
  return <LoginSessionPage lang={lang} sessionId={sessionId} />;
}
