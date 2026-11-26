import { createFileRoute } from "@tanstack/react-router";
import { LoginDetailPage } from "@/components/logins/login-detail-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins/$loginId")({
  staticData: { pendingShape: "detail" },
  component: LoginRoute,
});
function LoginRoute() {
  const { lang, loginId } = Route.useParams();
  return <LoginDetailPage lang={lang} loginId={loginId} />;
}
