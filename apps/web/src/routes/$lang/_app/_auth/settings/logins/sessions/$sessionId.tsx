import { createFileRoute } from "@tanstack/react-router";
import { LoginSessionPage } from "@/components/logins/login-session-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins/sessions/$sessionId")({
  staticData: { pendingShape: "detail" },
  component: LoginSessionRoute,
});
function LoginSessionRoute() {
  const { lang, sessionId } = Route.useParams();
  return <LoginSessionPage lang={lang} sessionId={sessionId} />;
}
