import { createFileRoute } from "@tanstack/react-router";
import { LoginsPage } from "@/components/logins/logins-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/logins/")({
  staticData: { pendingShape: "list" },
  component: LoginsRoute,
});
function LoginsRoute() {
  const { lang } = Route.useParams();
  return <LoginsPage lang={lang} />;
}
