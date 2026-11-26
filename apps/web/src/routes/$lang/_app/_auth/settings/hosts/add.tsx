import { createFileRoute } from "@tanstack/react-router";
import { AddHostPage } from "@/components/hosts/add-host-page";
export const Route = createFileRoute("/$lang/_app/_auth/settings/hosts/add")({
  staticData: { pendingShape: "form" },
  component: AddHostRoute,
});
function AddHostRoute() {
  const { lang } = Route.useParams();
  return <AddHostPage lang={lang} />;
}
