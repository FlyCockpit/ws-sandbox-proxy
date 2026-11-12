import { createWsspClient, isBuildFailed, Template } from "@wssp/sdk";

// A key with `templates:build` (plus `templates:write`, because `name` creates
// the template when it does not exist yet).
const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const template = Template()
  .fromTemplate("base") // your registered base template (slug, slug:tag or revision/<id>)
  .aptInstall(["jq"])
  .setEnvs({ APP_ENV: "production" })
  .setWorkdir("/home/user/app")
  .copy("app/", "./", { owner: "user" })
  .runCmd("make install")
  .egress({ presets: ["ubuntu-apt"] });

// Packs ./context (ustar, hashed), accepts the build, uploads the context,
// then follows the build to its end, streaming step output.
const build = await wssp.templates.build(template, {
  name: "my-app",
  hostId: "<owned-host-id>",
  contextDir: "./context",
  timeoutMinutes: 20,
  onBuildLogs: (entry) => {
    if (entry.type === "phase") console.log(`==> ${entry.message}`);
    else if (entry.type === "output") process.stdout.write(entry.text);
  },
});
if (isBuildFailed(build)) {
  console.error(`build ${build.id} ${build.state}: ${build.errorCode} ${build.errorDetail ?? ""}`);
} else {
  // `latest` of my-app now points at the new revision.
  console.log(`revision ${build.revisionId ?? build.cacheHitRevisionId}`);
}
