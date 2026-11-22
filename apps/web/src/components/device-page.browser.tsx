import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import en from "@wssp/locales/src/en-US/auth.json";
import enCommon from "@wssp/locales/src/en-US/common.json";
import { createInstance } from "i18next";
import { createRoot } from "react-dom/client";
import { I18nextProvider } from "react-i18next";
import { DevicePage } from "./device-page";

function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
const tick = () => new Promise((resolve) => setTimeout(resolve, 10));
async function until(predicate: () => boolean) {
  for (let count = 0; count < 100; count++) {
    if (predicate()) return;
    await tick();
  }
  throw new Error("DOM condition timed out");
}
async function run() {
  const i18n = createInstance();
  await i18n.init({
    lng: "en-US",
    resources: { "en-US": { auth: en, common: enCommon } },
    interpolation: { escapeValue: false },
  });
  const output: string[] = [];
  for (const mode of ["empty", "create", "replace", "claim-failure", "deny"] as const) {
    if (Reflect.get(globalThis, "deviceTestMode") !== mode) continue;
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const summary = {
      kind: "host",
      requestId: "request-row-1",
      slug: "desk-01",
      existingHost:
        mode === "replace" ? { id: "host-reviewed", slug: "desk-01", label: "My desk" } : null,
    };
    Reflect.set(globalThis, "deviceTestSummary", summary);
    Reflect.set(globalThis, "deviceTestQueries", 0);
    // Seed the summary cache: even cached details must never bypass a failed/pending claim.
    client.setQueryData(
      ["device-login-request", "owner-1", "request-row-1", { userCode: "ABCDEFGH" }],
      summary,
    );
    client.setQueryData(["hosts"], []);
    let releaseClaim!: (response: Response) => void;
    const claim = new Promise<Response>((resolve) => {
      releaseClaim = resolve;
    });
    const requests: { url: string; method?: string; body: Record<string, unknown> }[] = [];
    globalThis.fetch = async (url, options) => {
      requests.push({
        url: String(url),
        method: options?.method,
        body: JSON.parse(String(options?.body ?? "{}")),
      });
      if (String(url).endsWith("/device")) {
        return claim;
      }
      return Response.json({ success: true, deviceRequestId: "request-row-1" });
    };
    root.render(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <DevicePage
            lang="en-US"
            ownerId="owner-1"
            userCode={mode === "empty" ? "" : "ABCDEFGH"}
          />
        </QueryClientProvider>
      </I18nextProvider>,
    );
    if (mode === "empty") {
      await until(() => container.textContent?.includes(en.device.enterCodeTitle) ?? false);
      assert(requests.length === 0, "empty code must not claim");
    } else {
      const approve = () =>
        [...container.querySelectorAll("button")].find(
          (button) => button.textContent === en.device.approve,
        );
      const deny = () =>
        [...container.querySelectorAll("button")].find(
          (button) => button.textContent === en.device.deny,
        );
      await until(() => !!approve() && requests.length === 1);
      assert(
        approve()?.disabled,
        "approve must remain disabled until claim succeeds, including cached summary",
      );
      assert(deny()?.disabled, "deny must remain disabled until initial claim settles");
      deny()?.click();
      await tick();
      assert(requests.length === 1, "disabled Deny cannot race the initial claim");
      assert(requests[0]?.method === "POST", "claim must use POST");
      assert(
        Reflect.get(globalThis, "deviceTestQueries") === 0,
        "summary must not fetch before claim",
      );
      releaseClaim(
        Response.json(
          mode === "claim-failure"
            ? { error_description: "failed" }
            : { success: true, deviceRequestId: "request-row-1" },
          { status: mode === "claim-failure" ? 403 : 200 },
        ),
      );
      if (mode === "claim-failure") {
        await tick();
        await tick();
        assert(approve()?.disabled, "failed claim must keep approve disabled");
        assert(deny()?.disabled, "failed claim must keep deny disabled");
        assert(
          Reflect.get(globalThis, "deviceTestQueries") === 0,
          "failed claim must not fetch summary",
        );
      } else if (mode === "deny") {
        await until(() => deny()?.disabled === false);
        deny()?.click();
        await until(() => container.textContent?.includes(en.device.denied.title) ?? false);
        assert(
          Number(requests.length) === 2 && requests[1]?.url.endsWith("/deny"),
          "successful initial claim goes directly to Deny",
        );
      } else {
        await until(() => approve()?.disabled === false);
        assert(
          container.textContent?.includes(
            mode === "replace" ? en.device.request.replaceTitle : en.device.request.newTitle,
          ),
          "display create/replace intent",
        );
        approve()?.click();
        await until(() => requests.length === 2);
        assert(requests[1]?.url.endsWith("/approve"), "approve endpoint");
        assert(
          JSON.stringify(requests[1]?.body.intent) ===
            JSON.stringify(
              mode === "replace"
                ? { kind: "replace", hostId: "host-reviewed" }
                : { kind: "create" },
            ),
          "submit displayed intent",
        );
        assert(!("grant" in (requests[1]?.body ?? {})), "a host approval never sends a grant");
        await until(() => container.textContent?.includes(en.device.approved.title) ?? false);
        const hostsLink = Array.from(container.querySelectorAll("a")).find(
          (anchor) => anchor.textContent === en.device.approved.viewHosts,
        );
        assert(
          hostsLink?.dataset.to === "/$lang/settings/hosts" &&
            hostsLink.dataset.params === JSON.stringify({ lang: "en-US" }),
          "approved page links to the locale-prefixed hosts list",
        );
      }
    }
    if (mode === "deny" || mode === "create" || mode === "replace") {
      assert(
        client.getQueryState([
          "device-login-request",
          "owner-1",
          "request-row-1",
          { userCode: "ABCDEFGH" },
        ])?.isInvalidated,
        "decision invalidates cached request details without reclaiming the code",
      );
      if (mode !== "deny") {
        assert(client.getQueryState(["hosts"])?.isInvalidated, "approval invalidates hosts");
      }
    }
    root.unmount();
    client.clear();
    container.remove();
    output.push(mode);
  }
  for (const mode of [
    "reentry-approved",
    "reentry-denied",
    "late-approve",
    "late-deny",
    "late-error",
  ] as const) {
    if (Reflect.get(globalThis, "deviceTestMode") !== mode) continue;
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    Reflect.set(globalThis, "deviceTestSummary", {
      kind: "host",
      requestId: "request-row-a",
      slug: "desk-01",
      existingHost: null,
    });
    Reflect.set(globalThis, "deviceTestToasts", 0);
    const requests: { code: string; action: string }[] = [];
    let release!: () => void;
    const delayed = new Promise<void>((resolve) => {
      release = resolve;
    });
    globalThis.fetch = async (url, options) => {
      const body: unknown = JSON.parse(String(options?.body));
      assert(body !== null && typeof body === "object" && "userCode" in body, "request body");
      const code = body.userCode;
      assert(typeof code === "string", "request code");
      const action = String(url).split("/").at(-1) ?? "";
      requests.push({ code, action });
      if (code === "FIRSTAAA" && action !== "device" && mode.startsWith("late-")) {
        await delayed;
        if (mode === "late-error")
          return Response.json({ error_description: "old request failed" }, { status: 409 });
      }
      const requestId = code === "FIRSTAAA" ? "request-row-a" : "request-row-b";
      return Response.json({ success: true, deviceRequestId: requestId });
    };
    const render = (code: string) =>
      root.render(
        <I18nextProvider i18n={i18n}>
          <QueryClientProvider client={client}>
            <DevicePage lang="en-US" ownerId="owner-1" userCode={code} />
          </QueryClientProvider>
        </I18nextProvider>,
      );
    const button = (text: string) =>
      [...container.querySelectorAll("button")].find((element) => element.textContent === text);
    render("FIRSTAAA");
    await until(() => button(en.device.approve)?.disabled === false);
    const deny = mode === "reentry-denied" || mode === "late-deny";
    button(deny ? en.device.deny : en.device.approve)?.click();
    await until(() =>
      requests.some(
        (request) => request.code === "FIRSTAAA" && request.action === (deny ? "deny" : "approve"),
      ),
    );
    if (mode.startsWith("reentry-"))
      await until(
        () =>
          container.textContent?.includes(
            deny ? en.device.denied.title : en.device.approved.title,
          ) ?? false,
      );
    Reflect.set(globalThis, "deviceTestSummary", {
      kind: "host",
      requestId: "request-row-b",
      slug: "desk-01",
      existingHost: null,
    });
    render("SECONDBB");
    await until(() => requests.some((request) => request.code === "SECONDBB"));
    await tick();
    await tick();
    assert(
      button(en.device.approve),
      "second code must show its controls, never the previous decision",
    );
    await until(
      () =>
        button(en.device.approve)?.disabled === false && button(en.device.deny)?.disabled === false,
    );
    const toastsBefore = Reflect.get(globalThis, "deviceTestToasts");
    release();
    await tick();
    await tick();
    await tick();
    assert(
      button(en.device.approve)?.disabled === false,
      "late A response must not change B controls",
    );
    assert(
      !container.textContent?.includes(en.device.approved.title) &&
        !container.textContent?.includes(en.device.denied.title),
      "B must not inherit A outcome",
    );
    assert(
      Reflect.get(globalThis, "deviceTestToasts") === toastsBefore,
      "late A success/error must not toast on B",
    );
    assert(
      requests.filter((request) => request.code === "SECONDBB" && request.action !== "device")
        .length === 0,
      "B was not implicitly decided",
    );
    button(en.device.deny)?.click();
    await until(() => container.textContent?.includes(en.device.denied.title) ?? false);
    assert(
      requests.some((request) => request.code === "SECONDBB" && request.action === "deny"),
      "B decision remains functional",
    );
    root.unmount();
    client.clear();
    container.remove();
    output.push(mode);
  }
  if (Reflect.get(globalThis, "deviceTestMode") === "host-limit") {
    // C52-R2-3: an approval refused at the owner's host cap names the limit.
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    Reflect.set(globalThis, "deviceTestSummary", {
      kind: "host",
      requestId: "request-row-1",
      slug: "desk-21",
      existingHost: null,
    });
    Reflect.set(globalThis, "deviceTestToastErrors", []);
    globalThis.fetch = async (url) => {
      if (String(url).endsWith("/approve"))
        return Response.json(
          {
            error: "CONFLICT",
            error_description: "This account has reached its limit of 20 hosts.",
            data: { code: "sandbox.owner_host_limit", limit: 20 },
          },
          { status: 409 },
        );
      return Response.json({ success: true, deviceRequestId: "request-row-1" });
    };
    root.render(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <DevicePage lang="en-US" ownerId="owner-1" userCode="ABCDEFGH" />
        </QueryClientProvider>
      </I18nextProvider>,
    );
    const approve = () =>
      [...container.querySelectorAll("button")].find(
        (button) => button.textContent === en.device.approve,
      );
    await until(() => approve()?.disabled === false);
    approve()?.click();
    await until(() => (Reflect.get(globalThis, "deviceTestToastErrors") as unknown[]).length > 0);
    const errors = Reflect.get(globalThis, "deviceTestToastErrors") as string[];
    assert(
      errors[0] === en.device.hostLimit_other.replace("{{count}}", "20"),
      `host-limit toast names the limit: ${errors[0]}`,
    );
    assert(
      !container.textContent?.includes(en.device.approved.title),
      "a refused approval is not shown as approved",
    );
    root.unmount();
    client.clear();
    container.remove();
    output.push("host-limit");
  }
  if (Reflect.get(globalThis, "deviceTestMode") === "user-refetch-error") {
    // A transient refetch error keeps the form with an inline retry; a
    // not-found refetch hides it.
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    Reflect.set(globalThis, "deviceTestSummary", {
      kind: "user",
      requestId: "request-row-u",
      status: "pending",
    });
    Reflect.set(globalThis, "deviceTestPoolQueries", 0);
    Reflect.set(globalThis, "deviceTestPools", [
      { id: "pool-1", slug: "build", label: "Build farm" },
    ]);
    client.setQueryData(["sdk-keys"], []);
    let claimStatus = 200;
    globalThis.fetch = async () =>
      claimStatus === 200
        ? Response.json({ success: true, deviceRequestId: "request-row-u" })
        : Response.json({ message: "busy" }, { status: claimStatus });
    root.render(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <DevicePage lang="en-US" ownerId="owner-1" userCode="USERCODE" />
        </QueryClientProvider>
      </I18nextProvider>,
    );
    const button = (text: string) =>
      [...container.querySelectorAll("button")].find((element) => element.textContent === text);
    const form = () => container.querySelector('input[name="name"]');
    await until(() => button(en.device.approve)?.disabled === false);
    // A failed pool refetch keeps the loaded pools selectable, with a retry.
    const labelled = (text: string) =>
      [...container.querySelectorAll("label")].find((label) => label.textContent?.includes(text));
    labelled(en.device.user.poolMode.SELECTED)?.click();
    await until(() => !!labelled("Build farm"));
    Reflect.set(globalThis, "deviceTestPoolError", new Error("pools down"));
    await client.refetchQueries({ queryKey: ["pools", "infinite"] }).catch(() => undefined);
    await until(() => container.textContent?.includes(en.device.user.poolsLoadError) ?? false);
    assert(labelled("Build farm"), "loaded pools stay visible after a failed refetch");
    Reflect.set(globalThis, "deviceTestPoolError", undefined);
    button("Try again")?.click();
    await until(() => !(container.textContent?.includes(en.device.user.poolsLoadError) ?? true));
    // A failed claim refetch keeps the form, disables approval and offers a retry.
    claimStatus = 503;
    await client.refetchQueries({ queryKey: ["device-login-claim"] }).catch(() => undefined);
    await until(() => !!button("Try again"));
    assert(form(), "a failed claim refetch keeps the approver's form");
    assert(button(en.device.approve)?.disabled === true, "approval waits for a good claim");
    claimStatus = 200;
    button("Try again")?.click();
    await until(() => button(en.device.approve)?.disabled === false);
    Reflect.set(globalThis, "deviceTestSummaryError", {
      code: "INTERNAL_SERVER_ERROR",
      status: 500,
      message: "boom",
    });
    await client.refetchQueries({ queryKey: ["device-login-request"] }).catch(() => undefined);
    await until(() => !!button("Try again"));
    assert(form(), "a transient error keeps the approver's form");
    assert(button(en.device.approve)?.disabled === true, "approval waits for a good summary");
    Reflect.set(globalThis, "deviceTestSummaryError", {
      code: "NOT_FOUND",
      status: 404,
      message: "gone",
    });
    button("Try again")?.click();
    await until(() => !form());
    assert(!button("Try again"), "a gone request offers no retry of the form");
    Reflect.set(globalThis, "deviceTestSummaryError", undefined);
    root.unmount();
    client.clear();
    container.remove();
    output.push("user-refetch-error");
  }
  for (const mode of ["user-default", "user-selected", "user-invalid", "user-deny"] as const) {
    // `wssp login` user login: the approver's grant is sent, never an intent.
    if (Reflect.get(globalThis, "deviceTestMode") !== mode) continue;
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    Reflect.set(globalThis, "deviceTestSummary", {
      kind: "user",
      requestId: "request-row-u",
      status: "pending",
    });
    Reflect.set(globalThis, "deviceTestPoolQueries", 0);
    Reflect.set(globalThis, "deviceTestPools", [
      { id: "pool-1", slug: "build", label: "Build farm" },
      { id: "pool-2", slug: "shared", label: "Shared", owner: { id: "owner-2", name: "Ana" } },
    ]);
    client.setQueryData(["sdk-keys"], []);
    const requests: { url: string; body: Record<string, unknown> }[] = [];
    globalThis.fetch = async (url, options) => {
      requests.push({ url: String(url), body: JSON.parse(String(options?.body ?? "{}")) });
      return Response.json({ success: true, deviceRequestId: "request-row-u" });
    };
    root.render(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <DevicePage lang="en-US" ownerId="owner-1" userCode="USERCODE" />
        </QueryClientProvider>
      </I18nextProvider>,
    );
    const button = (text: string) =>
      [...container.querySelectorAll("button")].find((element) => element.textContent === text);
    const labelled = (text: string) =>
      [...container.querySelectorAll("label")].find((label) => label.textContent?.includes(text));
    const setInput = (input: HTMLInputElement, value: string) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set?.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    };
    await until(() => button(en.device.approve)?.disabled === false);
    assert(
      container.textContent?.includes(en.device.user.approveTitle),
      "user login has its own title",
    );
    assert(
      container.textContent?.includes(en.device.user.warning.replace(/<\/?code>/g, "")),
      "user login warns to approve only a login you started",
    );
    assert(
      !container.textContent?.includes(en.device.request.slugLabel),
      "user login shows no host details",
    );
    assert(
      Reflect.get(globalThis, "deviceTestPoolQueries") === 0,
      "pools load only once selected pools are chosen",
    );
    if (mode === "user-deny") {
      button(en.device.deny)?.click();
      await until(() => container.textContent?.includes(en.device.denied.title) ?? false);
      assert(
        container.textContent?.includes(en.device.user.denied.description),
        "user deny explains no API key is issued",
      );
      assert(
        requests.length === 2 && requests[1]?.url.endsWith("/deny"),
        "deny posts only the deny",
      );
    } else {
      if (mode === "user-selected" || mode === "user-invalid") {
        labelled(en.device.user.poolMode.SELECTED)?.click();
        await until(() => Reflect.get(globalThis, "deviceTestPoolQueries") === 1);
      }
      if (mode === "user-invalid") {
        // No pool chosen and a half-typed limit (a number input would report
        // `1e` as "", i.e. no limit): the form refuses and sends nothing.
        const limit = container.querySelector<HTMLInputElement>('input[name="maxLiveSandboxes"]');
        assert(limit, "live sandbox limit input");
        setInput(limit, "1e");
        await tick();
        button(en.device.approve)?.click();
        await until(
          () =>
            (container.textContent?.includes(en.device.user.poolsRequired) ?? false) &&
            (container.textContent?.includes(
              en.device.user.maxLiveInvalid.replace("{{max}}", "1000"),
            ) ??
              false),
        );
        assert(requests.length === 1, "an invalid grant is never submitted");
      } else {
        if (mode === "user-selected") {
          await until(() => !!labelled("Shared"));
          labelled("Build farm")?.click();
          const clear = () =>
            [...container.querySelectorAll("button")].find((element) =>
              element.textContent?.startsWith("Clear selection"),
            );
          await until(() => clear()?.textContent === "Clear selection (1 pool)");
          // Clearing works even for a pool whose checkbox disappeared.
          clear()?.click();
          await until(() => !clear());
          labelled("Shared")?.click();
          labelled(en.device.user.access.write)?.click();
          labelled(en.device.user.ownSandboxesOnly)?.click();
          const limit = container.querySelector<HTMLInputElement>('input[name="maxLiveSandboxes"]');
          assert(limit, "live sandbox limit input");
          setInput(limit, "3");
          const name = container.querySelector<HTMLInputElement>('input[name="name"]');
          assert(name, "name input");
          setInput(name, "  laptop  ");
          await tick();
          // A background refetch of the same request keeps the choices and
          // holds approval until it settles.
          Reflect.set(globalThis, "deviceTestSummaryDelayMs", 100);
          const refetch = client.refetchQueries({ queryKey: ["device-login-request"] });
          await until(() => button(en.device.approve)?.disabled === true);
          await refetch;
          Reflect.set(globalThis, "deviceTestSummaryDelayMs", 0);
          await until(() => button(en.device.approve)?.disabled === false);
          await tick();
        }
        button(en.device.approve)?.click();
        await until(() => requests.length === 2);
        const body = requests[1]?.body ?? {};
        assert(requests[1]?.url.endsWith("/approve"), "approve endpoint");
        assert(!("intent" in body), "a user approval never sends an intent");
        const expected =
          mode === "user-selected"
            ? {
                access: "write",
                poolMode: "SELECTED",
                poolIds: ["pool-2"],
                ownSandboxesOnly: true,
                maxLiveSandboxes: 3,
                expiresInDays: 30,
                name: "laptop",
              }
            : {
                access: "read",
                poolMode: "ALL_USABLE",
                poolIds: [],
                ownSandboxesOnly: false,
                maxLiveSandboxes: null,
                expiresInDays: 30,
                name: "wssp login",
              };
        assert(
          JSON.stringify(body) === JSON.stringify({ userCode: "USERCODE", grant: expected }),
          `submit the chosen grant: ${JSON.stringify(body)}`,
        );
        await until(() => container.textContent?.includes(en.device.user.approved.title) ?? false);
        const keysLink = [...container.querySelectorAll("a")].find(
          (anchor) => anchor.textContent === en.device.user.approved.viewKeys,
        );
        assert(
          keysLink?.dataset.to === "/$lang/settings/sdk-keys" &&
            keysLink.dataset.params === JSON.stringify({ lang: "en-US" }),
          "approved user login links to SDK keys",
        );
        assert(
          !container.textContent?.includes(en.device.approved.viewHosts),
          "approved user login does not point at hosts",
        );
        assert(client.getQueryState(["sdk-keys"])?.isInvalidated, "approval invalidates SDK keys");
      }
    }
    root.unmount();
    client.clear();
    container.remove();
    output.push(mode);
  }
  if (Reflect.get(globalThis, "deviceTestMode") === "recycled-user-code") {
    const container = document.createElement("div");
    document.body.append(container);
    const root = createRoot(container);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    let claimGeneration = 0;
    let releaseSecondClaim!: () => void;
    const secondClaimBarrier = new Promise<void>((resolve) => {
      releaseSecondClaim = () => resolve();
    });
    globalThis.fetch = async (url) => {
      const action = String(url).split("/").at(-1) ?? "device";
      if (action === "device") {
        claimGeneration += 1;
        if (claimGeneration === 2) await secondClaimBarrier;
        const requestId = claimGeneration === 1 ? "request-row-a" : "request-row-b";
        Reflect.set(globalThis, "deviceTestSummary", {
          kind: "host",
          requestId,
          slug: claimGeneration === 1 ? "desk-old" : "desk-new",
          existingHost: null,
        });
        return Response.json({ success: true, deviceRequestId: requestId });
      }
      return Response.json({ success: true });
    };
    Reflect.set(globalThis, "deviceTestQueries", 0);
    root.render(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <DevicePage key="visit-1" lang="en-US" ownerId="owner-1" userCode="RECYCLE1" />
        </QueryClientProvider>
      </I18nextProvider>,
    );
    const approve = () =>
      [...container.querySelectorAll("button")].find(
        (button) => button.textContent === en.device.approve,
      );
    const deny = () =>
      [...container.querySelectorAll("button")].find(
        (button) => button.textContent === en.device.deny,
      );
    await until(() => approve()?.disabled === false);
    approve()?.click();
    await until(() => container.textContent?.includes(en.device.approved.title) ?? false);
    root.render(
      <I18nextProvider i18n={i18n}>
        <QueryClientProvider client={client}>
          <DevicePage key="visit-2" lang="en-US" ownerId="owner-1" userCode="RECYCLE1" />
        </QueryClientProvider>
      </I18nextProvider>,
    );
    await until(() => claimGeneration >= 2);
    assert(approve()?.disabled, "recycled code must not enable approval before fresh claim");
    assert(deny()?.disabled, "recycled code must not enable deny before fresh claim");
    assert(
      !container.textContent?.includes("desk-old"),
      "recycled code must not show stale summary",
    );
    releaseSecondClaim();
    await until(() => approve()?.disabled === false);
    assert(
      container.textContent?.includes("desk-new"),
      "recycled user code must not inherit prior terminal decision or cached summary",
    );
    assert(
      !container.textContent?.includes(en.device.approved.title),
      "recycled user code retained prior terminal decision",
    );
    root.unmount();
    client.clear();
    container.remove();
    output.push("recycled-user-code");
  }
  return output;
}
run()
  .then((cases) => {
    document.body.textContent = `DEVICE_DOM_PASS:${cases.join(",")}`;
  })
  .catch((error: unknown) => {
    document.body.textContent = `DEVICE_DOM_FAIL:${String(error)}`;
  });
