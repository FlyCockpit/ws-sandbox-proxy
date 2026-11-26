import { useForm, useStore } from "@tanstack/react-form";
import { useInfiniteQuery, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import { sandboxNameSchema } from "@wssp/api/sandbox/contracts";
import { revisionRootTaint } from "@wssp/api/sandbox/guest-sudo-policy";
import { Button, buttonVariants } from "@wssp/ui/components/button";
import { AdvancedSection, FormPage, FormSection } from "@wssp/ui/components/form-page";
import {
  hasKeyValueErrors,
  KeyValueEditor,
  type KeyValueEntry,
} from "@wssp/ui/components/key-value-editor";
import { Label } from "@wssp/ui/components/label";
import { SelectItem } from "@wssp/ui/components/select";
import { toast } from "@wssp/ui/components/sileo";
import { Switch } from "@wssp/ui/components/switch";
import { TextareaField, TextField } from "@wssp/ui/components/text-field";
import { isBlankEntry } from "@wssp/ui/lib/dotenv";
import { ArrowLeft } from "lucide-react";
import { type ReactNode, useId, useMemo, useRef, useState } from "react";
import { Trans, useTranslation } from "react-i18next";
import { z } from "zod";
import { FormPageStatus } from "@/components/form-page-status";
import { FormSelect } from "@/components/form-select";
import { UnsavedChangesGuard } from "@/components/leave-guard-dialog";
import { LoadMore } from "@/components/load-more";
import { LoginsPicker } from "@/components/logins/login-picker";
import { useLoginsAvailability } from "@/components/logins/logins-shared";
import {
  lifetimeText,
  PickerStatus,
  PoolTrustNotice,
  SizeFields,
  type SizeValues,
  sizeSummary,
} from "@/components/sandboxes/create-sandbox-parts";
import { LifetimeFields } from "@/components/sandboxes/sandbox-parts";
import { SegmentedControl } from "@/components/segmented-control";
import { useKeyValueEditorLabels } from "@/hooks/use-form-field-labels";
import { useRerenderAt } from "@/hooks/use-rerender-at";
import { useStatusClock } from "@/hooks/use-status-clock";
import { useSubmissionFence } from "@/hooks/use-submission-fence";
import { useTwoFactorRedirect, useTwoFactorRedirectOnError } from "@/hooks/use-two-factor-redirect";
import { translateText } from "@/i18n/translate-text";
import { credentialErrorKey } from "@/lib/credential-errors";
import { focusFirstInvalidControl, hasInvalidControl } from "@/lib/focus-invalid-control";
import { hostConnectionState, nextHostStateChangeAt } from "@/lib/host-status";
import {
  entriesFitDotenvText,
  entriesToRecord,
  isUnreadLine,
  PROTOTYPE_NAMES,
  stateField,
} from "@/lib/key-value-entries";
import {
  type CapacityWaitChoice,
  capacityWaitChoices,
  createLifetimeDefault,
  DEFAULT_SANDBOX_DRAFT,
  IntentKeys,
  isCreateInputMistake,
  LEASE_DEFAULT_MS,
  type LifetimeLimit,
  parsePreviewPorts,
  type SandboxDraft,
  type SandboxDraftProblem,
  type SandboxProblem,
  sandboxDraftInput,
  sandboxDraftProblems,
  sandboxProblem,
} from "@/lib/sandbox-rules";
import { gibFromMib, hostChoice, hostSizeCap, type SizeCap } from "@/lib/sandbox-size";
import { orpc } from "@/utils/orpc";

/**
 * Create a sandbox (full page; it replaced the create dialog). Essential
 * first: template, where it runs, name and lifetime, each with a safe
 * default; everything else sits in collapsed Advanced sections that show
 * their current values. Placement and template identity are independent and
 * only the server decides compatibility and capacity: the page only prevents
 * obvious mistakes. Lost responses replay the exact accepted intent.
 */

/** Picker page size (the procedures' maximum). */
const PICKER_LIMIT = 100;
/** How long a pool capacity read is reused (the server allows 30 a minute per owner). */
const POOL_CAPACITY_STALE_MS = 30_000;
/**
 * Host list refresh, as on the Hosts page: a connected host keeps reading as
 * connected (its heartbeat goes stale after 30 s), and its free capacity is
 * current while the page stays open, not only after a refused create.
 */
const HOSTS_REFETCH_MS = 15_000;

const cursorPages = {
  initialPageParam: undefined as string | undefined,
  getNextPageParam: (lastPage: { nextCursor: string | null }) => lastPage.nextCursor ?? undefined,
};

/** Problems after which the same request cannot succeed: the next submit gets a new key. */
const DEFINITE: ReadonlySet<SandboxProblem> = new Set([
  "notFound",
  "stateChanged",
  "keyReused",
  "hostCapacity",
  "capacityRam",
  "capacityVcpu",
  "capacityDisk",
  "capacityStorage",
  "capacityCeiling",
  "sizeInvalid",
  "diskBelowImage",
  "sizeUnsupported",
  "hostUnavailable",
  "poolPolicyChanged",
  "shareQuota",
  "memberQuota",
  "poolFull",
  "poolUnavailable",
  "poolIncompatible",
  "poolMissing",
  "hostDraining",
  "hostDeleting",
  "templateMissing",
  "imageMissing",
  "templateNotOnHost",
  "tunnelUnavailable",
  "hostNoEgress",
  "egressGuardUnavailable",
  "openEgressNotPermitted",
  "labels",
  "nameTaken",
  "nameInvalid",
  "egress",
  "invalid",
  "forbidden",
]);

/** Where a problem is shown: next to its field, or at the action bar (`null`). */
type ProblemPlace =
  | "name"
  | "placement"
  | "template"
  | "version"
  | "lifetime"
  | "size"
  | "envs"
  | "labels"
  | "network"
  | "logins"
  | "wait";

const DRAFT_PLACE: Record<SandboxDraftProblem, ProblemPlace> = {
  name: "name",
  noHost: "placement",
  unknownHost: "placement",
  unknownPool: "placement",
  noTemplate: "template",
  templateOffHost: "template",
  lifetime: "lifetime",
  labelsSyntax: "labels",
  labels: "labels",
  envs: "envs",
  egress: "network",
  previewPorts: "network",
  cpuCount: "size",
  memoryMiB: "size",
  diskGiB: "size",
  credentials: "logins",
};

const SERVER_PLACE: Partial<Record<SandboxProblem, ProblemPlace>> = {
  nameTaken: "name",
  nameInvalid: "name",
  hostCapacity: "placement",
  hostUnavailable: "placement",
  hostDraining: "placement",
  hostDeleting: "placement",
  poolFull: "placement",
  poolUnavailable: "placement",
  poolIncompatible: "placement",
  poolMissing: "placement",
  poolPolicyChanged: "placement",
  shareQuota: "placement",
  memberQuota: "placement",
  capacityReserved: "placement",
  capacityStorage: "placement",
  capacityCeiling: "placement",
  capacityRam: "size",
  capacityVcpu: "size",
  capacityDisk: "size",
  sizeInvalid: "size",
  diskBelowImage: "size",
  sizeUnsupported: "size",
  templateMissing: "template",
  imageMissing: "template",
  templateNotOnHost: "template",
  templateUnavailable: "template",
  leaseExceedsPolicy: "lifetime",
  labels: "labels",
  egress: "network",
  tunnelUnavailable: "network",
  waitExceedsPolicy: "wait",
  queueFull: "wait",
};

/** Advanced sections a problem lives in (opened when it is shown). */
type Section = "version" | "size" | "envs" | "labels" | "network" | "access" | "logins" | "wait";
const SECTION_OF: Partial<Record<ProblemPlace, Section>> = {
  version: "version",
  size: "size",
  envs: "envs",
  labels: "labels",
  network: "network",
  logins: "logins",
  wait: "wait",
};

/**
 * Capacity refusals that name one size field: shown as that field's error
 * (so it is marked invalid and receives focus), not as a loose line.
 */
const SIZE_FIELD_OF: Partial<Record<SandboxProblem, keyof SizeValues>> = {
  capacityRam: "memoryMiB",
  capacityVcpu: "cpuCount",
  capacityDisk: "diskGiB",
  diskBelowImage: "diskGiB",
};

/** Env names the platform sets; the editor's default key rule is POSIX names. */
const ENV_VALIDATION = { reservedKeys: ["HOME", "SHELL", "TERM", ...PROTOTYPE_NAMES] };
/** Label names: any text without spaces, quotes or `=` (the server checks the rest). */
const LABEL_VALIDATION = { reservedKeys: [...PROTOTYPE_NAMES], keyPattern: /^[^\s"'=]+$/ };

/** Editor entries as the draft's JSON object (blank: none). */
const entriesJson = (entries: readonly KeyValueEntry[]) => {
  const record = entriesToRecord(entries);
  return Object.keys(record).length > 0 ? JSON.stringify(record) : "";
};
const sizeNumber = (text: string): number | null => (text.trim() ? Number(text) : null);
const lineCount = (text: string) => text.split("\n").filter((line) => line.trim()).length;

export function CreateSandboxPage({
  lang,
  initialHostId,
}: {
  lang: string;
  /** `?host=<id>` (e.g. "Create a sandbox on it" after enrolling a host): start on that host. */
  initialHostId?: string;
}) {
  const { t } = useTranslation(["sandboxes", "hosts", "common"]);
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  // Forced 2FA enrolment wins over the unsaved-changes prompt below.
  const redirect = useTwoFactorRedirect(lang, { overridesUnsavedInput: true });
  const ids = {
    host: useId(),
    pool: useId(),
    template: useId(),
    revision: useId(),
    wait: useId(),
    placement: useId(),
    problem: useId(),
  };
  const formRef = useRef<HTMLFormElement>(null);
  const fence = useSubmissionFence();
  const [logicalId, setLogicalId] = useState("");
  const intents = useRef(new IntentKeys());
  const lastSubmitted = useRef<string | null>(null);
  const lastQuote = useRef<number | undefined>(undefined);
  const [placementChoice, setPlacementChoice] = useState<"host" | "pool" | null>(
    initialHostId ? "host" : null,
  );
  const [lifetimeTouched, setLifetimeTouched] = useState(false);
  const [attempted, setAttempted] = useState(false);
  const [problem, setProblem] = useState<SandboxProblem | null>(null);
  const [loginProblemKey, setLoginProblemKey] = useState<string | null>(null);
  const [envRows, setEnvRows] = useState<KeyValueEntry[]>([]);
  // Bumped to remount the env editor (and drop its .env text) when cleared.
  const [envEditor, setEnvEditor] = useState(0);
  const [labelRows, setLabelRows] = useState<KeyValueEntry[]>([]);
  // Set by `submit` for its own pass through the form: the pool capacity it
  // just re-read (or "unknown" when that read failed).
  const submitCap = useRef<SizeCap | null | "unknown" | undefined>(undefined);
  const loginsAvailability = useLoginsAvailability();
  const editorLabels = useKeyValueEditorLabels();
  const envLabels = useMemo(
    () => ({ ...editorLabels, add: t("sandboxes:create.envAdd") }),
    [editorLabels, t],
  );
  const labelLabels = useMemo(
    () => ({
      ...editorLabels,
      add: t("sandboxes:create.labelsAdd"),
      errors: {
        ...editorLabels.errors,
        invalidKey: (key: string) => t("sandboxes:create.labelKeyInvalid", { key }),
      },
    }),
    [editorLabels, t],
  );

  const limits = useQuery({
    ...orpc.sandboxes.getLimits.queryOptions(),
    meta: { skipGlobalErrorToast: true },
  });
  // Direct targets: the deployment limit (hosts may allow less; the server
  // answers with the exact maximum). Pools: the best path for this caller.
  const deploymentLimit: LifetimeLimit = {
    maxTimeoutMs: limits.data?.sandboxTimeoutMaxMs ?? LEASE_DEFAULT_MS,
    allowUnlimited: limits.data?.sandboxTimeoutZero === true,
  };
  /** Preview ports are offered only while the deployment has a tunnel server. */
  const previewTunnels = limits.data?.previewTunnels === true;
  const hostsQuery = useInfiniteQuery({
    ...orpc.sandboxHosts.listHosts.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    refetchInterval: HOSTS_REFETCH_MS,
    meta: { skipGlobalErrorToast: true },
  });
  const hosts = (hostsQuery.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (host) => host.deletionRequestedAt == null,
  );
  // The Hosts page's clock: connection states turn on their own deadlines,
  // and storage reports are judged as of the list's read.
  const now = useStatusClock(hostsQuery.dataUpdatedAt);
  const storageNow = hostsQuery.dataUpdatedAt > 0 ? hostsQuery.dataUpdatedAt : now;
  useRerenderAt(nextHostStateChangeAt(hosts, now));
  const poolsQuery = useInfiniteQuery({
    ...orpc.sandboxPools.listUsable.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const pools = poolsQuery.data?.pages.flatMap((page) => page.items) ?? [];
  const templatesQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listTemplates.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({ limit: PICKER_LIMIT, cursor, status: "active" }),
    }),
    meta: { skipGlobalErrorToast: true },
  });
  const templates = templatesQuery.data?.pages.flatMap((page) => page.items) ?? [];
  /** A template with no launchable version cannot be created from (listed, not offered). */
  const hasVersions = (template: { versions?: { count: number } }) =>
    template.versions === undefined || template.versions.count > 0;
  const usableTemplates = templates.filter(hasVersions);
  const revisionsQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listRevisions.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({
        limit: PICKER_LIMIT,
        cursor,
        templateId: logicalId,
      }),
    }),
    enabled: Boolean(logicalId),
    meta: { skipGlobalErrorToast: true },
  });
  const revisions = (revisionsQuery.data?.pages.flatMap((page) => page.items) ?? []).filter(
    (revision) => revision.retiredAt == null,
  );

  /** Deployment and pool wait layers (null: no limit at that layer; 0: off). */
  const effectiveWaitMax = (poolId: string): number | null => {
    const layers = [
      limits.data?.capacityWaitMaxMs ?? 3_600_000,
      pools.find((candidate) => candidate.id === poolId)?.capacityWaitMaxMs ?? null,
    ].filter((value): value is number => value !== null);
    return layers.length === 0 ? null : Math.min(...layers);
  };
  const lifetimeLimit = (draft: SandboxDraft): LifetimeLimit => {
    const pool = draft.poolId
      ? pools.find((candidate) => candidate.id === draft.poolId)
      : undefined;
    return pool
      ? { maxTimeoutMs: pool.lease.maxTimeoutMs, allowUnlimited: pool.lease.timeoutZero }
      : deploymentLimit;
  };

  const form = useForm({
    defaultValues: initialHostId
      ? { ...DEFAULT_SANDBOX_DRAFT, hostId: initialHostId }
      : DEFAULT_SANDBOX_DRAFT,
    onSubmit: ({ value }) => {
      setAttempted(true);
      if (create.isPending) return;
      if (blockers(value, submitCap.current).length > 0) return;
      const selectedPool = pools.find((pool) => pool.id === value.poolId);
      const quoted =
        lastSubmitted.current === JSON.stringify(value)
          ? lastQuote.current
          : selectedPool?.disconnectGraceSeconds;
      lastQuote.current = quoted;
      const submitted = {
        ...value,
        ...(quoted !== undefined ? { expectedDisconnectGraceSeconds: quoted } : {}),
      };
      lastSubmitted.current = JSON.stringify(value);
      create.mutate(
        intents.current.for("create", JSON.stringify(submitted), (key) =>
          sandboxDraftInput(submitted, key, lifetimeLimit(submitted)),
        ),
      );
    },
  });
  const values = useStore(form.store, (state) => state.values);
  // Cancel, Back or a nav link with input not yet sent asks before it is lost
  // (Pool/Host lives outside the form, so a changed placement counts too).
  const formDirty = useStore(form.store, (state) => state.isDirty);
  const [placementTouched, setPlacementTouched] = useState(false);
  const dirty = formDirty || placementTouched;

  /**
   * Clear the private environment (rows, text mode and the draft's JSON) once
   * the sandbox is created. After a definite refusal the values stay in this
   * open form (React state only, never browser storage) so the user can fix
   * the cause and send again (ADR-003); leaving the page drops them.
   */
  const clearEnvs = () => {
    setEnvRows([]);
    setEnvEditor((current) => current + 1);
    form.setFieldValue("envs", "");
  };
  /** Open an Advanced section (a native `<details>`, so its fields stay mounted). */
  const openSection = (name: Section) => {
    const details = formRef.current?.querySelector<HTMLDetailsElement>(
      `details[data-section="${name}"]`,
    );
    if (details) details.open = true;
  };
  /**
   * Open the section of `place` and move focus to its first invalid field (or
   * to its message when the problem names no single field), after it renders.
   */
  const reveal = (place: ProblemPlace | null) => {
    const target = place ? SECTION_OF[place] : undefined;
    if (target) openSection(target);
    setTimeout(() => {
      const root = formRef.current;
      if (hasInvalidControl(root)) {
        focusFirstInvalidControl(root);
        return;
      }
      const message = root?.querySelector<HTMLElement>("[data-create-problem-inline]");
      if (!message) return;
      for (let node = message.parentElement; node && node !== root; node = node.parentElement)
        if (node instanceof HTMLDetailsElement && !node.open) node.open = true;
      message.focus();
      message.scrollIntoView?.({ block: "center" });
    }, 0);
  };

  const create = useMutation({
    ...orpc.sandboxes.createSandbox.mutationOptions(),
    gcTime: 0,
    meta: { skipGlobalErrorToast: true },
    onMutate: () => {
      setProblem(null);
      setLoginProblemKey(null);
    },
    onSuccess: (sandbox) => {
      lastSubmitted.current = null;
      clearEnvs();
      create.reset();
      intents.current.settle();
      toast.success(t("sandboxes:create.done"));
      void queryClient.invalidateQueries({ queryKey: orpc.sandboxes.key() });
      void navigate({
        to: "/$lang/dashboard/sandboxes/$sandboxId",
        params: { lang, sandboxId: sandbox.id },
        // Created: nothing is lost by leaving, so the unsaved-changes prompt stays out.
        ignoreBlocker: true,
      });
    },
    onError: (error) => {
      const inputMistake = isCreateInputMistake(error);
      const mapped = sandboxProblem(error);
      const next = inputMistake && mapped === "generic" ? "invalid" : mapped;
      setProblem(next);
      const loginKey = credentialErrorKey(error);
      setLoginProblemKey(loginKey);
      // Show it where it belongs and move there (the action bar repeats it).
      reveal(loginKey ? "logins" : (SERVER_PLACE[next] ?? null));
      if (DEFINITE.has(next)) {
        lastSubmitted.current = null;
        create.reset();
        intents.current.settle();
        void hostsQuery.refetch();
        void poolsQuery.refetch();
        void templatesQuery.refetch();
        if (logicalId) void revisionsQuery.refetch();
      }
      redirect(error);
    },
  });

  // The pinned revision's size is the sliders' default. Latest resolves the
  // template's `latest` tag at acceptance, which may point at an older
  // revision than the newest listed one, and the revision list does not say
  // which: its defaults are unknown here. Nothing is sent unless a value is
  // changed.
  const pinned =
    values.templateMode === "revision"
      ? revisions.find((item) => item.id === values.templateId)
      : undefined;
  // With Latest, an untouched size field shows the newest listed version's
  // value (marked "not set"): the version Latest resolves to decides.
  const newest = values.templateMode === "logical" ? revisions[0] : undefined;
  const latestSize = newest
    ? {
        revision: newest.revision,
        cpuCount: newest.cpuCount,
        memoryMiB: newest.memoryMiB,
        defaultDiskGiB: newest.defaultDiskGiB,
        minDiskGiB: newest.minDiskGiB,
      }
    : null;
  const defaults = pinned
    ? {
        revision: pinned.revision,
        cpuCount: pinned.cpuCount,
        memoryMiB: pinned.memoryMiB,
        defaultDiskGiB: pinned.defaultDiskGiB,
        minDiskGiB: pinned.minDiskGiB,
      }
    : null;
  const size: SizeValues = {
    cpuCount: sizeNumber(values.cpuCount),
    memoryMiB: sizeNumber(values.memoryMiB),
    diskGiB: sizeNumber(values.diskGiB),
  };
  const advisorySize = {
    cpuCount: size.cpuCount ?? defaults?.cpuCount,
    memoryMiB: size.memoryMiB ?? defaults?.memoryMiB,
    diskGiB: size.diskGiB ?? defaults?.defaultDiskGiB,
  };
  const choices = new Map(
    hosts.map((host) => [host.id, hostChoice(host, advisorySize, now, storageNow)]),
  );
  const selectableHosts = hosts.filter((host) => choices.get(host.id)?.kind !== "unavailable");

  // Safe placement defaults: Pool when any pool is usable (design-review2
  // #6), else Host; the only usable pool or host is preselected.
  // While the pools load, the page shows the pool fields (the usual default),
  // so it does not jump from Host to Pool when they arrive.
  const placement = placementChoice ?? (pools.length > 0 || poolsQuery.isPending ? "pool" : "host");
  const autoPoolId = pools.length === 1 ? (pools[0]?.id ?? "") : "";
  const autoHostId = selectableHosts.length === 1 ? (selectableHosts[0]?.id ?? "") : "";
  /** The draft as it will be sent: placement and the lifetime default applied. */
  const resolve = (draft: SandboxDraft): SandboxDraft => {
    const placed: SandboxDraft = {
      ...draft,
      hostId: placement === "host" ? draft.hostId || autoHostId : "",
      poolId: placement === "pool" ? draft.poolId || autoPoolId : "",
      // Never sent while the field is not offered.
      previewPorts: previewTunnels ? draft.previewPorts : "",
    };
    return lifetimeTouched
      ? placed
      : { ...placed, lifetimeMinutes: createLifetimeDefault(lifetimeLimit(placed)) };
  };
  const draft = resolve(values);
  const limit = lifetimeLimit(draft);
  const selectedPool = pools.find((pool) => pool.id === draft.poolId);
  const selectedHost = hosts.find((host) => host.id === draft.hostId);
  const selectedHostState = selectedHost ? hostConnectionState(selectedHost, now) : null;

  // Where the chosen template's revisions are (one bounded read over the
  // listed hosts): a host without one is marked before submit. A host may
  // still fetch the image from the store, so this warns and never blocks.
  const choiceHostIds = hosts.slice(0, 200).map((host) => host.id);
  const revisionHostsQuery = useInfiniteQuery({
    ...orpc.sandboxTemplates.listRevisionChoices.infiniteOptions({
      ...cursorPages,
      input: (cursor: string | undefined) => ({
        limit: PICKER_LIMIT,
        cursor,
        hostIds: choiceHostIds,
        includePending: true,
      }),
    }),
    enabled: placement === "host" && Boolean(logicalId) && choiceHostIds.length > 0,
    meta: { skipGlobalErrorToast: true },
  });
  const selectedTemplate = templates.find((template) => template.id === logicalId);
  /** Labels of the hosts that have the chosen template, or null when it is on the chosen host (or unknown). */
  const templateHosts = (() => {
    if (placement !== "host" || !selectedHost || !logicalId) return null;
    if (!revisionHostsQuery.isSuccess || revisionHostsQuery.hasNextPage) return null;
    const rows = revisionHostsQuery.data.pages.flatMap((page) => page.items);
    const matching = rows.filter((row) =>
      values.templateMode === "revision"
        ? row.id === values.templateId
        : row.templateId === logicalId,
    );
    const on = new Set(matching.flatMap((row) => row.availability.map((entry) => entry.hostId)));
    if (on.has(selectedHost.id)) return null;
    return hosts.filter((host) => on.has(host.id)).map((host) => host.label);
  })();
  /** "Ubuntu base isn't on Fake host B. Choose Fake host A or another template." */
  const templateOffHostText = (warn: boolean): string | null => {
    if (!selectedTemplate || !selectedHost) return null;
    const elsewhere = templateHosts ?? [];
    const variant = elsewhere.length > 0 ? "Elsewhere" : "Nowhere";
    return translateText(
      t,
      `sandboxes:create.templateOffHost.${warn ? `warn${variant}` : variant.toLowerCase()}`,
      {
        template: selectedTemplate.label,
        host: selectedHost.label,
        hosts: new Intl.ListFormat(lang, { type: "disjunction" }).format(elsewhere),
      },
    );
  };

  // The real capacity of the placement caps the sliders: a host's current
  // report, or (pools) the largest size one eligible member can take. The
  // read is budgeted (30 a minute per owner), so it is kept for 30 seconds;
  // a submit it would refuse reads it again first.
  const templateRef = values.templateId
    ? `${values.templateMode === "logical" ? "template" : "revision"}/${values.templateId}`
    : undefined;
  const poolCapacity = useQuery({
    ...orpc.sandboxPools.capacity.queryOptions({
      input: { id: draft.poolId ?? "", ...(templateRef ? { template: templateRef } : {}) },
    }),
    enabled: placement === "pool" && Boolean(draft.poolId),
    staleTime: POOL_CAPACITY_STALE_MS,
    refetchOnReconnect: false,
    retry: false,
    meta: { skipGlobalErrorToast: true },
  });
  /** Pooled creates with a capacity wait queue for room instead of failing now. */
  const waitsForRoom = (candidate: SandboxDraft) =>
    Boolean(candidate.poolId) &&
    candidate.capacityWait !== undefined &&
    candidate.capacityWait !== "none";
  const cap: SizeCap | null =
    placement === "pool"
      ? poolCapacity.isError
        ? null
        : (poolCapacity.data?.largest ?? null)
      : selectedHost
        ? hostSizeCap(selectedHost, now, storageNow)
        : null;

  useTwoFactorRedirectOnError(
    lang,
    [
      limits.error,
      hostsQuery.error,
      poolsQuery.error,
      templatesQuery.error,
      revisionsQuery.error,
      poolCapacity.error,
    ],
    { overridesUnsavedInput: true },
  );

  // Flagged rows, and `.env` lines that did not parse (kept as flagged rows,
  // never sent): either refuses the draft.
  const envInvalid = hasKeyValueErrors(envRows, ENV_VALIDATION);
  const labelsInvalid = hasKeyValueErrors(labelRows, LABEL_VALIDATION);
  /** Is this an exact replay of a request whose response was lost? */
  const isReplay = (candidate: SandboxDraft) =>
    problem === "generic" && lastSubmitted.current === JSON.stringify(candidate);
  const draftProblems = (candidate: SandboxDraft): SandboxDraftProblem[] => {
    // Accepted work replays even if discovery changed after a lost response.
    // Only an identical draft may bypass mutable picker checks.
    // Lines the `.env` text could not read are typed input, never sent.
    const unread: SandboxDraftProblem[] = [
      ...(envRows.some(isUnreadLine) ? ["envs" as const] : []),
      ...(labelRows.some(isUnreadLine) ? ["labelsSyntax" as const] : []),
    ];
    if (isReplay(candidate)) return unread;
    const bound = lifetimeLimit(candidate);
    const issues = sandboxDraftProblems(
      candidate,
      candidate.templateMode === "logical" ? usableTemplates : revisions,
      bound.maxTimeoutMs,
      bound.allowUnlimited,
    );
    if (candidate.hostId && !hosts.some((host) => host.id === candidate.hostId && !host.draining))
      issues.push("unknownHost");
    if (candidate.poolId && !pools.some((pool) => pool.id === candidate.poolId))
      issues.push("unknownPool");
    if (envInvalid && !issues.includes("envs")) issues.push("envs");
    if (labelsInvalid && !issues.includes("labelsSyntax")) issues.push("labelsSyntax");
    return issues;
  };
  /** Size values above `against` (untouched sizes under Latest are the server's to resolve). */
  const aboveCap = (candidate: SandboxDraft, against: SizeCap): (keyof SizeValues)[] => {
    // A pinned revision's size is what an untouched (or default-equal) field
    // sends; with Latest it is unknown here and the server resolves it.
    const pin =
      candidate.templateMode === "revision"
        ? revisions.find((item) => item.id === candidate.templateId)
        : undefined;
    return (["cpuCount", "memoryMiB", "diskGiB"] as const).filter((field) => {
      const value =
        sizeNumber(candidate[field]) ??
        (pin ? (field === "diskGiB" ? pin.defaultDiskGiB : pin[field]) : null);
      return value !== null && value > against[field];
    });
  };
  /**
   * Size values over the placement's capacity (the server would refuse them).
   * `against` replaces the cached cap ("unknown": a fresh read failed, so
   * only the server decides). A pooled create that waits for capacity is not
   * checked: the cap is what hosts have free now, which waiting outlasts.
   * The permanent bounds (the create limits) are draft problems, and a
   * host's per-VM maximum is the server's to apply.
   */
  const overCapacity = (
    candidate: SandboxDraft,
    against: SizeCap | null | "unknown" = cap,
  ): (keyof SizeValues)[] => {
    if (!against || against === "unknown" || isReplay(candidate) || waitsForRoom(candidate))
      return [];
    return aboveCap(candidate, against);
  };
  const blockers = (candidate: SandboxDraft, against?: SizeCap | null | "unknown") => [
    ...draftProblems(candidate),
    ...overCapacity(candidate, against === undefined ? cap : against),
  ];
  const problems = attempted ? draftProblems(draft) : [];
  /** A wait for room: the pool's free capacity is advisory, so nothing is capped. */
  const waiting = waitsForRoom(draft);
  const waitsOverCap = waiting && cap !== null && aboveCap(draft, cap).length > 0;
  const has = (place: ProblemPlace) => problems.some((item) => DRAFT_PLACE[item] === place);
  // Preview ports show their own rule under the field as you type.
  const draftMessages = (place: ProblemPlace) =>
    problems.filter((item) => DRAFT_PLACE[item] === place && item !== "previewPorts");
  const serverPlace = loginProblemKey ? null : problem ? (SERVER_PLACE[problem] ?? null) : null;
  /**
   * Changing the field a settled refusal is about hides that refusal (it
   * described the old value). An uncertain one stays: it marks a replay.
   */
  const dismissServerProblem = (...places: ProblemPlace[]) => {
    if (problem && DEFINITE.has(problem) && serverPlace !== null && places.includes(serverPlace))
      setProblem(null);
  };

  const problemText = (item: SandboxProblem) =>
    (item === "templateNotOnHost" ? templateOffHostText(false) : null) ??
    t(
      item === "notFound"
        ? "sandboxes:problem.createNotFound"
        : item === "forbidden"
          ? "sandboxes:problem.createForbidden"
          : `sandboxes:problem.${item}`,
    );
  /** A server problem shown as one size field's own error. */
  const serverSizeField = serverPlace === "size" && problem ? SIZE_FIELD_OF[problem] : undefined;
  /** Inline draft and server problems for one place. */
  const inline = (place: ProblemPlace): ReactNode => (
    <>
      {draftMessages(place).map((item) => (
        <p key={item} role="alert" data-draft-problem={item} className="text-sm text-destructive">
          {t(`sandboxes:draft.${item}`)}
        </p>
      ))}
      {serverPlace === place && problem && !(place === "size" && serverSizeField) ? (
        <p
          role="alert"
          tabIndex={-1}
          data-create-problem={problem}
          data-create-problem-inline=""
          className="text-sm text-destructive outline-none"
        >
          {problemText(problem)}
        </p>
      ) : null}
    </>
  );

  const submit = async () => {
    // Freeze the defaults the page applied, so a retry sends the same intent.
    form.setFieldValue("hostId", draft.hostId);
    form.setFieldValue("poolId", draft.poolId);
    form.setFieldValue("lifetimeMinutes", draft.lifetimeMinutes);
    form.setFieldValue("previewPorts", draft.previewPorts);
    // While pools are still loading, Pool is only a placeholder default: keep
    // placement derived so a "no pools" answer still falls back to Host.
    if (!poolsQuery.isPending) setPlacementChoice(placement);
    setLifetimeTouched(true);
    setAttempted(true);
    // A cached pool cap may be out of date: before refusing on it, read it
    // once more. A failed read refuses nothing (the server checks anyway).
    let against: SizeCap | null | "unknown" = cap;
    if (placement === "pool" && draft.poolId && overCapacity(draft).length > 0) {
      const stillCurrent = fence.begin();
      const fresh = await poolCapacity.refetch();
      // The person left (Cancel/Back) or submitted again meanwhile: send nothing.
      if (!stillCurrent()) return;
      against = fresh.isError ? "unknown" : (fresh.data?.largest ?? null);
    }
    const blocked = blockers(draft, against);
    if (blocked.length > 0) {
      const sections = blocked
        .map((item) =>
          item === "cpuCount" || item === "memoryMiB" || item === "diskGiB"
            ? "size"
            : SECTION_OF[DRAFT_PLACE[item]],
        )
        .filter((section): section is Section => section !== undefined);
      for (const name of new Set(sections)) openSection(name);
      // After the invalid fields render, move focus to the first one (its
      // section opens).
      focusFirstInvalidControl(formRef.current);
    }
    submitCap.current = against;
    try {
      await form.handleSubmit();
    } finally {
      submitCap.current = undefined;
    }
  };

  const sizeErrors: Partial<Record<keyof SizeValues, string>> = Object.fromEntries(
    (["cpuCount", "memoryMiB", "diskGiB"] as const).flatMap((field) =>
      problems.includes(field)
        ? [[field, t(`sandboxes:draft.${field}`)]]
        : serverSizeField === field && problem
          ? [[field, problemText(problem)]]
          : [],
    ),
  );
  const pending = create.isPending;

  // One set of grant fields: the allowlist when internet access is off, the
  // fallback grants (collapsed) when it is on.
  const grantFields = (
    <>
      <form.Field name="egressDomains">
        {(field) => (
          <TextareaField
            field={field}
            label={t("sandboxes:create.egressDomains")}
            description={t("sandboxes:create.egressDomainsHint")}
            autoComplete="off"
            inputClassName="font-mono"
            rows={2}
            disabled={pending}
          />
        )}
      </form.Field>
      <form.Field name="egressCidrs">
        {(field) => (
          <TextareaField
            field={field}
            label={t("sandboxes:create.egressCidrs")}
            description={t("sandboxes:create.egressCidrsHint")}
            autoComplete="off"
            inputClassName="font-mono"
            rows={2}
            disabled={pending}
          />
        )}
      </form.Field>
    </>
  );
  const grants = lineCount(values.egressDomains) + lineCount(values.egressCidrs);
  const envCount = envRows.filter((entry) => !isBlankEntry(entry)).length;
  const labelCount = labelRows.filter((entry) => !isBlankEntry(entry)).length;
  // A label key `.env` text cannot carry keeps the editor in rows.
  const labelsFitText = entriesFitDotenvText(labelRows);
  const loginCount = values.credentials?.length ?? 0;
  const previewPortCount = parsePreviewPorts(values.previewPorts)?.length ?? 0;
  const lifetime = lifetimeText(t, draft.lifetimeMinutes);
  const placementLabel = selectedPool
    ? t("sandboxes:create.status.pool", { label: selectedPool.label })
    : selectedHost
      ? t("sandboxes:create.status.host", { label: selectedHost.label })
      : t("sandboxes:create.status.noPlacement");
  const sizeText = sizeSummary(t, size, defaults);
  const status = [
    placementLabel,
    size.cpuCount === null && size.memoryMiB === null && size.diskGiB === null
      ? defaults
        ? sizeSummary(
            t,
            {
              cpuCount: defaults.cpuCount,
              memoryMiB: defaults.memoryMiB,
              diskGiB: defaults.defaultDiskGiB,
            },
            defaults,
          )
        : t("sandboxes:create.status.templateSize")
      : sizeText,
    draft.lifetimeMinutes === "0"
      ? t("sandboxes:create.status.unlimited")
      : t(
          draft.onExpire === "destroy"
            ? "sandboxes:create.status.destroys"
            : "sandboxes:create.status.stops",
          { lifetime },
        ),
  ].join(" · ");
  const fallbackProblem = loginProblemKey
    ? t(loginProblemKey)
    : problem && serverPlace === null
      ? problemText(problem)
      : null;

  const pageTitle = t("sandboxes:create.title");
  return (
    <FormPage
      ref={formRef}
      noValidate
      // Inside the dashboard frame, which already pads the content column.
      className="px-0 pt-0"
      title={pageTitle}
      aria-label={pageTitle}
      description={t("sandboxes:create.pageDescription")}
      back={
        <Link
          to="/$lang/dashboard/sandboxes"
          params={{ lang }}
          className={buttonVariants({ variant: "ghost", size: "touch", className: "-ms-3" })}
        >
          <ArrowLeft aria-hidden="true" />
          {t("sandboxes:create.back")}
        </Link>
      }
      onSubmit={(event) => {
        event.preventDefault();
        event.stopPropagation();
        void submit();
      }}
      actions={
        <>
          <FormPageStatus>
            <div className="flex min-w-0 flex-col gap-1">
              <span data-create-status="">{status}</span>
              {fallbackProblem ? (
                <p
                  role="alert"
                  id={ids.problem}
                  {...(loginProblemKey
                    ? { "data-create-login-problem": "" }
                    : { "data-create-problem": problem ?? "" })}
                  className="text-sm text-destructive"
                >
                  {fallbackProblem}
                </p>
              ) : problem && serverPlace !== null ? (
                // The refusal sits next to its field, maybe in a closed section or
                // off-screen: the action bar always repeats it, with a way there.
                <p
                  role="alert"
                  data-create-summary={problem}
                  className="flex min-w-0 flex-wrap items-center gap-x-2 text-sm text-destructive"
                >
                  {problemText(problem)}
                  <Button
                    type="button"
                    variant="link"
                    size="touch"
                    className="h-auto min-h-11 px-0"
                    onClick={() => reveal(serverPlace)}
                  >
                    {t("sandboxes:create.showProblem")}
                  </Button>
                </p>
              ) : problems.length > 0 ? (
                <p className="flex min-w-0 flex-wrap items-center gap-x-2 text-sm text-destructive">
                  <span>{t("common:form.fixErrors")}</span>
                  <Button
                    type="button"
                    variant="link"
                    size="touch"
                    className="h-auto min-h-11 px-0"
                    onClick={() => reveal(null)}
                  >
                    {t("sandboxes:create.showProblem")}
                  </Button>
                </p>
              ) : null}
            </div>
          </FormPageStatus>
          <Link
            to="/$lang/dashboard/sandboxes"
            params={{ lang }}
            className={buttonVariants({ variant: "outline", size: "touch" })}
          >
            {t("common:actions.cancel")}
          </Link>
          <Button type="submit" size="touch" disabled={pending}>
            {pending ? t("sandboxes:create.pending") : t("sandboxes:create.submit")}
          </Button>
        </>
      }
    >
      <UnsavedChangesGuard active={dirty} />
      <FormSection
        title={t("sandboxes:create.sectionTemplate")}
        description={t("sandboxes:create.sectionTemplateHint")}
        gridClassName="lg:grid-cols-1"
      >
        <fieldset className="flex min-w-0 flex-col gap-2" disabled={pending}>
          {/* The section heading names it on screen. */}
          <Label htmlFor={ids.template} className="sr-only">
            {t("sandboxes:create.template")}
          </Label>
          {/* While loading, the select itself (disabled) holds the place. */}
          <PickerStatus
            query={templatesQuery}
            failed={t("sandboxes:create.templatesFailed")}
            holdsPlace
          />
          <FormSelect
            id={ids.template}
            optionsSettled={
              templatesQuery.isSuccess && !templatesQuery.isFetching && !templatesQuery.hasNextPage
            }
            autoComplete="off"
            value={logicalId}
            disabled={templatesQuery.isPending}
            aria-invalid={has("template") || serverPlace === "template" ? true : undefined}
            onValueChange={(value) => {
              setLogicalId(value);
              form.setFieldValue("templateMode", "logical");
              form.setFieldValue("templateId", value);
              dismissServerProblem("template");
            }}
          >
            <SelectItem value="">{t("sandboxes:create.chooseTemplate")}</SelectItem>
            {templates.map((template) => (
              // A template without a launchable version is listed but cannot be chosen.
              <SelectItem
                key={template.id}
                value={template.id}
                disabled={!hasVersions(template)}
                data-no-versions={hasVersions(template) ? undefined : ""}
              >
                {translateText(
                  t,
                  hasVersions(template)
                    ? "sandboxes:create.logicalOption"
                    : "sandboxes:create.noVersions",
                  { label: template.label, slug: template.slug },
                )}
              </SelectItem>
            ))}
          </FormSelect>
          {templatesQuery.isSuccess &&
          !templatesQuery.hasNextPage &&
          usableTemplates.length === 0 ? (
            <p data-no-templates="" className="text-sm text-muted-foreground">
              {t("sandboxes:create.noTemplates")}{" "}
              <Link
                to="/$lang/dashboard/templates"
                params={{ lang }}
                search={{ new: true }}
                className="inline-flex min-h-11 items-center font-medium text-primary underline-offset-4 hover:underline"
              >
                {t("sandboxes:create.noTemplatesLink")}
              </Link>
            </p>
          ) : null}
          {serverPlace !== "template" && templateHosts !== null ? (
            <p data-template-off-host="" className="text-xs text-amber-700 dark:text-amber-400">
              {templateOffHostText(true)}
            </p>
          ) : null}
          <LoadMore
            hasNextPage={templatesQuery.hasNextPage}
            isFetchingNextPage={templatesQuery.isFetchingNextPage}
            onLoadMore={() => void templatesQuery.fetchNextPage()}
            label={t("sandboxes:create.moreTemplates")}
          />
          {inline("template")}
        </fieldset>
      </FormSection>

      <FormSection
        title={t("sandboxes:create.sectionPlacement")}
        description={t("sandboxes:create.sectionPlacementHint")}
        gridClassName="lg:grid-cols-1"
      >
        <fieldset className="flex min-w-0 flex-col gap-3" disabled={pending}>
          <SegmentedControl
            value={placement}
            ariaLabel={t("sandboxes:create.placement")}
            onChange={(next) => {
              setPlacementChoice(next);
              setPlacementTouched(true);
            }}
            items={[
              { value: "pool", label: t("sandboxes:create.placementPool") },
              { value: "host", label: t("sandboxes:create.placementHost") },
            ]}
          />
          {placement === "pool" ? (
            <div className="flex min-w-0 flex-col gap-2" data-pool-fields="">
              <Label htmlFor={ids.pool}>{t("sandboxes:create.pool")}</Label>
              <PickerStatus
                query={poolsQuery}
                failed={t("sandboxes:create.poolsFailed")}
                holdsPlace
              />
              {poolsQuery.isSuccess && pools.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("sandboxes:create.noPools")}</p>
              ) : (
                <FormSelect
                  id={ids.pool}
                  optionsSettled={
                    poolsQuery.isSuccess && !poolsQuery.isFetching && !poolsQuery.hasNextPage
                  }
                  autoComplete="off"
                  value={draft.poolId ?? ""}
                  disabled={poolsQuery.isPending}
                  aria-invalid={has("placement") || serverPlace === "placement" ? true : undefined}
                  onValueChange={(value) => {
                    form.setFieldValue("poolId", value);
                    dismissServerProblem("placement", "template", "size");
                  }}
                >
                  <SelectItem value="">{t("sandboxes:create.choosePool")}</SelectItem>
                  {pools.map((pool) => (
                    <SelectItem key={pool.id} value={pool.id}>
                      {translateText(t, "sandboxes:create.poolOption", {
                        label: pool.label,
                        owner:
                          "owner" in pool && pool.owner
                            ? pool.owner.name
                            : t("hosts:sharing.owned"),
                      })}
                    </SelectItem>
                  ))}
                </FormSelect>
              )}
              <LoadMore
                hasNextPage={poolsQuery.hasNextPage}
                isFetchingNextPage={poolsQuery.isFetchingNextPage}
                onLoadMore={() => void poolsQuery.fetchNextPage()}
              />
              {/* Drawn while the pools load too: the section keeps its loaded height. */}
              {pools.length > 0 || poolsQuery.isPending ? (
                <PoolTrustNotice graceSeconds={selectedPool?.disconnectGraceSeconds} lang={lang} />
              ) : null}
            </div>
          ) : (
            <div className="flex min-w-0 flex-col gap-2" data-host-fields="">
              <Label htmlFor={ids.host}>{t("sandboxes:create.host")}</Label>
              <PickerStatus
                query={hostsQuery}
                failed={t("sandboxes:create.hostsFailed")}
                holdsPlace
              />
              {hostsQuery.isSuccess && hosts.length === 0 ? (
                <p className="text-sm text-muted-foreground">{t("sandboxes:create.noHosts")}</p>
              ) : hostsQuery.isSuccess || hostsQuery.isPending ? (
                <FormSelect
                  id={ids.host}
                  optionsSettled={
                    hostsQuery.isSuccess && !hostsQuery.isFetching && !hostsQuery.hasNextPage
                  }
                  autoComplete="off"
                  value={draft.hostId}
                  disabled={hostsQuery.isPending}
                  aria-invalid={has("placement") || serverPlace === "placement" ? true : undefined}
                  onValueChange={(value) => {
                    form.setFieldValue("hostId", value);
                    dismissServerProblem("placement", "template", "size");
                  }}
                >
                  <SelectItem value="">{t("sandboxes:create.chooseHost")}</SelectItem>
                  {hosts.map((host) => {
                    const choice = choices.get(host.id) ?? { kind: "available" as const };
                    return (
                      // A draining or full host refuses new sandboxes: say why,
                      // and do not let it be chosen.
                      <SelectItem
                        key={host.id}
                        value={host.id}
                        disabled={choice.kind === "unavailable"}
                        data-draining={host.draining ? "" : undefined}
                      >
                        {choice.kind === "unavailable"
                          ? translateText(t, "sandboxes:create.hostUnavailable", {
                              label: host.label,
                              reason: t(`sandboxes:create.unavailable.${choice.reason}`),
                            })
                          : choice.kind === "offline"
                            ? translateText(t, "sandboxes:create.hostOffline", {
                                label: host.label,
                                state: t(`hosts:status.${choice.state}`),
                              })
                            : choice.kind === "unmeasured"
                              ? translateText(t, "sandboxes:create.hostUnmeasured", {
                                  label: host.label,
                                })
                              : translateText(t, "sandboxes:create.hostAvailable", {
                                  label: host.label,
                                })}
                      </SelectItem>
                    );
                  })}
                </FormSelect>
              ) : null}
              <LoadMore
                hasNextPage={hostsQuery.hasNextPage}
                isFetchingNextPage={hostsQuery.isFetchingNextPage}
                onLoadMore={() => void hostsQuery.fetchNextPage()}
                label={t("sandboxes:create.moreHosts")}
              />
              {hosts.some((host) => host.draining) ? (
                <p data-draining-hosts="" className="text-xs text-muted-foreground">
                  {t("sandboxes:create.drainingHosts")}
                </p>
              ) : null}
              {selectedHostState != null && selectedHostState !== "ready" ? (
                <p data-host-waits="" className="text-xs text-amber-700 dark:text-amber-400">
                  {t("sandboxes:create.hostWaits", {
                    state: t(`hosts:status.${selectedHostState}`),
                  })}
                </p>
              ) : selectedHost && cap ? (
                // What fits, as soon as a host is chosen (not only after a refusal).
                <p data-host-free="" className="text-xs text-muted-foreground">
                  {t("sandboxes:create.capacity.hostFree", {
                    cpu: cap.cpuCount,
                    memory: gibFromMib(cap.memoryMiB),
                    disk: cap.diskGiB,
                  })}
                </p>
              ) : selectedHost ? (
                <p data-host-free="unknown" className="text-xs text-muted-foreground">
                  {t("sandboxes:create.capacity.hostUnknown")}
                </p>
              ) : null}
            </div>
          )}
          {inline("placement")}
        </fieldset>
      </FormSection>

      <FormSection
        title={t("sandboxes:create.sectionBasics")}
        description={t("sandboxes:create.sectionBasicsHint")}
      >
        <form.Field
          name="name"
          validators={{
            // The rule Rename uses; blank lets the server pick a name.
            onChange: z
              .string()
              .refine((value) => !value || sandboxNameSchema.safeParse(value).success, {
                message: t("sandboxes:draft.name"),
              }),
          }}
        >
          {(field) => (
            <TextField
              field={field}
              label={t("sandboxes:create.name")}
              description={t("sandboxes:create.nameHint")}
              autoComplete="off"
              inputMode="text"
              autoCapitalize="none"
              spellCheck={false}
              inputClassName="min-h-11 font-mono"
              disabled={pending}
            />
          )}
        </form.Field>
        {/* The field shows its own rule as you type; the server's refusals show here. */}
        {serverPlace === "name" && problem ? (
          <p
            role="alert"
            tabIndex={-1}
            data-create-problem={problem}
            data-create-problem-inline=""
            className="text-sm text-destructive outline-none"
          >
            {problemText(problem)}
          </p>
        ) : null}
        {limits.isError ? (
          <PickerStatus query={limits} failed={t("sandboxes:lifetime.limitsFailed")} />
        ) : null}
        <LifetimeFields
          maxTimeoutMs={limit.maxTimeoutMs}
          allowUnlimited={limit.allowUnlimited}
          minutes={draft.lifetimeMinutes}
          onMinutes={(value) => {
            setLifetimeTouched(true);
            form.setFieldValue("lifetimeMinutes", value);
          }}
          onExpire={values.onExpire}
          onOnExpire={(value) => form.setFieldValue("onExpire", value)}
          disabled={pending}
          hint={t("sandboxes:create.lifetimeHint")}
          error={
            has("lifetime")
              ? t("sandboxes:draft.lifetime")
              : serverPlace === "lifetime" && problem
                ? problemText(problem)
                : null
          }
        />
      </FormSection>

      <FormSection
        title={t("sandboxes:create.sectionAdvanced")}
        description={t("sandboxes:create.sectionAdvancedHint")}
        gridClassName="lg:grid-cols-1"
      >
        {/* One cell: the sections join into one ruled list. */}
        <div className="min-w-0 space-y-8">
          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            data-section="version"
            title={t("sandboxes:create.versionTitle")}
            summary={
              pinned
                ? t("sandboxes:create.summary.revision", { revision: pinned.revision })
                : t("sandboxes:create.summary.latest")
            }
          >
            {logicalId ? (
              <fieldset className="flex min-w-0 flex-col gap-2" disabled={pending}>
                <Label htmlFor={ids.revision}>{t("sandboxes:create.revision")}</Label>
                <PickerStatus
                  query={revisionsQuery}
                  failed={t("sandboxes:create.revisionsFailed")}
                />
                <FormSelect
                  id={ids.revision}
                  optionsSettled={
                    revisionsQuery.isSuccess &&
                    !revisionsQuery.isFetching &&
                    !revisionsQuery.hasNextPage
                  }
                  autoComplete="off"
                  value={values.templateMode === "logical" ? "" : values.templateId}
                  onValueChange={(value) => {
                    form.setFieldValue("templateMode", value ? "revision" : "logical");
                    form.setFieldValue("templateId", value || logicalId);
                  }}
                >
                  <SelectItem value="">{t("sandboxes:create.latest")}</SelectItem>
                  {revisions.map((revision) => (
                    <SelectItem key={revision.id} value={revision.id}>
                      {t("sandboxes:create.revisionOption", {
                        revision: revision.revision,
                        architecture: revision.architecture,
                        cpuCount: revision.cpuCount,
                        memoryMiB: revision.memoryMiB,
                        defaultDiskGiB: revision.defaultDiskGiB,
                        minDiskGiB: revision.minDiskGiB,
                      })}
                    </SelectItem>
                  ))}
                </FormSelect>
                <LoadMore
                  hasNextPage={revisionsQuery.hasNextPage}
                  isFetchingNextPage={revisionsQuery.isFetchingNextPage}
                  onLoadMore={() => void revisionsQuery.fetchNextPage()}
                  label={t("sandboxes:create.moreRevisions")}
                />
                <p className="text-xs text-muted-foreground">
                  {t("sandboxes:create.selectorHint")}
                </p>
              </fieldset>
            ) : (
              <p className="text-sm text-muted-foreground">
                {t("sandboxes:create.chooseTemplateFirst")}
              </p>
            )}
          </AdvancedSection>

          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            data-section="size"
            title={t("sandboxes:create.sizeTitle")}
            summary={sizeText}
          >
            <p className="text-xs text-muted-foreground">{t("sandboxes:create.sizeIntro")}</p>
            {values.templateMode === "logical" ? (
              <p data-size-advisory="" className="text-xs text-muted-foreground">
                {t("sandboxes:create.latestSizeHint")}
              </p>
            ) : null}
            {placement === "pool" && poolCapacity.isError ? (
              <p data-pool-capacity-failed="" className="text-xs text-muted-foreground">
                {t("sandboxes:create.capacity.poolFailed")}
              </p>
            ) : placement === "pool" &&
              poolCapacity.isSuccess &&
              poolCapacity.data.largest === null ? (
              <p className="text-xs text-amber-700 dark:text-amber-400">
                {t("sandboxes:create.capacity.poolNone")}
              </p>
            ) : null}
            <SizeFields
              values={size}
              onChange={(field, value) => {
                const next = value === null ? "" : String(value);
                // Leaving a field unchanged (blur commits it) keeps the refusal.
                if (next === values[field]) return;
                form.setFieldValue(field, next);
                dismissServerProblem("size");
              }}
              defaults={defaults}
              fallback={latestSize}
              cap={cap}
              capAdvisory={waiting}
              capSource={placement}
              errors={sizeErrors}
              disabled={pending}
            />
            {waitsOverCap ? (
              <p data-size-waits="" role="status" className="text-xs text-muted-foreground">
                {t("sandboxes:create.capacity.poolWaits")}
              </p>
            ) : null}
            {inline("size")}
          </AdvancedSection>

          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            data-section="envs"
            title={t("sandboxes:create.envTitle")}
            summary={
              envCount > 0
                ? t("sandboxes:create.summary.envs", { count: envCount })
                : t("sandboxes:create.summary.none")
            }
          >
            <KeyValueEditor
              key={envEditor}
              field={stateField("envs", envRows, [], (entries) => {
                setEnvRows(entries);
                form.setFieldValue("envs", entriesJson(entries));
              })}
              label={t("sandboxes:create.envTitle")}
              description={t("sandboxes:create.envHint")}
              labels={envLabels}
              reservedKeys={ENV_VALIDATION.reservedKeys}
              secret
              disabled={pending}
            />
            {inline("envs")}
          </AdvancedSection>

          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            data-section="labels"
            title={t("sandboxes:create.labels")}
            summary={
              labelCount > 0
                ? t("sandboxes:create.summary.labels", { count: labelCount })
                : t("sandboxes:create.summary.none")
            }
          >
            <KeyValueEditor
              field={stateField("labels", labelRows, [], (entries) => {
                setLabelRows(entries);
                form.setFieldValue("labels", entriesJson(entries));
              })}
              label={t("sandboxes:create.labels")}
              description={t("sandboxes:create.labelsRowsHint")}
              labels={labelLabels}
              reservedKeys={LABEL_VALIDATION.reservedKeys}
              keyPattern={LABEL_VALIDATION.keyPattern}
              // Label names allow keys `.env` text cannot carry (`#team`):
              // while one exists, the text view would drop it, so rows only.
              textMode={labelsFitText}
              fileImport={false}
              disabled={pending}
            />
            {labelsFitText ? null : (
              <p role="status" data-labels-rows-only="" className="text-xs text-muted-foreground">
                {t("sandboxes:create.labelsTextUnavailable")}
              </p>
            )}
            {inline("labels")}
          </AdvancedSection>

          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            data-section="network"
            title={t("sandboxes:create.networkTitle")}
            summary={[
              values.internetAccess
                ? grants > 0
                  ? t("sandboxes:create.summary.internetFallback", { count: grants })
                  : t("sandboxes:create.summary.internet")
                : grants > 0
                  ? t("sandboxes:create.summary.allowlist", { count: grants })
                  : t("sandboxes:create.summary.denyAll"),
              ...(previewTunnels && previewPortCount > 0
                ? [t("sandboxes:create.summary.ports", { count: previewPortCount })]
                : []),
            ].join(" · ")}
          >
            <fieldset
              className="flex min-w-0 flex-col gap-3"
              disabled={pending}
              data-egress-fields=""
            >
              <legend className="mb-1 text-sm font-medium">{t("sandboxes:create.egress")}</legend>
              <form.Field name="internetAccess">
                {(field) => (
                  <label className="flex min-h-11 items-center gap-3 text-sm">
                    <Switch
                      data-internet-access=""
                      checked={field.state.value}
                      onCheckedChange={(checked) => field.handleChange(checked)}
                      disabled={pending}
                    />
                    {t("sandboxes:create.internetAccess")}
                  </label>
                )}
              </form.Field>
              <p data-egress-hint="" className="text-xs text-muted-foreground">
                {t(
                  values.internetAccess
                    ? "sandboxes:create.internetAccessOnHint"
                    : "sandboxes:create.egressHint",
                )}
              </p>
              {values.internetAccess ? (
                <details data-egress-fallback="" className="min-w-0 text-sm">
                  <summary className="flex min-h-11 cursor-pointer flex-wrap items-center gap-x-2 font-medium">
                    {t("sandboxes:create.fallbackSummary")}
                    <span className="font-normal text-muted-foreground">
                      {grants > 0
                        ? t("sandboxes:create.summary.allowlist", { count: grants })
                        : t("sandboxes:create.summary.none")}
                    </span>
                  </summary>
                  <div className="flex min-w-0 flex-col gap-3 pt-2">
                    <p className="text-xs text-muted-foreground">
                      {t("sandboxes:create.fallbackHint")}
                    </p>
                    {grantFields}
                  </div>
                </details>
              ) : (
                grantFields
              )}
            </fieldset>
            {previewTunnels ? (
              <form.Field
                name="previewPorts"
                validators={{
                  // Checked as you type; the draft also refuses it at submit.
                  onChange: z.string().refine((value) => parsePreviewPorts(value) !== null, {
                    message: t("sandboxes:draft.previewPorts"),
                  }),
                }}
              >
                {(field) => (
                  <TextField
                    field={field}
                    label={t("sandboxes:create.previewPorts")}
                    description={t("sandboxes:create.previewPortsHint")}
                    autoComplete="off"
                    inputMode="numeric"
                    spellCheck={false}
                    inputClassName="min-h-11 font-mono"
                    placeholder="3000, 8080"
                    disabled={pending}
                  />
                )}
              </form.Field>
            ) : null}
            {inline("network")}
          </AdvancedSection>

          <AdvancedSection
            gridClassName="lg:grid-cols-1"
            data-section="access"
            title={t("sandboxes:create.accessTitle")}
            summary={t(
              values.guestSudo
                ? "sandboxes:create.summary.sudoOn"
                : "sandboxes:create.summary.sudoOff",
            )}
          >
            <fieldset
              className="flex min-w-0 flex-col gap-3"
              disabled={pending}
              data-guest-sudo-fields=""
            >
              <legend className="mb-1 text-sm font-medium">
                {t("sandboxes:create.guestRoot")}
              </legend>
              <form.Field name="guestSudo">
                {(field) => (
                  <label className="flex min-h-11 items-center gap-3 text-sm">
                    <Switch
                      data-guest-sudo=""
                      checked={field.state.value}
                      onCheckedChange={(checked) => field.handleChange(checked)}
                      disabled={pending}
                    />
                    {t("sandboxes:create.guestSudo")}
                  </label>
                )}
              </form.Field>
              <p data-guest-sudo-hint="" className="text-xs text-muted-foreground">
                <Trans
                  t={t}
                  i18nKey={
                    values.guestSudo
                      ? "sandboxes:create.guestSudoOnHint"
                      : "sandboxes:create.guestSudoOffHint"
                  }
                  components={{ code: <code className="whitespace-nowrap" /> }}
                />
              </p>
              {!values.guestSudo && pinned && revisionRootTaint(pinned) ? (
                <p
                  data-guest-root-tainted=""
                  className="text-xs text-amber-700 dark:text-amber-400"
                >
                  {t("sandboxes:create.guestRootTainted")}
                </p>
              ) : null}
            </fieldset>
          </AdvancedSection>

          {loginsAvailability === "enabled" ? (
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              data-section="logins"
              title={t("sandboxes:create.loginsTitle")}
              summary={
                loginCount > 0
                  ? t("sandboxes:create.summary.logins", { count: loginCount })
                  : t("sandboxes:create.summary.none")
              }
            >
              <LoginsPicker
                value={values.credentials ?? []}
                disabled={pending}
                onChange={(next) => form.setFieldValue("credentials", next)}
              />
              {inline("logins")}
            </AdvancedSection>
          ) : null}

          {placement === "pool" ? (
            <AdvancedSection
              gridClassName="lg:grid-cols-1"
              data-section="wait"
              title={t("sandboxes:create.capacityWait")}
              summary={t(`sandboxes:create.wait.${values.capacityWait ?? "none"}`)}
            >
              <form.Field name="capacityWait">
                {(field) => (
                  <div className="flex min-w-0 flex-col gap-2">
                    <Label htmlFor={ids.wait}>{t("sandboxes:create.capacityWait")}</Label>
                    <FormSelect
                      id={ids.wait}
                      autoComplete="off"
                      disabled={pending}
                      value={field.state.value ?? "none"}
                      onValueChange={(value) => field.handleChange(value as CapacityWaitChoice)}
                    >
                      {capacityWaitChoices(effectiveWaitMax(draft.poolId ?? "")).map((choice) => (
                        <SelectItem key={choice} value={choice}>
                          {t(`sandboxes:create.wait.${choice}`)}
                        </SelectItem>
                      ))}
                    </FormSelect>
                    <p className="text-xs text-muted-foreground">
                      {t("sandboxes:create.capacityWaitHint")}
                    </p>
                  </div>
                )}
              </form.Field>
              {inline("wait")}
            </AdvancedSection>
          ) : null}
        </div>
      </FormSection>
    </FormPage>
  );
}
