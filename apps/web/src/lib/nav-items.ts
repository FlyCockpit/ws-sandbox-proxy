import type { LucideIcon } from "lucide-react";
import {
  Boxes,
  FileKey,
  HardDrive,
  Home,
  KeyRound,
  Layers,
  ListChecks,
  LogIn,
  Network,
  Server,
  Settings,
  Shield,
  SquareTerminal,
  User,
  Webhook,
} from "lucide-react";

export type NavDirection = "forward" | "back" | "none";
/**
 * `anonymous` is shown only to signed-out visitors: a signed-in user's root
 * (`/$lang`) redirects to Sandboxes, so a "Home" item would duplicate it.
 */
type NavAudience = "public" | "anonymous" | "authenticated" | "admin";
/**
 * - `desktop` / `mobile`: the signed-out top bar and bottom bar.
 * - `sidebar`: the signed-in sidebar (md and up) and, for items that are not
 *   tabs, the phone bottom bar's More sheet.
 * - `tabs`: the signed-in phone bottom bar (at most four, plus More).
 * - `userMenu`: the account menu.
 */
type NavPlacement = "desktop" | "mobile" | "sidebar" | "tabs" | "userMenu";
/** Sections of the signed-in sidebar (and phone tabs / More sheet). */
type PrimaryNavPath =
  | "/dashboard/sandboxes"
  | "/dashboard/templates"
  | "/dashboard/operations"
  | "/dashboard/terminals"
  | "/settings"
  | "/admin";
/** Pages reached from the Settings hub. */
type SettingsNavPath =
  | "/settings/hosts"
  | "/settings/host-credentials"
  | "/settings/pools"
  | "/settings/sdk-keys"
  | "/settings/agent-tokens"
  | "/settings/webhooks"
  | "/settings/logins"
  | "/settings/profile"
  | "/settings/security"
  | "/settings/images";
export type AppNavPath = "/" | PrimaryNavPath | SettingsNavPath;
export type LangNavRoute = "/$lang" | `/$lang${Exclude<AppNavPath, "/">}`;

export type RouteNavItem = {
  /** Path WITHOUT the `/$lang/` prefix, starts with "/". Use "/" for root. */
  path: AppNavPath;
  /** Translation key. App nav keys live in `nav`; nested nav may use another namespace. */
  labelKey: string;
  /** Icon rendered by shell navigation surfaces. */
  icon: LucideIcon;
  /** `activeOptions.exact` for the <Link>. */
  exact: boolean;
};

export type AppNavId =
  | "home"
  | "sandboxes"
  | "templates"
  | "activity"
  | "terminals"
  | "hosts"
  | "settings"
  | "admin";

export type AppNavItem = RouteNavItem & {
  id: AppNavId;
  audience: NavAudience;
  placements: readonly NavPlacement[];
  /** Sidebar group: the daily sections, or the footer pinned to the bottom. */
  group: "main" | "footer";
};

type VisibleNavInput = {
  placement: NavPlacement;
  isAuthenticated: boolean;
  /**
   * Whether to offer the admin area. Callers pass `useShowsAdminNavigation()`,
   * which mirrors the server admin gate (role, verified email, forced 2FA);
   * never derive it from the role alone.
   */
  showsAdmin?: boolean;
};

/** One signed-in section. Labels live in the `nav` namespace (`items.<id>`). */
function section(
  id: AppNavId,
  path: AppNavPath,
  icon: LucideIcon,
  placements: readonly NavPlacement[],
  group: "main" | "footer" = "main",
  audience: NavAudience = "authenticated",
): AppNavItem {
  return { id, path, labelKey: `nav:items.${id}`, icon, exact: false, audience, placements, group };
}

/**
 * Every shell nav item, in sidebar order. Signed in, the sidebar (md and up)
 * or the bottom tabs plus their More sheet (phones) are the one nav surface;
 * Settings and Admin also sit in the account menu. Every signed-in route is
 * under a session gate (`_auth`, or `admin`'s own) and each page's data comes
 * from an owner-scoped procedure, so this list is presentation only.
 *
 * Adding a section is one line here (plus its path in the type above):
 * `main` items sit at the top, `footer` items are pinned to the bottom.
 */
const appNavItems: readonly AppNavItem[] = [
  {
    id: "home",
    path: "/",
    labelKey: "nav:items.home",
    icon: Home,
    exact: true,
    audience: "anonymous",
    placements: ["desktop", "mobile"],
    group: "main",
  },
  section("sandboxes", "/dashboard/sandboxes", Boxes, ["sidebar", "tabs"]),
  section("templates", "/dashboard/templates", Layers, ["sidebar", "tabs"]),
  section("activity", "/dashboard/operations", ListChecks, ["sidebar", "tabs"]),
  // Operators enrol and watch hosts often enough to want it one click away;
  // the Settings hub keeps its card too. Phones reach it through More.
  section("hosts", "/settings/hosts", Server, ["sidebar"]),
  // Your live terminals across hosts and sandboxes; phones reach it through More.
  section("terminals", "/dashboard/terminals", SquareTerminal, ["sidebar"]),
  section("settings", "/settings", Settings, ["sidebar", "tabs", "userMenu"], "footer"),
  section("admin", "/admin", Shield, ["sidebar", "userMenu"], "footer", "admin"),
];

function canSeeNavItem(
  item: AppNavItem,
  input: Pick<VisibleNavInput, "isAuthenticated" | "showsAdmin">,
) {
  if (item.audience === "public") return true;
  if (item.audience === "anonymous") return !input.isAuthenticated;
  if (!input.isAuthenticated) return false;
  if (item.audience === "authenticated") return true;
  return input.showsAdmin === true;
}

export function getNavItems(input: VisibleNavInput): AppNavItem[] {
  return appNavItems.filter(
    (item) => item.placements.includes(input.placement) && canSeeNavItem(item, input),
  );
}

export function toLangRoute(path: AppNavPath): LangNavRoute {
  if (path === "/") return "/$lang";
  return `/$lang${path}` as LangNavRoute;
}

/** Signed-in sections the sidebar shows to everyone (Admin excluded). */
export const primaryNavItems: readonly AppNavItem[] = getNavItems({
  placement: "sidebar",
  isAuthenticated: true,
  showsAdmin: false,
});

/**
 * The signed-in section a pathname belongs to (locale prefix optional), or
 * `null` outside the signed-in app. The longest matching path wins, so
 * `/settings/hosts/...` and its Host credentials tab light Hosts while every
 * other `/settings/...` page keeps Settings active.
 */
export function primarySectionFor(pathname: string): AppNavId | null {
  const path = stripLangPrefix(pathname);
  let best: AppNavItem | null = null;
  for (const item of appNavItems) {
    if (!item.placements.includes("sidebar")) continue;
    const owns =
      path === item.path ||
      path.startsWith(`${item.path}/`) ||
      (item.id === "hosts" && path.startsWith("/settings/host-credentials"));
    if (owns && (!best || item.path.length > best.path.length)) best = item;
  }
  return best?.id ?? null;
}

type SettingsHubItem = RouteNavItem & {
  id:
    | "agentTokens"
    | "hosts"
    | "pools"
    | "sdkKeys"
    | "webhooks"
    | "logins"
    | "profile"
    | "security"
    | "images";
  path: SettingsNavPath;
  /** One-line card description, in the `settings` namespace. */
  descriptionKey: string;
};

export type SettingsHubGroup = {
  id: "infrastructure" | "developer" | "logins" | "account";
  labelKey: string;
  items: readonly SettingsHubItem[];
};

/**
 * The Settings hub, in card order. Host credentials is a tab on Hosts, not a
 * card of its own.
 */
export const settingsHubGroups: readonly SettingsHubGroup[] = [
  {
    id: "infrastructure",
    labelKey: "settings:hub.groups.infrastructure",
    items: [
      {
        id: "hosts",
        path: "/settings/hosts",
        labelKey: "settings:hub.items.hosts.label",
        descriptionKey: "settings:hub.items.hosts.description",
        icon: Server,
        exact: false,
      },
      {
        id: "pools",
        path: "/settings/pools",
        labelKey: "settings:hub.items.pools.label",
        descriptionKey: "settings:hub.items.pools.description",
        icon: Network,
        exact: false,
      },
    ],
  },
  {
    id: "developer",
    labelKey: "settings:hub.groups.developer",
    items: [
      {
        id: "sdkKeys",
        path: "/settings/sdk-keys",
        labelKey: "settings:hub.items.sdkKeys.label",
        descriptionKey: "settings:hub.items.sdkKeys.description",
        icon: KeyRound,
        exact: false,
      },
      {
        id: "agentTokens",
        path: "/settings/agent-tokens",
        labelKey: "settings:hub.items.agentTokens.label",
        descriptionKey: "settings:hub.items.agentTokens.description",
        icon: KeyRound,
        exact: false,
      },
      {
        id: "webhooks",
        path: "/settings/webhooks",
        labelKey: "settings:hub.items.webhooks.label",
        descriptionKey: "settings:hub.items.webhooks.description",
        icon: Webhook,
        exact: false,
      },
    ],
  },
  {
    id: "logins",
    labelKey: "settings:hub.groups.logins",
    items: [
      {
        id: "logins",
        path: "/settings/logins",
        labelKey: "settings:hub.items.logins.label",
        descriptionKey: "settings:hub.items.logins.description",
        icon: LogIn,
        exact: false,
      },
    ],
  },
  {
    id: "account",
    labelKey: "settings:hub.groups.account",
    items: [
      {
        id: "profile",
        path: "/settings/profile",
        labelKey: "settings:hub.items.profile.label",
        descriptionKey: "settings:hub.items.profile.description",
        icon: User,
        exact: false,
      },
      {
        id: "security",
        path: "/settings/security",
        labelKey: "settings:hub.items.security.label",
        descriptionKey: "settings:hub.items.security.description",
        icon: Shield,
        exact: false,
      },
      {
        id: "images",
        path: "/settings/images",
        labelKey: "settings:hub.items.images.label",
        descriptionKey: "settings:hub.items.images.description",
        icon: HardDrive,
        exact: false,
      },
    ],
  },
];

/**
 * Account tabs (Profile · Security · Images & builds), in left→right visual
 * order. The array order is also `getNavDirection`'s sibling slide direction.
 */
export const accountTabItems: readonly RouteNavItem[] = [
  { path: "/settings/profile", labelKey: "settings:navProfile", icon: User, exact: false },
  { path: "/settings/security", labelKey: "settings:navSecurity", icon: Shield, exact: false },
  { path: "/settings/images", labelKey: "settings:navImages", icon: HardDrive, exact: false },
];

/** Hosts tabs (Hosts · Host credentials). */
export const hostsTabItems: readonly RouteNavItem[] = [
  { path: "/settings/hosts", labelKey: "hosts:tabs.hosts", icon: Server, exact: false },
  {
    path: "/settings/host-credentials",
    labelKey: "hosts:tabs.hostCredentials",
    icon: FileKey,
    exact: false,
  },
];

const NAV_LISTS: readonly (readonly RouteNavItem[])[] = [
  appNavItems,
  accountTabItems,
  hostsTabItems,
];

// Precomputed path → position lookups (one per list, since a path like
// `/settings` can appear in several lists) so `getNavDirection` does Map reads
// on every navigation instead of scanning the arrays with `findIndex`.
const NAV_INDEX_MAPS: ReadonlyMap<string, number>[] = NAV_LISTS.map(
  (list) => new Map(list.map((item, index) => [item.path, index])),
);

export function stripLangPrefix(pathname: string): string {
  const match = pathname.match(/^\/[a-z]{2}(?:-[A-Z]{2})?(\/.*)?$/i);

  if (!match) {
    return pathname;
  }

  const rest = match[1] ?? "/";

  if (rest === "" || rest === "/") {
    return "/";
  }

  return rest;
}

export function getNavDirection(fromPath: string, toPath: string): NavDirection {
  if (fromPath === toPath) {
    return "none";
  }

  for (const indexMap of NAV_INDEX_MAPS) {
    const fromIndex = indexMap.get(fromPath);
    const toIndex = indexMap.get(toPath);

    if (fromIndex !== undefined && toIndex !== undefined) {
      return toIndex < fromIndex ? "back" : "forward";
    }
  }

  if (fromPath !== "/" && toPath.startsWith(`${fromPath}/`)) {
    return "forward";
  }

  if (toPath !== "/" && fromPath.startsWith(`${toPath}/`)) {
    return "back";
  }

  return "forward";
}
