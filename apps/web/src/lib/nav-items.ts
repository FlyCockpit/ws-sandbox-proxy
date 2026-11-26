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
type NavPlacement = "desktop" | "mobile" | "userMenu";
/** Primary sections: the sidebar (desktop) and bottom tabs (phone). */
type PrimaryNavPath =
  | "/dashboard/sandboxes"
  | "/dashboard/templates"
  | "/dashboard/operations"
  | "/dashboard/terminals"
  | "/settings";
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
export type AppNavPath = "/" | PrimaryNavPath | SettingsNavPath | "/admin";
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

export type AppNavItem = RouteNavItem & {
  id: "home" | "settings" | "admin";
  audience: NavAudience;
  placements: readonly NavPlacement[];
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

/**
 * Top-bar and user-menu items. Signed-in users get no top-bar links: their
 * one navigation surface is {@link primaryNavItems} (sidebar or bottom tabs),
 * and Settings and Admin live in the user menu.
 */
const appNavItems: AppNavItem[] = [
  {
    id: "home",
    path: "/",
    labelKey: "items.home",
    icon: Home,
    exact: true,
    audience: "anonymous",
    placements: ["desktop", "mobile"],
  },
  {
    id: "settings",
    path: "/settings",
    labelKey: "items.settings",
    icon: Settings,
    exact: false,
    audience: "authenticated",
    placements: ["userMenu"],
  },
  {
    id: "admin",
    path: "/admin",
    labelKey: "items.admin",
    icon: Shield,
    exact: false,
    audience: "admin",
    placements: ["userMenu"],
  },
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

export type PrimaryNavId = "sandboxes" | "templates" | "activity" | "terminals" | "settings";
export type PrimaryNavItem = RouteNavItem & { id: PrimaryNavId; path: PrimaryNavPath };

/**
 * The signed-in app's one navigation surface: the sidebar at `md` and up, the
 * bottom tab bar below. Daily-use order, Sandboxes first (it is the landing
 * page). Every route is under the `_auth` layout: signed-in only, forced-2FA
 * takeover, and each page's data comes from an owner-scoped procedure.
 */
export const primaryNavItems: readonly PrimaryNavItem[] = [
  {
    id: "sandboxes",
    path: "/dashboard/sandboxes",
    labelKey: "dashboard:nav.sandboxes",
    icon: Boxes,
    exact: false,
  },
  {
    id: "templates",
    path: "/dashboard/templates",
    labelKey: "dashboard:nav.templates",
    icon: Layers,
    exact: false,
  },
  {
    id: "activity",
    path: "/dashboard/operations",
    labelKey: "dashboard:nav.activity",
    icon: ListChecks,
    exact: false,
  },
  {
    id: "terminals",
    path: "/dashboard/terminals",
    labelKey: "dashboard:nav.terminals",
    icon: SquareTerminal,
    exact: false,
  },
  {
    id: "settings",
    path: "/settings",
    labelKey: "dashboard:nav.settings",
    icon: Settings,
    exact: false,
  },
];

/**
 * The primary section a pathname belongs to (locale prefix optional), or
 * `null` outside the signed-in app. Every `/settings/...` page, including the
 * set-up-once pages moved off the sidebar, keeps Settings active.
 */
export function primarySectionFor(pathname: string): PrimaryNavId | null {
  const path = stripLangPrefix(pathname);
  for (const item of primaryNavItems) {
    if (path === item.path || path.startsWith(`${item.path}/`)) return item.id;
  }
  return null;
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
  primaryNavItems,
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
