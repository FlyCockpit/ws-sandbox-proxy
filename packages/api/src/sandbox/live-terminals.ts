/**
 * The Terminals page's view of live browser terminals.
 *
 * Browser terminals live only in the relay process's memory
 * (`BrowserTerminalService`); they are not persistent and not reattachable
 * after their browser socket ends (WP8 resume covers only a relay drop or
 * server restart, in the same tab). The relay registers a directory at boot;
 * without one (worker, tests) the list is empty and `end` finds nothing.
 *
 * Both calls are owner-scoped inside the directory: only terminals whose
 * server-side binding names `userId` (the sandbox's creator, or the host's
 * owner) are ever listed or ended. Admins get no cross-owner view here.
 */
import { ORPCError } from "@orpc/server";
import prisma, { type Prisma } from "@wssp/db";
import { readHostTerminalPolicy } from "./host-terminal-policy";

/** One live terminal as the relay knows it (metadata only, never content). */
export type LiveTerminalEntry = {
  /** Server-minted listing id (`bt_<32 hex>`); not a ticket or relay fence id. */
  id: string;
  /** The binding's owner: the sandbox's creator or the host's owner. */
  userId: string;
  target: { kind: "sandbox"; sandboxId: string } | { kind: "host"; hostId: string };
  /** The Better Auth session that opened it (never returned to the browser). */
  sessionId: string;
  /** `connecting`: verifying or opening the PTY; `attached`: the PTY is open. */
  status: "connecting" | "attached";
  openedAt: Date;
  /** The last keystroke from the browser or output from the PTY. */
  lastActivityAt: Date;
};

export type LiveTerminalDirectory = {
  list(userId: string): LiveTerminalEntry[];
  /**
   * Ends one of `userId`'s terminals; false when there is no such live
   * terminal. Rejects when the end could not be made durable (nothing ended).
   */
  end(userId: string, id: string): Promise<boolean>;
};

let directory: LiveTerminalDirectory | null = null;

export function registerLiveTerminalDirectory(next: LiveTerminalDirectory | null): void {
  directory = next;
}

/** Live terminals listed at most (relay caps keep the real count far lower). */
export const LIVE_TERMINALS_MAX = 100;

const sandboxSelect = {
  id: true,
  name: true,
  state: true,
} satisfies Prisma.SandboxSelect;

const hostSelect = {
  id: true,
  label: true,
  status: true,
} satisfies Prisma.SandboxHostSelect;

const sessionSelect = {
  id: true,
  userAgent: true,
} satisfies Prisma.SessionSelect;

export type LiveTerminalView = {
  id: string;
  status: LiveTerminalEntry["status"];
  openedAt: Date;
  lastActivityAt: Date;
  /** Opened from the browser making this request. */
  thisBrowser: boolean;
  /** "Firefox on Linux"-style summary of the opening browser, if known. */
  device: { browser: string | null; os: string | null };
  target:
    | {
        kind: "sandbox";
        id: string;
        name: string | null;
        state: Prisma.SandboxGetPayload<{ select: typeof sandboxSelect }>["state"] | null;
      }
    | {
        kind: "host";
        id: string;
        name: string | null;
        status: Prisma.SandboxHostGetPayload<{ select: typeof hostSelect }>["status"] | null;
      };
};

/**
 * The caller's own live terminals, newest first, with each target's name and
 * state from owner-scoped reads. A target the owner no longer has (deleted
 * mid-read) keeps a null name instead of borrowing anyone else's.
 */
export async function listLiveTerminals(caller: {
  userId: string;
  sessionId: string;
}): Promise<{ terminals: LiveTerminalView[]; truncated: boolean }> {
  const all = (directory?.list(caller.userId) ?? [])
    // Defense in depth: the directory filters by owner already.
    .filter((entry) => entry.userId === caller.userId)
    .sort((a, b) => b.openedAt.getTime() - a.openedAt.getTime());
  const entries = all.slice(0, LIVE_TERMINALS_MAX);
  if (entries.length === 0) return { terminals: [], truncated: false };

  const sandboxIds = unique(
    entries.flatMap((e) => (e.target.kind === "sandbox" ? [e.target.sandboxId] : [])),
  );
  const hostIds = unique(
    entries.flatMap((e) => (e.target.kind === "host" ? [e.target.hostId] : [])),
  );
  const sessionIds = unique(entries.map((e) => e.sessionId));
  const [sandboxes, hosts, sessions] = await Promise.all([
    sandboxIds.length
      ? prisma.sandbox.findMany({
          where: { id: { in: sandboxIds }, userId: caller.userId },
          select: sandboxSelect,
          take: sandboxIds.length,
        })
      : [],
    hostIds.length
      ? prisma.sandboxHost.findMany({
          where: { id: { in: hostIds }, userId: caller.userId },
          select: hostSelect,
          take: hostIds.length,
        })
      : [],
    prisma.session.findMany({
      where: { id: { in: sessionIds }, userId: caller.userId },
      select: sessionSelect,
      take: sessionIds.length,
    }),
  ]);
  const sandboxById = new Map(sandboxes.map((row) => [row.id, row]));
  const hostById = new Map(hosts.map((row) => [row.id, row]));
  const agentBySession = new Map(sessions.map((row) => [row.id, row.userAgent]));

  const terminals = entries.map((entry): LiveTerminalView => {
    const base = {
      id: entry.id,
      status: entry.status,
      openedAt: entry.openedAt,
      lastActivityAt: entry.lastActivityAt,
      thisBrowser: entry.sessionId === caller.sessionId,
      device: describeUserAgent(agentBySession.get(entry.sessionId) ?? null),
    };
    if (entry.target.kind === "sandbox") {
      const row = sandboxById.get(entry.target.sandboxId);
      return {
        ...base,
        target: {
          kind: "sandbox",
          id: entry.target.sandboxId,
          name: row?.name ?? null,
          state: row?.state ?? null,
        },
      };
    }
    const row = hostById.get(entry.target.hostId);
    return {
      ...base,
      target: {
        kind: "host",
        id: entry.target.hostId,
        name: row?.label ?? null,
        status: row?.status ?? null,
      },
    };
  });
  return { terminals, truncated: all.length > entries.length };
}

/** Ends one of the caller's live terminals; false when it is not theirs or gone. */
export async function endLiveTerminal(caller: { userId: string }, id: string): Promise<boolean> {
  if (!directory) return false;
  try {
    return await directory.end(caller.userId, id);
  } catch (error) {
    console.error(
      `[terminals] end failed (${error instanceof Error ? error.constructor.name : typeof error})`,
    );
    throw new ORPCError("SERVICE_UNAVAILABLE", {
      message: "The terminal could not be ended. Try again.",
      data: { code: "terminal.end_unavailable" },
    });
  }
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

/** Hosts the "Open a new terminal" picker lists at most. */
export const HOST_TARGETS_MAX = 20;

const hostTargetSelect = {
  id: true,
  label: true,
  status: true,
  lastConnectedAt: true,
  lastHeartbeatAt: true,
  deletionRequestedAt: true,
  quarantinedAt: true,
  hostTerminalVetoedAt: true,
} satisfies Prisma.SandboxHostSelect;

/**
 * The caller's own hosts for the picker, with whether a host terminal can
 * open there now: `true`/`false` from the connected node's policy (and a
 * dashboard veto), `null` while the host is not connected here. The same
 * read as the host page's `terminalPolicy`; nothing else of the policy leaves.
 */
export async function listHostTargets(caller: { userId: string }) {
  const rows = await prisma.sandboxHost.findMany({
    where: { userId: caller.userId, deletionRequestedAt: null },
    select: hostTargetSelect,
    orderBy: [{ label: "asc" }, { id: "asc" }],
    take: HOST_TARGETS_MAX + 1,
  });
  return {
    hosts: rows.slice(0, HOST_TARGETS_MAX).map(({ hostTerminalVetoedAt, ...row }) => {
      const policy = readHostTerminalPolicy(row.id, caller.userId);
      return {
        ...row,
        hostTerminal: policy ? policy.hostTerminal && !hostTerminalVetoedAt : null,
      };
    }),
    more: rows.length > HOST_TARGETS_MAX,
  };
}

const BROWSERS: readonly [RegExp, string][] = [
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\bOPR\//, "Opera"],
  [/\bFirefox\/|\bFxiOS\//, "Firefox"],
  [/\b(?:Headless)?Chrome\/|\bCriOS\//, "Chrome"],
  [/\bVersion\/[\d.]+.*\bSafari\//, "Safari"],
];
const SYSTEMS: readonly [RegExp, string][] = [
  [/\biPhone|\biPad|\biPod/, "iOS"],
  [/\bAndroid\b/, "Android"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
  [/\bWindows\b/, "Windows"],
  [/\bLinux\b/, "Linux"],
];

/**
 * A coarse browser and OS name from a user agent, for recognizing one's own
 * devices. Unknown agents give nulls; the raw string never leaves the server.
 */
export function describeUserAgent(userAgent: string | null): {
  browser: string | null;
  os: string | null;
} {
  if (!userAgent) return { browser: null, os: null };
  const ua = userAgent.slice(0, 512);
  return {
    browser: BROWSERS.find(([pattern]) => pattern.test(ua))?.[1] ?? null,
    os: SYSTEMS.find(([pattern]) => pattern.test(ua))?.[1] ?? null,
  };
}
