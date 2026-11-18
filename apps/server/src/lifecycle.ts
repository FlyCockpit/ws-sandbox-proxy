import { readDataKeyring } from "@wssp/api/crypto/data-key";
import { startDataKeyHeartbeat } from "@wssp/api/crypto/data-key-heartbeat";
import { initializeHostMemoryReservations } from "@wssp/api/sandbox/host-admission";
import { bindHostImageVerifier, bindHostSandboxProbe } from "@wssp/api/sandbox/host-image-verifier";
import { bindHostTerminalPolicy } from "@wssp/api/sandbox/host-terminal-policy";
import { bindImageSchedulerWake } from "@wssp/api/sandbox/image-store/config";
import { releaseAllOperationWaiters } from "@wssp/api/sandbox/operation-waiters";
import { safeErrnoCode, safeErrorLog } from "@wssp/api/sandbox/sensitive-errors";
import { markTemplateBuildStorageUnavailable } from "@wssp/api/template-builds/config";
import { startTemplateBuildOrchestrator } from "@wssp/api/template-builds/orchestrator";
import prisma from "@wssp/db";
import { type InstanceHeartbeat, startInstanceHeartbeat } from "@wssp/db/instance-heartbeat";
import { env } from "@wssp/env/server";
import { redisConnection } from "@wssp/queue";
import { startWorkerRuntime, WorkerDrainError, type WorkerRuntime } from "worker/runtime";
import { bindHostAccess } from "../../../packages/api/src/sandbox/host-access.js";
import {
  bindTunnelBridge,
  bindTunnelWake,
} from "../../../packages/api/src/sandbox/tunnels/bridge.js";
import { tunnelController } from "../../../packages/api/src/sandbox/tunnels/controller.js";
import { resetImageRelay } from "./sandbox-image-relay/index.js";
import { startImageScheduler } from "./sandbox-image-relay/scheduler.js";
import { browserTerminalService } from "./sandbox-relay/browser-terminal.js";
import { startCommandOutputRetention } from "./sandbox-relay/command-output.js";
import { sweepConnectedHosts } from "./sandbox-relay/host-liveness.js";
import { bindCaptureResultListener } from "./sandbox-relay/operation-handlers.js";
import { startSandboxOutboxProcessor } from "./sandbox-relay/outbox-processor.js";
import { sandboxRelaySessionManager } from "./sandbox-relay/session-manager.js";
import { startTerminalSessionSweep } from "./sandbox-relay/terminal-session-sweep.js";

import { bindRelayCaptures } from "./sandbox-transfers/captures.js";
import { startTransferStore } from "./sandbox-transfers/runtime.js";
import { bindBuildContextStores, startBuildContextStore } from "./template-builds/runtime.js";

/** Values-free startup diagnostic: a fixed step label, the class, a safe code
 * and a Node errno token (EACCES, ENOENT, ...). Never a message or a path. */
function startupFailureLog(step: string, error: unknown, fallbackCode: string) {
  const errno = safeErrnoCode(error);
  return { step, ...safeErrorLog(error, fallbackCode), ...(errno ? { errno } : {}) };
}

export function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timeout`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** The HTTP host owns signals before dependency startup or the first job. */
export function createServerLifecycle() {
  const startup = new AbortController();
  let runtime: WorkerRuntime | undefined;
  let starting: Promise<WorkerRuntime> | undefined;
  // closeIdleConnections exists on plain HTTP servers (Node >= 18.2); hono's
  // serve() return union also admits Http2 servers, which lack it — hence optional.
  let server:
    | { close(callback: (error?: Error) => void): unknown; closeIdleConnections?(): void }
    | undefined;
  let serverStartup: Promise<NonNullable<typeof server>> | undefined;
  let instanceHeartbeat: InstanceHeartbeat | undefined;
  let closing: Promise<void> | undefined;
  let claimed = false;
  let exitCode = 0;
  let stopSandboxOutbox: (() => Promise<void>) | undefined;
  let transfers: Awaited<ReturnType<typeof startTransferStore>> | undefined;
  let transferStartup: ReturnType<typeof startTransferStore> | undefined;
  let contextStartup: ReturnType<typeof startBuildContextStore> | undefined;
  let stopOutputRetention: (() => Promise<void>) | undefined;
  let stopTerminalSessionSweep: (() => Promise<void>) | undefined;
  let stopTunnels: (() => Promise<void>) | undefined;
  let stopTemplateBuilds: (() => Promise<void>) | undefined;
  let readinessTimer: ReturnType<typeof setTimeout> | undefined;
  startup.signal.addEventListener("abort", () => clearTimeout(readinessTimer), { once: true });

  function requireRunning() {
    if (startup.signal.aborted) throw new Error("Server startup cancelled.");
  }
  async function waitForDependency(name: string, ping: () => Promise<unknown>) {
    for (let attempt = 1; attempt <= 5; attempt++) {
      requireRunning();
      try {
        await withTimeout(ping(), 5000, `${name} startup ping`);
        requireRunning();
        console.log(`[server] ${name} is reachable.`);
        return;
      } catch (error) {
        requireRunning();
        if (attempt === 5) throw error;
        const delay = 500 * 2 ** (attempt - 1);
        console.warn(`[server] ${name} not ready (attempt ${attempt}/5), retrying in ${delay}ms.`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
  function shutdown(reason: string, code = 0): Promise<void> {
    if (code) exitCode = code;
    if (closing) return closing;
    // Set the process watchdog before cancellation invokes runtime callbacks.
    const watchdog = setTimeout(() => process.exit(exitCode || 1), 25_000);
    // Held /v1 operation long-polls answer now and no new read holds, so the
    // HTTP drain below never waits out a 25 s long-poll.
    releaseAllOperationWaiters();
    // Publish the shared completion before abort callbacks can re-enter shutdown.
    closing = Promise.resolve()
      .then(async () => {
        // Stop admission immediately, but keep sockets and shared clients alive
        // until the current durable claim/send/finalization has completed.
        const relayDrain = (async () => {
          // Browser terminals first and unconditionally (C53, C55-CC-3): each
          // PTY is asked to close and each browser gets the explicit
          // `shutdown` intent with 4401 now, independent of the drains below,
          // so neither a rejected drain nor the watchdog can turn it into 1006.
          browserTerminalService.dispose();
          try {
            if (transferStartup) {
              try {
                transfers = await transferStartup;
              } catch {
                /* Startup already refused admission. */
              }
            }
            const contexts = await contextStartup?.catch(() => undefined);
            // The in-flight build tick reads the context store, the relay
            // and the database: it returns before any of them closes.
            await stopTemplateBuilds?.();
            await Promise.all([
              stopSandboxOutbox?.(),
              stopOutputRetention?.(),
              stopTerminalSessionSweep?.(),
              transfers?.close(),
              contexts?.close(),
            ]);
          } finally {
            // Host sockets stay up for the drains' in-flight sends, then close
            // even when a drain rejected (the rejection still fails the exit).
            bindHostAccess(null);
            await stopTunnels?.();
            bindTunnelWake(null);
            bindTunnelBridge(null);
            await sandboxRelaySessionManager.dispose();
          }
        })();
        const jobDrain = (async () => {
          let active = runtime;
          if (!active && starting) {
            try {
              active = await starting;
            } catch (error) {
              // Ordinary startup rejection follows a completed cleanup. A failed
              // cleanup must never authorize disconnecting shared clients.
              if (error instanceof WorkerDrainError) throw error;
            }
          }
          await active?.stop();
        })();
        // Handle rejection now while the independent HTTP drain is in progress.
        const jobResult = Promise.all([jobDrain, relayDrain]).then(
          () => true,
          (error: unknown) => {
            console.error(
              "[server] Background drain failed:",
              safeErrorLog(error, "server_background_drain_failed"),
            );
            return false;
          },
        );
        server ??= await serverStartup?.catch(() => undefined);
        if (server) {
          // /ready has already flipped to 503, allowing the proxy to stop routing.
          await new Promise((resolve) => setTimeout(resolve, 5000));
          // close() also waits on idle keep-alive sockets; release them now so only
          // in-flight requests hold the drain.
          server.closeIdleConnections?.();
          await new Promise<void>((resolve) => {
            const timeout = setTimeout(resolve, 10_000);
            server?.close((error) => {
              clearTimeout(timeout);
              if (error)
                console.error(
                  "[server] Error closing HTTP server:",
                  safeErrorLog(error, "server_http_close_failed"),
                );
              resolve();
            });
          });
        }
        if (!(await jobResult)) {
          process.exit(1);
          return;
        }
        await instanceHeartbeat?.stop();
        await prisma.$disconnect();
        redisConnection.disconnect();
        clearTimeout(watchdog);
        process.exit(exitCode);
      })
      .catch((error: unknown) => {
        console.error("[server] Shutdown failed:", safeErrorLog(error));
        process.exit(1);
      });
    startup.abort();
    console.log(`[server] Received ${reason} — starting graceful shutdown…`);
    return closing;
  }
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
  process.on("unhandledRejection", (error) => {
    console.error("[server] unhandledRejection", safeErrorLog(error));
    void shutdown("unhandledRejection", 1);
  });
  process.on("uncaughtException", (error) => {
    // An unwound stack may leave shared state inconsistent; don't run a drain.
    console.error("[server] uncaughtException", safeErrorLog(error));
    process.exit(1);
  });
  return {
    isShuttingDown: () => startup.signal.aborted,
    isWorkerReady: () => !startup.signal.aborted && (runtime?.isReady() ?? false),
    async start(listen: () => NonNullable<typeof server> | Promise<NonNullable<typeof server>>) {
      if (claimed) throw new Error("Server already started; restart the process to re-enter.");
      claimed = true;
      if (!env.BACKUP_ENABLED) {
        console.log(
          "[backup] Automatic database backups are OFF. Set BACKUP_ENABLED=true with a backup destination; enable the backup service with BACKUP_SCHEDULE=daily for daily backups. See docs/operations/backup-and-restore.md.",
        );
      }
      // A fixed label for the step in progress; the startup-failure log names it.
      let step = "dependencies";
      // Optional features never fail boot (owner rule): a failure leaves the
      // feature unavailable with a logged, values-free reason.
      const optional = async (feature: string, body: () => unknown) => {
        try {
          await body();
          return true;
        } catch (error) {
          requireRunning();
          console.error(
            "[server] Optional feature unavailable:",
            startupFailureLog(feature, error, "server_optional_feature_unavailable"),
          );
          return false;
        }
      };
      try {
        await waitForDependency("Postgres", () => prisma.$queryRaw`SELECT 1`);
        await waitForDependency("Redis", () => redisConnection.ping());
        requireRunning();
        instanceHeartbeat = startInstanceHeartbeat({ role: "server" });
        step = "host_memory_reservations";
        await initializeHostMemoryReservations();
        requireRunning();
        if (env.WORKER_MODE === "embedded") {
          step = "embedded_worker";
          starting = startWorkerRuntime({
            embedded: true,
            signal: startup.signal,
            onFatal: (error) => {
              console.error(
                "[server] Embedded consumer failed:",
                safeErrorLog(error, "server_embedded_consumer_failed"),
              );
              void shutdown("embedded consumer failure", 1);
            },
          });
          runtime = await starting;
        }
        requireRunning();
        // Build-context recovery first: it unlinks staged names of adopted
        // contexts, so transfer recovery never sees a spool with two names.
        // Optional: without its root, template builds are unavailable.
        let contexts: Awaited<ReturnType<typeof startBuildContextStore>> | undefined;
        const contextsReady = await optional("template_build_context_store", async () => {
          contextStartup = startBuildContextStore();
          contexts = await contextStartup;
        });
        if (!contextsReady) {
          contextStartup = undefined;
          markTemplateBuildStorageUnavailable();
        }
        requireRunning();
        step = "transfer_store";
        transferStartup = startTransferStore();
        transfers = await transferStartup;
        if (contexts) bindBuildContextStores(contexts, transfers);
        // The relay's file captures are owned by this store (C28): its
        // close() drains in-flight capture IO and refuses new captures.
        bindRelayCaptures(transfers);
        // Relayed image parts never survive a restart (daemons re-request).
        await optional("image_relay_spool", () => resetImageRelay());
        requireRunning();
        // WP4: no relay socket exists before the listener, so every host still
        // CONNECTED died with the previous process. A failure fails boot.
        step = "host_liveness_sweep";
        const swept = await sweepConnectedHosts();
        if (swept.disconnected > 0)
          console.log(
            `[server] Marked ${swept.disconnected} stale host connection(s) disconnected.`,
          );
        requireRunning();
        step = "http_listen";
        serverStartup = Promise.resolve(listen());
        server = await serverStartup;
        requireRunning();
        step = "post_listen";
        stopOutputRetention = startCommandOutputRetention(startup.signal);
        stopTerminalSessionSweep = startTerminalSessionSweep(startup.signal);
        // Advisory: which kids this process holds (data-key rotation status).
        await optional("data_key_heartbeat", () =>
          startDataKeyHeartbeat({
            redis: redisConnection,
            role: "server",
            readRing: readDataKeyring,
            signal: startup.signal,
          }),
        );
        bindHostImageVerifier((input) => sandboxRelaySessionManager.verifyHostImage(input));
        bindHostSandboxProbe((input) => sandboxRelaySessionManager.probeSandbox(input));
        bindHostAccess(sandboxRelaySessionManager.hostAccess);
        // Preview tunnels: optional; the controller idles without a configured server.
        bindTunnelBridge({ link: (hostId) => sandboxRelaySessionManager.tunnelLink(hostId) });
        bindTunnelWake(
          () =>
            void tunnelController()
              .tick()
              .catch(() => undefined),
        );
        stopTunnels = tunnelController().start(startup.signal);
        bindHostTerminalPolicy({
          read: (hostId, ownerId) =>
            sandboxRelaySessionManager.hostTerminalPolicies.read(hostId, ownerId),
          raise: (hostId, ownerId) =>
            sandboxRelaySessionManager.hostTerminalPolicies.raise(hostId, ownerId),
          authorize: (hostId, ownerId, epoch, tx) =>
            sandboxRelaySessionManager.authorizeTerminalTransport(hostId, ownerId, epoch, tx),
          connected: (hostId, ownerId, epoch) =>
            sandboxRelaySessionManager.terminalTransportConnected(hostId, ownerId, epoch),
        });
        stopSandboxOutbox = startSandboxOutboxProcessor(startup.signal);
        const wakeImages = startImageScheduler(
          (hostId, epoch, frame) => sandboxRelaySessionManager.sendImageFrame(hostId, epoch, frame),
          startup.signal,
          (hostId, epoch, frame) => sandboxRelaySessionManager.sendDiskFrame(hostId, epoch, frame),
        );
        bindCaptureResultListener(wakeImages);
        bindImageSchedulerWake(wakeImages);
        // Template builds: the tick runs here, where the context
        // port is bound; it stops with the startup signal.
        await optional("template_build_orchestrator", () => {
          stopTemplateBuilds = startTemplateBuildOrchestrator(startup.signal).stop;
        });
        requireRunning();
        const markReadyWhenHealthy = () => {
          if (startup.signal.aborted) return;
          if (env.WORKER_MODE !== "embedded" || runtime?.isReady()) {
            instanceHeartbeat?.markReady();
            return;
          }
          readinessTimer = setTimeout(markReadyWhenHealthy, 1000);
          readinessTimer.unref?.();
        };
        markReadyWhenHealthy();
      } catch (error) {
        console.error(
          "[server] Startup failed:",
          startupFailureLog(step, error, "server_startup_failed"),
        );
        await shutdown("startup failure", startup.signal.aborted ? 0 : 1);
      }
    },
  };
}
