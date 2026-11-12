// Load the repo-root `.env` before any `@wssp/env` validation below.
import "@wssp/env/load-dotenv";

/**
 * Data-key rotation CLI, run unbundled with tsx:
 *
 *   pnpm data-key:status            per-table per-kid counts, the epoch row,
 *                                   advisory heartbeats, safe_to_remove
 *   pnpm data-key:promote <kid>     switch writers to <kid> (must be held)
 *
 * Prints kids, counts and epochs only: never a key value or any other env
 * value. The admin data-key card offers the same status and promote.
 */

const [command, kid] = process.argv.slice(2);

async function main(): Promise<number> {
  const { default: prisma } = await import("@wssp/db");
  const { readDataKeyring } = await import("./data-key");
  try {
    const ring = readDataKeyring();
    if (command === "status") {
      const { readDataKeyStatus } = await import("./data-key-status");
      const { redisConnection } = await import("@wssp/queue/connection");
      try {
        const status = await readDataKeyStatus({ ring, redis: redisConnection });
        console.log(JSON.stringify(status, null, 2));
      } finally {
        redisConnection.disconnect();
      }
      return 0;
    }
    if (command === "promote" && kid) {
      if (!ring) {
        console.error("DATA_ENCRYPTION_KEY is not set; nothing to promote.");
        return 1;
      }
      const { promoteDataKey } = await import("./data-key-epoch");
      const result = await promoteDataKey(ring, kid);
      if (!result.ok) {
        console.error(`Refused: ${result.reason}.`);
        return 1;
      }
      console.log(
        JSON.stringify({
          changed: result.changed,
          currentKid: result.currentKid,
          previousKid: result.previousKid,
          epoch: result.epoch.toString(),
        }),
      );
      return 0;
    }
    console.error("Usage: data-key status | data-key promote <kid>");
    return 2;
  } finally {
    await prisma.$disconnect();
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    // A class and code only: messages, stacks and causes can carry connection details.
    const code =
      typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
    console.error(
      `data-key command failed: ${error instanceof Error ? error.name : "error"} ${code}`.trim(),
    );
    process.exitCode = 1;
  },
);
