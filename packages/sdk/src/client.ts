import { type CommandsApi, createCommandsApi } from "./commands";
import { type CredentialsApi, createCredentialsApi } from "./credentials";
import { createFilesApi, type FilesApi } from "./files";
import { createOperationsApi, type OperationsApi } from "./operations";
import { type PollingOptions, resolvePolling } from "./polling";
import { createPoolsApi, type PoolsApi } from "./pools";
import { createSandboxesApi, type SandboxesApi } from "./sandboxes";
import { createTemplatesApi, type TemplatesApi } from "./templates";
import { createTransfersApi, type TransfersApi } from "./transfers";
import { createWsspTransport, type WsspTransport, type WsspTransportOptions } from "./transport";
import { createWebhooksApi, type WebhooksApi } from "./webhooks";

export type WsspClientOptions = WsspTransportOptions & {
  /** Default bounds for every wait; per-call options override them. */
  polling?: PollingOptions;
};

export type WsspClient = {
  /** The raw C39 transport for routes without a convenience method. */
  readonly transport: WsspTransport;
  readonly sandboxes: SandboxesApi;
  readonly templates: TemplatesApi;
  readonly pools: PoolsApi;
  readonly operations: OperationsApi;
  readonly commands: CommandsApi;
  readonly transfers: TransfersApi;
  readonly files: FilesApi;
  /** Webhook endpoints and their delivery log (scope `webhooks:write`). */
  readonly webhooks: WebhooksApi;
  /** CLI logins: definitions, logins, accounts, instances, write-only values
   * (scopes `credentials:read` / `credentials:write`). */
  readonly credentials: CredentialsApi;
};

/**
 * Lifecycle client on top of the C39 transport: create/get/list/connect/
 * stop/destroy/setTimeout/isAlive plus explicit waitReady/waitOperation/
 * waitDeleted. Every mutation preserves ONE idempotency key through transport
 * retries and polling; an `unknown` outcome is never retried under a new key.
 */
export function createWsspClient(options: WsspClientOptions): WsspClient {
  const transport = createWsspTransport(options);
  const polling = options.polling;
  resolvePolling(polling, undefined);
  const commands = createCommandsApi(transport, polling);
  const files = createFilesApi(
    transport,
    polling,
    createTransfersApi(transport, polling),
    (id, opts) => commands.cancelAndWait(id, opts),
  );
  return {
    transport,
    templates: createTemplatesApi(transport),
    pools: createPoolsApi(transport),
    sandboxes: createSandboxesApi(transport, polling, { commands, files }),
    operations: createOperationsApi(transport, polling),
    commands,
    transfers: createTransfersApi(transport, polling),
    files,
    webhooks: createWebhooksApi(transport),
    credentials: createCredentialsApi(transport),
  };
}
