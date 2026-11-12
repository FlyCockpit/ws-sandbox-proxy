import {
  listDirInput,
  mkdirInput,
  movePathInput,
  readFileInput,
  removePathInput,
  statPathInput,
} from "@wssp/api/sandbox/contracts";
import {
  listDir,
  mkdir,
  movePath,
  readFile,
  removePath,
  statPath,
} from "@wssp/api/sandbox/services/sandboxes";
import type { RouteHandlers } from "./reads.js";

export const fileMutationHandlers = {
  listDir: (owner, { params, body, idempotencyKey }) =>
    listDir(owner, listDirInput.parse({ ...body, id: params.id, idempotencyKey })),
  statPath: (owner, { params, body, idempotencyKey }) =>
    statPath(owner, statPathInput.parse({ ...body, id: params.id, idempotencyKey })),
  mkdir: (owner, { params, body, idempotencyKey }) =>
    mkdir(owner, mkdirInput.parse({ ...body, id: params.id, idempotencyKey })),
  movePath: (owner, { params, body, idempotencyKey }) =>
    movePath(owner, movePathInput.parse({ ...body, id: params.id, idempotencyKey })),
  removePath: (owner, { params, body, idempotencyKey }) =>
    removePath(owner, removePathInput.parse({ ...body, id: params.id, idempotencyKey })),
  // Queues one immutable GET_FILE capture; bytes are served by the ranged
  // download route once the operation succeeds (C30).
  requestDownload: (owner, { params, body, idempotencyKey }) =>
    readFile(owner, readFileInput.parse({ ...body, id: params.id, idempotencyKey })),
} satisfies Pick<
  RouteHandlers,
  "listDir" | "statPath" | "mkdir" | "movePath" | "removePath" | "requestDownload"
>;
