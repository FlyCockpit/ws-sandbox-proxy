import { createReadStream, createWriteStream } from "node:fs";
import { stat } from "node:fs/promises";
import { pipeline } from "node:stream/promises";
import { createWsspClient } from "@wssp/sdk";

const wssp = createWsspClient({
  baseUrl: "https://wssp.example.com",
  apiKey: process.env.WSSP_SDK_KEY ?? "",
});

const sandboxId = "sbx_…";
const limits = await wssp.files.limits(); // per-transfer cap, 1 MiB chunks
console.log("max transfer bytes", limits.transferMaxBytes);

// Streaming upload. A factory source can be re-read, so a retry with the SAME
// idempotency key resumes after the chunks the server already acknowledged.
const local = "./repo.tar";
const { size } = await stat(local);
const uploaded = await wssp.files.upload(
  sandboxId,
  "/home/user/repo.tar",
  () => createReadStream(local),
  { totalBytes: size, idempotencyKey: `upload:${sandboxId}:repo.tar` },
);
console.log("sha256", uploaded.sha256);

// Streaming download: one capture of the guest file, validated as it flows.
const download = await wssp.files.download(sandboxId, "/home/user/repo/report.json");
await pipeline(download.nodeStream(), createWriteStream("./report.json"));

// Small files: bounded in-memory conveniences (client cap 32 MiB).
await wssp.files.writeBytes(sandboxId, "/home/user/note.txt", new TextEncoder().encode("hi\n"));
const note = await wssp.files.readBytes(sandboxId, "/home/user/note.txt");
console.log(new TextDecoder().decode(note), await wssp.files.exists(sandboxId, "/tmp/x"));

// Rich observations are bounded live pages; continuation is explicit.
const page = await wssp.files.list(sandboxId, "/home/user", { limit: 100 });
console.log(page.items, page.nextCursor);
const info = await wssp.files.getInfo(sandboxId, "/home/user/note.txt");
console.log(info.size, info.permissions);
console.log("created", await wssp.files.makeDir(sandboxId, "/home/user/reports"));
await wssp.files.rename(sandboxId, "/home/user/note.txt", "/home/user/reports/note.txt");
await wssp.files.remove(sandboxId, "/home/user/reports/note.txt"); // nonrecursive
