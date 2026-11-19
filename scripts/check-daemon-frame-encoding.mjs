/**
 * B2R3-2: raw JSON byte encoders outside sandbox-protocol are a closed
 * inventory of reviewed non-frame calls. New calls fail closed, even when
 * the argument's frame type is hidden behind a local variable or alias.
 * Daemon frames must use spell/plain_frame -> WireCodes::encode.
 */
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

// A small lexical scan, rather than a line grep: ignore comments and literals,
// retain literal tokens in call signatures, and balance multiline calls/items.
function tokens(source) {
  const out = [];
  let i = 0;
  while (i < source.length) {
    if (/\s/.test(source[i])) {
      i++;
      continue;
    }
    if (source.startsWith("//", i)) {
      const end = source.indexOf("\n", i);
      i = end < 0 ? source.length : end;
      continue;
    }
    if (source.startsWith("/*", i)) {
      let depth = 1;
      i += 2;
      while (i < source.length && depth) {
        if (source.startsWith("/*", i)) {
          depth++;
          i += 2;
        } else if (source.startsWith("*/", i)) {
          depth--;
          i += 2;
        } else i++;
      }
      assert.equal(depth, 0, "unterminated Rust comment");
      continue;
    }
    const start = i;
    const raw = /^(?:br|r)(#*)"/.exec(source.slice(i));
    if (raw) {
      const end = source.indexOf(`"${raw[1]}`, i + raw[0].length);
      assert.ok(end >= 0, "unterminated Rust raw string");
      i = end + 1 + raw[1].length;
    } else if (source[i] === '"') {
      i++;
      while (i < source.length) {
        if (source[i] === "\\") i += 2;
        else if (source[i++] === '"') break;
      }
    } else {
      // Character literals; a lifetime ('a) remains punctuation + identifier.
      const character = /^'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'/u.exec(
        source.slice(i),
      );
      const word = /^[A-Za-z_][A-Za-z_0-9]*/.exec(source.slice(i));
      i += character ? character[0].length : word ? word[0].length : 1;
    }
    out.push({ text: source.slice(start, i), offset: start });
  }
  return out;
}

function afterBalanced(ts, start, open, close) {
  let depth = 0;
  for (let i = start; i < ts.length; i++) {
    if (ts[i].text === open) depth++;
    else if (ts[i].text === close && --depth === 0) return i + 1;
  }
  throw new Error(`unbalanced Rust ${open}`);
}

function testOnlyCfg(attribute) {
  if (attribute.join(" ") === "cfg ( test )") return true;
  if (attribute.slice(0, 4).join(" ") !== "cfg ( all (") return false;
  // Only a positive, top-level `test` conjunct proves a test-only item.
  // `all(unix, not(test))` is production code and must stay in the scan.
  let depth = 0;
  for (const token of attribute.slice(4, -2)) {
    if (token === "(") depth++;
    else if (token === ")") depth--;
    else if (token === "test" && depth === 0) return true;
  }
  return false;
}

function productionTokens(source) {
  const ts = tokens(source);
  const out = [];
  for (let i = 0; i < ts.length; ) {
    if (ts[i].text === "#" && ts[i + 1]?.text === "[") {
      const end = afterBalanced(ts, i + 1, "[", "]");
      const attribute = ts.slice(i + 2, end - 1).map((t) => t.text);
      if (testOnlyCfg(attribute)) {
        i = end;
        // Skip the test-only item, including any further attributes.
        while (ts[i]?.text === "#" && ts[i + 1]?.text === "[")
          i = afterBalanced(ts, i + 1, "[", "]");
        while (i < ts.length && !["{", ";"].includes(ts[i].text)) i++;
        i = ts[i]?.text === "{" ? afterBalanced(ts, i, "{", "}") : i + 1;
        continue;
      }
    }
    out.push(ts[i++]);
  }
  return out;
}

function encoders(source) {
  const ts = productionTokens(source);
  const calls = [];
  for (let i = 0; i < ts.length; i++) {
    // Defence in depth alongside the protocol crate's non-Serialize frame.
    const macro = ["json", "to_value"].includes(ts[i].text) && ts[i + 1]?.text === "!";
    if (macro && ["(", "[", "{"].includes(ts[i + 2]?.text)) {
      const open = i + 2;
      const close = { "(": ")", "[": "]", "{": "}" }[ts[open].text];
      const end = afterBalanced(ts, open, ts[open].text, close);
      const arg = ts.slice(open + 1, end - 1);
      const object = arg[0]?.text === "{";
      const array = arg[0]?.text === "[";
      const frame =
        object &&
        arg.some(
          (t, n) =>
            t.text === '"type"' &&
            arg[n + 1]?.text === ":" &&
            /^"(?:hello|heartbeat|process\.started|operation\.(?:progress|result|receipt(?:\.pruned)?)|private\.config\.(?:ack|refused)|journal\.key\.ack|host\.admission|availability\.result|inventory\.update|sandbox\.(?:inventory|expiry_status|probe\.result)|reconcile\.complete|file\.chunk\.ack|image\.verify\.result|terminal\.(?:ready|ack|exit))"$/.test(
              arg[n + 2]?.text,
            ),
        );
      if ((!object && !array) || frame)
        calls.push({
          signature: ts
            .slice(i, end)
            .map((t) => t.text)
            .join(" "),
          line: source.slice(0, ts[i].offset).split("\n").length,
        });
    }
    if (
      (ts[i].text === "serialize" && ts[i + 1]?.text === "(") ||
      (ts[i].text === "Serializer" &&
        ts
          .slice(i + 1, i + 5)
          .map((t) => t.text)
          .join("") === "::new(")
    ) {
      const open = ts[i].text === "serialize" ? i + 1 : i + 4;
      const end = afterBalanced(ts, open, "(", ")");
      calls.push({
        signature: ts
          .slice(i, end)
          .map((t) => t.text)
          .join(" "),
        line: source.slice(0, ts[i].offset).split("\n").length,
      });
    }
    // Match qualified, imported and aliased function calls. Ordinary method
    // calls like value.to_string() do not encode a serde daemon frame.
    if (
      /^to_(?:string|vec|writer|value)(?:_pretty)?$/.test(ts[i].text) &&
      ts[i + 1]?.text === "as"
    ) {
      calls.push({
        signature: "raw encoder alias requires review",
        line: source.slice(0, ts[i].offset).split("\n").length,
      });
    }
    if (
      /^to_(?:string|vec|writer|value)(?:_pretty)?$/.test(ts[i].text) &&
      ["(", ":"].includes(ts[i + 1]?.text) &&
      ts[i - 1]?.text !== "."
    ) {
      let open = i + 1;
      // Explicit generic arguments (to_string::<Frame>) are raw calls too.
      while (open < ts.length && ts[open].text !== "(") open++;
      assert.ok(open < ts.length, "raw encoder without a call");
      const end = afterBalanced(ts, open, "(", ")");
      calls.push({
        signature: ts
          .slice(i, end)
          .map((t) => t.text)
          .join(" "),
        line: source.slice(0, ts[i].offset).split("\n").length,
      });
    }
  }
  return calls;
}

function sources(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) {
      if (["target", "node_modules", "tests", "sandbox-protocol"].includes(entry.name)) return [];
      return sources(path);
    }
    return entry.name.endsWith(".rs") && !/(?:_tests|_test)\.rs$/.test(entry.name) ? [path] : [];
  });
}

// Exact call signatures and multiplicities, audited as non-frame data. This
// is deliberately NOT a file/function exemption. Adding even a duplicate call
// requires reviewing this inventory. No DaemonControlMessage/ProcessStarted
// serialization belongs here.
const reviewed = new Map([
  // Capacity B3: read-only TOML comments, durable ledger checksums/envelopes,
  // and nested allocation digest/validation data. None is a relay frame.
  ["apps/cli/src/commands/config.rs|to_string_pretty ( pool )", 1],
  ["apps/cli/src/sandbox_relay/journal/storage.rs|to_vec ( & e . ledger )", 1],
  ["apps/cli/src/sandbox_relay/journal/storage.rs|to_vec ( ledger )", 1],
  ["apps/cli/src/sandbox_relay/journal/storage.rs|to_vec ( & envelope )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_value ( a )", 1],
  // B6: typed filesystem result bodies only; these are nested data, never daemon frames.
  [
    "apps/cli/src/sandbox_relay/supervisor.rs|to_value ( HostFilePage { result : ResultBody : : List { path : response . path , depth : response . depth , items : response . items , next_cursor : response . continuation . as_ref ( ) . map ( | _ | job . dispatch . operation_id . clone ( ) ) , consistency : LiveConsistency : : Live , } , continuation : response . continuation , } )",
    1,
  ],
  [
    "apps/cli/src/sandbox_relay/supervisor.rs|to_value ( ResultBody : : Stat { entry : response } )",
    1,
  ],
  // B7: fallible mutation-result encoder.
  ["apps/cli/src/sandbox_relay/supervisor.rs|to_value ( value )", 1],

  // B4: digest fields and expiry flags only.
  ["apps/cli/src/sandbox_relay/journal.rs|json ! ( version )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|json ! ( limit )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|json ! ( cursor )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|json ! ( true )", 2],
  ["apps/cli/src/sandbox_relay/expiry/tests.rs|json ! ( shorten . lease )", 1],
  // M7: the (settled) HostLease placed in a create result payload, as before.
  ["apps/cli/src/sandbox_relay/reconcile.rs|json ! ( lease )", 1],
  ["apps/cli/src/sandbox_relay/supervisor.rs|json ! ( settled )", 1],
  // CLI logins C8b: the typed, non-secret teardown outcomes
  // (CredentialTeardownOutcomeV11 list) placed in a stop/kill result payload.
  ["apps/cli/src/sandbox_relay/supervisor.rs|json ! ( outcomes )", 1],
  ["apps/cli/src/sandbox_relay/supervisor.rs|json ! ( output_bytes )", 1],
  ["apps/cli/src/sandbox_relay/supervisor.rs|to_value ( & body )", 1],
  ["apps/cli/src/sandbox_relay/supervisor.rs|json ! ( dispatch . lease )", 1],
  ["crates/sandbox-runtime/src/incus/acl.rs|json ! ( grants )", 1],
  // Persisted network-plan record (default-open egress): the mode, the
  // captured node settings and the denied grants, never a relay frame.
  ["crates/sandbox-runtime/src/incus/acl.rs|json ! ( plan . denied_grants )", 1],
  ["crates/sandbox-runtime/src/incus/acl.rs|to_value ( plan . mode )", 1],
  ["crates/sandbox-runtime/src/incus/acl.rs|to_value ( settings )", 1],
  // B12 upgrade: the FIFO-era plan record rewritten to v2 (its version and
  // the migrated node settings); a local durable record, never a frame.
  ["apps/cli/src/commands/config.rs|to_string_pretty ( & config )", 1],
  // Read-only TOML inspection comments on stdout, never relay frames.
  ["apps/cli/src/commands/config.rs|to_string_pretty ( & capacity )", 1],
  ["apps/cli/src/output.rs|to_string ( value )", 1],
  // User commands (`wssp sandbox …`): typed `/v1` HTTP request bodies sent
  // to the control plane with the user login, never a relay frame.
  ["apps/cli/src/api.rs|to_vec ( body )", 1],
  // Preview tunnels: newline-JSON requests (`expose`/`status`) to the local
  // tunnel client's private socket, never a relay frame.
  ["apps/cli/src/sandbox_relay/tunnel.rs|to_vec ( request )", 1],
  // Preview tunnels: a runtime port change rewrites the persisted network-plan
  // record's rules and egress settings, never a relay frame.
  ["crates/sandbox-runtime/src/incus/tunnel_ports.rs|to_value ( & rules )", 1],
  ["crates/sandbox-runtime/src/incus/tunnel_ports.rs|to_value ( & settings )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_value ( & canonical )", 1],
  // Unit fixture scalars inserted into an already decoded dispatch object.
  ["apps/cli/src/sandbox_relay/test_support.rs|json ! ( tagged . digest_scheme )", 1],
  ["apps/cli/src/sandbox_relay/test_support.rs|json ! ( key_id )", 1],
  // CLI logins C2: capture-envelope v1 header (build + canonical re-check on
  // parse). A durable outbox file format, never a relay frame.
  ["apps/cli/src/sandbox_relay/credentials/envelope.rs|to_vec ( & header )", 2],
  // WP7: the private daemon control file (`daemon.json`), not a frame.
  ["apps/cli/src/sandbox_relay/quiesce.rs|to_vec ( & file )", 1],
  // CLI logins C6b: the non-secret credential journal file, not a frame.
  ["apps/cli/src/sandbox_relay/credentials/journal.rs|to_vec ( & next )", 1],
  // B4: borrowed ProcessInfo preview, byte sizing only; never a daemon frame.
  ["apps/cli/src/sandbox_relay/supervisor.rs|to_vec ( & preview )", 1],
  ["crates/sandbox-runtime/src/incus/acl.rs|to_value ( installed_rules )", 1],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_vec ( frame )", 1],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_vec ( & old . record )", 1],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_vec ( & record )", 2],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_string ( & record )", 1],
  [
    "apps/cli/src/sandbox_relay/journal/configs.rs|to_vec ( & ConfigEnvelope { record : record . clone ( ) , checksum : checksum . clone ( ) , } )",
    1,
  ],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_vec ( & retained . record )", 2],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_string ( & config . record )", 1],
  ["apps/cli/src/sandbox_relay/journal/configs.rs|to_vec ( & disk . record )", 1],
  ["apps/cli/src/sandbox_relay/journal/leases.rs|to_vec ( record )", 1],
  [
    "apps/cli/src/sandbox_relay/journal/leases.rs|to_vec ( & Envelope { record : record . clone ( ) , checksum , } )",
    1,
  ],
  ["apps/cli/src/sandbox_relay/journal/leases.rs|to_vec ( & envelope . record )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_vec ( & existing )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_vec ( receipt )", 1],
  // WP0.5 journal records: raw-byte checksums (receipts and cleanup
  // watermarks) and the bounded `ext` size check, all local files.
  ["apps/cli/src/sandbox_relay/journal.rs|to_string ( record )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_vec ( & JournalEnvelope { receipt , checksum } )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_vec ( ext )", 1],
  [
    "apps/cli/src/sandbox_relay/journal.rs|to_vec ( & CleanupEnvelope { watermark : watermark_raw , checksum , } )",
    1,
  ],
  // E6: the server's last deployment egress blocklist, persisted in the
  // daemon state directory (a local file, never a frame).
  ["apps/cli/src/sandbox_relay/egress_state.rs|to_vec ( list )", 1],
  // Local image cache journal file (never a frame).
  ["apps/cli/src/sandbox_relay/images/journal.rs|to_vec ( & self . file )", 1],
  // Disk offload journal: local 0600 state, no key material.
  ["apps/cli/src/sandbox_relay/offload.rs|to_vec ( & self . file )", 1],
  ["apps/cli/src/sandbox_relay/journal.rs|to_vec ( & value )", 1],
  ["apps/cli/src/state.rs|to_string_pretty ( config )", 1],
  ["apps/cli/src/state.rs|to_vec_pretty ( value )", 1],
  ["crates/sandbox-runtime/src/fake/policy.rs|to_vec ( & self . journal )", 1],
  ["crates/sandbox-runtime/src/incus/acl.rs|to_string ( & body )", 1],
  // Incus API ETag hash inputs, in Go struct order; never a daemon frame.
  [
    "crates/sandbox-runtime/src/incus/acl.rs|to_string ( & ( doc . name , doc . description , doc . ingress , doc . egress , doc . config , ) )",
    1,
  ],
  ["crates/sandbox-runtime/src/incus/client.rs|to_string ( & request . lease )", 1],
  [
    "crates/sandbox-runtime/src/incus/client.rs|to_string ( & ReadinessSpec { guest : request . guest . clone ( ) , architecture : request . architecture . clone ( ) . unwrap_or_default ( ) , mode : request . readiness , privilege , root_disk_bytes , } )",
    1,
  ],
  ["crates/sandbox-runtime/src/incus/dns.rs|to_string ( state )", 1],
  ["crates/sandbox-runtime/src/incus/dns.rs|to_string ( & record )", 1],
  [
    'crates/sandbox-runtime/src/incus/dns.rs|to_string ( & serde_json : : json ! ( { "sandbox_id" : sandbox_id , "generations" : history . generations , "request_floor" : history . request_floor , "lease_fence_floor" : history . lease_fence_floor , } ) )',
    2,
  ],
  [
    "crates/sandbox-runtime/src/incus/dns.rs|to_string ( & DnsLeaseObligations { sandbox_id : sandbox_id . to_string ( ) , project : Some ( self . project . clone ( ) ) , entries : armed . to_vec ( ) , } )",
    1,
  ],
  ["crates/sandbox-runtime/src/incus/kvm.rs|to_string ( journal )", 1],
  ["crates/sandbox-runtime/src/incus/kvm.rs|to_string ( & request . lease )", 1],
  ["crates/sandbox-runtime/src/metadata.rs|to_vec ( value )", 1],
  ["crates/sandbox-runtime/src/trait.rs|to_vec ( arg )", 1],
  [
    'crates/sandbox-runtime/src/trait.rs|to_vec ( & serde_json : : json ! ( { "cmd" : description . cmd , "args" : description . args , "argsTruncated" : description . args_truncated , "cwd" : description . cwd , } ) )',
    1,
  ],
  // G1 egress guard: the root guard's own socket protocol (request/reply on
  // /run/wssp-guard/guard.sock), its root-owned state files and the TOML
  // config. None is a relay frame.
  [
    "apps/cli/src/commands/guard/daemon.rs|to_vec ( & PersistedSource { content : content . clone ( ) , } )",
    1,
  ],
  [
    "apps/cli/src/commands/guard/daemon.rs|to_vec ( & FenceRecord { links : self . fenced . clone ( ) , } )",
    1,
  ],
  ["apps/cli/src/commands/guard/daemon.rs|to_vec_pretty ( & status )", 1],
  ["apps/cli/src/commands/guard/mod.rs|to_string ( self )", 1],
  ["crates/sandbox-runtime/src/guard/protocol.rs|to_vec ( reply )", 1],
  ["crates/sandbox-runtime/src/guard/protocol.rs|to_vec ( request )", 1],
]);

function inventory() {
  return ["apps", "crates"]
    .flatMap((dir) => sources(resolve(root, dir)))
    .flatMap((path) => {
      const source = readFileSync(path, "utf8");
      return encoders(source).map((call) => ({ ...call, path: relative(root, path) }));
    });
}

function check() {
  const remaining = new Map(reviewed);
  const violations = [];
  for (const call of inventory()) {
    const key = `${call.path}|${call.signature}`;
    const count = remaining.get(key) ?? 0;
    if (count <= 0)
      violations.push(`${call.path}:${call.line}: raw JSON encoder: ${call.signature}`);
    else remaining.set(key, count - 1);
  }
  for (const [key, count] of remaining)
    if (count) violations.push(`stale non-frame JSON encoder inventory (${count}): ${key}`);
  assert.deepEqual(
    violations,
    [],
    "daemon frames must use WireCodes::encode through spell/plain_frame",
  );
}

function selfTest() {
  for (const source of [
    "serde_json::to_string(&frame)?;",
    "serde_json::json!(frame).to_string();",
    "json!(DaemonControlMessage::from(started));",
    "to_value!(frame);",
    'json!({"type": "operation.result", "state": "failed"});',
    "serde::Serialize::serialize(&frame, serializer);",
    "frame.serialize(serializer);",
    "serde_json::Serializer::new(&mut buf);",
    "serde_json::to_vec(&DaemonControlMessage::ReconcileComplete)?;",
    "serde_json::to_writer(writer, &frame)?;",
    "serde_json::to_value(&frame)?;",
    "serde_json::to_string::<DaemonControlMessage>(&frame)?;",
    "json::to_string_pretty(\n &started\n)?;",
  ])
    assert.equal(encoders(source).length, 1, source);
  assert.equal(
    encoders('/* serde_json::to_vec(&frame) */ const S: &str = r#"serde_json::to_vec(&frame)"#;')
      .length,
    0,
  );
  assert.equal(
    encoders(
      "#[cfg(test)] mod tests { serde_json::to_string(&frame); } serde_json::to_vec(&frame);",
    ).length,
    1,
  );
  assert.equal(
    encoders("#[cfg(all(test, unix))] fn test() { serde_json::to_vec(&frame); }").length,
    0,
  );
  assert.equal(
    encoders("#[cfg(all(unix, test))] fn test() { serde_json::to_vec(&frame); }").length,
    0,
  );
  for (const condition of ["not(test)", "all(unix, not(test))", "any(test, unix)"]) {
    assert.equal(
      encoders(`#[cfg(${condition})] fn production() { serde_json::to_vec(&frame); }`).length,
      1,
    );
  }
  assert.equal(encoders("value.to_string();").length, 0);
  assert.equal(encoders('json!({"pid": 42}); json!([1, 2]);').length, 0);
  assert.equal(encoders("use serde_json::to_string as encode; encode(&frame);").length, 1);
}

selfTest();
if (process.argv.includes("--inventory")) {
  for (const call of inventory()) console.log(`${call.path}|${call.signature}`);
} else {
  check();
  console.log("Daemon frame encoding policy passed (including scanner self-tests).");
}
