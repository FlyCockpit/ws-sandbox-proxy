/** Parse documentary schema CHECK declarations; committed migrations enforce them. */
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { basename, join, relative } from "node:path";

const hash = (value) => createHash("sha256").update(value).digest("hex");
const failure = (message) => new Error(message);

const BLOCK_OPEN = /^\s*(model|enum|type|view|datasource|generator)\s+(\w+)\s*\{\s*(?:\/\/.*)?$/;
const BLOCK_KEYWORD = /^\s*(model|enum|type|view|datasource|generator)\b/;
const BLOCK_CLOSE = /^\s*\}\s*(?:\/\/.*)?$/;
const CHECK_MENTION = /^\s*\/\/+\s*@check\b/i;
const CHECK_DECLARATION = /^\s*\/\/\s*@check\s+([a-z][a-z0-9_]*)\s*:\s*(\S.*?)\s*$/;
const MAP_MENTION = /^\s*@@map\b/;
const MAP = /^\s*@@map\(\s*(?:name\s*:\s*)?"([^"]*)"\s*\)\s*(?:\/\/.*)?$/;
// `//` is refused like `--`: a trailing Prisma comment after the expression
// would otherwise be embedded in the CHECK and fail late, at apply time, with
// a SQL syntax error that names no declaration (C21c-O4).
const FORBIDDEN_IN_EXPRESSION = [";", "--", "//", "/*", "*/", "$wssp_check$"];

export function schemaCheckConstraints(schemaDir) {
  const files = [];
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const next = join(dir, entry.name);
      if (entry.isDirectory()) visit(next);
      else if (entry.isFile() && entry.name.endsWith(".prisma")) files.push(next);
    }
  };
  visit(schemaDir);
  files.sort();
  const checks = [];
  const declaredAt = new Map();
  for (const file of files) {
    const where = (index) => `${relative(schemaDir, file) || basename(file)}:${index + 1}`;
    const lines = readFileSync(file, "utf8").split("\n");
    let block;
    const closeModel = () => {
      const table = block.table ?? block.name;
      if (block.checks.length && !/^[a-z_][a-z0-9_]*$/.test(table))
        throw failure(`${where(block.line)}: unsupported table name for a // @check: ${table}`);
      for (const check of block.checks) checks.push({ ...check, table });
    };
    lines.forEach((raw, index) => {
      const line = raw.replace(/\r$/, "");
      if (!block) {
        const open = BLOCK_OPEN.exec(line);
        if (open) {
          block = { kind: open[1], name: open[2], line: index, checks: [] };
          return;
        }
        if (BLOCK_KEYWORD.test(line))
          throw failure(`${where(index)}: unsupported block header layout; run prisma format`);
        if (CHECK_MENTION.test(line))
          throw failure(`${where(index)}: // @check outside a model body`);
        return;
      }
      if (BLOCK_CLOSE.test(line)) {
        if (block.kind === "model") closeModel();
        block = undefined;
        return;
      }
      if (BLOCK_OPEN.test(line))
        throw failure(
          `${where(index)}: cannot attribute this line to ${block.kind} ${block.name}; run prisma format`,
        );
      if (MAP_MENTION.test(line)) {
        const map = MAP.exec(line);
        if (!map || block.table !== undefined)
          throw failure(`${where(index)}: ambiguous @@map in ${block.kind} ${block.name}`);
        block.table = map[1];
        return;
      }
      if (!CHECK_MENTION.test(line)) return;
      const declaration = CHECK_DECLARATION.exec(line);
      if (!declaration)
        throw failure(
          `${where(index)}: malformed // @check; expected "// @check <lowercase_name>: <SQL boolean expression>"`,
        );
      if (block.kind !== "model")
        throw failure(`${where(index)}: // @check is only allowed in a model body`);
      const [, name, expression] = declaration;
      const forbidden = FORBIDDEN_IN_EXPRESSION.find((token) => expression.includes(token));
      if (forbidden)
        throw failure(
          `${where(index)}: // @check ${name} expression contains "${forbidden}"; it must be one SQL boolean expression`,
        );
      if (declaredAt.has(name))
        throw failure(
          `${where(index)}: duplicate // @check name ${name} (first declared at ${declaredAt.get(name)})`,
        );
      declaredAt.set(name, where(index));
      const constraint = `${name}_ck${hash(expression).slice(0, 8)}`;
      if (constraint.length > 63)
        throw failure(`${where(index)}: CHECK constraint name too long: ${name}`);
      block.checks.push({ name, constraint, expression, declaredAt: where(index) });
    });
    if (block) throw failure(`${where(block.line)}: ${block.kind} ${block.name} is never closed`);
  }
  return checks;
}
