/**
 * The account-deletion inventory's schema side: every model holding an FK to
 * User, read from the Prisma schema files. Used by the unit inventory
 * (account-deletion.test.ts) AND cross-checked against the live `pg_constraint`
 * inventory (account-deletion.pg.test.ts), so the parser cannot silently drift
 * from what the applied schema really contains.
 *
 * A field declaration may span several lines (Prisma allows line breaks inside
 * attribute arguments), so fields are read as logical statements: lines are
 * joined until their parentheses and brackets balance.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** One FK to User: the owning model, its table, the FK column and its ON DELETE. */
export type UserRelation = { model: string; table: string; column: string; onDelete: string };

/**
 * The inventory key of one FK to User. A model may hold several FKs to User
 * (an owner and a reviewer, say), each with its own ON DELETE, so the key is
 * (model, FK column), never the model or table alone.
 */
export function userRelationKey(model: string, column: string): string {
  return `${model}.${column}`;
}

/** pg_constraint.confdeltype for each Prisma referential action. */
export const CONFDELTYPE: Record<string, string> = {
  Cascade: "c",
  Restrict: "r",
  NoAction: "a",
  SetNull: "n",
  SetDefault: "d",
};

/** Strips a `//` comment that is not inside a string literal. */
function stripComment(line: string): string {
  let quoted = false;
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (char === "\\" && quoted) index++;
    else if (char === '"') quoted = !quoted;
    else if (!quoted && char === "/" && line[index + 1] === "/") return line.slice(0, index);
  }
  return line;
}

function depth(text: string): number {
  let open = 0;
  let quoted = false;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (char === "\\" && quoted) index++;
    else if (char === '"') quoted = !quoted;
    else if (!quoted && (char === "(" || char === "[")) open++;
    else if (!quoted && (char === ")" || char === "]")) open--;
  }
  return open;
}

/** Every relation field typed `User`/`User?` that owns the FK (`fields:`). */
export function userRelationsFromSource(source: string): UserRelation[] {
  const relations: UserRelation[] = [];
  const lines = source.split(/\r?\n/).map(stripComment);
  for (let index = 0; index < lines.length; index++) {
    const open = /^\s*model\s+(\w+)\s*\{\s*$/.exec(lines[index]!);
    if (!open) continue;
    const model = open[1]!;
    const statements: string[] = [];
    let pending = "";
    for (index++; index < lines.length && !/^\s*\}\s*$/.test(lines[index]!); index++) {
      pending = pending ? `${pending} ${lines[index]!.trim()}` : lines[index]!.trim();
      if (depth(pending) > 0) continue;
      if (pending) statements.push(pending);
      pending = "";
    }
    if (index >= lines.length || pending)
      throw new Error(`model ${model}: unterminated block or unbalanced field statement`);
    const map = statements
      .map((statement) => /^@@map\(\s*(?:name\s*:\s*)?"([^"]+)"\s*\)$/.exec(statement))
      .find(Boolean);
    const table = map?.[1] ?? model;
    // The database column of a scalar field: its @map name, else the field name.
    const columnOf = (name: string) => {
      const scalar = statements.find((statement) => new RegExp(`^${name}\\s`).test(statement));
      return /@map\(\s*(?:name\s*:\s*)?"([^"]+)"\s*\)/.exec(scalar ?? "")?.[1] ?? name;
    };
    for (const statement of statements) {
      const field = /^\w+\s+User(\?)?\s+(.*)$/.exec(statement);
      const relation = field && /@relation\(([\s\S]*)\)/.exec(field[2]!);
      if (!relation || !/\bfields\s*:/.test(relation[1]!)) continue;
      const fields = /\bfields\s*:\s*\[([^\]]*)\]/.exec(relation[1]!)?.[1]?.split(",");
      const names = (fields ?? []).map((name) => name.trim()).filter(Boolean);
      if (names.length !== 1)
        throw new Error(`model ${model}: a User relation must have exactly one FK field`);
      // Prisma's defaults when onDelete is omitted.
      const onDelete =
        /onDelete\s*:\s*(\w+)/.exec(relation[1]!)?.[1] ?? (field![1] ? "SetNull" : "Restrict");
      relations.push({ model, table, column: columnOf(names[0]!), onDelete });
    }
  }
  return relations;
}

/** Keys relations by `userRelationKey(model, column)`; a repeated key throws
 * instead of silently keeping one of the two. */
export function userRelationInventory(relations: UserRelation[]): Map<string, UserRelation> {
  const inventory = new Map<string, UserRelation>();
  for (const relation of relations) {
    const key = userRelationKey(relation.model, relation.column);
    if (inventory.has(key)) throw new Error(`duplicate FK to User: ${key}`);
    inventory.set(key, relation);
  }
  return inventory;
}

/** The inventory for every `.prisma` file under the package schema directory. */
export function userRelationsFromSchema(
  dir = fileURLToPath(new URL("../../prisma/schema/", import.meta.url)),
): Map<string, UserRelation> {
  return userRelationInventory(
    readdirSync(dir)
      .filter((name) => name.endsWith(".prisma"))
      .sort()
      .flatMap((file) => userRelationsFromSource(readFileSync(join(dir, file), "utf8"))),
  );
}
