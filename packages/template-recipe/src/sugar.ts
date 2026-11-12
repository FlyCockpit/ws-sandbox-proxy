import { recipeFail } from "./errors";
import type { RecipeStep, RecipeUser } from "./schema";

/**
 * Step sugar shared by the SDK builder and the dashboard. E2B-like naming,
 * unverified against E2B; confirm before the release note.
 */

const PACKAGE = /^[A-Za-z0-9@][A-Za-z0-9@._+:=~/<>^*-]*$/;

function packages(kind: string, names: string | string[]): string {
  const list = typeof names === "string" ? [names] : names;
  if (list.length === 0)
    recipeFail({ code: "recipe_invalid", message: `${kind} needs a package.` });
  for (const name of list) {
    // A leading "-" would be read as an option by the package manager.
    if (!PACKAGE.test(name) || name.length > 214)
      recipeFail({ code: "recipe_invalid", message: `Invalid ${kind} package "${name}".` });
  }
  return list.map((name) => `'${name}'`).join(" ");
}

/** Root `apt-get install` with the list cleanup that keeps images small. */
export function aptInstallStep(
  names: string | string[],
  options: { noInstallRecommends?: boolean } = {},
): RecipeStep {
  const recommends = options.noInstallRecommends === false ? "" : " --no-install-recommends";
  return {
    type: "run",
    user: "root",
    script: `apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y${recommends} ${packages("apt", names)} && rm -rf /var/lib/apt/lists/*`,
  };
}

/** `pip install` as the given user (default: the current USER). */
export function pipInstallStep(
  names: string | string[],
  options: { user?: RecipeUser } = {},
): RecipeStep {
  return {
    type: "run",
    ...(options.user ? { user: options.user } : {}),
    script: `python3 -m pip install --no-cache-dir ${packages("pip", names)}`,
  };
}

/** `npm install`; `global` installs as root with `-g`. */
export function npmInstallStep(
  names: string | string[],
  options: { global?: boolean; user?: RecipeUser } = {},
): RecipeStep {
  if (options.global)
    return { type: "run", user: "root", script: `npm install -g ${packages("npm", names)}` };
  return {
    type: "run",
    ...(options.user ? { user: options.user } : {}),
    script: `npm install ${packages("npm", names)}`,
  };
}
