/** Incus instance-name prefix. Guest names are `{prefix}{sandboxId}`. */
export const INCUS_INSTANCE_NAME_PREFIX = "wssp-sbx-";

const MANAGED_INSTANCE_NAME = /^wssp-sbx-[A-Za-z0-9][A-Za-z0-9_-]{0,53}$/;

/** Default Incus instance name for a control-plane sandbox id (`wssp-sbx-<id>`). */
export function defaultIncusInstanceName(sandboxId: string): string {
  return `${INCUS_INSTANCE_NAME_PREFIX}${sandboxId}`;
}

/** True when `name` is a host-managed `wssp-sbx-` instance (strict charset/length). */
export function isManagedIncusInstanceName(name: string): boolean {
  return (
    INCUS_INSTANCE_NAME_PREFIX.length + 1 <= name.length &&
    name.length <= 63 &&
    MANAGED_INSTANCE_NAME.test(name) &&
    !name.includes("/") &&
    !name.includes("%") &&
    !name.startsWith("-")
  );
}
