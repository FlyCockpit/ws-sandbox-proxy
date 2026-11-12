/**
 * `wssp login` binds the host slug to the device authorization request itself,
 * so the browser approval covers exactly one slug: the CLI sends
 * `scope = "host-slug:<slug>"` to `/api/auth/device/code`, Better Auth stores it
 * on the `DeviceCode` row, the approval page shows it, and the exchange mints
 * for that slug only.
 */
export const HOST_DEVICE_LOGIN_SCOPE_PREFIX = "host-slug:";

export function hostDeviceLoginScope(slug: string): string {
  return `${HOST_DEVICE_LOGIN_SCOPE_PREFIX}${slug}`;
}

const HOST_SLUG_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export function isValidHostSlug(slug: string): boolean {
  return slug.length >= 1 && slug.length <= 63 && HOST_SLUG_PATTERN.test(slug);
}

/**
 * The host slug a device authorization request was made for, or null when the
 * scope is missing, has anything besides one `host-slug:<slug>` token, or names
 * an invalid slug.
 */
export function hostSlugFromDeviceLoginScope(scope: string | null | undefined): string | null {
  if (typeof scope !== "string" || !scope.startsWith(HOST_DEVICE_LOGIN_SCOPE_PREFIX)) return null;
  const slug = scope.slice(HOST_DEVICE_LOGIN_SCOPE_PREFIX.length);
  return isValidHostSlug(slug) ? slug : null;
}
