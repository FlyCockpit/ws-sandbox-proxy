/** A person types this into their own terminal. No trailing newline. */
export function queuedHostCommandWrapper(command: string): string {
  const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
  // Returned text for the person to review and type; never executed by this service.
  const wrapper =
    'if command -v sudo >/dev/null 2>&1; then sudo -k >/dev/null 2>&1; fi; /bin/sh -c "$1"; s=$?; if command -v sudo >/dev/null 2>&1; then sudo -k >/dev/null 2>&1; fi; exit $s';
  return `env -u SUDO_ASKPASS -u BASH_ENV -u ENV /bin/sh -c ${quote(wrapper)} wssp-queued ${quote(command)}`;
}
