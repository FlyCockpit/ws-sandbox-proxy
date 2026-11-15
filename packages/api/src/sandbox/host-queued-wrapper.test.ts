import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { queuedHostCommandWrapper } from "./host-queued-wrapper";

it("quotes hostile shell input, clears startup variables and brackets the exact exit status with privilege-ticket invalidation", () => {
  const dir = mkdtempSync(join(tmpdir(), "wssp-queued-"));
  try {
    const log = join(dir, "calls");
    writeFileSync(
      join(dir, "sudo"),
      // biome-ignore lint/suspicious/noTemplateCurlyInString: Shell parameter expansion must remain literal.
      '#!/bin/sh\nprintf "%s:%s:%s:%s\\n" "$*" "${SUDO_ASKPASS-unset}" "${BASH_ENV-unset}" "${ENV-unset}" >> "$WSSP_TEST_LOG"\n',
      { mode: 0o755 },
    );
    const command = `printf "%s\\n" "quotes: ' ; $(printf injection) \`printf backtick\`"; printf "body:%s:%s:%s\\n" "\${SUDO_ASKPASS-unset}" "\${BASH_ENV-unset}" "\${ENV-unset}" >> "$WSSP_TEST_LOG"; exit 37`;
    const wrapper = queuedHostCommandWrapper(command);
    expect(wrapper.endsWith("\n")).toBe(false);
    execFileSync("/bin/sh", ["-n", "-c", wrapper]);
    const result = spawnSync("/bin/sh", ["-c", wrapper], {
      encoding: "utf8",
      env: {
        PATH: `${dir}:/usr/bin:/bin`,
        WSSP_TEST_LOG: log,
        SUDO_ASKPASS: "hostile",
        BASH_ENV: "hostile",
        ENV: "hostile",
      },
    });
    expect(result.status).toBe(37);
    expect(result.stdout).toBe("quotes: ' ; injection backtick\n");
    expect(readFileSync(log, "utf8")).toBe(
      "-k:unset:unset:unset\nbody:unset:unset:unset\n-k:unset:unset:unset\n",
    );
  } finally {
    rmSync(dir, { recursive: true });
  }
});
