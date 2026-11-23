#!/bin/sh
# Refuses a CLI release that /install.sh would refuse, before anything is published
# (.github/workflows/release.yml runs it on the cargo-dist output and again on the files it
# uploads): every target's archive is present, sha256.sum names it on exactly one well-formed
# line, the archive holds only wssp-<target>/ with wssp-<target>/wssp once, and every listed
# checksum matches.
# Keep the targets in step with apps/cli/dist-workspace.toml and CLI_RELEASE_TARGETS in
# apps/server/src/install-script.ts (install-script.test.ts checks both).
set -eu

dir=${1:?usage: check-cli-artifacts.sh <artifacts directory>}
cd "$dir"

fail() {
  printf '::error::%s\n' "$*" >&2
  exit 1
}

[ -f sha256.sum ] || fail "sha256.sum is missing from the release artifacts."
# cargo-dist ends sha256.sum with a blank line, which `sha256sum --strict` refuses as improperly
# formatted. Drop blank lines so the published file passes a strict check.
sed '/^[[:space:]]*$/d' sha256.sum >sha256.sum.tmp && mv sha256.sum.tmp sha256.sum

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  archive="wssp-$target.tar.xz"
  [ -f "$archive" ] || fail "$archive is missing from the release artifacts."
  awk -v f="$archive" '
    { sub(/\r$/, "") }
    index($0, f) { seen++ }
    NF == 2 && ($2 == f || $2 == "*" f) && $1 ~ /^[0-9a-f]+$/ && length($1) == 64 { ok++ }
    END { exit !(seen == 1 && ok == 1) }' sha256.sum ||
    fail "sha256.sum must name $archive on exactly one '<sha256>  <name>' line."
  # The layout /install.sh accepts: only wssp-<target>/ entries, no "..", one binary.
  tar -tJf "$archive" >members.tmp || fail "could not list $archive."
  awk -v d="wssp-$target" '
    $0 != d && $0 != d "/" && index($0, d "/") != 1 { bad = 1 }
    $0 ~ /(^|\/)[.][.](\/|$)/ { bad = 1 }
    $0 == d "/wssp" { binaries++ }
    END { exit !(binaries == 1 && !bad) }' members.tmp ||
    fail "$archive must hold only wssp-$target/ entries, with wssp-$target/wssp once."
  rm -f members.tmp
done

sha256sum --check --strict sha256.sum
