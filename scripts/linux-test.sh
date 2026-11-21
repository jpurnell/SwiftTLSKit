#!/usr/bin/env bash
# Build and test SwiftTLSKit on a real Linux host over ssh, with no GitHub involved.
#
# usage: scripts/linux-test.sh [toolchain] [--no-ca-store] [--musl] [-- extra swift-test args]
#   toolchain      a swiftly release name installed on the host (default: the host's active one)
#   --no-ca-store  after the normal suite, run the bare-box suite with /etc/ssl hidden from that one
#                  process by bubblewrap (a private mount namespace; no root, no change to the host)
#   --musl         also build the package (not its tests) against the static Linux SDK (Musl libc),
#                  which must be installed on the host: swift sdk install <static-linux bundle>.
#                  Build-only: the static SDK ships no Testing module, so the suite cannot link.
#
# environment:
#   LINUX_HOST  ssh host to run on (default: starscream.local)
#   LINUX_DIR   scratch directory on the host (default: ~/linux-verify/SwiftTLSKit)
#
# The tree is copied WITHOUT .build and .git, so macOS build products never reach the Linux build
# and nothing is written outside LINUX_DIR on the host. Runs as whatever user the ssh login is
# (starscream: uid 1000, non-root, which is the case the owner check in PEMFile needs).
set -euo pipefail

HOST="${LINUX_HOST:-starscream.local}"
DIR="${LINUX_DIR:-linux-verify/SwiftTLSKit}"
TOOLCHAIN=""
NO_CA_STORE=0
case "${1:-}" in -*|"") ;; *) TOOLCHAIN="$1"; shift ;; esac
MUSL=0
while [ "${1:-}" = "--no-ca-store" ] || [ "${1:-}" = "--musl" ]; do
  case "$1" in --no-ca-store) NO_CA_STORE=1 ;; --musl) MUSL=1 ;; esac
  shift
done
[ "${1:-}" = "--" ] && shift
EXTRA="$*"

cd "$(dirname "$0")/.."

ssh -o BatchMode=yes "${HOST}" "mkdir -p '${DIR}'"
rsync -az --delete \
  --exclude '.build/' --exclude '.git/' --exclude '.swiftpm/' --exclude '.DS_Store' \
  ./ "${HOST}:${DIR}/"

# shellcheck disable=SC2029
ssh -o BatchMode=yes "${HOST}" "TOOLCHAIN='${TOOLCHAIN}' NO_CA_STORE='${NO_CA_STORE}' MUSL='${MUSL}' EXTRA='${EXTRA}' DIR='${DIR}' bash -s" <<'REMOTE'
set -euo pipefail
export PATH="$HOME/.local/share/swiftly/bin:$PATH"
cd "$DIR"
# The linker warning is noise from the host's libxml2, not from this package. Filter it, and do not
# let "nothing left to print" count as a failure (grep exits 1 then); a failing swift still does.
quiet() { grep -v 'no version information' || true; }
if [ -n "$TOOLCHAIN" ]; then
  # `swiftly use` persists, so put the host's own choice back when the run ends.
  ORIGINAL="$(swiftly list 2>/dev/null | sed -n 's/^Swift \([0-9.]*\) (in use).*/\1/p' | head -1)"
  trap '[ -n "$ORIGINAL" ] && swiftly use "$ORIGINAL" >/dev/null 2>&1 || true' EXIT
  swiftly use "$TOOLCHAIN" >/dev/null
fi
echo "== host: $(uname -sm), uid $(id -u), $(. /etc/os-release; echo "$PRETTY_NAME")"
swift --version 2>&1 | quiet
swift package resolve 2>&1 | quiet
swift build --build-tests 2>&1 | quiet
# shellcheck disable=SC2086
swift test $EXTRA 2>&1 | quiet
if [ "$MUSL" = "1" ]; then
  # A static SDK is built by one compiler and can only be used by that compiler.
  VERSION="$(swift --version 2>&1 | sed -n 's/.*Swift version \([0-9.]*\).*/\1/p' | head -1)"
  if swift sdk list 2>&1 | grep -q "swift-${VERSION}-RELEASE_static-linux"; then
    echo "== musl: static Linux SDK for ${VERSION} ($(uname -m))"
    SDK="$(uname -m)-swift-linux-musl"
    swift build --swift-sdk "$SDK" --scratch-path .build-musl 2>&1 | quiet
  else
    echo "== musl: skipped, no static Linux SDK installed for Swift ${VERSION}"
  fi
fi
if [ "$NO_CA_STORE" = "1" ]; then
  echo "== bare box: /etc/ssl hidden from this process only"
  bwrap --bind / / --dev-bind /dev /dev --tmpfs /etc/ssl \
    env SWIFTTLSKIT_NO_CA_STORE=1 swift test --skip-build --filter BareBoxTrustTests 2>&1 | quiet
fi
REMOTE
