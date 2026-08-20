#!/usr/bin/env bash
# Safe-by-default capability report; it never installs a system extension.
set -euo pipefail
[[ ${1:-} == --report || ${1:-} == --offline-recovery-test ]] || { echo "Usage: $0 --report|--offline-recovery-test" >&2; exit 64; }
if [[ ${1:-} == --offline-recovery-test ]]; then
  [[ $EUID -eq 0 ]] || { echo 'offline recovery test requires root' >&2; exit 77; }
  [[ -x /usr/local/libexec/redteam-macos-transport ]] || { echo 'macOS transport is not installed' >&2; exit 1; }
  exec /usr/local/libexec/redteam-macos-transport offline-recovery-test
fi
if [[ $(uname -s) != Darwin ]]; then
  echo 'macOS capability check: not running on macOS'
  exit 0
fi
version=$(sw_vers -productVersion)
printf 'macOS %s\n' "$version"
printf 'interactive collector: supported through BSD script -F output-only recording\n'
printf 'OpenBSM kernel audit: deprecated since macOS 11 and disabled since macOS 14; it is not coverage.\n'
printf 'EndpointSecurity: requires an organization-signed, Apple-approved entitlement and system extension; this project does not install or claim it.\n'
printf 'noninteractive SSH: unsupported; no ForceCommand or sshd configuration is installed.\n'
