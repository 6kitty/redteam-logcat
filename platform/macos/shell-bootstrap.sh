# shellcheck shell=sh
# Installed into the monitored user's bash/zsh startup file.
[ -r '/Library/Application Support/RedteamLogcat/config' ] || return 0
. '/Library/Application Support/RedteamLogcat/config'
[ "${USER:-}" = "$REDTEAM_RECORD_USER" ] || return 0
case $- in *i*) ;; *) return 0;; esac
if [ "${RT_SESSION_RECORDING:-}" = 1 ]; then
  . '/Library/Application Support/RedteamLogcat/shell-hooks.sh'
elif [ -z "${REDTEAM_RECORDING_BOOTSTRAP:-}" ]; then
  export REDTEAM_RECORDING_BOOTSTRAP=1
  exec /usr/bin/sudo -n /usr/local/libexec/redteam-macos-record-session
fi
