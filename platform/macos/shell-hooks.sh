# Loaded only inside a root-owned BSD `script -F` session. Never add `script -k`:
# it logs input/keystrokes and can capture passwords.
_redteam_clean() { printf '%s' "$1" | tr '\r\n' '  ' | cut -c 1-2048; }
_redteam_marker() { printf '\033]777;redteam-logcat;%s;%s;%s%s\007' "$1" "$REDTEAM_SESSION_ID" "$2" "${3:+;$3}"; }
_redteam_event() { /usr/bin/sudo -n /usr/local/libexec/redteam-macos-event "$@"; }

if [ -n "${ZSH_VERSION:-}" ] && [ -z "${_REDTEAM_ZSH_ACTIVE:-}" ]; then
  typeset -g _REDTEAM_ZSH_ACTIVE=1 _REDTEAM_SEQUENCE=0 _REDTEAM_ACTIVE_SEQ='' _REDTEAM_ACTIVE_CMD=''
  _redteam_zsh_preexec() {
    local cmd=$(_redteam_clean "$1")
    [[ -n $cmd ]] || return
    (( _REDTEAM_SEQUENCE += 1 )); _REDTEAM_ACTIVE_SEQ=$_REDTEAM_SEQUENCE; _REDTEAM_ACTIVE_CMD=$cmd
    _redteam_event start "$REDTEAM_SESSION_ID" "$_REDTEAM_ACTIVE_SEQ" "$cmd" "$(tty 2>/dev/null || print -rn -- '-')" "$PWD" "${SSH_CONNECTION:-local}"
    _redteam_marker start "$_REDTEAM_ACTIVE_SEQ"
  }
  _redteam_zsh_finish() {
    local result=$1
    [[ -n $_REDTEAM_ACTIVE_SEQ ]] || return
    _redteam_marker end "$_REDTEAM_ACTIVE_SEQ" "$result"
    _redteam_event end "$REDTEAM_SESSION_ID" "$_REDTEAM_ACTIVE_SEQ" "$_REDTEAM_ACTIVE_CMD" "$(tty 2>/dev/null || print -rn -- '-')" "$PWD" "${SSH_CONNECTION:-local}" "$result"
    _REDTEAM_ACTIVE_SEQ=''; _REDTEAM_ACTIVE_CMD=''
  }
  _redteam_zsh_precmd() { _redteam_zsh_finish "$?"; }
  _redteam_zsh_zshexit() { _redteam_zsh_finish "$?"; }
  autoload -Uz add-zsh-hook; add-zsh-hook preexec _redteam_zsh_preexec; add-zsh-hook precmd _redteam_zsh_precmd; add-zsh-hook zshexit _redteam_zsh_zshexit
elif [ -n "${BASH_VERSION:-}" ] && [ -z "${_REDTEAM_BASH_ACTIVE:-}" ]; then
  _REDTEAM_BASH_ACTIVE=1; _REDTEAM_SEQUENCE=0; _REDTEAM_ACTIVE_SEQ=''; _REDTEAM_ACTIVE_CMD=''; _REDTEAM_READY=0
  _redteam_bash_start() {
    local cmd; cmd=$(builtin history 1); cmd=${cmd#*  }; cmd=$(_redteam_clean "$cmd"); [ -n "$cmd" ] || return
    _REDTEAM_SEQUENCE=$((_REDTEAM_SEQUENCE + 1)); _REDTEAM_ACTIVE_SEQ=$_REDTEAM_SEQUENCE; _REDTEAM_ACTIVE_CMD=$cmd
    _redteam_event start "$REDTEAM_SESSION_ID" "$_REDTEAM_ACTIVE_SEQ" "$cmd" "$(tty 2>/dev/null || printf -- -)" "$PWD" "${SSH_CONNECTION:-local}"
    _redteam_marker start "$_REDTEAM_ACTIVE_SEQ"
  }
  _redteam_bash_debug() { [ "${_REDTEAM_READY:-0}" = 1 ] || return; case ${BASH_COMMAND:-} in _redteam_*|trap\ *|history\ *) return;; esac; _REDTEAM_READY=0; _redteam_bash_start; }
  _redteam_bash_prompt() {
    local result=$?
    if [ -n "${_REDTEAM_ACTIVE_SEQ:-}" ]; then
      _redteam_marker end "$_REDTEAM_ACTIVE_SEQ" "$result"
      _redteam_event end "$REDTEAM_SESSION_ID" "$_REDTEAM_ACTIVE_SEQ" "$_REDTEAM_ACTIVE_CMD" "$(tty 2>/dev/null || printf -- -)" "$PWD" "${SSH_CONNECTION:-local}" "$result"
    fi
    _REDTEAM_ACTIVE_SEQ=''; _REDTEAM_ACTIVE_CMD=''; _REDTEAM_READY=1
  }
  PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}_redteam_bash_prompt"; trap '_redteam_bash_debug' DEBUG
fi
