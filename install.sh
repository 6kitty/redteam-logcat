#!/usr/bin/env bash
# Install local command, execution, and terminal-output evidence collection on Kali/Debian.
set -euo pipefail

readonly SCRIPT_NAME=${0##*/}
readonly SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
readonly REDTEAM_DIR=/etc/redteam
readonly LOG_DIR=/var/log/redteam
readonly SESSION_DIR=/var/log/redteam/sessions
readonly SPOOL_DIR=/var/spool/rsyslog

target_user=${SUDO_USER:-}
retention_days=90
check_only=false

die() {
  printf '%s\n' "${SCRIPT_NAME}: $*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh --user USER [--retention-days DAYS]
  sudo ./install.sh --check

Installs local evidence collection for one account:
  - shell command records in /var/log/redteam/commands.log
  - non-interactive SSH command records and output for that account
  - auditd execve and execveat records for that account
  - root-owned structured terminal recordings in /var/log/redteam/sessions/USER
  - a root-only live viewer: sudo logcat

The installer does not configure an off-host collector. Add a collector only with
an approved TLS endpoint and its CA/client certificates.
EOF
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "run this installer with sudo or as root"
}

require_debian_family() {
  [[ -r /etc/os-release ]] || die "cannot identify the operating system"
  # shellcheck disable=SC1091
  . /etc/os-release
  [[ ${ID:-} == "kali" || ${ID_LIKE:-} == *"debian"* || ${ID:-} == "debian" ]] || \
    die "this installer supports Kali/Debian systems"
}

validate_user() {
  [[ -n ${target_user} ]] || die "pass --user USER when sudo cannot identify the target account"
  [[ ${target_user} =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || die "invalid user name: ${target_user}"
  getent passwd "${target_user}" >/dev/null || die "unknown user: ${target_user}"
}

validate_retention() {
  [[ ${retention_days} =~ ^[0-9]+$ ]] || die "retention days must be an integer"
  (( retention_days >= 1 && retention_days <= 3650 )) || die "retention days must be between 1 and 3650"
}

install_from_stdin() {
  local destination=$1
  local mode=$2
  local temporary

  temporary=$(mktemp)
  cat >"${temporary}"
  install -o root -g root -m "${mode}" "${temporary}" "${destination}"
  rm -f "${temporary}"
}

append_block_once() {
  local destination=$1
  local marker=$2
  local temporary

  grep -Fqx "${marker}" "${destination}" 2>/dev/null && return 0
  temporary=$(mktemp)
  cat >"${temporary}"
  printf '\n' >>"${destination}"
  cat "${temporary}" >>"${destination}"
  rm -f "${temporary}"
}

install_packages() {
  local package
  local -a missing_packages=()

  for package in rsyslog auditd zsh util-linux openssh-server; do
    if ! dpkg-query -W -f='${db:Status-Status}' "${package}" 2>/dev/null | grep -Fxq installed; then
      missing_packages+=("${package}")
    fi
  done

  ((${#missing_packages[@]})) || return 0

  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y "${missing_packages[@]}"
}

write_recording_config() {
  local target_home target_shell

  target_home=$(getent passwd "${target_user}" | awk -F: '{print $6}')
  target_shell=$(getent passwd "${target_user}" | awk -F: '{print $7}')
  [[ -n ${target_home} && -d ${target_home} ]] || die "invalid home directory for ${target_user}"
  [[ -x ${target_shell} ]] || die "invalid login shell for ${target_user}"

  install -d -o root -g root -m 0755 "${REDTEAM_DIR}"
  install_from_stdin "${REDTEAM_DIR}/recording.conf" 0644 <<EOF
REDTEAM_RECORD_USER='${target_user}'
REDTEAM_USER_HOME='${target_home}'
REDTEAM_USER_SHELL='${target_shell}'
REDTEAM_WRAPPER='/usr/local/sbin/redteam-record-session'
REDTEAM_SSH_RECORD_WRAPPER='/usr/local/sbin/redteam-record-ssh-command'
EOF
}

write_rsyslog_config() {
  install -d -o root -g root -m 0750 "${LOG_DIR}" "${SESSION_DIR}" "${SESSION_DIR}/${target_user}" "${SPOOL_DIR}"
  if [[ -L ${LOG_DIR}/commands.log || ( -e ${LOG_DIR}/commands.log && ! -f ${LOG_DIR}/commands.log ) ]]; then
    die "refusing non-regular command log: ${LOG_DIR}/commands.log"
  fi
  if [[ ! -e ${LOG_DIR}/commands.log ]]; then
    install -o root -g root -m 0600 /dev/null "${LOG_DIR}/commands.log"
  else
    chown root:root "${LOG_DIR}/commands.log"
    chmod 0600 "${LOG_DIR}/commands.log"
  fi

  install_from_stdin /etc/rsyslog.d/30-redteam-command.conf 0644 <<'EOF'
if ($syslogfacility-text == "local6" and $programname == "redteam-cmd") then {
    action(
        type="omfile"
        file="/var/log/redteam/commands.log"
        fileCreateMode="0600"
        dirCreateMode="0750"
        fileOwner="root"
        fileGroup="root"
    )
    stop
}
EOF

  install_from_stdin /etc/logrotate.d/redteam-command-log 0644 <<EOF
${LOG_DIR}/commands.log {
    daily
    rotate ${retention_days}
    missingok
    notifempty
    compress
    delaycompress
    create 0600 root root
    postrotate
        systemctl kill -s HUP rsyslog.service >/dev/null 2>&1 || true
    endscript
}
EOF
}

write_bash_logging() {
  install_from_stdin /etc/profile.d/redteam-command-logging.sh 0644 <<'EOF'
[ -r /etc/redteam/recording.conf ] || return 0
. /etc/redteam/recording.conf
[ "${USER:-}" = "${REDTEAM_RECORD_USER}" ] || return 0

case $- in
  *i*)
    if [ -n "${BASH_VERSION:-}" ]; then
      _redteam_bash_clean() {
        local value=$1
        value=${value//$'\n'/ }
        value=${value//$'\r'/ }
        printf '%s' "${value:0:2048}"
      }

      _redteam_bash_marker() {
        local event=$1 sequence=$2 result=${3:-}
        [ -n "${REDTEAM_SESSION_ID:-}" ] || return 0
        printf '\033]777;redteam-logcat;%s;%s;%s%s\007' \
          "$event" "$REDTEAM_SESSION_ID" "$sequence" "${result:+;$result}"
      }

      _redteam_bash_log_start() {
        local command tty ssh_connection
        [ -n "${REDTEAM_SESSION_ID:-}" ] || return 0
        command=$(builtin history 1)
        command=${command#*  }
        command=$(_redteam_bash_clean "$command")
        [ -n "$command" ] || return 0
        _REDTEAM_BASH_SEQUENCE=$((_REDTEAM_BASH_SEQUENCE + 1))
        _REDTEAM_BASH_ACTIVE_SEQUENCE=$_REDTEAM_BASH_SEQUENCE
        _REDTEAM_BASH_ACTIVE_COMMAND=$command
        tty=$(tty 2>/dev/null || printf '%s' '-')
        ssh_connection=${SSH_CONNECTION:-local}
        /usr/bin/logger --id --tag redteam-cmd --priority local6.info -- \
          "[event=start] [session=$REDTEAM_SESSION_ID] [seq=$_REDTEAM_BASH_ACTIVE_SEQUENCE] [uid=$UID] [user=$USER] [tty=$tty] [pwd=$PWD] [ssh=$ssh_connection] cmd=$command"
        _redteam_bash_marker start "$_REDTEAM_BASH_ACTIVE_SEQUENCE"
      }

      _redteam_bash_preexec() {
        [ "${_REDTEAM_BASH_READY:-0}" = 1 ] || return 0
        case "${BASH_COMMAND:-}" in
          _redteam_bash_*|trap\ *|history\ *) return 0 ;;
        esac
        _REDTEAM_BASH_READY=0
        _redteam_bash_log_start
      }

      _redteam_bash_prompt() {
        local ret=$? tty ssh_connection
        if [ -n "${_REDTEAM_BASH_ACTIVE_SEQUENCE:-}" ]; then
          _redteam_bash_marker end "$_REDTEAM_BASH_ACTIVE_SEQUENCE" "$ret"
          tty=$(tty 2>/dev/null || printf '%s' '-')
          ssh_connection=${SSH_CONNECTION:-local}
          /usr/bin/logger --id --tag redteam-cmd --priority local6.info -- \
            "[event=end] [session=${REDTEAM_SESSION_ID:-none}] [seq=$_REDTEAM_BASH_ACTIVE_SEQUENCE] [uid=$UID] [user=$USER] [tty=$tty] [pwd=$PWD] [ssh=$ssh_connection] [ret=$ret] cmd=${_REDTEAM_BASH_ACTIVE_COMMAND:-}"
        fi
        _REDTEAM_BASH_ACTIVE_SEQUENCE=
        _REDTEAM_BASH_ACTIVE_COMMAND=
        _REDTEAM_BASH_READY=1
      }

      _REDTEAM_BASH_SEQUENCE=0
      _REDTEAM_BASH_ACTIVE_SEQUENCE=
      _REDTEAM_BASH_ACTIVE_COMMAND=
      _REDTEAM_BASH_READY=0
      case ";${PROMPT_COMMAND:-};" in
        *";_redteam_bash_prompt;"*) ;;
        *) PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND;}_redteam_bash_prompt" ;;
      esac
      trap '_redteam_bash_preexec' DEBUG
    fi
    ;;
esac
EOF

  local target_home
  target_home=$(getent passwd "${target_user}" | awk -F: '{print $6}')
  if [[ ! -e ${target_home}/.bashrc ]]; then
    install -o "${target_user}" -g "$(id -gn "${target_user}")" -m 0644 /dev/null "${target_home}/.bashrc"
  fi
  append_block_once "${target_home}/.bashrc" '# BEGIN REDTEAM BASH SESSION BOOTSTRAP' <<'EOF'

# BEGIN REDTEAM BASH SESSION BOOTSTRAP
if [ -r /etc/profile.d/redteam-command-logging.sh ]; then
  . /etc/profile.d/redteam-command-logging.sh
fi
if [ -r /etc/redteam/session-bootstrap.sh ]; then
  . /etc/redteam/session-bootstrap.sh
fi
# END REDTEAM BASH SESSION BOOTSTRAP
EOF
  chown "${target_user}:$(id -gn "${target_user}")" "${target_home}/.bashrc"
}

write_zsh_logging() {
  install -d -o root -g root -m 0755 /etc/zsh
  install_from_stdin /etc/zsh/redteam-command-logging.zsh 0644 <<'EOF'
[[ -r /etc/redteam/recording.conf ]] || return 0
source /etc/redteam/recording.conf
[[ ${USER:-} == ${REDTEAM_RECORD_USER} ]] || return 0

if [[ -o interactive && -z ${_REDTEAM_ZSH_LOGGING_ACTIVE:-} ]]; then
  typeset -g _REDTEAM_ZSH_LOGGING_ACTIVE=1
  typeset -g _REDTEAM_ZSH_LAST_COMMAND=''
  typeset -g _REDTEAM_ZSH_ACTIVE_SEQUENCE=''
  typeset -g _REDTEAM_ZSH_SEQUENCE=0

  _redteam_zsh_clean() {
    local value=$1
    value=${value//$'\n'/ }
    value=${value//$'\r'/ }
    print -rn -- "${value:0:2048}"
  }

  _redteam_zsh_marker() {
    local event=$1 sequence=$2 result=${3:-}
    [[ -n ${REDTEAM_SESSION_ID:-} ]] || return 0
    printf '\033]777;redteam-logcat;%s;%s;%s%s\007' \
      "$event" "$REDTEAM_SESSION_ID" "$sequence" "${result:+;$result}"
  }

  _redteam_zsh_preexec() {
    local cmd tty ssh_connection
    [[ -n ${REDTEAM_SESSION_ID:-} ]] || return 0
    cmd=$(_redteam_zsh_clean "$1")
    [[ -n $cmd ]] || return 0
    (( _REDTEAM_ZSH_SEQUENCE += 1 ))
    typeset -g _REDTEAM_ZSH_LAST_COMMAND=$cmd
    typeset -g _REDTEAM_ZSH_ACTIVE_SEQUENCE=$_REDTEAM_ZSH_SEQUENCE
    tty=$(tty 2>/dev/null || print -rn -- '-')
    ssh_connection=${SSH_CONNECTION:-}
    if [[ -z $ssh_connection && $tty == /dev/pts/* ]]; then
      ssh_connection=$(/usr/bin/who | /usr/bin/awk -v terminal="${tty#/dev/}" '$2 == terminal {value=$NF; gsub(/[()]/, "", value); print value; exit}')
    fi
    ssh_connection=${ssh_connection:-local}
    /usr/bin/logger --id --tag redteam-cmd --priority local6.info -- \
      "[event=start] [session=$REDTEAM_SESSION_ID] [seq=$_REDTEAM_ZSH_ACTIVE_SEQUENCE] [uid=$UID] [user=$USER] [tty=$tty] [pwd=$PWD] [ssh=$ssh_connection] cmd=$cmd"
    _redteam_zsh_marker start "$_REDTEAM_ZSH_ACTIVE_SEQUENCE"
  }

  _redteam_zsh_finish() {
    local ret=$1
    local tty ssh_connection
    [[ -n ${_REDTEAM_ZSH_ACTIVE_SEQUENCE:-} ]] || return 0
    _redteam_zsh_marker end "$_REDTEAM_ZSH_ACTIVE_SEQUENCE" "$ret"
    tty=$(tty 2>/dev/null || printf '%s' '-')
    ssh_connection=${SSH_CONNECTION:-local}
    /usr/bin/logger --id --tag redteam-cmd --priority local6.info -- \
      "[event=end] [session=${REDTEAM_SESSION_ID:-none}] [seq=$_REDTEAM_ZSH_ACTIVE_SEQUENCE] [uid=$UID] [user=$USER] [tty=$tty] [pwd=$PWD] [ssh=$ssh_connection] [ret=$ret] cmd=${_REDTEAM_ZSH_LAST_COMMAND:-}"
    _REDTEAM_ZSH_LAST_COMMAND=''
    _REDTEAM_ZSH_ACTIVE_SEQUENCE=''
  }

  _redteam_zsh_precmd() {
    local ret=$?
    _redteam_zsh_finish "$ret"
  }

  _redteam_zsh_zshexit() {
    local ret=$?
    _redteam_zsh_finish "$ret"
  }

  autoload -Uz add-zsh-hook
  add-zsh-hook preexec _redteam_zsh_preexec
  add-zsh-hook precmd _redteam_zsh_precmd
  add-zsh-hook zshexit _redteam_zsh_zshexit
  # Boundary hooks must run before theme hooks that draw the next prompt;
  # otherwise prompt redraw bytes would be displayed as command output.
  preexec_functions=(_redteam_zsh_preexec ${preexec_functions:#_redteam_zsh_preexec})
  precmd_functions=(_redteam_zsh_precmd ${precmd_functions:#_redteam_zsh_precmd})
fi
EOF

  append_block_once /etc/zsh/zshrc '# BEGIN REDTEAM ZSH LOGGING' <<'EOF'

# BEGIN REDTEAM ZSH LOGGING
if [[ -r /etc/zsh/redteam-command-logging.zsh ]]; then
  source /etc/zsh/redteam-command-logging.zsh
fi
if [[ -r /etc/redteam/session-bootstrap.sh ]]; then
  source /etc/redteam/session-bootstrap.sh
fi
# END REDTEAM ZSH LOGGING
EOF
}

write_session_recorder() {
  install_from_stdin "${REDTEAM_DIR}/session-bootstrap.sh" 0644 <<'EOF'
[ -r /etc/redteam/recording.conf ] || return 0
. /etc/redteam/recording.conf

case $- in
  *i*) ;;
  *) return 0 ;;
esac

[ "${USER:-}" = "${REDTEAM_RECORD_USER}" ] || return 0
[ -z "${RT_SESSION_RECORDING:-}" ] || return 0
[ -z "${REDTEAM_RECORDING_BOOTSTRAP:-}" ] || return 0

export REDTEAM_RECORDING_BOOTSTRAP=1
exec /usr/bin/sudo -n "${REDTEAM_WRAPPER}"
EOF

  install_from_stdin /usr/local/sbin/redteam-record-session 0755 <<'EOF'
#!/bin/sh
set -eu

. /etc/redteam/recording.conf

[ "$#" -eq 0 ] || exit 64
[ "${SUDO_USER:-}" = "${REDTEAM_RECORD_USER}" ] || exit 64
[ "$(id -u)" -eq 0 ] || exit 64

umask 077
base=/var/log/redteam/sessions/${REDTEAM_RECORD_USER}
stamp=$(/usr/bin/date -u +%Y%m%dT%H%M%S.%N)-$$
session=$base/$stamp
ssh_connection=${SSH_CONNECTION:-local}
case "$ssh_connection" in
  *[!0-9A-Fa-f.:[:space:]]*) ssh_connection=local ;;
esac

/usr/bin/install -d -o root -g root -m 0750 "$session"
{
  printf 'session=%s\n' "$stamp"
  printf 'user=%s\n' "$REDTEAM_RECORD_USER"
  printf 'started_utc=%s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$session/metadata"
/usr/bin/chown root:root "$session/metadata"
/usr/bin/chmod 0600 "$session/metadata"

set +e
/usr/bin/script --quiet --flush --logging-format advanced \
  --log-out "$session/output.log" --log-timing "$session/timing.log" \
  --command "/usr/sbin/runuser -u ${REDTEAM_RECORD_USER} -- /usr/bin/env -i HOME=${REDTEAM_USER_HOME} USER=${REDTEAM_RECORD_USER} LOGNAME=${REDTEAM_RECORD_USER} SHELL=${REDTEAM_USER_SHELL} TERM=xterm-256color PATH=/usr/bin:/bin SSH_CONNECTION='$ssh_connection' RT_SESSION_RECORDING=1 REDTEAM_SESSION_ID=$stamp ${REDTEAM_USER_SHELL} -l"
result=$?
set -e
printf 'ended_utc=%s\nexit_status=%s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" >>"$session/metadata"
exit "$result"
EOF

  install_from_stdin /etc/sudoers.d/90-redteam-record-session 0440 <<EOF
Cmnd_Alias REDTEAM_RECORD = /usr/local/sbin/redteam-record-session, /usr/local/sbin/redteam-record-ssh-command *
Defaults:${target_user} env_keep += "SSH_CONNECTION"
${target_user} ALL=(root) NOPASSWD: REDTEAM_RECORD
EOF
}

write_logcat() {
  local source=${SCRIPT_DIRECTORY}/redteam_logcat.py
  [[ -r ${source} ]] || die "missing ${source}; keep redteam_logcat.py beside this installer"
  install -o root -g root -m 0755 "${source}" /usr/local/bin/logcat
}

write_ssh_command_recorder() {
  local source=${SCRIPT_DIRECTORY}/redteam_ssh_stream.py
  [[ -r ${source} ]] || die "missing ${source}; keep redteam_ssh_stream.py beside this installer"
  install -d -o root -g root -m 0755 /usr/local/libexec /etc/ssh/sshd_config.d
  install -o root -g root -m 0755 "${source}" /usr/local/libexec/redteam-ssh-stream

  install_from_stdin /usr/local/sbin/redteam-record-ssh-command 0755 <<'EOF'
#!/bin/sh
set -eu

. /etc/redteam/recording.conf

[ "$#" -eq 1 ] || exit 64
[ "${SUDO_USER:-}" = "${REDTEAM_RECORD_USER}" ] || exit 64
[ "$(id -u)" -eq 0 ] || exit 64

umask 077
base=/var/log/redteam/sessions/${REDTEAM_RECORD_USER}
stamp=$(/usr/bin/date -u +%Y%m%dT%H%M%S.%N)-$$
session=$base/$stamp
ssh_connection=${SSH_CONNECTION:-local}
case "$ssh_connection" in
  *[!0-9A-Fa-f.:[:space:]]*) ssh_connection=local ;;
esac

/usr/bin/install -d -o root -g root -m 0750 "$session"
printf '%s' "$1" >"$session/command.txt"
/usr/bin/chown root:root "$session/command.txt"
/usr/bin/chmod 0600 "$session/command.txt"
{
  printf 'session=%s\n' "$stamp"
  printf 'user=%s\n' "$REDTEAM_RECORD_USER"
  printf 'capture=ssh-command\n'
  printf 'started_utc=%s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$session/metadata"
/usr/bin/chown root:root "$session/metadata"
/usr/bin/chmod 0600 "$session/metadata"

command_for_log=$(printf '%s' "$1" | /usr/bin/tr '\r\n' '  ' | /usr/bin/cut -c 1-2048)
/usr/bin/logger --id --tag redteam-cmd --priority local6.info -- \
  "[event=start] [session=$stamp] [seq=1] [uid=$(id -u "$REDTEAM_RECORD_USER")] [user=$REDTEAM_RECORD_USER] [tty=ssh-command] [pwd=$REDTEAM_USER_HOME] [ssh=$ssh_connection] cmd=$command_for_log"

set +e
REDTEAM_SSH_RECORD_USER="$REDTEAM_RECORD_USER" \
REDTEAM_SSH_CONNECTION="$ssh_connection" \
  /usr/local/libexec/redteam-ssh-stream "$session"
result=$?
set -e
printf 'ended_utc=%s\nexit_status=%s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" >>"$session/metadata"
/usr/bin/logger --id --tag redteam-cmd --priority local6.info -- \
  "[event=end] [session=$stamp] [seq=1] [uid=$(id -u "$REDTEAM_RECORD_USER")] [user=$REDTEAM_RECORD_USER] [tty=ssh-command] [pwd=$REDTEAM_USER_HOME] [ssh=$ssh_connection] [ret=$result] cmd=$command_for_log"
exit "$result"
EOF

  install_from_stdin /usr/local/sbin/redteam-ssh-force-command 0755 <<'EOF'
#!/bin/sh
set -eu

. /etc/redteam/recording.conf

[ "$(id -un)" = "${REDTEAM_RECORD_USER}" ] || exit 126
if [ -z "${SSH_ORIGINAL_COMMAND:-}" ]; then
  exec "${REDTEAM_USER_SHELL}" -l
fi

# Preserve the OpenSSH SFTP subsystem without injecting a recording stream into
# its binary protocol.  Ordinary remote commands are captured below.
case "$SSH_ORIGINAL_COMMAND" in
  internal-sftp|sftp-server|/usr/lib/openssh/sftp-server*)
    exec /usr/lib/openssh/sftp-server
    ;;
esac

exec /usr/bin/sudo -n "${REDTEAM_SSH_RECORD_WRAPPER}" "$SSH_ORIGINAL_COMMAND"
EOF

  install_from_stdin /etc/ssh/sshd_config.d/90-redteam-command-recording.conf 0644 <<EOF
# Managed by redteam-logcat.  Scope forced command recording to the configured account.
Match User ${target_user}
    ForceCommand /usr/local/sbin/redteam-ssh-force-command
EOF
}

write_audit_rules() {
  local target_uid
  target_uid=$(id -u "${target_user}")
  install -d -o root -g root -m 0750 /etc/audit/rules.d
  install_from_stdin /etc/audit/rules.d/50-redteam-exec.rules 0640 <<EOF
-a always,exit -F arch=b64 -S execve -S execveat -F auid=${target_uid} -k redteam_exec
-a always,exit -F arch=b32 -S execve -S execveat -F auid=${target_uid} -k redteam_exec
EOF
}

validate_files() {
  bash -n /etc/profile.d/redteam-command-logging.sh
  zsh -n /etc/zsh/redteam-command-logging.zsh
  sh -n /etc/redteam/session-bootstrap.sh
  sh -n /usr/local/sbin/redteam-record-session
  sh -n /usr/local/sbin/redteam-record-ssh-command
  sh -n /usr/local/sbin/redteam-ssh-force-command
  python3 -c 'compile(open("/usr/local/libexec/redteam-ssh-stream", "rb").read(), "/usr/local/libexec/redteam-ssh-stream", "exec")'
  python3 -c 'compile(open("/usr/local/bin/logcat", "rb").read(), "/usr/local/bin/logcat", "exec")'
  visudo -cf /etc/sudoers.d/90-redteam-record-session
  rsyslogd -N1
  logrotate -d /etc/logrotate.d/redteam-command-log >/dev/null
  sshd -t
  . /etc/redteam/recording.conf
  sshd -T -C "user=${REDTEAM_RECORD_USER},addr=127.0.0.1,host=localhost" | \
    grep -Fxq 'forcecommand /usr/local/sbin/redteam-ssh-force-command'
}

activate_logging() {
  local target_uid
  target_uid=$(id -u "${target_user}")

  systemctl enable --now rsyslog
  systemctl enable --now auditd
  # augenrules may reject a second semantically identical rule on some Kali
  # auditd builds.  A re-run does not need to load it again when both ABI
  # rules for the configured audit login UID are already active.
  if ! auditctl -l | grep -F 'arch=b64' | grep -Fq "auid=${target_uid} -F key=redteam_exec" || \
     ! auditctl -l | grep -F 'arch=b32' | grep -Fq "auid=${target_uid} -F key=redteam_exec"; then
    augenrules --load
  fi
  systemctl restart rsyslog
  # Kali's packaged ssh.service may accept a reload without applying a newly
  # added Match/ForceCommand rule to new sessions.  A listener restart applies
  # the already-validated configuration; existing session children continue.
  systemctl restart ssh
  systemctl is-active --quiet rsyslog
  systemctl is-active --quiet auditd
  auditctl -l | grep -Fq 'key=redteam_exec'
}

validate_and_activate() {
  validate_files
  activate_logging
}

run_check() {
  require_root
  command -v rsyslogd >/dev/null || die "rsyslog is not installed"
  command -v auditctl >/dev/null || die "auditd is not installed"
  command -v sshd >/dev/null || die "openssh-server is not installed"
  [[ -r /etc/redteam/recording.conf ]] || die "redteam logging is not installed"
  validate_files
  systemctl is-active --quiet rsyslog
  systemctl is-active --quiet auditd
  auditctl -l | grep -Fq 'key=redteam_exec'
  printf 'redteam logging checks passed\n'
}

main() {
  while (($#)); do
    case $1 in
      --user)
        (($# >= 2)) || die "--user requires a value"
        target_user=$2
        shift 2
        ;;
      --retention-days)
        (($# >= 2)) || die "--retention-days requires a value"
        retention_days=$2
        shift 2
        ;;
      --check)
        check_only=true
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        die "unknown option: $1"
        ;;
    esac
  done

  if [[ ${check_only} == true ]]; then
    run_check
    return
  fi

  require_root
  require_debian_family
  validate_user
  validate_retention
  install_packages
  write_recording_config
  write_rsyslog_config
  write_bash_logging
  write_zsh_logging
  write_session_recorder
  write_logcat
  write_ssh_command_recorder
  write_audit_rules
  validate_and_activate

  printf 'installed redteam evidence collection for %s\n' "${target_user}"
  printf 'command log: %s/commands.log\n' "${LOG_DIR}"
  printf 'session output: %s/%s\n' "${SESSION_DIR}" "${target_user}"
  printf 'live view: sudo logcat\n'
}

main "$@"
