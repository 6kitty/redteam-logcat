#!/usr/bin/env bash
# Install macOS interactive-shell evidence collection for one authorized user.
set -euo pipefail
readonly APP_DIR='/Library/Application Support/RedteamLogcat'
readonly LOG_DIR=/var/log/redteam
readonly SESSION_DIR=/var/log/redteam/sessions
readonly LIBEXEC_DIR=/usr/local/libexec
readonly BIN_DIR=/usr/local/bin
readonly SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
target_user=${SUDO_USER:-}; dry_run=false; check_only=false; uninstall=false; disable_transport=false
transport_endpoint=; transport_endpoint_id=; transport_ca_cert=; transport_client_cert=; transport_client_key=
die() { printf 'install-macos.sh: %s\n' "$*" >&2; exit 1; }
usage() { cat <<'EOF'
Usage: sudo ./platform/macos/install-macos.sh --user USER [--dry-run]
       sudo ./platform/macos/install-macos.sh --user USER --transport-endpoint https://host/v1/evidence --transport-endpoint-id ID --transport-ca-cert PATH --transport-client-cert PATH --transport-client-key PATH
       sudo ./platform/macos/install-macos.sh --user USER --disable-transport
       sudo ./platform/macos/install-macos.sh --check
       sudo ./platform/macos/install-macos.sh --uninstall [--dry-run]
EOF
}
run() { if "$dry_run"; then printf '+ '; printf '%q ' "$@"; printf '\n'; else "$@"; fi; }
require_root() { [[ $EUID -eq 0 ]] || die 'run as root with sudo'; }
require_macos() { [[ $(uname -s) == Darwin ]] || die 'this installer supports macOS only'; }
validate_user() { [[ $target_user =~ ^[a-z_][a-z0-9_-]*\$?$ ]] || die 'pass a valid --user USER'; dscl . -read "/Users/$target_user" NFSHomeDirectory UserShell >/dev/null 2>&1 || die "unknown user: $target_user"; }
user_value() { dscl . -read "/Users/$target_user" "$1" | awk 'NR == 1 { $1=""; sub(/^ /, ""); print }'; }
append_once() { local file=$1 marker=$2 temporary; grep -Fqx "$marker" "$file" 2>/dev/null && return; temporary=$(mktemp); cat >"$temporary"; if "$dry_run"; then printf '+ append managed bootstrap to %q\n' "$file"; else printf '\n' >>"$file"; cat "$temporary" >>"$file"; fi; rm -f "$temporary"; }
remove_block() { local file=$1 begin=$2 end=$3 temporary; [[ -e $file ]] || return; temporary=$(mktemp); awk -v begin="$begin" -v end="$end" '$0 == begin { skip=1; next } $0 == end { skip=0; next } !skip { print }' "$file" >"$temporary"; if "$dry_run"; then printf '+ remove managed bootstrap from %q\n' "$file"; else cat "$temporary" >"$file"; fi; rm -f "$temporary"; }
install_file() { local source=$1 destination=$2 mode=$3; if "$dry_run"; then printf '+ install -o root -g wheel -m %s %q %q\n' "$mode" "$source" "$destination"; else install -o root -g wheel -m "$mode" "$source" "$destination"; fi; }
safe_directory() { [[ ! -L $1 && ( ! -e $1 || -d $1 ) ]] || die "refusing non-directory or symlink: $1"; }
safe_regular_file() { [[ ! -L $1 && ( ! -e $1 || -f $1 ) ]] || die "refusing non-regular or symlink: $1"; }
transport_value() { awk -F= -v key="$1" '$1 == key { print substr($0, length(key) + 2); exit }' "$APP_DIR/transport.conf" 2>/dev/null; }
active_chain_exists() { [[ -e /var/log/redteam/transport/chain-state.json ]] || find /var/log/redteam/transport/{pending,claimed,acknowledged} -name '*.json' -print -quit 2>/dev/null | grep -q .; }
write_files() {
  local home shell group bashrc bash_profile zshrc
  home=$(user_value NFSHomeDirectory); shell=$(user_value UserShell); group=$(id -gn "$target_user")
  [[ -d $home && -x $shell ]] || die 'target account has an invalid home or shell'
  safe_directory "$APP_DIR"; safe_directory "$LOG_DIR"; safe_directory "$SESSION_DIR"; safe_directory "$LOG_DIR/spool"
  safe_regular_file "$LOG_DIR/commands.log"; safe_regular_file "$LOG_DIR/spool/events.jsonl"
  run install -d -o root -g wheel -m 0755 "$APP_DIR" "$LIBEXEC_DIR" "$BIN_DIR"
  run install -d -o root -g wheel -m 0750 "$LOG_DIR" "$SESSION_DIR" "$SESSION_DIR/$target_user" "$LOG_DIR/spool"
  if ! "$dry_run"; then chown root:wheel "$LOG_DIR" "$SESSION_DIR" "$SESSION_DIR/$target_user" "$LOG_DIR/spool"; chmod 0750 "$LOG_DIR" "$SESSION_DIR" "$SESSION_DIR/$target_user" "$LOG_DIR/spool"; touch "$LOG_DIR/commands.log" "$LOG_DIR/spool/events.jsonl"; chown root:wheel "$LOG_DIR/commands.log" "$LOG_DIR/spool/events.jsonl"; chmod 0600 "$LOG_DIR/commands.log" "$LOG_DIR/spool/events.jsonl"; fi
  if "$dry_run"; then printf '+ write %q/config\n' "$APP_DIR"; else printf "REDTEAM_RECORD_USER='%s'\nREDTEAM_USER_HOME='%s'\nREDTEAM_USER_SHELL='%s'\n" "$target_user" "$home" "$shell" >"$APP_DIR/config"; chown root:wheel "$APP_DIR/config"; chmod 0644 "$APP_DIR/config"; fi
  install_file "$SCRIPT_DIR/shell-bootstrap.sh" "$APP_DIR/shell-bootstrap.sh" 0644
  install_file "$SCRIPT_DIR/shell-hooks.sh" "$APP_DIR/shell-hooks.sh" 0644
  install_file "$SCRIPT_DIR/redteam-macos-record-session" "$LIBEXEC_DIR/redteam-macos-record-session" 0755
  install_file "$SCRIPT_DIR/redteam-macos-event" "$LIBEXEC_DIR/redteam-macos-event" 0755
  install_file "$SCRIPT_DIR/redteam-macos-spool-export" "$BIN_DIR/redteam-macos-spool-export" 0755
  install_file "$SCRIPT_DIR/redteam-macos-transport.py" "$LIBEXEC_DIR/redteam-macos-transport" 0755
  install_file "$SCRIPT_DIR/../../redteam_logcat.py" "$BIN_DIR/logcat" 0755
  install_file "$SCRIPT_DIR/../../central_collector.py" "$APP_DIR/central_collector.py" 0644
  install_file "$SCRIPT_DIR/../../redteam_evidence_protocol.py" "$APP_DIR/redteam_evidence_protocol.py" 0644
  if "$disable_transport"; then
    if "$dry_run"; then printf '+ disable launchd transport while preserving spool and evidence\n'; else launchctl bootout system /Library/LaunchDaemons/org.redteam.logcat.transport.plist 2>/dev/null || true; rm -f /Library/LaunchDaemons/org.redteam.logcat.transport.plist; printf 'MACOS_TRANSPORT_ENABLED=0\n' >"$APP_DIR/transport.conf"; chown root:wheel "$APP_DIR/transport.conf"; chmod 0600 "$APP_DIR/transport.conf"; fi
  elif [[ -n $transport_endpoint ]]; then
    [[ -n $transport_endpoint_id && -n $transport_ca_cert && -n $transport_client_cert && -n $transport_client_key ]] || die 'all five --transport-* values are required together'
    [[ $transport_endpoint =~ ^https://[^/?#[:space:]]+/v1/evidence$ && $transport_endpoint != *$'\n'* && $transport_endpoint_id != *$'\n'* && $transport_ca_cert != *$'\n'* && $transport_client_cert != *$'\n'* && $transport_client_key != *$'\n'* ]] || die 'transport endpoint must be exact newline-free https://HOST/v1/evidence; config values must be newline-free'
    [[ -r $transport_ca_cert && -r $transport_client_cert && -r $transport_client_key ]] || die 'transport TLS files must be readable during install'
    old_endpoint_id=$(transport_value MACOS_TRANSPORT_ENDPOINT_ID)
    if [[ -n $old_endpoint_id && $old_endpoint_id != "$transport_endpoint_id" ]] && active_chain_exists; then die 'refusing endpoint-ID change while transport chain state exists; run --disable-transport, preserve/reset the spool under approved procedure, then configure the new endpoint'; fi
    if "$dry_run"; then printf '+ write enabled transport.conf and launchd plist\n'; else printf 'MACOS_TRANSPORT_ENABLED=1\nMACOS_TRANSPORT_ENDPOINT=%s\nMACOS_TRANSPORT_ENDPOINT_ID=%s\nMACOS_TRANSPORT_CA_CERT=%s\nMACOS_TRANSPORT_CLIENT_CERT=%s\nMACOS_TRANSPORT_CLIENT_KEY=%s\n' "$transport_endpoint" "$transport_endpoint_id" "$transport_ca_cert" "$transport_client_cert" "$transport_client_key" >"$APP_DIR/transport.conf"; chown root:wheel "$APP_DIR/transport.conf"; chmod 0600 "$APP_DIR/transport.conf"; printf '<plist version="1.0"><dict><key>Label</key><string>org.redteam.logcat.transport</string><key>ProgramArguments</key><array><string>%s/redteam-macos-transport</string><string>forward-once</string></array><key>StartInterval</key><integer>5</integer></dict></plist>\n' "$LIBEXEC_DIR" >/Library/LaunchDaemons/org.redteam.logcat.transport.plist; chown root:wheel /Library/LaunchDaemons/org.redteam.logcat.transport.plist; chmod 0644 /Library/LaunchDaemons/org.redteam.logcat.transport.plist; launchctl bootout system /Library/LaunchDaemons/org.redteam.logcat.transport.plist 2>/dev/null || true; launchctl bootstrap system /Library/LaunchDaemons/org.redteam.logcat.transport.plist; fi
  elif [[ ! -e $APP_DIR/transport.conf ]] && ! "$dry_run"; then printf 'MACOS_TRANSPORT_ENABLED=0\n' >"$APP_DIR/transport.conf"; chown root:wheel "$APP_DIR/transport.conf"; chmod 0600 "$APP_DIR/transport.conf"; fi
  if "$dry_run"; then printf '+ write /etc/sudoers.d/redteam-macos-logcat\n'; else printf 'Cmnd_Alias REDTEAM_MACOS = %s/redteam-macos-record-session, %s/redteam-macos-event *\n%s ALL=(root) NOPASSWD: REDTEAM_MACOS\n' "$LIBEXEC_DIR" "$LIBEXEC_DIR" "$target_user" >/etc/sudoers.d/redteam-macos-logcat; chown root:wheel /etc/sudoers.d/redteam-macos-logcat; chmod 0440 /etc/sudoers.d/redteam-macos-logcat; fi
  bashrc="$home/.bashrc"; bash_profile="$home/.bash_profile"; zshrc="$home/.zshrc"; [[ -e $bashrc ]] || run install -o "$target_user" -g "$group" -m 0644 /dev/null "$bashrc"; [[ -e $bash_profile ]] || run install -o "$target_user" -g "$group" -m 0644 /dev/null "$bash_profile"; [[ -e $zshrc ]] || run install -o "$target_user" -g "$group" -m 0644 /dev/null "$zshrc"
  append_once "$bashrc" '# BEGIN REDTEAM MACOS BASH' <<'EOF'
# BEGIN REDTEAM MACOS BASH
[ -r '/Library/Application Support/RedteamLogcat/shell-bootstrap.sh' ] && . '/Library/Application Support/RedteamLogcat/shell-bootstrap.sh'
# END REDTEAM MACOS BASH
EOF
  append_once "$bash_profile" '# BEGIN REDTEAM MACOS BASH PROFILE' <<'EOF'
# BEGIN REDTEAM MACOS BASH PROFILE
[ -r '/Library/Application Support/RedteamLogcat/shell-bootstrap.sh' ] && . '/Library/Application Support/RedteamLogcat/shell-bootstrap.sh'
# END REDTEAM MACOS BASH PROFILE
EOF
  append_once "$zshrc" '# BEGIN REDTEAM MACOS ZSH' <<'EOF'
# BEGIN REDTEAM MACOS ZSH
[[ -r '/Library/Application Support/RedteamLogcat/shell-bootstrap.sh' ]] && source '/Library/Application Support/RedteamLogcat/shell-bootstrap.sh'
# END REDTEAM MACOS ZSH
EOF
  "$dry_run" || chown "$target_user:$group" "$bashrc" "$bash_profile" "$zshrc"
}
check() { require_root; require_macos; [[ -r $APP_DIR/config ]] || die 'not installed'; visudo -cf /etc/sudoers.d/redteam-macos-logcat >/dev/null; bash -n "$APP_DIR/shell-bootstrap.sh" "$APP_DIR/shell-hooks.sh" "$LIBEXEC_DIR/redteam-macos-record-session" "$LIBEXEC_DIR/redteam-macos-event"; python3 -c 'compile(open("/usr/local/bin/logcat", "rb").read(), "/usr/local/bin/logcat", "exec")'; [[ $(stat -f '%Su:%Lp' "$LOG_DIR/commands.log") == root:600 ]] || die 'commands.log must be root-owned mode 0600'; [[ -r $APP_DIR/transport.conf ]] || die 'transport config missing'; if grep -Fxq 'MACOS_TRANSPORT_ENABLED=1' "$APP_DIR/transport.conf"; then [[ -f /Library/LaunchDaemons/org.redteam.logcat.transport.plist ]] || die 'enabled transport launchd plist is missing'; launchctl print system/org.redteam.logcat.transport >/dev/null || die 'enabled transport launchd job is not healthy'; fi; echo 'macOS interactive collector checks passed'; echo 'viewer: sudo logcat'; echo 'noninteractive SSH capture: unsupported (no forced-command interception installed)'; "$SCRIPT_DIR/validate-hardware.sh" --report; }
do_uninstall() { local home; require_root; require_macos; if [[ -r $APP_DIR/config ]]; then target_user=$(awk -F= '/^REDTEAM_RECORD_USER=/{gsub(/\047/, "", $2); print $2}' "$APP_DIR/config"); home=$(user_value NFSHomeDirectory); remove_block "$home/.bashrc" '# BEGIN REDTEAM MACOS BASH' '# END REDTEAM MACOS BASH'; remove_block "$home/.bash_profile" '# BEGIN REDTEAM MACOS BASH PROFILE' '# END REDTEAM MACOS BASH PROFILE'; remove_block "$home/.zshrc" '# BEGIN REDTEAM MACOS ZSH' '# END REDTEAM MACOS ZSH'; fi; run rm -f /etc/sudoers.d/redteam-macos-logcat "$LIBEXEC_DIR/redteam-macos-record-session" "$LIBEXEC_DIR/redteam-macos-event" "$BIN_DIR/redteam-macos-spool-export" "$BIN_DIR/logcat"; run rm -rf "$APP_DIR"; echo "collector removed; preserved evidence under $LOG_DIR"; }
while (($#)); do case $1 in --user) target_user=${2:?}; shift 2;; --transport-endpoint) transport_endpoint=${2:?}; shift 2;; --transport-endpoint-id) transport_endpoint_id=${2:?}; shift 2;; --transport-ca-cert) transport_ca_cert=${2:?}; shift 2;; --transport-client-cert) transport_client_cert=${2:?}; shift 2;; --transport-client-key) transport_client_key=${2:?}; shift 2;; --disable-transport) disable_transport=true; shift;; --dry-run) dry_run=true; shift;; --check) check_only=true; shift;; --uninstall) uninstall=true; shift;; -h|--help) usage; exit 0;; *) die "unknown option: $1";; esac; done
"$disable_transport" && [[ -n $transport_endpoint$transport_endpoint_id$transport_ca_cert$transport_client_cert$transport_client_key ]] && die '--disable-transport cannot be combined with transport configuration values'
if "$check_only"; then check; elif "$uninstall"; then do_uninstall; else require_root; require_macos; validate_user; write_files; check; echo "installed macOS interactive collector for $target_user"; fi
