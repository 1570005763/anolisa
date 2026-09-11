#!/usr/bin/env bash
# Keep execution inside a function so a truncated piped download cannot run it.
ecs_demo() {
    set -euo pipefail
    die() { echo "ERROR: $*" >&2; exit 1; }
    if [[ "${1:-}" == --help ]]; then
        echo 'Usage: bash ecs-demo.sh SSH_DESTINATION [qoder|control|prepare|doctor|tamper|reset|down]'
        echo 'Default: qoder. Use an SSH config alias for custom ports, keys, or jump hosts.'
        echo 'Set LOCAL_PORT to change the local dashboard port (default: 17396).'
        return
    fi
    [[ $# -ge 1 && $# -le 2 ]] || die 'Usage: bash ecs-demo.sh SSH_DESTINATION [qoder|control|prepare|doctor|tamper|reset|down]'
    destination=$1
    [[ "$destination" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.@:-]*$ ]] || die 'Use user@hostname, user@IP, or a simple SSH config alias.'
    action=${2:-qoder}
    case "$action" in qoder|control|prepare|doctor|tamper|reset|down) ;; *) die "Unknown action: $action" ;; esac
    command -v ssh >/dev/null || die 'Install an OpenSSH client first.'
    case "$(uname -s)" in Darwin|Linux) ;; *) die 'Run this script in macOS, Linux, or Windows WSL.' ;; esac
    port=${LOCAL_PORT:-17396}
    [[ "$port" =~ ^[1-9][0-9]{0,4}$ ]] && (( port <= 65535 )) || die 'LOCAL_PORT must be between 1 and 65535.'

    # The remote script is fixed text; only an allowlisted action becomes an argument.
    IFS= read -r -d '' remote_script <<'REMOTE' || true
set -euo pipefail
umask 077
action=$1
directory="$HOME/agentseccore-demo"
die() { echo "ERROR: $*" >&2; exit 1; }
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || die 'The remote host must be Linux amd64.'
[[ ! -L "$directory" ]] || die 'The demo directory must not be a symlink.'
prepared=false
current=false
if [[ -d "$directory" && -f "$directory/SHA256SUMS" ]]; then
    manifest=$(sha256sum "$directory/SHA256SUMS")
    case "${manifest%% *}" in __CURRENT_MANIFESTS__) current=true ;; esac
fi
if [[ "$current" == false ]]; then
    case "$action" in
        prepare|qoder)
            temporary=$(mktemp -d)
            trap 'rm -rf -- "$temporary"' EXIT
            curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
                --retry 3 --connect-timeout 15 --max-time 180 \
                https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-__VERSION__/install.sh \
                --output "$temporary/install.sh"
            printf '%s  %s\n' __INSTALLER_SHA256__ "$temporary/install.sh" | sha256sum --check
            bash "$temporary/install.sh" "$directory"
            prepared=true
            rm -rf -- "$temporary"
            trap - EXIT
            ;;
        *) die 'Run prepare or qoder first to install the demo.' ;;
    esac
fi
cd -- "$directory"
# Only generated, pinned manifests may authorize execution, including offline installations.
manifest=$(sha256sum SHA256SUMS)
case "${manifest%% *}" in __CURRENT_MANIFESTS__) ;; *) die 'Unsupported installation manifest.' ;; esac
[[ -z "$(find . -type l -print -quit)" ]] || die 'Installation contains symlinks.'
sha256sum --check --status SHA256SUMS || die 'Installed demo files changed; restore the supported starter release before continuing.'
case "$action" in
    prepare|qoder)
        if [[ "$prepared" == false ]]; then ./demo.sh up; ./demo.sh doctor; fi
        if [[ "$action" == qoder ]]; then exec ./demo.sh qoder; fi
        ;;
    control)
        echo 'Control terminal B: use ./demo.sh tamper or ./demo.sh reset here.'
        exec bash --noprofile --norc -i
        ;;
    *) exec ./demo.sh "$action" ;;
esac
REMOTE
    # POSIX quoting also works when the SSH account's login shell is not Bash.
    quoted_script=${remote_script//\'/\'\\\'\'}
    remote_command="bash -c '$quoted_script' -- '$action'"
    ssh_options=(-o ControlPath=none -o ServerAliveInterval=30 -o ServerAliveCountMax=3)
    if [[ "$action" == qoder || "$action" == control ]]; then
        [[ -t 1 ]] && ( : </dev/tty ) 2>/dev/null || die 'Qoder requires a real terminal. Use prepare for unattended setup.'
        if [[ "$action" == control ]]; then
            exec ssh "${ssh_options[@]}" -t -- "$destination" "$remote_command" </dev/tty
        fi
        printf 'Local dashboard: http://127.0.0.1:%s/#/security\n' "$port"
        echo 'Keep this session open while using Chrome. Exit Qoder CLI to close the tunnel.'
        echo 'In Qoder CLI, use /login if needed; account authentication remains interactive.'
        # Reopen the terminal so curl | bash leaves a real input TTY for SSH and Qoder CLI.
        exec ssh "${ssh_options[@]}" -t -o ExitOnForwardFailure=yes \
            -L "127.0.0.1:$port:127.0.0.1:17396" -- "$destination" "$remote_command" </dev/tty
    fi
    exec ssh "${ssh_options[@]}" -T -- "$destination" "$remote_command" </dev/null
}

ecs_demo "$@"
