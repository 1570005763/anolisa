#!/usr/bin/env bash
# Keep execution inside a function so a truncated piped download cannot run it.
ecs_demo() {
    set -euo pipefail
    die() { echo "ERROR: $*" >&2; exit 1; }
    if [[ "${1:-}" == --help ]]; then
        echo 'Usage: bash ecs-demo.sh SSH_DESTINATION [qoder|prepare|doctor|tamper|reset|down]'
        echo 'Default: qoder. Use an SSH config alias for custom ports, keys, or jump hosts.'
        echo 'Set LOCAL_PORT to change the local dashboard port (default: 17396).'
        return
    fi
    [[ $# -ge 1 && $# -le 2 ]] || die 'Usage: bash ecs-demo.sh SSH_DESTINATION [qoder|prepare|doctor|tamper|reset|down]'
    destination=$1
    [[ "$destination" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.@:-]*$ ]] || die 'Use user@hostname, user@IP, or a simple SSH config alias.'
    action=${2:-qoder}
    case "$action" in qoder|prepare|doctor|tamper|reset|down) ;; *) die "Unknown action: $action" ;; esac
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
if [[ ! -e "$directory" ]]; then
    case "$action" in
        prepare|qoder)
            temporary=$(mktemp -d)
            trap 'rm -rf -- "$temporary"' EXIT
            curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
                --retry 3 --connect-timeout 15 --max-time 180 \
                https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh \
                --output "$temporary/install.sh"
            printf '%s  %s\n' bb3bfd89b4f5f09527868b6e74213c16f9d6c6c9c73d6694e2fe84289325ae7a "$temporary/install.sh" | sha256sum --check
            bash "$temporary/install.sh" "$directory"
            rm -rf -- "$temporary"
            trap - EXIT
            ;;
        *) die 'Run prepare or qoder first to install the demo.' ;;
    esac
fi
cd -- "$directory"
# Pin the manifest as well as its entries before executing an existing installation.
echo '65c47b9a36f3b79859311d861d19a19e65fd3d51ce536d8c6e4a848ccb45f3f5  SHA256SUMS' | sha256sum --check --status || die 'This directory is not the supported starter release; no existing files were changed.'
sha256sum --check --status SHA256SUMS || die 'Installed demo files changed; restore the supported starter release before continuing.'
case "$action" in
    prepare|qoder)
        ./demo.sh up
        ./demo.sh doctor
        if [[ "$action" == qoder ]]; then exec ./demo.sh qoder; fi
        ;;
    *) exec ./demo.sh "$action" ;;
esac
REMOTE
    # POSIX quoting also works when the SSH account's login shell is not Bash.
    quoted_script=${remote_script//\'/\'\\\'\'}
    remote_command="bash -c '$quoted_script' -- '$action'"
    ssh_options=(-o ControlPath=none -o ServerAliveInterval=30 -o ServerAliveCountMax=3)
    if [[ "$action" == qoder ]]; then
        [[ -t 1 ]] && ( : </dev/tty ) 2>/dev/null || die 'Qoder requires a real terminal. Use prepare for unattended setup.'
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
