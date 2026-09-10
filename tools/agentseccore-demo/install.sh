#!/usr/bin/env bash
# package.py pins the starter checksum in the published installer.
# Keep execution inside a function so a truncated piped download cannot run it.
install_demo() {
    set -euo pipefail
    umask 077
    unset DOCKER_HOST DOCKER_CONTEXT
    die() { echo "ERROR: $*" >&2; exit 1; }
    [[ $# -le 1 ]] || die 'Usage: bash install.sh [INSTALL_DIRECTORY]'
    [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || die 'Use a Linux amd64 host with Docker installed and running.'
    for command in curl tar sha256sum docker cmp; do
        command -v "$command" >/dev/null || die "Missing $command. Install it on the Linux host, then rerun this installer."
    done
    docker --host unix:///var/run/docker.sock info >/dev/null || die 'Cannot access the local Docker engine. Start Docker and check your socket permissions, then rerun.'

    install_dir=${1:-"$HOME/agentseccore-demo"}
    [[ -n "$install_dir" && ! -L "$install_dir" ]] || die 'Choose a non-symlink installation directory.'
    [[ ! -e "$install_dir" || -d "$install_dir" ]] || die 'The installation path is an existing file.'
    release=agentseccore-demo-20260910.1
    asset=agentseccore-demo-starter-linux-amd64-20260910.1.tar.gz
    expected_sha256=__STARTER_SHA256__
    [[ "$expected_sha256" =~ ^[0-9a-f]{64}$ ]] || die 'Use install.sh from the published GitHub Release; the source is a packaging template.'

    mkdir -p -- "$(dirname -- "$install_dir")"
    temporary=$(mktemp -d "$(dirname -- "$install_dir")/.agentseccore-install.XXXXXX")
    temporary=$(cd -- "$temporary" && pwd -P)
    trap 'rm -rf -- "$temporary"' EXIT
    echo 'Downloading and verifying the demo launcher...'
    curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 15 --max-time 180 \
        "https://github.com/1570005763/anolisa/releases/download/$release/$asset" \
        --output "$temporary/starter.tar.gz"
    printf '%s  %s\n' "$expected_sha256" "$temporary/starter.tar.gz" | sha256sum --check
    tar --extract --gzip --file "$temporary/starter.tar.gz" --directory "$temporary" --no-same-owner
    staged="$temporary/agentseccore-demo"
    (cd -- "$staged" && sha256sum --check SHA256SUMS)

    if [[ -d "$install_dir" ]]; then
        # Reuse only this exact release; private configuration and instance state stay in place.
        cmp -- "$staged/SHA256SUMS" "$install_dir/SHA256SUMS" >/dev/null 2>&1 || die 'Directory contains other files or another release. Choose a new installation directory; nothing was overwritten.'
        (cd -- "$install_dir" && sha256sum --check SHA256SUMS) || die 'Installed files have changed. Choose a new installation directory; nothing was overwritten.'
        echo 'Verified existing installation; retaining configuration and instance data.'
    else
        mv --no-clobber --no-target-directory -- "$staged" "$install_dir"
        [[ ! -d "$staged" ]] || die 'Installation directory appeared during download. Nothing was overwritten; rerun to verify it.'
    fi

    cd -- "$install_dir"
    ./demo.sh pull
    ./demo.sh up
    ./demo.sh doctor
    echo
    echo 'AgentSecCore demo is ready: http://127.0.0.1:17396/#/security'
    printf 'Next, open Qoder CLI in your terminal:\n  cd %q && ./demo.sh qoder\n' "$PWD"
    echo 'In Qoder CLI, enter /login and complete your own account authentication.'
    echo 'For remote hosts or Token authentication, follow guides/zh.md or guides/en.md.'
    echo 'Operation card: AgentSecCore上手体验操作卡.md'
}

install_demo "$@"
