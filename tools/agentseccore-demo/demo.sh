#!/usr/bin/env bash
# The delivered bundle runs against the local Docker engine only.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
unset DOCKER_HOST DOCKER_CONTEXT
image=agentseccore-demo:20260909
container=agentseccore-demo-20260909
volume=agentseccore-demo-20260909-state
label=agentseccore-demo-20260909
die() { echo "ERROR: $*" >&2; exit 1; }
engine() { docker --host unix:///var/run/docker.sock "$@"; }
owned() {
    [[ "$(engine inspect --format '{{index .Config.Labels "com.anolisa.demo"}}' "$container")" == "$label" ]] || die 'Container name belongs to another workload.'
}
read_image_id() {
    [[ -f image.id ]] || die 'Missing image.id; use the complete verified bundle.'
    expected_image=$(cat image.id)
    [[ "$expected_image" =~ ^sha256:[0-9a-f]{64}$ ]] || die 'Invalid image.id.'
}
case "${1:-}" in
pull)
    [[ $# -le 2 ]] || die 'Usage: ./demo.sh pull [IMAGE_REFERENCE]'
    reference=${2:-}
    if [[ -z "$reference" && -f image.ref ]]; then reference=$(cat image.ref); fi
    [[ "$reference" =~ ^[[:alnum:]][[:alnum:]_.:/@-]*$ ]] || die 'Supply an image reference or a valid image.ref file.'
    # Pulling an alias of our local tag would overwrite it before identity verification.
    local_reference=${reference#docker.io/}
    local_reference=${local_reference#index.docker.io/}
    local_reference=${local_reference#library/}
    [[ "$local_reference" != "$image" ]] || die 'Use the published registry reference, not the local demo tag.'
    read_image_id
    engine pull --platform linux/amd64 -- "$reference"
    pulled_image=$(engine image inspect --format '{{.Id}}' "$reference")
    [[ "$pulled_image" == "$expected_image" ]] || die 'Pulled image identity does not match image.id; local demo tag unchanged.'
    engine image tag "$pulled_image" "$image"
    echo 'Verified image ready. Next: ./demo.sh up'
    ;;
up)
    [[ "$(uname -m)" == x86_64 ]] || die 'This bundle requires Linux amd64.'
    [[ "$(uname -s)" == Linux ]] || die 'Start this bundle on the Linux demo host.'
    engine info >/dev/null
    read_image_id
    if engine inspect "$container" >/dev/null 2>&1; then
        owned
        [[ "$(engine inspect --format '{{.Image}}' "$container")" == "$expected_image" ]] || die 'Existing demo uses another image; run down before up.'
        engine start "$container" >/dev/null
    else
        if [[ "$(engine image inspect --format '{{.Id}}' "$image" 2>/dev/null || true)" != "$expected_image" ]]; then
            if [[ -f image.tar.gz ]]; then
                sha256sum --check image.tar.gz.sha256
                gzip -dc image.tar.gz | engine load
            else
                reference=$(cat image.ref)
                [[ "$reference" =~ ^ghcr\.io/1570005763/agentseccore-demo@sha256:[0-9a-f]{64}$ ]] || die 'Invalid pinned image.ref.'
                bash "$0" pull "$reference"
            fi
        fi
        [[ "$(engine image inspect --format '{{.Id}}' "$image")" == "$expected_image" ]] || die 'Loaded image identity does not match image.id.'
        env_args=()
        if [[ -f demo.env ]]; then
            [[ ! -L demo.env && "$(stat -c %a demo.env)" == 600 ]] || die 'demo.env must be a regular private file with mode 600.'
            env_args=(--env-file "$PWD/demo.env")
        fi
        if engine volume inspect "$volume" >/dev/null 2>&1; then
            [[ "$(engine volume inspect --format '{{index .Labels "com.anolisa.demo"}}' "$volume")" == "$label" ]] || die 'Volume name belongs to another workload.'
        else
            engine volume create --label "com.anolisa.demo=$label" "$volume" >/dev/null
        fi
        engine run -d --init --name "$container" --label "com.anolisa.demo=$label" \
            --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 256 \
            -p 127.0.0.1:17396:7396 -v "$volume:/home/demo" "${env_args[@]}" "$image" >/dev/null
    fi
    for _ in {1..120}; do
        state=$(engine inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container")
        [[ "$state" != exited* ]] || { engine logs --tail 30 "$container"; die 'Container exited during startup.'; }
        if [[ "$state" == 'running healthy' ]]; then
            echo 'Dashboard: http://127.0.0.1:17396/#/security'
            echo 'Next: ./demo.sh doctor, then ./demo.sh qoder'
            exit 0
        fi
        sleep 1
    done
    engine logs --tail 30 "$container"
    die 'Readiness timed out; inspect the reported service failure.'
    ;;
doctor|tamper|reset)
    owned
    engine exec "$container" /opt/demo/runtime.sh "$1"
    ;;
qoder)
    owned
    [[ -t 0 && -t 1 ]] || die 'Qoder requires a real interactive terminal.'
    exec docker --host unix:///var/run/docker.sock exec -it "$container" /opt/demo/runtime.sh qoder
    ;;
down)
    if ! engine inspect "$container" >/dev/null 2>&1; then
        echo 'Already stopped. Instance data is retained.'
        exit 0
    fi
    owned
    engine stop "$container" >/dev/null
    engine rm "$container" >/dev/null
    echo 'Stopped. Instance data and history are retained.'
    ;;
*) echo 'Usage: ./demo.sh pull [IMAGE_REFERENCE] | up|doctor|qoder|tamper|reset|down'; exit 2 ;;
esac
