#!/usr/bin/env bash
set -euo pipefail

DEMO_ROOT="${DEMO_ROOT:-/root/skillfs-demo}"
SKILLFS_BIN="${SKILLFS_BIN:-/root/skillfs-demo-ledger-hot-refresh-rsync/target/debug/skillfs}"
LEDGER_CLI="${LEDGER_CLI:-/usr/local/bin/agent-sec-cli-demo}"
TRUSTED_LEDGER_WRITER="${TRUSTED_LEDGER_WRITER:-agent-sec-cli-demo}"

SOURCE="${SOURCE:-$DEMO_ROOT/source}"
MOUNT="${MOUNT:-$DEMO_ROOT/mount}"
EVENTS="${EVENTS:-$DEMO_ROOT/events.jsonl}"
LOG_DIR="${LOG_DIR:-$DEMO_ROOT/logs}"
PID_FILE="${PID_FILE:-$DEMO_ROOT/skillfs.pid}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/skillfs.log}"

mkdir -p "$SOURCE" "$MOUNT" "$LOG_DIR"

if [[ -f "$PID_FILE" ]]; then
  old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    kill "$old_pid" 2>/dev/null || true
  fi
fi

sleep 0.5

if mountpoint -q "$MOUNT" 2>/dev/null; then
  fusermount3 -u "$MOUNT" >/dev/null 2>&1 || umount -l "$MOUNT" >/dev/null 2>&1 || true
fi

nohup "$SKILLFS_BIN" mount "$SOURCE" "$MOUNT" \
  --foreground \
  --ledger-demo-mode \
  --decision-command "$LEDGER_CLI skill-ledger" \
  --trusted-ledger-writer "$TRUSTED_LEDGER_WRITER" \
  --demo-events "$EVENTS" \
  > "$LOG_FILE" 2>&1 &

echo $! > "$PID_FILE"

for _ in $(seq 1 100); do
  if mountpoint -q "$MOUNT" 2>/dev/null; then
    exit 0
  fi
  sleep 0.1
done

echo "SkillFS mount did not become ready: $MOUNT" >&2
exit 1
