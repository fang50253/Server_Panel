#!/usr/bin/env bash
# Helper: run a command on the target host with retries.
# The host occasionally drops connections mid-handshake, so every call retries.
set -uo pipefail

HOST=${HOST:-203.0.113.10}
PORT=${PORT:-22}
USER_=${USER_:-root}
PASS=${PASS:-}

if [ -z "$PASS" ]; then
  echo "PASS is not set" >&2
  exit 2
fi

attempt=0
while [ $attempt -lt 6 ]; do
  attempt=$((attempt + 1))
  out=$(sshpass -p "$PASS" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o LogLevel=ERROR \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o NumberOfPasswordPrompts=1 \
      -o ConnectTimeout=20 \
      -o ServerAliveInterval=15 \
      -p "$PORT" "$USER_@$HOST" "$@" 2>&1)
  rc=$?
  if [ $rc -eq 0 ]; then
    printf '%s\n' "$out"
    exit 0
  fi
  case "$out" in
    ""|*"Connection closed"*|*"Connection refused"*|*"timed out"*|*"Connection reset"*|*"kex_exchange_identification"*|*"Broken pipe"*)
      sleep 10
      ;;
    *)
      printf '%s\n' "$out"
      exit $rc
      ;;
  esac
done

echo "ssh failed after $attempt attempts" >&2
printf '%s\n' "$out" >&2
# 255 is reserved for "the connection never worked", so callers can tell a
# transport failure apart from the remote command legitimately returning 1.
# Without this, `if rsh "test -f FILE"` would treat a dropped connection as
# "the file is missing" and overwrite a good file with a stale copy.
exit 255
