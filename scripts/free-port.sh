#!/usr/bin/env bash
# Print one random, confirmed-free loopback TCP port above 10000.
#
# Ports are used ONLY as run markers (passed as an env var into the container); nothing ever
# listens on them. They exist so a run on a shared machine is identifiable, and so two concurrent
# runs cannot be confused for one.
set -euo pipefail

for _ in $(seq 1 200); do
  port=$(( 10001 + RANDOM % 55000 ))
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then continue; fi
  if nc -z 127.0.0.1 "$port" >/dev/null 2>&1; then continue; fi
  printf '%s\n' "$port"
  exit 0
done

echo "could not find a free marker port above 10000" >&2
exit 97
