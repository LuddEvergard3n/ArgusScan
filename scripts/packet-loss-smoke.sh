#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "error: packet-loss smoke must run as root" >&2
  exit 1
fi

for command in unshare ip nft; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "error: required command not found: ${command}" >&2
    exit 1
  fi
done

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scanner=${project_dir}/build/argusscan
listener=${project_dir}/build/argus_test_listener

unshare --net -- "${BASH}" -s -- "${scanner}" "${listener}" <<'INNER'
set -euo pipefail
scanner=$1
listener=$2
port=18092

ip link set lo up
"${listener}" "${port}" >/tmp/argusscan-loss-listener.log 2>&1 &
listener_pid=$!
cleanup() {
  kill "${listener_pid}" 2>/dev/null || true
  wait "${listener_pid}" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.2
kill -0 "${listener_pid}"

nft add table inet argus_loss
nft 'add chain inet argus_loss input { type filter hook input priority 0; policy accept; }'
nft "add rule inet argus_loss input tcp dport ${port} tcp flags & syn == syn numgen inc mod 2 == 0 counter drop"

output=$("${scanner}" --scan syn --ports "${port}" --timing aggressive 127.0.0.1)
rules=$(nft list chain inet argus_loss input)
printf '%s\n%s\n' "${output}" "${rules}"
grep -Eq "${port}[[:space:]]+tcp[[:space:]]+open" <<<"${output}"
grep -Eq 'counter packets 1 bytes [1-9][0-9]* drop' <<<"${rules}"
INNER
