#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "error: firewall smoke must run as root" >&2
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

unshare --net -- "${BASH}" -s -- "${scanner}" <<'INNER'
set -euo pipefail
scanner=$1

ip link set lo up
nft add table inet argus_test
nft 'add chain inet argus_test input { type filter hook input priority 0; policy accept; }'
nft add rule inet argus_test input tcp dport 18090 drop
nft add rule inet argus_test input udp dport 18091 drop

syn_output=$("${scanner}" --scan syn --ports 18090 --timing aggressive 127.0.0.1)
udp_output=$("${scanner}" --scan udp --ports 18091 --timing aggressive 127.0.0.1)
connect_output=$("${scanner}" --scan tcp-connect --ports 18090 --timing aggressive 127.0.0.1)

printf '%s\n' "${syn_output}" "${udp_output}" "${connect_output}"
grep -Eq '18090[[:space:]]+tcp[[:space:]]+filtered' <<<"${syn_output}"
grep -Eq '18091[[:space:]]+udp[[:space:]]+open\|filtered' <<<"${udp_output}"
grep -Eq '18090[[:space:]]+tcp[[:space:]]+filtered' <<<"${connect_output}"
INNER
