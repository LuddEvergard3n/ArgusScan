#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "error: raw loopback smoke must run as root or with equivalent capture/raw capabilities" >&2
  exit 1
fi

project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
listener_port=18080
closed_port=18081
second_listener_port=18082

"${project_dir}/build/argus_test_listener" "${listener_port}" >/tmp/argusscan-listener.log 2>&1 &
listener_pid=$!
"${project_dir}/build/argus_test_listener" "${second_listener_port}" >/tmp/argusscan-listener-2.log 2>&1 &
second_listener_pid=$!
"${project_dir}/build/argus_test_udp_listener" "${listener_port}" >/tmp/argusscan-udp-listener.log 2>&1 &
udp_listener_pid=$!
cleanup() {
  kill "${listener_pid}" 2>/dev/null || true
  kill "${second_listener_pid}" 2>/dev/null || true
  kill "${udp_listener_pid}" 2>/dev/null || true
  wait "${listener_pid}" 2>/dev/null || true
  wait "${second_listener_pid}" 2>/dev/null || true
  wait "${udp_listener_pid}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 0.2
if ! kill -0 "${listener_pid}" 2>/dev/null; then
  echo "error: loopback listener did not remain running" >&2
  wait "${listener_pid}"
  exit 1
fi
if ! kill -0 "${second_listener_pid}" 2>/dev/null; then
  echo "error: second loopback listener did not remain running" >&2
  wait "${second_listener_pid}"
  exit 1
fi
if ! kill -0 "${udp_listener_pid}" 2>/dev/null; then
  echo "error: UDP loopback listener did not remain running" >&2
  wait "${udp_listener_pid}"
  exit 1
fi
for scan_type in syn fin null xmas ack window; do
  echo "== ${scan_type} =="
  "${project_dir}/build/argusscan" \
    --scan "${scan_type}" \
    --ports "${listener_port},${closed_port},${second_listener_port}" \
    --timing normal \
    127.0.0.1
done

echo "== service detection =="
"${project_dir}/build/argusscan" \
  --scan tcp-connect \
  --services \
  --ports "${listener_port}" \
  --timing normal \
  127.0.0.1

echo "== udp =="
"${project_dir}/build/argusscan" \
  --scan udp \
  --ports "${listener_port},${closed_port}" \
  --timing normal \
  127.0.0.1
