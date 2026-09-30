#!/bin/sh
# Run the real Linux DHCPv4 SocketListener loopback regression in a private
# network namespace. No privileged DHCP port, lease file, or physical
# interface is touched. The test itself supplies a deterministic ACK provider
# so this probe covers socket admission, pktinfo, runtime wire construction and
# the peer reply path without pretending to validate the full lease policy.
set -eu

repo=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
exec "$repo/tools/dnsmasq/run_isolated.sh" \
  cargo test --manifest-path "$repo/components/dnsmasq/Cargo.toml" --lib \
  dhcp::service::tests::socket_listener_processes_local_ack_and_replies_to_peer \
  -- --ignored --nocapture
