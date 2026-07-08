#!/usr/bin/env bash
# trigger.sh - drive / preview the investigation.
#
# The DevOps Agent investigation itself runs in the Operator Web App (a browser chat),
# so this script does two things:
#   1. Prints the investigation prompt to paste into the Operator App chat.
#   2. PRE-FLIGHTS the exact MCP tool chain against the live endpoint (same calls the
#      agent will make), so you can confirm the current network state before demoing.
#
# Usage: scripts/trigger.sh [--preview-only]
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"

URL="$(cfn_output "$MCP_STACK" McpApiUrl)"; [[ -n "$URL" && "$URL" != "None" ]] || die "No McpApiUrl."
KEY="$(mcp_api_key_value)"
HOST="db.corp.internal"

call() { # $1 = json-rpc body -> prints content[].text
  curl -s -X POST "$URL" -H "x-api-key: $KEY" -H "Content-Type: application/json" -d "$1" \
    | python3 -c "import sys,json
try:
    r=json.load(sys.stdin); print(r['result']['content'][0]['text'])
except Exception as e:
    print('PARSE_ERROR', e)"
}

log "Previewing the tool chain against $HOST (the same calls the agent makes)"
echo "--- resolve_dns $HOST ---"
call "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"resolve_dns\",\"arguments\":{\"host\":\"$HOST\"}}}"
echo "--- ping_host $HOST ---"
call "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"ping_host\",\"arguments\":{\"host\":\"$HOST\"}}}"
echo "--- tcp_reachability $HOST:80 ---"
call "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"tcp_reachability\",\"arguments\":{\"host\":\"$HOST\",\"port\":80}}}"
echo "--- tcp_reachability $HOST:5432 ---"
call "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"tcp_reachability\",\"arguments\":{\"host\":\"$HOST\",\"port\":5432}}}"

# flow_log_query keys on the resolved IP (flow logs store IPs, not hostnames), so
# resolve first, then query the historical/forensic view over the last 60 minutes.
TARGET_IP="$(cfn_output "$PROBE_STACK" TargetPrivateIp)"
if [[ -n "$TARGET_IP" && "$TARGET_IP" != "None" ]]; then
  echo "--- flow_log_query to $TARGET_IP:5432 (last 60m, forensic) ---"
  call "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"tools/call\",\"params\":{\"name\":\"flow_log_query\",\"arguments\":{\"ip\":\"$TARGET_IP\",\"direction\":\"to\",\"port\":5432,\"window_minutes\":60}}}"
  echo "--- flow_log_query to $TARGET_IP:80 (last 60m, forensic) ---"
  call "{\"jsonrpc\":\"2.0\",\"id\":6,\"method\":\"tools/call\",\"params\":{\"name\":\"flow_log_query\",\"arguments\":{\"ip\":\"$TARGET_IP\",\"direction\":\"to\",\"port\":80,\"window_minutes\":60}}}"
fi

cat <<EOF

Paste this into the Operator Web App chat for the 'devops-agent-networking' space:

  A service cannot connect to its database at $HOST on port 5432. Using the network
  diagnostics tools, determine whether the host is reachable, whether DNS resolves,
  and whether the database port is open. Confirm with the VPC flow logs whether traffic
  to that port is being rejected and since when. Identify the root cause and recommend a fix.

Expected agent chain: resolve_dns -> ping_host (ALIVE) -> tcp_reachability:80 (OPEN)
-> tcp_reachability:5432 (CONNECTION_TIMEOUT) -> flow_log_query:5432 (PERSISTENT_REJECT
or INTERMITTENT, with first_reject timestamp and top_peers showing the probe IP) =>
root cause: security group blocks 5432, corroborated by the flow logs. Notes:
- Flow logs lag ~10-20 min; a freshly seeded fault may read NO_DATA until records land.
- If you ran the baseline check before seeding, prior ACCEPTs blend into the 60-min window
  and the verdict reads INTERMITTENT instead of PERSISTENT_REJECT. The first_reject timestamp
  and top_peers breakdown still pin the fault precisely - the agent can reason from these.
- The :80 query may show a REJECT from an internet scanner (public peer, not the probe);
  top_peers will show the probe has 0 rejects on :80, confirming the port is not the fault.
EOF
