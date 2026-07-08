#!/usr/bin/env bash
# scenario-forensic.sh - stage a RESOLVED (historical) connectivity incident.
#
# This is the scenario the LIVE probe tools cannot solve: a client reported it could
# not reach db.corp.internal:5432 during a past window, but it is FINE NOW. Probing
# live returns healthy - only VPC Flow Logs (flow_log_query) can reconstruct what
# happened and when. Pairs with the vpc-network-connectivity-investigation Skill,
# which teaches the agent to reach for flow logs when the problem is not reproducing.
#
# What it does:
#   1. seed the fault (revoke tcp/5432 from the probe) -> real packet drops
#   2. generate probe->target :5432 traffic for ~N minutes (the "remote client" trying)
#   3. wait for flow-log delivery (1-min aggregation + up to ~10-min S3 delivery)
#   4. reset (restore :5432) -> the environment is HEALTHY again
#   => leaves a bounded past window of REJECTs that only flow_log_query can surface.
#
# Usage: scripts/scenario-forensic.sh [inject_minutes] [wait_minutes]
#   inject_minutes default 3, wait_minutes default 11.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

INJECT_MIN="${1:-3}"
WAIT_MIN="${2:-11}"

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"

URL="$(cfn_output "$MCP_STACK" McpApiUrl)"; [[ -n "$URL" && "$URL" != "None" ]] || die "No McpApiUrl."
KEY="$(mcp_api_key_value)"
IP="$(cfn_output "$PROBE_STACK" TargetPrivateIp)"; [[ -n "$IP" && "$IP" != "None" ]] || die "No TargetPrivateIp."
HOST="db.corp.internal"
ok "endpoint=$URL  target=$IP"

call() { curl -s -X POST "$URL" -H "x-api-key: $KEY" -H "Content-Type: application/json" -d "$1" >/dev/null; }

INCIDENT_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "INCIDENT START $INCIDENT_START - seeding the fault (revoke tcp/5432)"
bash "$SCRIPT_DIR/seed.sh" >/dev/null

log "Generating 'remote client' traffic to $HOST:5432 for ${INJECT_MIN} min (real REJECTs)"
END=$(( $(date +%s) + INJECT_MIN * 60 ))
while [ "$(date +%s)" -lt "$END" ]; do
  call "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"tcp_reachability\",\"arguments\":{\"host\":\"$HOST\",\"port\":5432}}}"
  # also a little :80 traffic so ACCEPT baseline exists in the same window
  call "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"tcp_reachability\",\"arguments\":{\"host\":\"$HOST\",\"port\":80}}}"
  sleep 10
done
INCIDENT_END="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

log "INCIDENT END $INCIDENT_END - restoring baseline (reset)"
bash "$SCRIPT_DIR/reset.sh" >/dev/null
ok "Environment is HEALTHY again. The incident window was $INCIDENT_START -> $INCIDENT_END."

log "Waiting ${WAIT_MIN} min for flow-log delivery so the past window is queryable..."
sleep $(( WAIT_MIN * 60 ))

cat <<EOF

Forensic scenario staged. The live probes now report HEALTHY (fault is cleared),
so they cannot explain the report. Drive the agent in the Operator Web App:

  A remote client reported they could not connect to $HOST (port 5432) a little
  while ago, roughly between $INCIDENT_START and $INCIDENT_END. It appears to work
  now. Investigate what happened, confirm whether it was a network issue, and tell
  me when it started and stopped.

Expected: live tcp_reachability:5432 now returns OPEN (problem not reproducing) ->
the agent (guided by the vpc-network-connectivity-investigation Skill) uses
flow_log_query over that window -> PERSISTENT_REJECT with first_reject/last_reject
bracketing the incident, top_peers = the client (probe) private IP => root cause:
a security group was blocking tcp/5432 during that window; now restored.

Sanity-check the tool directly with the EXACT incident window (clean PERSISTENT_REJECT,
bracketed to the report - not blended with surrounding healthy traffic):
  curl -s -X POST "$URL" -H "x-api-key: $KEY" -H "Content-Type: application/json" \\
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"flow_log_query","arguments":{"ip":"$IP","direction":"to","port":5432,"action":"REJECT","start_time":"$INCIDENT_START","end_time":"$INCIDENT_END"}}}'
EOF
