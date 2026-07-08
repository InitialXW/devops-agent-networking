#!/usr/bin/env bash
# register.sh - register the NetDiag MCP server at account level (with its API key) and
# associate it to the agent space with the 4 read-only tools allow-listed.
#
# Fully scriptable via `aws devops-agent register-service` + `associate-service` (the
# CLI accepts the API-key secret inline; it cannot pass through CloudFormation, which is
# why this is a post-deploy step rather than part of the CDK stacks - see findings.md s6).
# Idempotent: deregisters any pre-existing server of the same name first.
#
# Usage: scripts/register.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"

URL="$(cfn_output "$MCP_STACK" McpApiUrl)"
[[ -n "$URL" && "$URL" != "None" ]] || die "Could not read McpApiUrl from $MCP_STACK. Deploy first."
SPACE_ID="$(agent_space_id)"
[[ -n "$SPACE_ID" && "$SPACE_ID" != "None" ]] || die "Could not read AgentSpaceId from $AGENT_STACK."
KEY_VALUE="$(mcp_api_key_value)"
ok "endpoint=$URL  space=$SPACE_ID"

# 1. If a server with our name is already registered, deregister it (idempotency).
EXISTING="$(aws devops-agent list-services --profile "$PROFILE" --region "$REGION" \
  --query "services[?name=='$MCP_SERVER_NAME'].serviceId | [0]" --output text 2>/dev/null || true)"
if [[ -n "$EXISTING" && "$EXISTING" != "None" ]]; then
  warn "Existing '$MCP_SERVER_NAME' (serviceId $EXISTING) - disassociating + deregistering first"
  # disassociate-service is keyed by association-id (NOT service-id); look it up first.
  ASSOC="$(aws devops-agent list-associations --agent-space-id "$SPACE_ID" \
    --profile "$PROFILE" --region "$REGION" \
    --query "associations[?serviceId=='$EXISTING'].associationId | [0]" --output text 2>/dev/null || true)"
  if [[ -n "$ASSOC" && "$ASSOC" != "None" ]]; then
    aws devops-agent disassociate-service --agent-space-id "$SPACE_ID" --association-id "$ASSOC" \
      --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 || true
  fi
  # deregister fails while the association still exists; poll until it succeeds.
  for _ in $(seq 1 12); do
    if aws devops-agent deregister-service --service-id "$EXISTING" \
         --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1; then
      break
    fi
    sleep 5
  done
  # Wait for the name to actually free up before RegisterService (it 400s if the name lingers).
  for _ in $(seq 1 12); do
    n="$(aws devops-agent list-services --profile "$PROFILE" --region "$REGION" \
      --query "length(services[?name=='$MCP_SERVER_NAME'])" --output text 2>/dev/null || echo 0)"
    [[ "$n" == "0" ]] && break
    sleep 5
  done
fi

# 2. Register the MCP server at account level WITH the API key.
log "Registering MCP server '$MCP_SERVER_NAME'"
SERVICE_ID="$(aws devops-agent register-service \
  --service mcpserver \
  --name "$MCP_SERVER_NAME" \
  --service-details "{\"mcpserver\":{\"name\":\"$MCP_SERVER_NAME\",\"endpoint\":\"$URL\",\"description\":\"Network diagnostics: dig/nc/ping/traceroute on EC2 probe via SSM, structured results\",\"authorizationConfig\":{\"apiKey\":{\"apiKeyName\":\"netdiag-mcp-key\",\"apiKeyValue\":\"$KEY_VALUE\",\"apiKeyHeader\":\"x-api-key\"}}}}" \
  --profile "$PROFILE" --region "$REGION" \
  --query serviceId --output text)"
[[ -n "$SERVICE_ID" && "$SERVICE_ID" != "None" ]] || die "register-service did not return a serviceId."
ok "Registered serviceId=$SERVICE_ID"

# 3. Associate to the agent space with the tool allow-list.
log "Associating to space $SPACE_ID with tools $TOOLS"
aws devops-agent associate-service \
  --agent-space-id "$SPACE_ID" \
  --service-id "$SERVICE_ID" \
  --configuration "{\"mcpserver\":{\"tools\":$TOOLS}}" \
  --profile "$PROFILE" --region "$REGION" >/dev/null
ok "Associated. Tools allow-listed: $TOOLS"

cat <<EOF

MCP server is registered and wired to the agent space.
  serviceId : $SERVICE_ID
  space     : $SPACE_ID
  endpoint  : $URL

Open the Operator Web App for this space and start a chat, e.g.:
  "From the network probe, check DNS and TCP reachability to db.corp.internal on
   ports 80 and 5432, and tell me if anything is blocked and why."
EOF
