#!/usr/bin/env bash
# teardown.sh - deregister the MCP server (runtime API, not CFN) then destroy all stacks.
#
# The MCP registration + association are created by register.sh via the devops-agent API,
# so they are NOT owned by CloudFormation and must be removed explicitly before cdk destroy.
#
# Usage: scripts/teardown.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"

# 1. Disassociate + deregister the MCP server (best-effort; ignore if already gone).
SPACE_ID="$(agent_space_id 2>/dev/null || true)"
SERVICE_ID="$(aws devops-agent list-services --profile "$PROFILE" --region "$REGION" \
  --query "services[?name=='$MCP_SERVER_NAME'].serviceId | [0]" --output text 2>/dev/null || true)"
if [[ -n "$SERVICE_ID" && "$SERVICE_ID" != "None" ]]; then
  if [[ -n "$SPACE_ID" && "$SPACE_ID" != "None" ]]; then
    log "Disassociating MCP server from space $SPACE_ID"
    # disassociate-service is keyed by association-id (NOT service-id); look it up first.
    ASSOC="$(aws devops-agent list-associations --agent-space-id "$SPACE_ID" \
      --profile "$PROFILE" --region "$REGION" \
      --query "associations[?serviceId=='$SERVICE_ID'].associationId | [0]" --output text 2>/dev/null || true)"
    if [[ -n "$ASSOC" && "$ASSOC" != "None" ]]; then
      aws devops-agent disassociate-service --agent-space-id "$SPACE_ID" --association-id "$ASSOC" \
        --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 || true
    fi
  fi
  log "Deregistering MCP server $SERVICE_ID"
  # deregister fails while the association still exists; poll until it succeeds.
  for _ in $(seq 1 12); do
    aws devops-agent deregister-service --service-id "$SERVICE_ID" \
      --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 && break
    sleep 5
  done
  ok "MCP server removed"
else
  warn "No '$MCP_SERVER_NAME' MCP server registered - skipping deregistration"
fi

# NOTE: the network-investigation Skill asset (created by skill.sh) is NOT deleted here.
# It lives INSIDE the agent space, so destroying the CfnAgentSpace (AgentStack) removes it
# by cascade - no separate delete-asset needed (verified 2026-07-01). This differs from the
# MCP registration above, which is ACCOUNT-level and does NOT belong to any space, so it
# must be deregistered explicitly.

# 2. Destroy all CDK stacks.
log "Destroying CDK stacks (profile $PROFILE)"
( cd "$REPO_ROOT" && npx cdk destroy "$AGENT_STACK" "$MCP_STACK" "$FLOWLOGS_STACK" "$PROBE_STACK" \
    --force --profile "$PROFILE" )
ok "Stacks destroyed"

log "Verify nothing lingers: probe/target instances, roles, and the agent space should be gone."
