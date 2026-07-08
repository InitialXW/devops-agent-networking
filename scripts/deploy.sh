#!/usr/bin/env bash
# deploy.sh - SAM-build the MCP Lambda, then CDK-deploy all four stacks to the target account.
#
# Order matters: ProbeStack first (its VPC + probe instance id feed the others), then
# FlowLogsStack (attaches flow logs to the probe VPC + Athena surface), then McpStack
# (needs the probe id AND the flow-logs/Athena names), then AgentStack. CDK resolves the
# cross-stack refs automatically, but we list them explicitly for clarity.
#
# Usage: scripts/deploy.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

log "Pre-flight: verifying profile resolves to the expected account"
assert_account "$PROFILE" "$ACCOUNT" "target account"

# 1. Build the MCP Lambda with SAM (local; no profile needed). --use-container so the
#    artifact matches the Lambda runtime regardless of host. NEVER build a single
#    function - that wipes other functions' build dirs CDK's fromAsset() paths expect.
log "Building Lambdas with SAM (--use-container)"
( cd "$REPO_ROOT/lambda/src" && sam build --use-container >/dev/null ) && ok "sam build complete"

# 2. Deploy all stacks (CDK orders them by dependency).
log "Deploying CDK stacks -> $ACCOUNT (profile $PROFILE)"
( cd "$REPO_ROOT" && npx cdk deploy "$PROBE_STACK" "$FLOWLOGS_STACK" "$MCP_STACK" "$AGENT_STACK" \
    --require-approval never --profile "$PROFILE" )
ok "All stacks deployed"

log "Next: scripts/register.sh   (register the MCP server with the agent space)"
log "Then: scripts/trigger.sh    (instructions to drive the investigation)"
