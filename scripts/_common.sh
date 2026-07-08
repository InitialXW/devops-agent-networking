#!/usr/bin/env bash
# Shared config + helpers for the devops-agent-networking demo scripts.
# Sourced by deploy.sh / register.sh / seed.sh / trigger.sh / reset.sh / teardown.sh.
#
# Single-account POC:
#   - one AWS account, one profile (everything: probe VPC, MCP server, agent
#     space). Account/region come from .env; profile via PROFILE (default below).
set -euo pipefail

# ---- Resolve repo root + load .env ----
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ -f "$REPO_ROOT/.env" ]]; then
  # shellcheck disable=SC1091
  set -a; source "$REPO_ROOT/.env"; set +a
fi

# ---- Account / region (from .env; required) ----
ACCOUNT="${CDK_PROCESSING_ACCOUNT:?set CDK_PROCESSING_ACCOUNT in .env}"
REGION="${CDK_PROCESSING_REGION:-us-east-1}"
PROFILE="${PROFILE:?set PROFILE to the AWS CLI profile for your account}"
SSM_PREFIX="${SSM_PREFIX:-/devops-agent-networking}"

# ---- Solution constants ----
PROBE_STACK="NetDiagProbeStack"
FLOWLOGS_STACK="NetDiagFlowLogsStack"
MCP_STACK="NetDiagMcpStack"
AGENT_STACK="NetDiagAgentStack"
MCP_SERVER_NAME="netdiag-mcp"
TOOLS='["resolve_dns","tcp_reachability","ping_host","traceroute_host","flow_log_query"]'

# ---- Pretty logging ----
log()  { printf '\033[1;34m[%s]\033[0m %s\n' "$(date -u +%H:%M:%S)" "$*"; }
ok()   { printf '\033[1;32m  v\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m  ! \033[0m%s\n' "$*"; }
die()  { printf '\033[1;31m  x %s\033[0m\n' "$*" >&2; exit 1; }

# ---- Guardrail: verify the profile resolves to the expected account before any mutation ----
assert_account() {
  local profile="$1" expected="$2" label="${3:-}" actual
  actual="$(aws sts get-caller-identity --profile "$profile" --query Account --output text 2>/dev/null || true)"
  [[ "$actual" == "$expected" ]] \
    || die "Profile '$profile' resolves to account '$actual', expected '$expected' ${label:+($label)}. Aborting."
  ok "profile '$profile' -> account $actual"
}

# ---- Read a CloudFormation stack output value ----
cfn_output() {
  local stack="$1" key="$2"
  aws cloudformation describe-stacks --stack-name "$stack" \
    --profile "$PROFILE" --region "$REGION" \
    --query "Stacks[0].Outputs[?OutputKey=='$key'].OutputValue | [0]" --output text 2>/dev/null
}

# ---- Resolve the deployed MCP API key value (the secret used at registration) ----
mcp_api_key_value() {
  local key_id; key_id="$(cfn_output "$MCP_STACK" McpApiKeyId)"
  [[ -n "$key_id" && "$key_id" != "None" ]] || die "Could not read McpApiKeyId from $MCP_STACK."
  aws apigateway get-api-key --api-key "$key_id" --include-value \
    --profile "$PROFILE" --region "$REGION" --query value --output text
}

# ---- Resolve the agent space id from the agent stack ----
agent_space_id() { cfn_output "$AGENT_STACK" AgentSpaceId; }

# ---- Resolve the target host's security group id (the demo fault dial) ----
target_sg_id()   { cfn_output "$PROBE_STACK" TargetSecurityGroupId; }
probe_sg_id()    { cfn_output "$PROBE_STACK" ProbeSecurityGroupId; }
