#!/usr/bin/env bash
# skill.sh - install (or update) the generic VPC network-connectivity-investigation
# DevOps Agent Skill into the agent space via the Asset API.
#
# The Skill is METHODOLOGY (how to investigate: live-vs-forensic triage, decision
# tree, verdict interpretation), layered over the netdiag MCP tools (capability).
# It does NOT hand the agent raw SQL - it steers the already-hard-bounded MCP tools -
# so it adds flexibility without weakening the Option-M output guarantee.
#
# Two ways to install the Skill:
#   1. This script (Asset API, fully scriptable, idempotent) - `aws devops-agent create-asset`.
#   2. Manually in the Operator Web App: Knowledge -> Skills -> Add skill -> Upload,
#      pasting skills/network-connectivity-investigation/SKILL.md.
# Either works; the console upload reads name/description from the SKILL.md frontmatter.
#
# Usage: scripts/skill.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

SKILL_NAME="vpc-network-connectivity-investigation"
SKILL_MD="$REPO_ROOT/skills/network-connectivity-investigation/SKILL.md"
# The 5 netdiag tools this Skill orchestrates (steers the agent toward them).
SKILL_TOOLS='["resolve_dns","tcp_reachability","ping_host","traceroute_host","flow_log_query"]'

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"
[[ -f "$SKILL_MD" ]] || die "SKILL.md not found at $SKILL_MD"
SPACE_ID="$(agent_space_id)"
[[ -n "$SPACE_ID" && "$SPACE_ID" != "None" ]] || die "Could not read AgentSpaceId from $AGENT_STACK."
ok "space=$SPACE_ID  skill=$SKILL_NAME"

# Single source of truth: name + description come from the SKILL.md frontmatter, so editing
# the .md alone is enough (a single-file upload does not auto-read frontmatter, so we parse it
# here and pass it as metadata). SKILL_NAME above is only a fallback / the lookup key.
REQ="$(python3 - "$SPACE_ID" "$SKILL_NAME" "$SKILL_MD" "$SKILL_TOOLS" <<'PY'
import json, re, sys
space, fallback_name, md_path, tools = sys.argv[1:5]
text = open(md_path, encoding="utf-8").read()

# Parse YAML-ish frontmatter (name + a possibly-multiline folded description).
name, desc = fallback_name, None
m = re.match(r'^---\s*\n(.*?)\n---\s*\n', text, re.DOTALL)
if m:
    fm = m.group(1)
    nm = re.search(r'^name:\s*(.+)$', fm, re.MULTILINE)
    if nm:
        name = nm.group(1).strip()
    dm = re.search(r'^description:\s*(.+(?:\n[ \t]+.+)*)', fm, re.MULTILINE)
    if dm:
        desc = " ".join(line.strip() for line in dm.group(1).splitlines())
if not desc:
    desc = "VPC network connectivity investigation methodology."

req = {
    "agentSpaceId": space,
    "assetType": "skill",
    "metadata": {
        "name": name,
        "description": desc,
        "agent_types": ["GENERIC"],
        "status": "ACTIVE",
        "enable_tools": json.loads(tools),
    },
    "content": {"file": {"path": "SKILL.md", "body": {"text": text}}},
}
print(json.dumps(req))
PY
)"

# Is a skill with this name already present? (idempotency -> update instead of create)
EXISTING_ID="$(aws devops-agent list-assets --agent-space-id "$SPACE_ID" --asset-type skill \
  --profile "$PROFILE" --region "$REGION" \
  --query "items[?metadata.name=='$SKILL_NAME'].assetId | [0]" --output text 2>/dev/null || true)"

TMP="$(mktemp)"; printf '%s' "$REQ" > "$TMP"
if [[ -n "$EXISTING_ID" && "$EXISTING_ID" != "None" ]]; then
  log "Updating existing skill (assetId $EXISTING_ID)"
  # UpdateAsset uses assetId; reuse the same metadata + content body.
  python3 - "$TMP" "$EXISTING_ID" <<'PY'
import json, sys
req = json.load(open(sys.argv[1]))
req["assetId"] = sys.argv[2]
del req["assetType"]  # assetType is immutable / not accepted on update
json.dump(req, open(sys.argv[1], "w"))
PY
  aws devops-agent update-asset --cli-input-json "file://$TMP" \
    --profile "$PROFILE" --region "$REGION" >/dev/null
  ok "Skill updated."
else
  log "Creating skill '$SKILL_NAME'"
  ASSET_ID="$(aws devops-agent create-asset --cli-input-json "file://$TMP" \
    --profile "$PROFILE" --region "$REGION" --query "asset.assetId" --output text)"
  ok "Skill created (assetId $ASSET_ID)."
fi
rm -f "$TMP"

cat <<EOF

Skill '$SKILL_NAME' is active in space $SPACE_ID (agent_types=GENERIC).
It orchestrates: resolve_dns, tcp_reachability, ping_host, traceroute_host, flow_log_query.

Verify:  aws devops-agent list-assets --agent-space-id $SPACE_ID --asset-type skill \\
           --profile $PROFILE --region $REGION --query "items[].metadata.name"

Demo it in the Operator Web App with a HISTORICAL prompt (live probes alone can't answer):
  "A remote client reported they could not reach db.corp.internal on port 5432 earlier;
   it seems fine now. Investigate what happened and when."
EOF
