#!/usr/bin/env bash
# reset.sh - restore the healthy baseline (re-add the tcp/5432 ingress rule).
# Inverse of seed.sh. Safe to run repeatedly.
#
# Usage: scripts/reset.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"

SG="$(target_sg_id)";  [[ -n "$SG"  && "$SG"  != "None" ]] || die "Could not read TargetSecurityGroupId."
PSG="$(probe_sg_id)";  [[ -n "$PSG" && "$PSG" != "None" ]] || die "Could not read ProbeSecurityGroupId."

log "Restoring tcp/5432 ingress (probe -> target) on $SG"
if aws ec2 authorize-security-group-ingress --group-id "$SG" --profile "$PROFILE" --region "$REGION" \
     --ip-permissions "IpProtocol=tcp,FromPort=5432,ToPort=5432,UserIdGroupPairs=[{GroupId=$PSG,Description=\"PostgreSQL from application tier\"}]" \
     --query 'Return' --output text 2>/dev/null | grep -qi true; then
  ok "Baseline restored: port 5432 reachable from the probe again."
else
  warn "Rule already present - baseline is already healthy."
fi
