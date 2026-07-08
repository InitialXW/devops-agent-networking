#!/usr/bin/env bash
# seed.sh - inject the GENUINE-BY-CONSTRUCTION network fault.
#
# Removes the tcp/5432 ingress rule on the target host's security group (the rule that
# allows the probe host to reach it). Nothing is faked: after this, real packets to
# port 5432 are genuinely dropped by the SG, so nc times out, while port 80 and ICMP
# still work - exactly the evidence chain the agent follows to conclude "SG blocks 5432".
#
# Usage: scripts/seed.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_common.sh"

log "Pre-flight"
assert_account "$PROFILE" "$ACCOUNT" "target account"

SG="$(target_sg_id)";  [[ -n "$SG"  && "$SG"  != "None" ]] || die "Could not read TargetSecurityGroupId."
PSG="$(probe_sg_id)";  [[ -n "$PSG" && "$PSG" != "None" ]] || die "Could not read ProbeSecurityGroupId."
ok "target SG=$SG  probe SG=$PSG"

log "Injecting fault: revoking tcp/5432 ingress (probe -> target) on $SG"
if aws ec2 revoke-security-group-ingress --group-id "$SG" --profile "$PROFILE" --region "$REGION" \
     --ip-permissions "IpProtocol=tcp,FromPort=5432,ToPort=5432,UserIdGroupPairs=[{GroupId=$PSG}]" \
     --query 'Return' --output text 2>/dev/null | grep -qi true; then
  ok "Fault injected: port 5432 is now blocked by the security group."
else
  warn "Rule not present (already seeded?) - port 5432 is blocked either way."
fi

cat <<EOF

Fault is live. The host is up and port 80 is open; only 5432 is blocked at the SG.
Run scripts/trigger.sh for the investigation prompt, or scripts/reset.sh to restore.
EOF
