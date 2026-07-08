---
name: vpc-network-connectivity-investigation
description: Methodology for investigating network CONNECTIVITY / reachability problems
  involving AWS - a client or service cannot reach a host/port, connections time out or
  are refused, DNS resolves wrong, or a client reported a connectivity problem during a
  past time window. Use whenever the symptom is packet-level reachability (L3/L4), not an
  application error. This skill governs the netdiag MCP tools (resolve_dns, ping_host,
  tcp_reachability, traceroute_host for LIVE probing; flow_log_query for HISTORICAL VPC
  Flow Log evidence): when to use each, what parameters to pass, and how to read the
  verdicts - and how to reason about the network boundary when one endpoint is outside AWS.
---

# Network Connectivity Investigation (AWS)

Use this skill for reachability symptoms: connection timeouts, connection refused, DNS
failures or wrong answers, "the database is unreachable", "a client could not connect
between 02:00 and 02:40". These are **network (L3/L4)** problems - packets, ports,
security groups, NACLs, routing, load balancers. If packets are being delivered and
accepted but the application still misbehaves (HTTP 5xx, TLS errors, slow queries), that
is application-layer - hand off, this skill does not cover it.

## Division of labour - do NOT re-invent what you already have

You already have built-in capabilities. USE them; this skill does not duplicate them:

- **Topology discovery / Agent Space Understanding** - you automatically discover the
  application topology and how resources interconnect (endpoints -> load balancers ->
  targets -> databases, route tables, endpoints, peering). **Rely on that discovered
  topology to identify the hops on the path.** Do NOT try to re-enumerate the environment
  from scratch here.
- **Infrastructure-change investigation** - you have a skill for finding recent changes
  (CloudTrail: security-group / NACL / route edits). Use it to answer "what changed and
  when" once the evidence points at a hop.

**What THIS skill adds** and nothing else provides: how to drive the five netdiag MCP
tools to gather live and historical network *evidence* along that path, and the L3/L4
reasoning to turn that evidence into a root cause. The netdiag tools are your packet-level
instruments; your native topology tells you *where* on the path to point them.

## The netdiag tools (your instruments)

| Tool | Vantage / source | Use it to |
| --- | --- | --- |
| resolve_dns | probe host's resolver | Confirm the name resolves and to WHAT (right IP? private vs public? stale?). |
| ping_host | probe host (ICMP) | Liveness / gross path check (ICMP is often filtered - absence is not proof of down). |
| tcp_reachability | probe host (TCP) | The authoritative live L4 test: OPEN / CONNECTION_REFUSED / CONNECTION_TIMEOUT. |
| traceroute_host | probe host (ICMP) | Where a multi-hop path stops (last responding hop). |
| flow_log_query | VPC Flow Logs (ALL ENIs) | Historical/forensic: was traffic ACCEPTed/REJECTed over a window, from whom, which port, since when. Sees every ENI, not just the probe's vantage point. |

Two hard facts about these tools:
- **The live probes run from ONE probe host**, not from the reporting client. A live result
  is "from the probe's vantage point." It may share the client's path or not - say which.
- **flow_log_query is forensic**: records lag reality by ~10-20 min (aggregation + delivery).
  `NO_DATA` for a very recent event is expected, not proof of health.

## Step 0: Scope the problem

Answer three questions before probing - they set the whole approach:

1. **Layer** - is this reachability (L3/L4) or application? If tcp is OPEN and packets are
   accepted, it is not this skill - hand off to the application layer.
2. **Time** - is it happening NOW, or is it HISTORICAL / already-resolved / intermittent?
   - **NOW** -> live probes are authoritative; start there, corroborate with flow logs.
   - **HISTORICAL** -> the live probes are MISLEADING (probing now is green because the
     problem isn't occurring). You MUST use `flow_log_query` over the reported window. Do
     not conclude "no problem" from a green live probe - it only means "not broken this
     instant."
3. **Boundary** - where does the traffic ORIGINATE relative to AWS visibility? (see next
   section). This decides how much of the path you can actually observe.

## Step 1: Establish the network boundary (critical for a correct, honest answer)

You can only observe the **AWS side**: VPC Flow Logs cover ENIs inside the VPC(s) you can
see; your topology covers AWS (and integrated) resources. Classify the source:

- **In-VPC / peered / same AWS org** - both ends are AWS-visible; you can trace end to end.
- **On-prem via Direct Connect or VPN** - only the AWS side is visible. Traffic enters
  through a VGW / TGW / DX gateway; the on-prem firewall, router, and LAN are NOT visible.
- **Public internet client** (user browser, partner) - you see traffic only once it hits an
  AWS public entry point (IGW, public ALB/NLB, CloudFront); the client's ISP/NAT/firewall
  are not visible.

State the boundary explicitly in your findings. When the evidence points at a hop OUTSIDE
AWS visibility, your job is (a) to RULE OUT the AWS side conclusively, and (b) to hand off
with actionable hypotheses - not to claim certainty you cannot have (see Step 4).

## Step 2: Form hypotheses across the path (don't jump to "security group")

Using your discovered topology, list the hops between source and destination and the
failure modes each can contribute. Treat these as competing hypotheses to eliminate with
evidence - the same symptom (`CONNECTION_TIMEOUT`) can come from ANY of them:

- **DNS** - unresolved, or resolves to the WRONG/stale IP (split-horizon, public vs private).
- **Security group** (stateful, per-ENI) - missing ingress/egress rule. Timeout, per-source.
- **NACL** (stateless, per-subnet) - missing rule **including the RETURN / ephemeral-port
  rule** (a classic miss: outbound allowed, return traffic on 1024-65535 denied).
- **Route table** - no route to the destination CIDR (peering/TGW/NAT/IGW route absent).
- **Load balancer** (ALB/NLB) - LB security group, listener config, or **target-group health**
  (targets failing health checks look like a connectivity failure to the client).
- **VPC endpoint / PrivateLink** - endpoint policy or SG blocking the service.
- **NAT / IGW** - egress path for private subnets missing or misconfigured.
- **Transit Gateway / peering** - route-table association/propagation, or asymmetric routing.
- **Outside AWS** (per the boundary) - on-prem firewall, DX/VPN tunnel down, ISP.
- **Application** - listener down / wrong port (this shows as CONNECTION_REFUSED, path open).

## Step 3: Investigate with the netdiag tools

### Live path (ONGOING problems)
Resolve first (you need the IP for the other tools and for flow_log_query):
1. `resolve_dns(host)` - NXDOMAIN/SERVFAIL => DNS is the cause. NOERROR => check the IP is
   the RIGHT one (private where you expect private; not a stale/public answer).
2. `tcp_reachability(host, port)` - the decisive L4 test:
   - `OPEN` -> path + listener fine at L4; if the app still fails it's application-layer.
   - `CONNECTION_REFUSED` -> path is open, nothing listening (service down / wrong port).
   - `CONNECTION_TIMEOUT` -> packets dropped, no response. Do NOT stop at "security group" -
     this is where you eliminate hypotheses (Step 2): compare a port known to be allowed
     (one OPEN + one TIMEOUT on the same host => per-port SG/NACL; all ports TIMEOUT =>
     suspect route/NACL/host/LB), and use flow logs + your topology to localize the hop.
3. `ping_host` to distinguish gross path/liveness from a port-specific block (ICMP-filtered
   is common - treat NO_RESPONSE as inconclusive, not "host down").
4. `traceroute_host` when reachability fails across a multi-hop (peered/TGW) path - the last
   responding hop localizes the break.

### Historical / forensic, and correlation (use flow_log_query well)
- **Bracket the reported incident with `start_time`/`end_time`** (ISO-8601 or epoch) instead
  of `window_minutes`. A wide look-back blends the fault with healthy traffic and yields a
  muddy INTERMITTENT; the explicit window gives a clean verdict for the incident. The result
  echoes `window_start`/`window_end` so you can confirm the scope.
- **Correlate BOTH directions** to locate the break relative to the destination:
  - `direction="to"` (ip = destination): did traffic ARRIVE at the destination ENI, and was
    it ACCEPTed or REJECTed there?
  - `direction="from"` (ip = source): did the source's traffic LEAVE, and to where?
  - Powerful signal: **REJECT at the destination** => SG/NACL at the destination.
    **Source shows attempts but destination shows `NO_DATA`** => packets never reached the
    target ENI => routing / LB / NAT / an upstream (possibly out-of-AWS) hop.
- **Blast radius**: read `top_peers` (only the one client, or everyone? -> per-source SG vs
  global) and `top_ports` (one port or many? -> targeted rule vs broad outage). Omit `port`
  to discover which ports are affected; set `protocol` to test UDP/ICMP-specific issues.
- **Verdicts**: PERSISTENT_REJECT (standing block) / INTERMITTENT (rule changed mid-window -
  use first_reject to time it, or only some peers/ports affected) / ALL_ACCEPT (network
  delivered it - fault is not L3/L4, look at the app) / NO_DATA (too recent, filters too
  narrow, or traffic never arrived - interpret with the direction correlation above).

Once evidence points at a hop that CHANGED, use your infrastructure-change capability to
find the CloudTrail event (who/when) - do not re-derive that here.

## Step 4: The boundary rule (when evidence points outside AWS)

If the correlation shows the AWS side is clean - e.g. traffic that reached AWS was ACCEPTed,
SGs/NACLs/routes/LB health on the path are healthy, or the source IP never appears in any
VPC flow log at all - then the fault is upstream of AWS visibility. Do two things:

1. **Rule out the AWS side explicitly and with evidence**: "All traffic that reached the VPC
   on port X was ACCEPTed; target-group health is healthy; no SG/NACL/route on the AWS path
   would drop it." This is a valuable result - it tells the user to stop investigating AWS.
2. **Hand off with actionable, clearly-labelled hypotheses** for the invisible hop, based on
   the boundary type: on-prem firewall / NAT rules, a down or flapping DX/VPN tunnel (check
   tunnel state, BGP), asymmetric routing, ISP/internet path, or client-side resolver. Say
   plainly these are beyond AWS-observable evidence and name what the user should check on
   their side. Never assert a root cause you cannot see.

## Success criteria

Conclude with:
1. Whether this is/was a network (L3/L4) issue at all (or an app-layer / out-of-AWS one).
2. The specific root cause with a HOP-BY-HOP evidence chain - cite the tool verdicts and
   `finding_id`s that eliminated the alternatives, not just the winning hypothesis.
3. The timeline (from flow-log first_reject/last_reject) - when it started and stopped.
4. A concrete remediation, OR - if the fault is outside AWS visibility - an explicit
   AWS-side "all clear" plus the external hypotheses the user should follow up on.
