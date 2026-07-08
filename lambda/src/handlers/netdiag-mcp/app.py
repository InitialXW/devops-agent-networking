"""
MCP Streamable HTTP server exposing read-only NETWORK DIAGNOSTICS to AWS DevOps Agent.

The agent is read-only and the permission guardrail blocks ssm:SendCommand on its
investigation role (see findings.md s1). This Lambda is the sanctioned workaround: it
holds the SSM permission and mediates a FIXED set of network probes that run on a tagged
EC2 probe host via SSM Run Command. The agent never gets a shell and never sees raw
stdout -- it sees only the STRUCTURED JSON these parsers produce.

Design principles (AWS EKS custom-MCP reference, findings.md s2):
  1. Return structured data, not raw text (stable finding_id, typed verdict fields).
  2. Never give the agent a shell (fixed argv per tool, args validated, SSM-mediated).
  3. Make tools composable (resolve_dns -> ip feeds tcp_reachability / ping / traceroute).

Implements minimal JSON-RPC 2.0: initialize, tools/list, tools/call.
"""
import json
import os
import re
import time
import hashlib
import ipaddress
import boto3

REGION = os.environ.get('AWS_REGION', 'us-east-1')
PROBE_INSTANCE_ID = os.environ.get('PROBE_INSTANCE_ID', '')
# Hard ceilings so a tool call can never hang the agent or the Lambda.
SSM_POLL_TIMEOUT_S = int(os.environ.get('SSM_POLL_TIMEOUT_S', '20'))
SSM_POLL_INTERVAL_S = 1.0

# flow_log_query (Phase 7) - Athena over the VPC flow-logs Glue table.
ATHENA_DATABASE = os.environ.get('ATHENA_DATABASE', 'netdiag_flow_logs')
ATHENA_TABLE = os.environ.get('ATHENA_TABLE', 'vpc_flow_logs')
ATHENA_WORKGROUP = os.environ.get('ATHENA_WORKGROUP', '')
ATHENA_POLL_TIMEOUT_S = int(os.environ.get('ATHENA_POLL_TIMEOUT_S', '25'))
# Bound the window the agent can ask for (also bounds bytes scanned).
FLOW_LOG_MAX_WINDOW_MIN = 180
# Cap rows returned to the Lambda; the query is already an aggregation.
FLOW_LOG_ROW_LIMIT = 500
# How many top peers / ports to surface in the compact verdict.
FLOW_LOG_TOP_PEERS = 10
# IANA protocol numbers as they appear in flow-log records (the `protocol` field).
_PROTO_MAP = {"TCP": 6, "UDP": 17, "ICMP": 1}

_ssm = boto3.client('ssm', region_name=REGION)
_athena = boto3.client('athena', region_name=REGION)


def _log(label, data):
    print(json.dumps({"label": label, "data": data}, default=str))


# =============================================================================
# Input validation -- the ONLY values the agent controls. Everything else in the
# command is a fixed literal, so a hostile arg cannot inject shell.
# =============================================================================

# RFC-1123-ish hostname OR IPv4 literal. No spaces, quotes, shell metachars.
_HOST_RE = re.compile(r'^[A-Za-z0-9._-]{1,253}$')


def _valid_host(host):
    if not isinstance(host, str) or not _HOST_RE.match(host):
        return False
    # Reject a leading dash so it can never be parsed as a command flag.
    return not host.startswith('-')


def _valid_port(port):
    return isinstance(port, int) and 1 <= port <= 65535


def _finding_id(*parts):
    """Stable short id so the agent can reference/correlate a finding."""
    h = hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()
    return f"net-{h[:6]}"


# =============================================================================
# SSM execution -- run a FIXED command vector on the probe host, return raw text.
# The command list is built ONLY from server-side literals + validated args.
# =============================================================================

def _run_on_probe(commands):
    """Send a shell command to the probe host and return combined stdout/stderr.

    Raises RuntimeError on any SSM-level failure so the caller maps it to a
    clean TOOL_ERROR rather than leaking internals to the agent.
    """
    if not PROBE_INSTANCE_ID:
        raise RuntimeError("PROBE_INSTANCE_ID not configured")

    resp = _ssm.send_command(
        InstanceIds=[PROBE_INSTANCE_ID],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=30,
    )
    command_id = resp["Command"]["CommandId"]

    deadline = time.time() + SSM_POLL_TIMEOUT_S
    while time.time() < deadline:
        time.sleep(SSM_POLL_INTERVAL_S)
        try:
            inv = _ssm.get_command_invocation(
                CommandId=command_id, InstanceId=PROBE_INSTANCE_ID
            )
        except _ssm.exceptions.InvocationDoesNotExist:
            continue
        status = inv["Status"]
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            return {
                "status": status,
                "stdout": inv.get("StandardOutputContent", ""),
                "stderr": inv.get("StandardErrorContent", ""),
                "command_id": command_id,
            }
    raise RuntimeError(f"SSM command {command_id} did not complete in {SSM_POLL_TIMEOUT_S}s")


# =============================================================================
# Parsers -- turn raw tool stdout into structured findings.
# Formats verified against the live AL2023 probe host (findings.md s12).
# =============================================================================

def _parse_dig(host, raw):
    """dig 9.18 output -> {dns_status, records[], resolver, query_ms}."""
    status = None
    m = re.search(r'status:\s*(\w+)', raw)
    if m:
        status = m.group(1)  # NOERROR | NXDOMAIN | SERVFAIL | ...

    records = []
    # ANSWER rows: name  TTL  IN  TYPE  value   (tabs or spaces)
    for line in raw.splitlines():
        rm = re.match(r'^(\S+)\s+(\d+)\s+IN\s+(A|AAAA|CNAME)\s+(\S+)$', line.strip())
        if rm:
            records.append({
                "name": rm.group(1).rstrip('.'),
                "ttl": int(rm.group(2)),
                "type": rm.group(3),
                "value": rm.group(4).rstrip('.'),
            })

    resolver = None
    rm = re.search(r';;\s*SERVER:\s*([0-9.]+)', raw)
    if rm:
        resolver = rm.group(1)

    query_ms = None
    rm = re.search(r';;\s*Query time:\s*(\d+)\s*msec', raw)
    if rm:
        query_ms = int(rm.group(1))

    resolved = records[0]["value"] if records else None
    return {
        "tool": "resolve_dns",
        "target": host,
        "dns_status": status,
        "resolved_ip": resolved,
        "records": records,
        "resolver": resolver,
        "query_ms": query_ms,
        "finding_id": _finding_id("dns", host, status, resolved),
    }


def _parse_nc(host, port, raw):
    """nmap-ncat -zv output -> {reachable, verdict, evidence}.

    Verified signatures (findings.md s12):
      'Ncat: Connected to <ip>:<port>.' -> OPEN
      'Ncat: TIMEOUT.'                  -> CONNECTION_TIMEOUT (SG/NACL block or host down)
      'refused' / 'Connection refused'  -> CONNECTION_REFUSED (path open, port closed)
    """
    evidence = ""
    for line in raw.splitlines():
        s = line.strip()
        if s.startswith("Ncat:") and "Version" not in s:
            evidence = s
            break

    low = raw.lower()
    if "connected to" in low:
        reachable, verdict = True, "OPEN"
    elif "refused" in low:
        reachable, verdict = False, "CONNECTION_REFUSED"
    elif "timeout" in low or "timed out" in low:
        reachable, verdict = False, "CONNECTION_TIMEOUT"
    else:
        reachable, verdict = False, "UNKNOWN"

    return {
        "tool": "tcp_reachability",
        "target": f"{host}:{port}",
        "port": port,
        "reachable": reachable,
        "verdict": verdict,
        "evidence": evidence or raw.strip()[:200],
        "remediation_hint": (
            "Path open." if verdict == "OPEN" else
            "Port reachable but no listener; check the service is running." if verdict == "CONNECTION_REFUSED" else
            "Packets dropped with no response; most likely a security group / NACL blocks this port, "
            "or the host is down. Compare with a port known to be allowed."
            if verdict == "CONNECTION_TIMEOUT" else
            "Unexpected output; inspect evidence."
        ),
        "finding_id": _finding_id("tcp", host, port, verdict),
    }


def _parse_ping(host, raw):
    """iputils ping -c4 -> {reachable, loss_pct, rtt_avg_ms, packets_*}."""
    sent = recv = loss = None
    m = re.search(r'(\d+)\s+packets transmitted,\s*(\d+)\s+received,\s*([\d.]+)%\s+packet loss', raw)
    if m:
        sent, recv, loss = int(m.group(1)), int(m.group(2)), float(m.group(3))

    rtt_avg = None
    m = re.search(r'rtt min/avg/max/\w+\s*=\s*[\d.]+/([\d.]+)/', raw)
    if m:
        rtt_avg = float(m.group(1))

    reachable = recv is not None and recv > 0
    return {
        "tool": "ping_host",
        "target": host,
        "reachable": reachable,
        "packets_sent": sent,
        "packets_received": recv,
        "loss_pct": loss,
        "rtt_avg_ms": rtt_avg,
        "verdict": (
            "ALIVE" if reachable and (loss or 0) == 0 else
            "PARTIAL_LOSS" if reachable else
            "NO_RESPONSE"
        ),
        "finding_id": _finding_id("ping", host, recv, loss),
    }


def _parse_traceroute(host, raw):
    """traceroute -I -n -> {hops[], last_responding_hop, hop_count}."""
    hops = []
    last_responding = None
    for line in raw.splitlines():
        hm = re.match(r'^\s*(\d+)\s+(.*)$', line)
        if not hm:
            continue
        n = int(hm.group(1))
        rest = hm.group(2).strip()
        if rest == "*" or rest.startswith("* "):
            hops.append({"n": n, "ip": None, "rtt_ms": None, "timed_out": True})
            continue
        rm = re.match(r'^([0-9.]+)\s+([\d.]+)\s*ms', rest)
        if rm:
            ip = rm.group(1)
            rtt = float(rm.group(2))
            hops.append({"n": n, "ip": ip, "rtt_ms": rtt, "timed_out": False})
            last_responding = n
        else:
            hops.append({"n": n, "ip": None, "rtt_ms": None, "timed_out": True})

    return {
        "tool": "traceroute_host",
        "target": host,
        "hop_count": len(hops),
        "last_responding_hop": last_responding,
        "hops": hops,
        "verdict": "REACHED" if (hops and not hops[-1]["timed_out"]) else "INCOMPLETE",
        "finding_id": _finding_id("trace", host, len(hops), last_responding),
    }


# =============================================================================
# flow_log_query (Phase 7) - bounded, aggregation-only Athena over VPC flow logs.
#
# The agent supplies PARAMETERS only (ip/port/action/window); the SQL is a FIXED
# template built here. It is always partition-pruned (day IN ...) + time-filtered +
# GROUP BY + LIMIT, so the tool physically cannot emit `SELECT *` or an unbounded
# scan (Option M, findings.md s13.3). Output is a compact structured verdict, never
# raw rows. Same "fixed command set / structured output / no free-form" principle as
# the v1 SSM tools, one layer up.
# =============================================================================

def _valid_ip(value):
    """flow_log_query keys on dst IP (flow logs store IPs, not hostnames).

    The agent resolves a hostname with resolve_dns first, then passes the IP here.
    Validating to a real IPv4/IPv6 literal also guarantees no SQL metacharacters.
    """
    if not isinstance(value, str):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _day_partitions(lo_epoch, hi_epoch):
    """UTC 'yyyy/MM/dd' partition values covering [lo, hi] inclusive.

    Bounded by the caller (window <= 180 min, or an explicit range capped the same
    way), so this yields at most a couple of day values - keeps every query
    partition-pruned to a tiny slice of the bucket.
    """
    days, seen = [], set()
    t = lo_epoch
    while t <= hi_epoch + 86400:
        d = time.strftime('%Y/%m/%d', time.gmtime(min(t, hi_epoch)))
        if d not in seen:
            seen.add(d)
            days.append(d)
        if t >= hi_epoch:
            break
        t += 86400
    return days


def _parse_time(value):
    """Parse an ISO-8601 string ('2026-07-01T04:41:00Z' or with offset) or epoch seconds
    (int / numeric string) to epoch seconds. Returns None if unparseable."""
    if value is None:
        return None
    # Epoch seconds (int or numeric string).
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        if s.isdigit():
            return int(s)
        # ISO-8601: accept a trailing 'Z' (Python's fromisoformat wants +00:00).
        iso = s.replace('Z', '+00:00') if s.endswith('Z') else s
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp())
        except ValueError:
            return None
    return None


def _run_athena(sql):
    """Run a query in the bounded WorkGroup, poll to completion, return result rows.

    Raises RuntimeError on any Athena-level failure so the caller maps it to a clean
    TOOL_ERROR. The WorkGroup enforces the output location + bytes-scanned cutoff, so
    a runaway scan fails here rather than running up cost.
    """
    start = _athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": ATHENA_DATABASE},
        WorkGroup=ATHENA_WORKGROUP,
    )
    qid = start["QueryExecutionId"]

    deadline = time.time() + ATHENA_POLL_TIMEOUT_S
    state = "QUEUED"
    while time.time() < deadline:
        time.sleep(0.7)
        ex = _athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = ex["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            break
    if state != "SUCCEEDED":
        reason = ""
        try:
            reason = ex["Status"].get("StateChangeReason", "")
        except Exception:
            pass
        raise RuntimeError(f"Athena query {state}: {reason or qid}")

    scanned = ex.get("Statistics", {}).get("DataScannedInBytes", 0)
    res = _athena.get_query_results(QueryExecutionId=qid, MaxResults=FLOW_LOG_ROW_LIMIT + 1)
    rows = res["ResultSet"]["Rows"]
    # First row is the header.
    header = [c.get("VarCharValue", "") for c in rows[0]["Data"]] if rows else []
    out = []
    for r in rows[1:]:
        vals = [c.get("VarCharValue") for c in r["Data"]]
        out.append(dict(zip(header, vals)))
    return {"rows": out, "bytes_scanned": scanned, "query_id": qid}


def _build_flow_log_sql(ip, direction, port, protocol, action, days, epoch_lo, epoch_hi):
    """FIXED, parameterized, partition-pruned aggregation. No free-form SQL reaches here.

    Every interpolated value is pre-validated by the caller: ip is a real IP literal,
    port/protocol are ints, direction/action are from fixed sets, days are computed by
    us. The SHAPE is always the same - GROUP BY peer/port/action + LIMIT - so the tool
    physically cannot emit SELECT * or an unbounded result regardless of the params.

    direction selects which endpoint `ip` pins and which is reported as the "peer":
      to   -> WHERE dstaddr = ip, GROUP BY srcaddr  (who is talking TO this destination)
      from -> WHERE srcaddr = ip, GROUP BY dstaddr  (where is this source going)
    """
    focus_col, peer_col = ("dstaddr", "srcaddr") if direction == "to" else ("srcaddr", "dstaddr")

    # Always bounded on BOTH ends: partition-pruned by day + the flow's `start` epoch in
    # [epoch_lo, epoch_hi]. An explicit incident window brackets exactly; window_minutes
    # sets epoch_hi = now. Either way the scan is a small time slice.
    filters = [
        f"day IN ({', '.join(chr(39) + d + chr(39) for d in days)})",
        f"start >= {epoch_lo}",
        f"start <= {epoch_hi}",
    ]
    if ip:
        filters.append(f"{focus_col} = '{ip}'")
    if port is not None:
        filters.append(f"dstport = {port}")
    if protocol is not None:
        filters.append(f"protocol = {protocol}")
    if action in ("ACCEPT", "REJECT"):
        filters.append(f"action = '{action}'")
    where = "\n  AND ".join(filters)

    return (
        f"SELECT {peer_col} AS peer, dstport, action,\n"
        "       COUNT(*) AS cnt,\n"
        "       SUM(bytes) AS total_bytes,\n"
        "       MIN(start) AS first_seen,\n"
        "       MAX(start) AS last_seen\n"
        f'FROM "{ATHENA_DATABASE}"."{ATHENA_TABLE}"\n'
        f"WHERE {where}\n"
        f"GROUP BY {peer_col}, dstport, action\n"
        "ORDER BY cnt DESC\n"
        f"LIMIT {FLOW_LOG_ROW_LIMIT}"
    )


def _iso(epoch):
    if epoch is None:
        return None
    try:
        return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(int(epoch)))
    except (ValueError, TypeError):
        return None


def _parse_flow_log_rows(ip, direction, port, protocol, action, epoch_lo, epoch_hi, result):
    """Aggregate the (peer, dstport, action) rows into ONE compact structured verdict.

    Generalized over direction/port/protocol/action: reports accept/reject totals, the
    rejection time span, and the top peers AND top ports by traffic. `peer` is the OTHER
    endpoint relative to `ip` (sources when direction=to, destinations when direction=from).
    """
    rows = result["rows"]
    accepts = rejects = 0
    first_reject = last_reject = None
    peer_counts = {}   # peer ip -> total flows
    port_counts = {}   # dstport -> total flows
    reject_peers = {}  # peer ip -> reject flows

    for row in rows:
        try:
            cnt = int(row.get("cnt") or 0)
        except (ValueError, TypeError):
            cnt = 0
        act = (row.get("action") or "").upper()
        peer = row.get("peer")
        dport = row.get("dstport")
        peer_counts[peer] = peer_counts.get(peer, 0) + cnt
        if dport is not None:
            port_counts[dport] = port_counts.get(dport, 0) + cnt
        if act == "REJECT":
            rejects += cnt
            reject_peers[peer] = reject_peers.get(peer, 0) + cnt
            fs, ls = row.get("first_seen"), row.get("last_seen")
            if fs is not None:
                first_reject = int(fs) if first_reject is None else min(first_reject, int(fs))
            if ls is not None:
                last_reject = int(ls) if last_reject is None else max(last_reject, int(ls))
        elif act == "ACCEPT":
            accepts += cnt

    top_peers = [
        {"peer": p, "flows": c, "rejects": reject_peers.get(p, 0)}
        for p, c in sorted(peer_counts.items(), key=lambda kv: kv[1], reverse=True)[:FLOW_LOG_TOP_PEERS]
    ]
    top_ports = [
        {"dstport": int(pt) if str(pt).isdigit() else pt, "flows": c}
        for pt, c in sorted(port_counts.items(), key=lambda kv: kv[1], reverse=True)[:FLOW_LOG_TOP_PEERS]
    ]

    if rejects == 0 and accepts == 0:
        verdict = "NO_DATA"
    elif rejects > 0 and accepts == 0:
        verdict = "PERSISTENT_REJECT"
    elif rejects > 0 and accepts > 0:
        verdict = "INTERMITTENT"
    else:
        verdict = "ALL_ACCEPT"

    remediation = {
        "NO_DATA": (
            "No flow-log records matched this query in the window. Flow logs lag reality by up "
            "to ~20 min (aggregation + delivery); the fault may be too recent, the filters too "
            "narrow, or there is genuinely no matching traffic. Corroborate with the live probe tools."
        ),
        "PERSISTENT_REJECT": (
            "Every matching flow was REJECTed - consistent with a security group / NACL blocking "
            "this traffic. Cross-check tcp_reachability (should be CONNECTION_TIMEOUT) and compare "
            "with traffic known to ACCEPT."
        ),
        "INTERMITTENT": (
            "Both ACCEPT and REJECT seen in the window - a rule may have changed mid-window, or "
            "only some peers/ports are blocked. Inspect first_reject to time the change and the "
            "top_peers/top_ports breakdown to localize it."
        ),
        "ALL_ACCEPT": "All matching flows were ACCEPTed - the path is open at the flow-log layer.",
    }[verdict]

    # Human-readable description of exactly what was asked (the query scope), including the
    # ACTUAL time window queried so the agent can confirm it matched the reported incident.
    scope = {
        "focus_ip": ip,
        "direction": direction,   # 'to' = ip is destination; 'from' = ip is source
        "dstport": port,
        "protocol": protocol,
        "action": action,
        "window_start": _iso(epoch_lo),
        "window_end": _iso(epoch_hi),
        "window_minutes": round((epoch_hi - epoch_lo) / 60),
    }

    return {
        "tool": "flow_log_query",
        "scope": scope,
        "accepts": accepts,
        "rejects": rejects,
        "first_reject": _iso(first_reject),
        "last_reject": _iso(last_reject),
        "top_peers": top_peers,   # peers = sources if direction=to, destinations if direction=from
        "top_ports": top_ports,
        "verdict": verdict,
        "remediation_hint": remediation,
        "bytes_scanned": result.get("bytes_scanned"),
        "note": "Flow logs are forensic (up to ~20 min behind live). Complements, not replaces, the active probes.",
        "finding_id": _finding_id("flowlog", ip, direction, port, protocol, verdict, rejects, accepts),
    }


# =============================================================================
# Tool schemas (MCP tools/list)
# =============================================================================

TOOL_SCHEMAS = [
    {
        "name": "resolve_dns",
        "description": (
            "Resolve a hostname from inside the VPC using the probe host's resolver (dig). "
            "Returns DNS status (NOERROR/NXDOMAIN/SERVFAIL), the resolved IP(s), TTLs, and the "
            "resolver used. Use this FIRST when investigating reachability -- the resolved IP "
            "feeds tcp_reachability, ping_host, and traceroute_host."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP to resolve, e.g. db.corp.internal"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "tcp_reachability",
        "description": (
            "Test TCP reachability to host:port from the probe host (nc -zv). Returns a verdict: "
            "OPEN (path clear), CONNECTION_REFUSED (port reachable, no listener), or "
            "CONNECTION_TIMEOUT (packets dropped -- usually a security group/NACL block or host down). "
            "Compare an allowed port with a suspect port to localize a security-group fault."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP to test"},
                "port": {"type": "integer", "description": "TCP port (1-65535)"},
            },
            "required": ["host", "port"],
        },
    },
    {
        "name": "ping_host",
        "description": (
            "ICMP ping a host from the probe (ping -c4). Returns reachability, packet loss %, and "
            "average RTT. Use to distinguish 'host down / network unreachable' from a port-specific "
            "block: if ping succeeds but tcp_reachability times out, the host is up and the issue is "
            "a port-level filter (security group / NACL)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP to ping"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "traceroute_host",
        "description": (
            "Trace the network path to a host from the probe (traceroute -I, ICMP mode). Returns the "
            "per-hop list with RTTs and the last responding hop. Use to see where a path stops when "
            "reachability fails across a routed/peered network."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname or IP to trace"},
                "max_hops": {"type": "integer", "description": "Max hops (default 8, max 30)"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "flow_log_query",
        "description": (
            "Query VPC Flow Logs (historical/forensic) and return a compact structured verdict: "
            "PERSISTENT_REJECT (all matching traffic blocked -- consistent with a security group/NACL "
            "block), ALL_ACCEPT, INTERMITTENT (rule changed mid-window), or NO_DATA. Reports "
            "accept/reject totals, when rejects started/ended, and the top peers and top ports by "
            "traffic volume. Flexible across dimensions -- filter by any combination of:\n"
            "  - ip + direction: pin an endpoint. direction='to' (default) means ip is the "
            "DESTINATION (who is connecting TO it); direction='from' means ip is the SOURCE (where it "
            "is connecting TO). Resolve a hostname to an IP with resolve_dns first.\n"
            "  - port: destination port (omit to see ALL ports -- use this to discover which ports a "
            "host uses or is blocked on).\n"
            "  - protocol: TCP / UDP / ICMP (omit for all).\n"
            "  - action: ACCEPT / REJECT / ALL.\n"
            "  - TIME WINDOW: for a reported incident with a known time range, pass start_time and "
            "end_time (ISO-8601 or epoch) to bracket EXACTLY that window - this gives a clean verdict "
            "for the incident instead of blending it with surrounding healthy traffic. Otherwise use "
            "window_minutes (look-back from now).\n"
            "Examples: 'who was rejected reaching 10.0.0.5:5432 between 04:41Z and 04:45Z' (ip=10.0.0.5, "
            "port=5432, action=REJECT, start_time=...T04:41:00Z, end_time=...T04:45:00Z); 'what is host "
            "10.0.0.9 failing to reach now' (ip=10.0.0.9, direction=from, action=REJECT); 'all rejects "
            "in the VPC on any port' (action=REJECT, no ip). "
            "CORROBORATES the live probe tools over time; flow logs lag reality by up to ~20 minutes, "
            "so a very recent fault may show NO_DATA. Never returns raw log rows. At least one of "
            "ip / port / protocol should be given to keep the query focused."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP (IPv4/IPv6) to pin, e.g. 10.20.0.208. Interpreted per 'direction'."},
                "direction": {
                    "type": "string",
                    "description": "Whether 'ip' is the destination ('to', default) or the source ('from') of the traffic",
                    "enum": ["to", "from"],
                },
                "port": {"type": "integer", "description": "Destination port 1-65535 (omit for all ports)"},
                "protocol": {
                    "type": "string",
                    "description": "Transport protocol filter (omit for all)",
                    "enum": ["TCP", "UDP", "ICMP"],
                },
                "action": {
                    "type": "string",
                    "description": "Filter to ACCEPT, REJECT, or ALL (default ALL)",
                    "enum": ["ACCEPT", "REJECT", "ALL"],
                },
                "window_minutes": {
                    "type": "integer",
                    "description": f"Look-back window in minutes from now (default 60, max {FLOW_LOG_MAX_WINDOW_MIN}). Ignored if start_time/end_time are given.",
                },
                "start_time": {
                    "type": "string",
                    "description": "Start of an explicit incident window, ISO-8601 (e.g. 2026-07-01T04:41:00Z) or epoch seconds. Use this to bracket exactly the window a client reported, instead of window_minutes.",
                },
                "end_time": {
                    "type": "string",
                    "description": "End of the explicit incident window, ISO-8601 or epoch seconds. Defaults to now if only start_time is given.",
                },
            },
            "required": [],
        },
    },
]


# =============================================================================
# tools/call dispatch -- validate args, build FIXED command, run, parse.
# =============================================================================

def _tool_error(id, message):
    return _ok(id, {"content": [{"type": "text", "text": json.dumps(
        {"status": "TOOL_ERROR", "detail": message})}], "isError": True})


def _structured_result(id, structured):
    """Return the structured finding as JSON text in MCP content (agent reads content[].text)."""
    return _ok(id, {"content": [{"type": "text", "text": json.dumps(structured)}]})


def _call_resolve_dns(id, args):
    host = args.get("host", "")
    if not _valid_host(host):
        return _tool_error(id, f"Invalid host: {host!r}")
    res = _run_on_probe([f"dig +tries=1 +time=2 {host} A"])
    if res["status"] != "Success":
        return _tool_error(id, f"dig did not run cleanly (SSM status {res['status']})")
    return _structured_result(id, _parse_dig(host, res["stdout"] + res["stderr"]))


def _call_tcp_reachability(id, args):
    host = args.get("host", "")
    port = args.get("port")
    if not _valid_host(host):
        return _tool_error(id, f"Invalid host: {host!r}")
    if not _valid_port(port):
        return _tool_error(id, f"Invalid port: {port!r}")
    # nc/Ncat writes to stderr; redirect so GetCommandInvocation captures it in stdout.
    res = _run_on_probe([f"nc -zv -w3 {host} {port} 2>&1"])
    if res["status"] not in ("Success", "Failed"):
        # nc exits non-zero on closed/timeout -> SSM marks 'Failed' but stdout is valid.
        return _tool_error(id, f"nc did not run (SSM status {res['status']})")
    return _structured_result(id, _parse_nc(host, port, res["stdout"] + res["stderr"]))


def _call_ping_host(id, args):
    host = args.get("host", "")
    if not _valid_host(host):
        return _tool_error(id, f"Invalid host: {host!r}")
    res = _run_on_probe([f"ping -c4 -W2 {host} 2>&1"])
    if res["status"] not in ("Success", "Failed"):
        return _tool_error(id, f"ping did not run (SSM status {res['status']})")
    return _structured_result(id, _parse_ping(host, res["stdout"] + res["stderr"]))


def _call_traceroute_host(id, args):
    host = args.get("host", "")
    if not _valid_host(host):
        return _tool_error(id, f"Invalid host: {host!r}")
    max_hops = args.get("max_hops", 8)
    if not isinstance(max_hops, int) or not 1 <= max_hops <= 30:
        max_hops = 8
    res = _run_on_probe([f"traceroute -I -n -w2 -q1 -m{max_hops} {host} 2>&1"])
    if res["status"] not in ("Success", "Failed"):
        return _tool_error(id, f"traceroute did not run (SSM status {res['status']})")
    return _structured_result(id, _parse_traceroute(host, res["stdout"] + res["stderr"]))


def _call_flow_log_query(id, args):
    if not ATHENA_WORKGROUP:
        return _tool_error(id, "flow_log_query is not configured (no Athena workgroup)")

    # ip is optional now, but if given it must be a real IP literal (not a hostname);
    # this also blocks any SQL metacharacters from reaching the query text.
    ip = args.get("ip")
    if ip is not None:
        if not isinstance(ip, str) or not ip:
            ip = None
        elif not _valid_ip(ip):
            return _tool_error(id, f"Invalid ip: {ip!r} (pass a resolved IP literal, not a hostname)")

    direction = args.get("direction", "to")
    if direction not in ("to", "from"):
        direction = "to"

    port = args.get("port")
    if port is not None and not _valid_port(port):
        return _tool_error(id, f"Invalid port: {port!r}")

    protocol_name = args.get("protocol")
    protocol = None
    if protocol_name is not None:
        protocol = _PROTO_MAP.get(str(protocol_name).upper())
        if protocol is None:
            return _tool_error(id, f"Invalid protocol: {protocol_name!r} (use TCP, UDP, or ICMP)")

    action = args.get("action", "ALL")
    if action not in ("ACCEPT", "REJECT", "ALL"):
        action = "ALL"

    # Require at least one focusing filter so a call can't aggregate an entire busy
    # partition with no selectivity. Keeps every query bounded and cheap.
    if ip is None and port is None and protocol is None:
        return _tool_error(
            id, "Provide at least one of ip, port, or protocol so the query stays focused."
        )

    # Time window: prefer an EXPLICIT incident range (start_time/end_time) so the agent can
    # bracket exactly the window a client reported; otherwise fall back to window_minutes
    # (lookback from now). Either way the span is capped at FLOW_LOG_MAX_WINDOW_MIN so the
    # scan stays small and partition-pruned.
    now = int(time.time())
    start_t = _parse_time(args.get("start_time"))
    end_t = _parse_time(args.get("end_time"))

    if args.get("start_time") is not None and start_t is None:
        return _tool_error(id, f"Invalid start_time: {args.get('start_time')!r} (use ISO-8601 or epoch seconds)")
    if args.get("end_time") is not None and end_t is None:
        return _tool_error(id, f"Invalid end_time: {args.get('end_time')!r} (use ISO-8601 or epoch seconds)")

    if start_t is not None or end_t is not None:
        # Explicit range. Default a missing end to now, a missing start to end - 60 min.
        epoch_hi = end_t if end_t is not None else now
        epoch_lo = start_t if start_t is not None else epoch_hi - 3600
        if epoch_lo > epoch_hi:
            return _tool_error(id, "start_time must be before end_time.")
        # Pad slightly (flow-log aggregation buckets) and cap the total span.
        epoch_lo -= 60
        epoch_hi += 60
        max_span = FLOW_LOG_MAX_WINDOW_MIN * 60
        if epoch_hi - epoch_lo > max_span:
            epoch_lo = epoch_hi - max_span  # keep the most recent slice of an over-wide range
    else:
        window = args.get("window_minutes", 60)
        if not isinstance(window, int) or window < 1:
            window = 60
        window = min(window, FLOW_LOG_MAX_WINDOW_MIN)
        epoch_hi = now
        epoch_lo = now - window * 60

    days = _day_partitions(epoch_lo, epoch_hi)
    sql = _build_flow_log_sql(ip, direction, port, protocol, action, days, epoch_lo, epoch_hi)

    result = _run_athena(sql)
    return _structured_result(
        id, _parse_flow_log_rows(ip, direction, port, protocol, action, epoch_lo, epoch_hi, result)
    )


TOOL_HANDLERS = {
    "resolve_dns": _call_resolve_dns,
    "tcp_reachability": _call_tcp_reachability,
    "ping_host": _call_ping_host,
    "traceroute_host": _call_traceroute_host,
    "flow_log_query": _call_flow_log_query,
}


# =============================================================================
# JSON-RPC plumbing
# =============================================================================

def _ok(id, result):
    return {"jsonrpc": "2.0", "id": id, "result": result}


def _error(id, code, message):
    return {"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}


def _handle_initialize(id, _params):
    return _ok(id, {
        "protocolVersion": "2025-03-26",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "netdiag-mcp", "version": "1.0.0"},
    })


def _handle_tools_list(id, _params):
    return _ok(id, {"tools": TOOL_SCHEMAS})


def _handle_tools_call(id, params):
    name = params.get("name")
    handler = TOOL_HANDLERS.get(name)
    if not handler:
        return _error(id, -32602, f"Unknown tool: {name}")
    args = params.get("arguments", {}) or {}
    try:
        return handler(id, args)
    except Exception as e:
        _log("TOOL_EXCEPTION", {"tool": name, "error": str(e)})
        return _tool_error(id, f"{name} failed: {e}")


METHODS = {
    "initialize": _handle_initialize,
    "tools/list": _handle_tools_list,
    "tools/call": _handle_tools_call,
}


def _dispatch(body):
    id = body.get("id")
    if id is None:
        return None  # notification -> ack silently (HTTP 202)
    handler = METHODS.get(body.get("method"))
    if not handler:
        return _error(id, -32601, f"Method not found: {body.get('method')}")
    return handler(id, body.get("params", {}) or {})


def lambda_handler(event, context):
    http_method = event.get("httpMethod", "")
    _log("INPUT_EVENT", {"method": http_method, "path": event.get("path")})

    if http_method == "GET":
        return {
            "statusCode": 200,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"name": "netdiag-mcp", "version": "1.0.0", "status": "ok"}),
        }

    raw_body = event.get("body", "{}")
    if event.get("isBase64Encoded"):
        import base64
        raw_body = base64.b64decode(raw_body).decode("utf-8")

    try:
        rpc_request = json.loads(raw_body)
    except json.JSONDecodeError as e:
        return {
            "statusCode": 400,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(_error(None, -32700, f"Parse error: {e}")),
        }

    _log("RPC_REQUEST", {"method": rpc_request.get("method"), "id": rpc_request.get("id")})
    result = _dispatch(rpc_request)

    if result is None:
        return {"statusCode": 202, "body": ""}

    return {
        "statusCode": 200,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(result),
    }
