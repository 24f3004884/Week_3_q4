import re

from .util import new_hex

TP_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})(-.*)?$")
TS_KEY = re.compile(r"^[a-z0-9][a-z0-9_\-*/@]{0,255}$")
TS_VAL = re.compile(r"^[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]$")


def parse_traceparent(v):
    if not isinstance(v, str):
        return None
    m = TP_RE.match(v.strip())
    if not m:
        return None
    ver, tid, sid, _flags, extra = m.groups()
    if ver == "ff" or (ver == "00" and extra):
        return None
    if set(tid) == {"0"} or set(sid) == {"0"}:
        return None
    return tid, sid


def valid_tracestate(v):
    if not isinstance(v, str) or not v.strip() or len(v) > 512:
        return False
    members = [m.strip() for m in v.split(",") if m.strip()]
    if not members or len(members) > 32:
        return False
    for m in members:
        k, eq, val = m.partition("=")
        if not eq or not TS_KEY.match(k) or not TS_VAL.match(val):
            return False
    return True


def _find(o, key, depth=0):
    if depth > 4:
        return None
    if isinstance(o, dict):
        for k, v in o.items():
            if k != "sensitive" and isinstance(k, str) and k.lower() == key and isinstance(v, str):
                return v
        for k, v in o.items():
            if k != "sensitive":
                r = _find(v, key, depth + 1)
                if r:
                    return r
    elif isinstance(o, list):
        for v in o:
            r = _find(v, key, depth + 1)
            if r:
                return r
    return None


def make_context(body, headers):
    tp, ts = headers.get("traceparent"), headers.get("tracestate")
    parsed = parse_traceparent(tp)
    if not parsed:
        tp, ts = _find(body, "traceparent"), _find(body, "tracestate")
        parsed = parse_traceparent(tp)
    ctx = {"serverSpanId": new_hex(8)}
    if parsed:
        ctx["traceId"], ctx["parentSpanId"] = parsed
        ctx["traceState"] = ts.strip() if valid_tracestate(ts) else None
    else:
        ctx["traceId"], ctx["parentSpanId"], ctx["traceState"] = new_hex(16), None, None
    return ctx


def _a(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": v}}
    return {"key": k, "value": {"stringValue": str(v)}}


def build_otlp(state):
    tid = state["traceId"]
    base = {"ga5.run.id": state["runId"], "ga5.public.marker": state["publicMarker"]}
    t_end = state["times"]["end"]
    used = {state["serverSpanId"]}

    def sid():
        while True:
            v = new_hex(8)
            if v not in used:
                used.add(v)
                return v

    for c in state["calls"].values():
        for a in c["attempts"]:
            used.add(a["spanId"])

    def span(name, kind, span_id, parent, start, end, attrs, status=None, links=None):
        end = max(end, start + 1000)
        s = {
            "traceId": tid,
            "spanId": span_id,
            "name": name,
            "kind": kind,
            "startTimeUnixNano": str(start),
            "endTimeUnixNano": str(end),
            "attributes": [_a(k, v) for k, v in {**base, **attrs}.items()],
        }
        if parent:
            s["parentSpanId"] = parent
        if state.get("traceState"):
            s["traceState"] = state["traceState"]
        if status is not None:
            s["status"] = {"code": status}
        if links:
            s["links"] = [{"traceId": tid, "spanId": x} for x in links]
        return s

    t0 = state["times"]["start"]
    spans = []
    spans.append(
        span(
            "POST /v2/incidents", 2, state["serverSpanId"], state.get("parentSpanId"), t0, t_end,
            {"http.request.method": "POST", "http.route": "/v2/incidents", "url.path": "/v2/incidents"},
        )
    )
    agent_id = sid()
    spans.append(
        span(
            f"invoke_agent {state['agentName']}", 1, agent_id, state["serverSpanId"], t0, t_end,
            {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": state["agentName"]},
        )
    )
    spans.append(
        span(
            "chat incident-plan", 3, sid(), agent_id, state["times"]["planStart"], state["times"]["planEnd"],
            {
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": state["model"] or "unknown-model",
                "gen_ai.provider.name": state.get("provider") or "openai",
            },
        )
    )

    diag_exec = []
    for aid in state["order"]:
        c = state["calls"][aid]
        atts = c["attempts"]
        ex_id = sid()
        ex_start = atts[0]["start"]
        ex_end = max((a["end"] or t_end) for a in atts)
        spans.append(
            span(
                f"execute_tool {c['toolName']}", 1, ex_id, agent_id, ex_start, ex_end,
                {
                    "ga5.action.id": c["actionId"],
                    "gen_ai.tool.name": c["toolName"],
                    "gen_ai.tool.call.id": c["callId"],
                    "gen_ai.operation.name": "execute_tool",
                },
            )
        )
        if c["phase"] == "diagnostic":
            diag_exec.append((ex_id, ex_start, ex_end))
        for a in atts:
            status = a.get("status")
            attrs = {
                "ga5.action.id": c["actionId"],
                "ga5.attempt": a["attempt"],
                "ga5.receipt.id": a.get("receiptId") or "",
                "ga5.receipt.nonce": a.get("nonce") or "",
                "http.request.method": "POST",
                "http.request.resend_count": a["attempt"] - 1,
                "http.response.status_code": status if isinstance(status, int) else 0,
            }
            ok = isinstance(status, int) and 200 <= status < 300
            if not ok:
                if status == 0 or a.get("errorType"):
                    attrs["error.type"] = a.get("errorType") or "timeout"
                else:
                    attrs["error.type"] = str(status)
            spans.append(
                span(
                    f"POST tool/{c['toolName']}", 3, a["spanId"], ex_id, a["start"], a["end"] or t_end, attrs,
                    status=1 if ok else 2,
                )
            )

    if len(diag_exec) > 1:
        spans.append(
            span(
                "incident.join", 1, sid(), agent_id,
                min(x[1] for x in diag_exec), max(x[2] for x in diag_exec), {},
                links=[x[0] for x in diag_exec],
            )
        )

    ap = state.get("approval")
    if ap:
        spans.append(
            span(
                "approval_gate", 1, sid(), agent_id, ap["requestedAt"], ap.get("decidedAt") or t_end,
                {
                    "ga5.action.id": ap["actionId"],
                    "ga5.approval.id": ap["approvalId"],
                    "ga5.approval.nonce": ap.get("nonce") or "",
                    "ga5.approval.receipt.nonce": ap.get("nonce") or "",
                    "ga5.approval.receipt.id": ap.get("receiptId") or "",
                    "ga5.receipt.id": ap.get("receiptId") or "",
                    "ga5.receipt.nonce": ap.get("nonce") or "",
                    "ga5.approval.decision": ap.get("decision") or "pending",
                },
            )
        )

    return {
        "resourceSpans": [
            {
                "resource": {"attributes": [_a("service.name", "incident-agent")]},
                "scopeSpans": [{"scope": {"name": "incident-agent"}, "spans": spans}],
            }
        ]
    }


