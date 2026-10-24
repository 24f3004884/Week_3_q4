import json
import os
import sys
import uuid

import httpx

BASE = os.getenv("BASE_URL", "http://127.0.0.1:8000").rstrip("/")


def make_body(effect="rollback_deployment", tp=None):
    lines = "\n".join(f"[ev_{i:03d}] line {i} noise" for i in range(1, 30))
    return {
        "profile": "ga5-incident-agent/v2",
        "runId": "run-" + uuid.uuid4().hex,
        "agentName": "incident-response",
        "publicMarker": "marker-" + uuid.uuid4().hex[:6],
        "sensitive": {"accessToken": "SECRET-TOKEN-123", "privateNote": "SECRET-NOTE-456"},
        "incident": {
            "incidentId": "inc-1", "title": "t", "service": "checkout", "severity": "SEV-1",
            "transcript": lines, "allowedRootCauses": ["bad_deploy", "capacity"],
        },
        "toolCatalog": [
            {"name": "query_metrics", "description": "d", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
            {"name": "fetch_logs", "description": "d", "inputSchema": {"type": "object", "properties": {"service": {"type": "string"}}, "required": ["service"]}},
            {"name": effect, "description": "e", "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}}, "required": ["target"]}},
        ],
        "policy": {"maximumDiagnostics": 3, "effectTools": [effect], "approvalRequiredFor": ["rollback_deployment", "disable_feature"], "doNotExport": []},
    }


def rc(c, run, receipt, outcomes=None, approvals=None):
    b = {"receiptId": receipt}
    if outcomes is not None:
        b["outcomes"] = outcomes
    if approvals is not None:
        b["approvals"] = approvals
    return c.post(f"{BASE}/v2/incidents/{run}/receipts", json=b)


def oc(d, status=200, **kw):
    o = {"actionId": d["actionId"], "callId": d["callId"], "attempt": d["attempt"], "status": status,
         "resultClass": "diagnosis_confirmed", "nonce": str(uuid.uuid4())}
    o.update(kw)
    return o


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        check.bad += 1


check.bad = 0


def flow_approval_503(c):
    body = make_body()
    r = c.post(f"{BASE}/v2/incidents", json=body, headers={"traceparent": "00-" + "a" * 32 + "-" + "b" * 16 + "-01", "tracestate": "vendor=1"})
    first = r.json()
    first_text = r.text
    run = body["runId"]
    check("first waiting", r.status_code == 200 and first["status"] == "waiting" and len(first["dispatches"]) == 2)
    check("trace continued", all(d["traceparent"].split("-")[1] == "a" * 32 and d.get("tracestate") == "vendor=1" for d in first["dispatches"]))
    d1, d2 = first["dispatches"]
    r = rc(c, run, "rcpt-0001", [oc(d1, 503, resultClass="unavailable"), oc(d2)])
    j = r.json()
    check("retry only, no approval", len(j["dispatches"]) == 1 and j["dispatches"][0]["attempt"] == 2 and j["approvals"] == [])
    check("retry new span id", j["dispatches"][0]["traceparent"] != d1["traceparent"])
    rr = j["dispatches"][0]
    r = rc(c, run, "rcpt-0002", [oc(rr)])
    j = r.json()
    check("approval requested", j["dispatches"] == [] and len(j["approvals"]) == 1)
    ap = j["approvals"][0]
    r = rc(c, run, "rcpt-0003", approvals=[{"approvalId": ap["approvalId"], "decision": "approved", "nonce": str(uuid.uuid4())}])
    j = r.json()
    eff = j["dispatches"][0]
    check("effect has approval", eff["approvalId"] == ap["approvalId"] and "approvalNonce" in eff and eff["actionId"] == ap["actionId"])
    last = [oc(eff, resultClass="effect_applied")]
    r = rc(c, run, "rcpt-0004", last)
    fin = r.json()
    check("completed", fin["status"] == "completed" and fin["chosenEffect"] == "rollback_deployment")
    check("logs", len(fin["actionLog"]) == 4 and len(fin["receiptLog"]) == 5)
    spans = fin["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    names = [s["name"] for s in spans]
    check("span counts", names.count("chat incident-plan") == 1 and names.count("incident.join") == 1 and names.count("approval_gate") == 1)
    check("client spans", sum(1 for s in spans if s["name"].startswith("POST tool/")) == 4)
    check("one trace id", {s["traceId"] for s in spans} == {"a" * 32})
    check("server parent", [s for s in spans if s["kind"] == 2][0]["parentSpanId"] == "b" * 16)
    cl = {s["spanId"] for s in spans if s["kind"] == 3}
    check("traceparent <-> client span", all(d["traceparent"].split("-")[2] in cl for d in fin["actionLog"]))
    blob = json.dumps(fin)
    check("no secrets", "SECRET-TOKEN" not in blob and "SECRET-NOTE" not in blob)
    check("GET same", c.get(f"{BASE}/v2/incidents/{run}").json() == fin)
    check("POST replay same", c.post(f"{BASE}/v2/incidents", json=body).text == first_text)
    again = rc(c, run, "rcpt-0004", last)
    check("receipt replay stable", again.status_code == 200 and again.json() == fin)
    same = rc(c, run, "rcpt-0003", approvals=[{"approvalId": ap["approvalId"], "decision": "approved", "nonce": "x"}])
    check("changed receipt 409", same.status_code == 409)
    b2 = dict(body)
    b2["publicMarker"] = "changed"
    check("changed run 409", c.post(f"{BASE}/v2/incidents", json=b2).status_code == 409)
    check("late receipt 422", rc(c, run, "rcpt-9999", [oc(eff)]).status_code == 422)
    bad = make_body()
    bad["profile"] = "nope"
    check("bad profile 400", c.post(f"{BASE}/v2/incidents", json=bad).status_code == 400)
    check("bad profile creates nothing", c.get(f"{BASE}/v2/incidents/{bad['runId']}").status_code == 404)


def flow_timeout(c):
    body = make_body(effect="scale_service")
    first = c.post(f"{BASE}/v2/incidents", json=body).json()
    run = body["runId"]
    d1, d2 = first["dispatches"]
    check("no tp header -> fresh ctx", "tracestate" not in d1)
    r = rc(c, run, "rcpt-t001", [oc(d1, 0, errorType="timeout", resultClass="timeout"), oc(d2)])
    fin = r.json()
    check("failed + suppressed", fin["status"] == "failed" and fin["chosenEffect"] is None and fin["suppressed"] == ["scale_service"])
    check("no effect dispatched", all(d["phase"] == "diagnostic" for d in fin["actionLog"]))
    spans = fin["otlp"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    t = [s for s in spans if s["kind"] == 3 and s["name"].startswith("POST tool/")]
    errs = [s for s in t if s["status"]["code"] == 2]
    check("timeout span", len(errs) == 1 and any(a["key"] == "error.type" and a["value"]["stringValue"] == "timeout" for a in errs[0]["attributes"]))


def flow_direct_effect(c):
    body = make_body(effect="scale_service")
    first = c.post(f"{BASE}/v2/incidents", json=body).json()
    run = body["runId"]
    j = rc(c, run, "rcpt-s001", [oc(d) for d in first["dispatches"]]).json()
    check("direct effect dispatch", len(j["dispatches"]) == 1 and j["dispatches"][0]["phase"] == "effect" and "approvalId" not in j["dispatches"][0])
    fin = rc(c, run, "rcpt-s002", [oc(j["dispatches"][0])]).json()
    check("completed direct", fin["status"] == "completed")
    check("wrong attempt rejected", rc(c, run, "rcpt-s003", [oc(first["dispatches"][0])]).status_code == 422)


with httpx.Client(timeout=30) as c:
    flow_approval_503(c)
    flow_timeout(c)
    flow_direct_effect(c)
print("FAILURES:", check.bad)
sys.exit(1 if check.bad else 0)