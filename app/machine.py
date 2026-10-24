import copy

from . import trace
from .util import digest_args, new_hex, new_id

DESTRUCTIVE = {"rollback_deployment", "disable_feature"}


class Invalid(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code
        self.msg = msg


def _mk_call(phase, item):
    return {
        "actionId": new_id("act"),
        "callId": new_id("call"),
        "phase": phase,
        "toolName": item["toolName"],
        "arguments": item["arguments"],
        "evidence": item["evidence"],
        "attempts": [],
        "state": "reserved",
    }


def _dispatch(state, call, now):
    attempt = len(call["attempts"]) + 1
    span_id = new_hex(8)
    d = {
        "actionId": call["actionId"],
        "callId": call["callId"],
        "phase": call["phase"],
        "toolName": call["toolName"],
        "arguments": copy.deepcopy(call["arguments"]),
        "evidence": list(call["evidence"]),
        "attempt": attempt,
        "traceparent": f"00-{state['traceId']}-{span_id}-01",
    }
    if state.get("traceState"):
        d["tracestate"] = state["traceState"]
    if call.get("approvalId"):
        d["approvalId"] = call["approvalId"]
        d["approvalNonce"] = call["approvalNonce"]
    call["attempts"].append({"attempt": attempt, "spanId": span_id, "start": now, "end": None})
    call["state"] = "pending"
    state["actionLog"].append(copy.deepcopy(d))
    if call["actionId"] not in state["order"]:
        state["order"].append(call["actionId"])
    return d


def _waiting(state, dispatches, approvals):
    resp = {
        "runId": state["runId"],
        "status": "waiting",
        "diagnosis": state["diagnosis"],
        "dispatches": dispatches,
        "approvals": approvals,
    }
    state["view"] = resp
    return resp


def start_run(body, plan, ctx, model, provider, times):
    state = {
        "runId": body["runId"],
        "agentName": body["agentName"],
        "publicMarker": body["publicMarker"],
        "model": model,
        "provider": provider,
        "traceId": ctx["traceId"],
        "serverSpanId": ctx["serverSpanId"],
        "parentSpanId": ctx.get("parentSpanId"),
        "traceState": ctx.get("traceState"),
        "diagnosis": {"rootCause": plan["rootCause"], "evidence": plan["evidence"]},
        "times": times,
        "calls": {},
        "order": [],
        "actionLog": [],
        "receiptLog": [],
        "approval": None,
        "diagFailed": False,
        "status": "waiting",
        "chosenEffect": None,
        "suppressed": [],
        "view": None,
    }
    diag = [_mk_call("diagnostic", d) for d in plan["diagnostics"]]
    eff = _mk_call("effect", plan["effect"])
    pol = body.get("policy") or {}
    eff["requiresApproval"] = eff["toolName"] in DESTRUCTIVE or eff["toolName"] in (pol.get("approvalRequiredFor") or [])
    state["effectKey"] = eff["actionId"]
    for c in diag + [eff]:
        state["calls"][c["actionId"]] = c
    now = times["planEnd"] + 1000
    dispatches = [_dispatch(state, c, now) for c in diag]
    return state, _waiting(state, dispatches, [])


def _finalize(state, now, status, chosen):
    eff = state["calls"][state["effectKey"]]
    state["status"] = status
    state["chosenEffect"] = chosen
    state["suppressed"] = [] if chosen else [eff["toolName"]]
    state["times"]["end"] = now
    resp = {
        "runId": state["runId"],
        "status": status,
        "diagnosis": state["diagnosis"],
        "chosenEffect": state["chosenEffect"],
        "suppressed": state["suppressed"],
        "actionLog": state["actionLog"],
        "receiptLog": state["receiptLog"],
        "otlp": trace.build_otlp(state),
    }
    state["view"] = resp
    return resp


def _advance(state, now, dispatches):
    if state["status"] != "waiting":
        return []
    calls = list(state["calls"].values())
    if any(c["state"] == "pending" for c in calls):
        return []
    eff = state["calls"][state["effectKey"]]
    if eff["state"] == "reserved":
        diag = [c for c in calls if c["phase"] == "diagnostic"]
        if state["diagFailed"] or any(c["state"] != "ok" for c in diag):
            _finalize(state, now, "failed", None)
            return []
        if eff["requiresApproval"] and not eff.get("approvalId"):
            ap = {
                "approvalId": new_id("apr"),
                "actionId": eff["actionId"],
                "toolName": eff["toolName"],
                "argumentsDigest": digest_args(eff["arguments"]),
            }
            state["approval"] = {**ap, "status": "pending", "requestedAt": now}
            return [ap]
        dispatches.append(_dispatch(state, eff, now))
        return []
    _finalize(state, now, "completed" if eff["state"] == "ok" else "failed", eff["toolName"])
    return []


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _nonempty(x):
    return isinstance(x, str) and x.strip() != ""


def apply_receipt(state_in, body, now):
    if state_in["status"] != "waiting":
        raise Invalid(422, "run is not waiting")
    rid = body["receiptId"]
    outcomes = body.get("outcomes") or []
    approvals = body.get("approvals") or []
    if not isinstance(outcomes, list) or not isinstance(approvals, list) or not (outcomes or approvals):
        raise Invalid(422, "receipt needs outcomes or approvals")

    state = copy.deepcopy(state_in)
    seen = set()
    for o in outcomes:
        if not isinstance(o, dict):
            raise Invalid(422, "bad outcome")
        c = state["calls"].get(o.get("actionId"))
        if (
            not c
            or c["state"] != "pending"
            or o.get("callId") != c["callId"]
            or not _is_int(o.get("attempt"))
            or o["attempt"] != c["attempts"][-1]["attempt"]
            or not _is_int(o.get("status"))
            or not _nonempty(o.get("nonce"))
            or o["actionId"] in seen
        ):
            raise Invalid(422, "outcome does not match a pending call")
        seen.add(o["actionId"])
    ap = state.get("approval")
    seen_ap = set()
    for a in approvals:
        if (
            not isinstance(a, dict)
            or not ap
            or ap["status"] != "pending"
            or a.get("approvalId") != ap["approvalId"]
            or not _nonempty(a.get("nonce"))
            or not _nonempty(a.get("decision"))
            or a["approvalId"] in seen_ap
        ):
            raise Invalid(422, "approval does not match a pending request")
        seen_ap.add(a["approvalId"])

    dispatches = []
    retry = []
    for o in outcomes:
        c = state["calls"][o["actionId"]]
        att = c["attempts"][-1]
        att.update(
            end=now, receiptId=rid, nonce=o["nonce"], status=o["status"],
            errorType=o.get("errorType"), resultClass=o.get("resultClass"),
        )
        entry = {"receiptId": rid, "actionId": o["actionId"], "callId": o["callId"],
                 "attempt": o["attempt"], "status": o["status"]}
        if "resultClass" in o:
            entry["resultClass"] = o["resultClass"]
        if "errorType" in o:
            entry["errorType"] = o["errorType"]
        entry["nonce"] = o["nonce"]
        state["receiptLog"].append(entry)
        st = o["status"]
        if 200 <= st < 300:
            c["state"] = "ok"
        elif st == 503 and c["attempts"][-1]["attempt"] == 1:
            retry.append(c)
        else:
            c["state"] = "failed"
            if c["phase"] == "diagnostic":
                state["diagFailed"] = True
    for c in retry:
        if c["phase"] == "diagnostic" and state["diagFailed"]:
            c["state"] = "failed"
        else:
            dispatches.append(_dispatch(state, c, now))

    denied = False
    for a in approvals:
        ap = state["approval"]
        ap.update(status="decided", decision=a["decision"], nonce=a["nonce"], receiptId=rid, decidedAt=now)
        state["receiptLog"].append(
            {"receiptId": rid, "approvalId": a["approvalId"], "decision": a["decision"], "nonce": a["nonce"]}
        )
        if str(a["decision"]).lower() == "approved":
            eff = state["calls"][state["effectKey"]]
            eff["approvalId"] = a["approvalId"]
            eff["approvalNonce"] = a["nonce"]
        else:
            denied = True

    if denied:
        return state, _finalize(state, now, "completed", None)

    approvals_out = _advance(state, now, dispatches)
    if state["status"] != "waiting":
        return state, state["view"]
    if dispatches:
        approvals_out = []
    return state, _waiting(state, dispatches, approvals_out)