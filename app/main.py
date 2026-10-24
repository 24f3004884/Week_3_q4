import asyncio
import json
import logging
from collections import defaultdict

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import config, machine, planner, store, trace
from .util import canon, dumps, now_ns, sha256_hex

app = FastAPI(redirect_slashes=False, docs_url=None, redoc_url=None, openapi_url=None)
_locks = defaultdict(asyncio.Lock)
log = logging.getLogger("uvicorn.error")


def jtext(text, status=200):
    return Response(content=text.encode("utf-8"), status_code=status, media_type="application/json")


def err(status, msg):
    return jtext(dumps({"error": msg}), status)


@app.exception_handler(RequestValidationError)
async def _v(_r, _e):
    return err(422, "invalid request")


@app.exception_handler(StarletteHTTPException)
async def _h(_r, e):
    return err(e.status_code, "error")


@app.exception_handler(Exception)
async def _x(_r, _e):
    return err(500, "internal error")


def _validate_request(b):
    if b.get("profile") != config.PROFILE:
        return 400, "unsupported profile"
    for k in ("runId", "agentName", "publicMarker"):
        if not isinstance(b.get(k), str) or not b[k].strip():
            return 422, f"invalid {k}"
    inc, pol = b.get("incident"), b.get("policy")
    if not isinstance(inc, dict) or not isinstance(inc.get("transcript"), str) or not inc["transcript"].strip():
        return 422, "invalid incident"
    arc = inc.get("allowedRootCauses")
    if not isinstance(arc, list) or not arc or not all(isinstance(x, str) for x in arc):
        return 422, "invalid allowedRootCauses"
    cat = b.get("toolCatalog")
    if not isinstance(cat, list) or not cat or not all(isinstance(t, dict) and isinstance(t.get("name"), str) for t in cat):
        return 422, "invalid toolCatalog"
    if not isinstance(pol, dict):
        return 422, "invalid policy"
    eff = pol.get("effectTools")
    names = {t["name"] for t in cat}
    if not isinstance(eff, list) or not any(e in names for e in eff):
        return 422, "invalid effectTools"
    if "sensitive" in b and not isinstance(b["sensitive"], dict):
        return 422, "invalid sensitive"
    return None


async def _json_body(request):
    try:
        body = json.loads(await request.body())
    except Exception:
        return None
    return body if isinstance(body, dict) else None


@app.get("/")
@app.get("/healthz")
async def health():
    return jtext(dumps({"ok": True}))


@app.post("/v2/incidents")
async def create_incident(request: Request):
    t_start = now_ns()
    body = await _json_body(request)
    if body is None:
        return err(400, "invalid json")
    run_id = body.get("runId")
    if not isinstance(run_id, str) or not run_id.strip() or len(run_id) > 512:
        return err(422, "invalid runId")
    h = sha256_hex(canon(body))
    async with _locks[run_id]:
        ex = store.get_idem(run_id, "POST")
        if ex:
            return jtext(ex[1]) if ex[0] == h else err(409, "conflict")
        bad = _validate_request(body)
        if bad:
            return err(*bad)
        ctx = trace.make_context(body, request.headers)
        plan_start = now_ns()
        try:
            plan = await planner.make_plan(body)
        except Exception as e:
            log.error("planner crashed run=%s %s", run_id, type(e).__name__)
            return err(502, "planner unavailable")
        plan_end = now_ns()
        log.info("POST run=%s planned in %.1fs", run_id, (plan_end - plan_start) / 1e9)
        times = {"start": t_start, "planStart": plan_start, "planEnd": plan_end, "end": None}
        state, resp = machine.start_run(body, plan, ctx, config.LLM_MODEL, config.LLM_PROVIDER, times)
        text = dumps(resp)
        store.commit(run_id, state, "POST", h, text)
        return jtext(text)


@app.post("/v2/incidents/{run_id}/receipts")
async def post_receipt(run_id: str, request: Request):
    body = await _json_body(request)
    if body is None:
        return err(400, "invalid json")
    rid = body.get("receiptId")
    if not isinstance(rid, str) or not rid.strip() or len(rid) > 512:
        return err(422, "invalid receiptId")
    h = sha256_hex(canon(body))
    async with _locks[run_id]:
        state = store.get_state(run_id)
        if state is None:
            return err(404, "run not found")
        key = "receipt:" + rid
        ex = store.get_idem(run_id, key)
        if ex:
            return jtext(ex[1]) if ex[0] == h else err(409, "conflict")
        try:
            new_state, resp = machine.apply_receipt(state, body, now_ns())
        except machine.Invalid as e:
            return err(e.code, e.msg)
        text = dumps(resp)
        store.commit(run_id, new_state, key, h, text)
        log.info("RECEIPT run=%s id=%s -> %s", run_id, rid, resp.get("status"))
        return jtext(text)


@app.get("/v2/incidents/{run_id}")
async def get_incident(run_id: str):
    state = store.get_state(run_id)
    if state is None:
        return err(404, "run not found")
    return jtext(dumps(state["view"]))
