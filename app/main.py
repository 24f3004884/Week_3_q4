from fastapi import FastAPI
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database import *
from app.models import *
from app.schemas import *

import hashlib
import json
import re
import secrets


SUPPORTED_PROFILE = "ga5-incident-agent/v2"

app = FastAPI()

Base.metadata.create_all(bind=engine)


def make_hash(data):

    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True
        ).encode()
    ).hexdigest()


def extract_evidence_ids(transcript):

    matches = re.findall(
        r"\[(.*?)\]",
        transcript
    )

    return matches[:4]


def build_traceparent():

    trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)

    return f"00-{trace_id}-{span_id}-01"


def build_dispatch(tool_name, service, evidence):

    action_id = secrets.token_hex(8)
    call_id = secrets.token_hex(8)

    return {
        "actionId": action_id,
        "callId": call_id,
        "phase": "diagnostic",
        "toolName": tool_name,
        "arguments": {
            "service": service
        },
        "evidence": evidence[:1],
        "attempt": 1,
        "traceparent": build_traceparent()
    }


@app.get("/")
def root():

    return {
        "status": "ok"
    }


@app.post("/v2/incidents")
def create_incident(
        request: IncidentRequest):

    if request.profile != SUPPORTED_PROFILE:

        raise HTTPException(
            status_code=422,
            detail="Unsupported profile"
        )

    db: Session = SessionLocal()

    request_dict = request.model_dump()

    request_hash = make_hash(
        request_dict
    )

    existing = db.get(
        Run,
        request.runId
    )

    #
    # Replay handling
    #

    if existing:

        if existing.request_hash != request_hash:

            raise HTTPException(
                status_code=409,
                detail="runId reused with different content"
            )

        return json.loads(
            existing.state_json
        )

    transcript = request.incident.transcript

    evidence_ids = extract_evidence_ids(
        transcript
    )

    root_cause = (
        request.incident.allowedRootCauses[0]
        if request.incident.allowedRootCauses
        else "unknown"
    )

    dispatches = []

    if request.toolCatalog:

        tool_name = request.toolCatalog[0]["name"]

        dispatches.append(
            build_dispatch(
                tool_name,
                request.incident.service,
                evidence_ids
            )
        )

    response = {
        "runId": request.runId,
        "status": "waiting",
        "diagnosis": {
            "rootCause": root_cause,
            "evidence": evidence_ids[:2]
        },
        "dispatches": dispatches,
        "approvals": []
    }

    db.add(
        Run(
            run_id=request.runId,
            request_hash=request_hash,
            state_json=json.dumps(response)
        )
    )

    db.commit()

    return response


@app.post(
    "/v2/incidents/{run_id}/receipts"
)
def process_receipt(
        run_id: str,
        body: dict):

    db: Session = SessionLocal()

    run = db.get(
        Run,
        run_id
    )

    if not run:

        raise HTTPException(
            status_code=404,
            detail="Run not found"
        )

    state = json.loads(
        run.state_json
    )

    state["status"] = "completed"

    state["chosenEffect"] = None

    state["actionLog"] = state.get(
        "dispatches",
        []
    )

    state["receiptLog"] = [
        {
            "receiptId": body.get(
                "receiptId",
                "unknown"
            )
        }
    ]

    run.state_json = json.dumps(
        state
    )

    db.commit()

    return state


@app.get(
    "/v2/incidents/{run_id}"
)
def get_run(run_id: str):

    db: Session = SessionLocal()

    run = db.get(
        Run,
        run_id
    )

    if not run:

        raise HTTPException(
            status_code=404,
            detail="Run not found"
        )

    return json.loads(
        run.state_json
    )
