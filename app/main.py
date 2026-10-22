from fastapi import FastAPI
from fastapi import HTTPException

from sqlalchemy.orm import Session

from app.database import *
from app.models import *
from app.schemas import *

import json

app = FastAPI()

Base.metadata.create_all(
    bind=engine
)

@app.get("/")
def root():

    return {
        "message": "incident agent running"
    }


@app.post("/v2/incidents")
def create_incident(
        request: IncidentRequest):

    db: Session = SessionLocal()

    run = db.get(
        Run,
        request.runId
    )

    if run:

        return json.loads(
            run.state_json
        )

    response = {
        "runId": request.runId,
        "status": "waiting",
        "diagnosis": {
            "rootCause": "unknown",
            "evidence": []
        },
        "dispatches": [],
        "approvals": []
    }

    row = Run(
        run_id=request.runId,
        state_json=json.dumps(response)
    )

    db.add(row)

    db.commit()

    return response


@app.post("/v2/incidents/{run_id}/receipts")
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

    run.state_json = json.dumps(
        state
    )

    db.commit()

    return state


@app.get("/v2/incidents/{run_id}")
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