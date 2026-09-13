import json
import logging
import os
from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from actions import execute_action
from database import get_connection
from enrichment import enrich_ioc
from metrics import get_dashboard_metrics
from models import ActionRequest, EnrichRequest, ReportRequest
from reports import generate_report

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
# Plain text logs are fine for a single dev reading a terminal, but once this
# runs unattended (Schedule Trigger every 15 min) you want machine-parseable
# logs you can grep, ship to a log aggregator, or alert on. JSON-per-line is
# the simplest structured format that works everywhere.
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "message": %(message)s}',
)
logger = logging.getLogger("sentinelflow")


# ---------------------------------------------------------------------------
# API key auth
# ---------------------------------------------------------------------------
# Every route on this service currently accepts requests from anyone who can
# reach the container on the Docker network. That's fine while it's just you
# and n8n talking to it, but it costs nothing to require a shared secret, and
# it's the kind of thing worth being able to say "yes, I did this" about.
API_SECRET_KEY = os.getenv("API_SECRET_KEY")


def verify_api_key(x_api_key: str = Header(...)):
    if not API_SECRET_KEY:
        # Fail loudly in a misconfigured environment rather than silently
        # accepting everything because the env var was never set.
        logger.error('"API_SECRET_KEY is not set on the server"')
        raise HTTPException(status_code=500, detail="Server misconfigured")
    if x_api_key != API_SECRET_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


app = FastAPI(
    title="SentinelFlow AI - Enrichment & Action Service",
    dependencies=[Depends(verify_api_key)],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for real production
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def create_tables():
    pass  # schema is run separately via n8n/psql, as before


def find_recent_open_case(cur, ioc: str):
    """
    Deduplication check: if this exact IOC already has an active case
    opened in the last hour, return it instead of creating a new one.
    'Active' means it hasn't reached a terminal status yet — auto_resolved
    and closed cases don't block a fresh investigation, since those
    represent a completed decision, not an in-flight one.
    """
    cur.execute(
        """SELECT id, risk_score, verdict, status, created_at
           FROM cases
           WHERE ioc = %s
             AND created_at > NOW() - INTERVAL '1 hour'
             AND status NOT IN ('closed', 'auto_resolved')
           ORDER BY created_at DESC
           LIMIT 1""",
        (ioc,),
    )
    return cur.fetchone()


@app.post("/enrich")
async def enrich(req: EnrichRequest):
    conn = get_connection()
    cur = conn.cursor()

    existing = find_recent_open_case(cur, req.ioc)
    if existing:
        cur.close()
        conn.close()
        logger.info(
            '{"event": "duplicate_case_skipped", "ioc": "%s", "existingCaseId": %s}'
            % (req.ioc, existing["id"])
        )
        return {
            "ioc": req.ioc,
            "caseId": existing["id"],
            "riskScore": existing["risk_score"],
            "verdict": existing["verdict"],
            "status": existing["status"],
            "duplicate": True,
            "message": "An active case for this indicator already exists; reusing it instead of creating a new one.",
        }

    result = await enrich_ioc(req.ioc, req.ioc_type)

    cur.execute(
        """INSERT INTO cases (ioc, ioc_type, risk_score, verdict, source)
           VALUES (%s, %s, %s, %s, %s) RETURNING id""",
        (req.ioc, req.ioc_type, result["riskScore"], result["verdict"], "manual_report"),
    )
    case_id = cur.fetchone()["id"]

    for source in result["sources"]:
        cur.execute(
            """INSERT INTO enrichment_log (case_id, source, raw_response, contributed_score)
               VALUES (%s, %s, %s, %s)""",
            (case_id, source["source"], json.dumps(source.get("raw", {})), result["riskScore"]),
        )
    conn.commit()
    cur.close()
    conn.close()

    result["caseId"] = case_id
    result["duplicate"] = False

    logger.info(
        '{"event": "case_created", "caseId": %s, "ioc": "%s", "riskScore": %s, "verdict": "%s"}'
        % (case_id, req.ioc, result["riskScore"], result["verdict"])
    )

    # Raw vendor payloads are already logged to enrichment_log above.
    # Strip them from the response so the AI Agent's tool call doesn't
    # burn tokens on data it never needs to reason over directly.
    for source in result["sources"]:
        source.pop("raw", None)

    return result


@app.post("/action")
def action(req: ActionRequest):
    logger.info(
        '{"event": "action_requested", "caseId": %s, "actionType": "%s", "executedBy": "%s"}'
        % (req.case_id, req.action_type, req.executed_by)
    )
    return execute_action(req.case_id, req.action_type, req.executed_by)


@app.post("/report")
def report(req: ReportRequest):
    return generate_report(req.case_id)


@app.get("/metrics")
def metrics():
    return get_dashboard_metrics()