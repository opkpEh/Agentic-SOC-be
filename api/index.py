import os
import json
import gspread
from mangum import Mangum
from fastapi import FastAPI, Body, Query
from datetime import datetime, timedelta
from google.oauth2.service_account import Credentials

from helpers import enrich, parse_log, parse_date, process_pipeline
from config import WEBHOOK_URL, recent_threshold_days


app = FastAPI()

creds = json.loads(os.environ["GOOGLE_CREDS"])

credentials = Credentials.from_service_account_info(
    creds,
    scopes=[
        "https://www.googleapis.com/auth/spreadsheets",
        "https://www.googleapis.com/auth/drive"
    ]
)

client = gspread.authorize(credentials)

def get_sheet():
    # user history
    return client.open_by_key("1pz0k4MUBUVreH-yC-H3D2ZYAqfbZys2ef-kafEGFOJI").sheet1

def get_alert_sheet():
    return client.open_by_key("1t8DDSoJ3-YTvvQgPt11yW6mqcGpqKQh4VTThUq0vVuc").sheet1

@app.get("/")
def root():
    return {"message": "API running"}


@app.post("/send-alert")
async def send_alert(body: dict = Body(...)):
    log = body.get("log", "")
    result = await process_pipeline(log)
    return result


@app.get("/get-user-history")
def get_user_history(user: str = Query(...)):
    sheet = get_sheet() 
    records = sheet.get_all_records()

    user_records = [r for r in records if r.get("User") == user]

    if not user_records:
        return {
            "notfound": 1,
            "user": user,
            "recent_alerts": 0,
            "failed_logins": 0,
            "high_severity_count": 0,
            "risk_score": 0
        }

    now = datetime.utcnow()
    recent_threshold = now - timedelta(days=recent_threshold_days)

    recent_alerts = 0
    failed_logins = 0
    high_severity = 0

    for r in user_records:
        date_str = r.get("Date")
        severity = r.get("Severity", "").upper()
        event = r.get("Event", "").lower()

        event_time = parse_date(date_str)
        if not event_time:
            continue

        if event_time >= recent_threshold:
            recent_alerts += 1

        if "failed" in event:
            failed_logins += 1

        if severity in ["HIGH", "CRITICAL"]:
            high_severity += 1

    risk_score = min(100, (failed_logins * 5 + high_severity * 15))

    return {
        "user": user,
        "recent_alerts": recent_alerts,
        "failed_logins": failed_logins,
        "high_severity_count": high_severity,
        "risk_score": risk_score
    }

@app.post("/update-user-history")
async def update_user_history(body: dict = Body(...)):
    sheet = get_sheet()

    AlertID = body.get("AlertID", "")
    User = body.get("User", "")
    Role = body.get("Role", "")
    Event = body.get("Event", "")
    Date = body.get("Date", "")
    Summary = body.get("summary", "")
    Risk = body.get("risk", "")
    Confidence = body.get("confidence", "")

    row = [
        AlertID,
        User,
        Role,
        Event,
        Date,
        Summary,
        Risk,
        Confidence
    ]

    sheet.append_row(row)

    return {
        "status": "success",
        "message": "Row added to user_history"
    }

@app.post("/update-alert-record")
async def update_alert_record(body: dict = Body(...)):
    sheet = get_alert_sheet()

    AlertID = body.get("AlertID", "")
    Date = body.get("Date", "")
    User = body.get("User", "")
    Role = body.get("Role", "")
    Event = body.get("Event", "")
    SourceIP = body.get("SourceIP", "")
    Service = body.get("Service", "")
    Outcome = body.get("Outcome", "")

    Severity = body.get("severity", "")
    Noise = body.get("noise", "")
    RequiresInvestigation = body.get("requires_investigation", "")

    Summary = body.get("summary", "")
    Reasoning = body.get("reasoning", "")
    Risk = body.get("risk", "")
    Confidence = body.get("confidence", "")

    Status = "open" if RequiresInvestigation else "no action"
    Comments = Summary + " | " + Reasoning
    LastUpdated = Date

    row = [
        AlertID,
        Date,
        User,
        Role,
        Event,
        SourceIP,
        Service,
        Outcome,
        Severity,
        Noise,
        RequiresInvestigation,
        Summary,
        Reasoning,
        Risk,
        Confidence,
        Status,
        Comments,
        LastUpdated
    ]

    sheet.append_row(row)

    return {
        "status": "success",
        "message": "Alert recorded"
    }

handler = Mangum(app)
def main(request, context):
    return handler(request, context)