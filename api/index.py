import os
import json
import gspread
import urllib.request
from mangum import Mangum
from fastapi import FastAPI, Body, Query
from datetime import datetime, timedelta
from google.oauth2.service_account import Credentials

from helpers import enrich, parse_log, parse_date, process_pipeline
from config import WEBHOOK_URL, recent_threshold_days , WEBHOOK_URL_TESTING


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

@app.post("/send-alert-manual")
async def send_alert_manual(body: dict = Body(...)):
    log = body.get("log", "")

    payload = {
        "log": log,
        "source": "manual_test"
    }

    try:
        data = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(
            WEBHOOK_URL_TESTING,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(req) as response:
            response_body = response.read().decode()

        return {
            "status": "sent",
            "webhook_status_code": response.getcode(),
            "webhook_response": response_body
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
        
@app.get("/get-user-history")
def get_user_history(user: str = Query(...)):
    sheet = get_sheet()
    records = sheet.get_all_records()

    user_records = [r for r in records if str(r.get("User", "")).strip() == user.strip()]

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
        date_str = str(r.get("Date", "")).strip()
        event = str(r.get("Event", "")).lower().strip()
        summary = str(r.get("Summary", "")).lower().strip()
        risk = str(r.get("Risk", "")).lower().strip()

        event_time = parse_date(date_str)
        if not event_time:
            continue

        if event_time >= recent_threshold:
            recent_alerts += 1

        # Check event AND summary since Event column appears empty
        combined_text = event + " " + summary
        if "failed" in combined_text:
            failed_logins += 1

        # Risk is a sentence, check for keywords instead of exact match
        if any(word in risk for word in ["high", "critical", "unauthorized", "suspicious", "escalation"]):
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

@app.get("/debug-user")
def debug_user(user: str = Query(...)):
    sheet = get_sheet()
    records = sheet.get_all_records()
    user_records = [r for r in records if str(r.get("User", "")).strip() == user.strip()]
    
    debug = []
    for r in user_records:
        date_str = str(r.get("Date", "")).strip()
        event = str(r.get("Event", "")).lower().strip()
        risk = str(r.get("Risk", "")).upper().strip()
        parsed = parse_date(date_str)
        debug.append({
            "raw_date": date_str,
            "parsed_date": str(parsed),
            "event": event,
            "risk": risk
        })
    
    return {"count": len(user_records), "records": debug}
    
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
