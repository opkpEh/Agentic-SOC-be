import os
import json
import gspread
from fastapi import FastAPI, Body, Query
from datetime import datetime, timedelta
from google.oauth2.service_account import Credentials
from mangum import Mangum
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
    return client.open_by_key("1pz0k4MUBUVreH-yC-H3D2ZYAqfbZys2ef-kafEGFOJI").sheet1


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

handler = Mangum(app)