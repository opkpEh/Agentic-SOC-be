import httpx
import hashlib
import gspread
from fastapi import FastAPI, Body, Query
from datetime import datetime, timedelta
from oauth2client.service_account import ServiceAccountCredentials
from helpers import enrich, parse_log
from config import TRUSTED_IPS, INTERNAL_PREFIXES, KNOWN_DEVICES, WEBHOOK_URL

app = FastAPI()

scope = [
    "https://spreadsheets.google.com/feeds",
    "https://www.googleapis.com/auth/drive"
]

creds = ServiceAccountCredentials.from_json_keyfile_name("creds.json", scope)
client = gspread.authorize(creds)

sheet = client.open_by_key("1pz0k4MUBUVreH-yC-H3D2ZYAqfbZys2ef-kafEGFOJI").sheet1

recent_threshold_days= 1

def is_internal_ip(ip: str) -> bool:
    if ip in TRUSTED_IPS:
        return True
    return any(ip.startswith(prefix) for prefix in INTERNAL_PREFIXES)


def generate_session_id(ip, user, host):
    time_bucket = int(datetime.utcnow().timestamp() // 300)
    raw = f"{ip}|{user}|{host}|{time_bucket}"
    return hashlib.sha1(raw.encode()).hexdigest()


async def process_pipeline(log: str):
    parsed = parse_log(log)
    enriched = enrich(parsed)

    async with httpx.AsyncClient() as client:
        response = await client.post(WEBHOOK_URL, json=enriched)

    return {
        "status": "processed",
        "webhook_status": response.status_code
    }

def parse_date(date_str):
    for fmt in ("%Y-%m-%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(date_str, fmt)
        except:
            continue
    return None

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
    records = sheet.get_all_records()

    user_records = [r for r in records if r.get("User") == user]

    if not user_records:
        return {
            "notfound":1,
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

        try:
            event_time = parse_date(date_str)
            if not event_time:
                continue
        except:
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