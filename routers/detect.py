from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db
from models import Log, Alert

router = APIRouter(prefix="/detect", tags=["Detection"])

@router.post("/{log_id}")
def detect_threat(log_id: int, db: Session = Depends(get_db)):
    log = db.query(Log).filter(Log.id == log_id).first()

    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    existing_alert = db.query(Alert).filter(Alert.log_id == log.id).first()
    if existing_alert:
        return {
            "message": "Alert already exists",
            "alert_id": existing_alert.id
        }

    if log.severity.upper() == "HIGH":
        alert = Alert(
            log_id=log.id,
            threat_type="High Severity Activity",
            severity="HIGH",
            explanation=f"Auto alert generated because severity is {log.severity}",
            status="OPEN"
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return {
            "message": "Threat detected, alert created",
            "alert_id": alert.id,
            "severity": alert.severity
        }

    return {"message": "No threat detected"}