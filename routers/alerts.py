from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List

from database import get_db
from models import Alert
from schemas import AlertResponse

router = APIRouter(prefix="/alerts", tags=["Alerts"])

@router.get("/", response_model=List[AlertResponse])
def get_alerts( # added pagination
    status: str = Query(None), 
    severity: str = Query(None),
    limit: int = Query(10, le=100),
    offset: int = Query(0),
    db: Session = Depends(get_db)
):
    query = db.query(Alert)

    if status:
        query = query.filter(Alert.status == status.upper())

    if severity:
        query = query.filter(Alert.severity == severity.upper())

    return query.order_by(Alert.id.desc()).offset(offset).limit(limit).all()

# Resolve alert
@router.patch("/{alert_id}/resolve")
def resolve_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    if alert.status == "RESOLVED":
        return {"message": "Already resolved", "alert_id": alert.id}

    alert.status = "RESOLVED"
    db.commit()
    db.refresh(alert)

    return {
        "message": "Alert resolved",
        "alert_id": alert.id,
        "status": alert.status
    }
