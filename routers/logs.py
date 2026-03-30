from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from database import get_db
from models import Log
from schemas import LogCreate, LogResponse

router = APIRouter(prefix="/logs", tags=["Logs"])


@router.post("/", response_model=LogResponse)
def create_log(log: LogCreate, db: Session = Depends(get_db)):
    new_log = Log(**log.model_dump())

    db.add(new_log)
    db.commit()
    db.refresh(new_log)

    return new_log