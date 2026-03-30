from sqlalchemy import Column, Integer, String, Text, DateTime
from datetime import datetime, timezone
from database import Base

class Log(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(50), nullable=False)
    dest_ip = Column(String(50), nullable=False)
    activity = Column(String(255), nullable=False)
    severity = Column(String(20), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

class Alert(Base):
  __tablename__ = "alerts"
  
  id = Column(Integer, primary_key=True, index=True)
  log_id= Column(Integer,nullable=False)
  threat_type = Column(String(100), nullable=False)
  severity = Column(String(10), nullable=False)
  explanation = Column(Text, nullable=False)
  status = Column(String(20), default="OPEN")
  timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))