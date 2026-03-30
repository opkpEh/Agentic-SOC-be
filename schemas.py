from pydantic import BaseModel


class AlertResponse(BaseModel):
    id: int
    log_id: int
    threat_type: str
    severity: str
    explanation: str
    status: str

    class Config:
        from_attributes = True
class LogCreate(BaseModel):
    source_ip: str
    dest_ip: str
    activity: str
    severity: str


class LogResponse(BaseModel):
    id: int
    source_ip: str
    dest_ip: str
    activity: str
    severity: str

    class Config:
        from_attributes = True