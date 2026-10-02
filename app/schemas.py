from pydantic import BaseModel
from datetime import datetime
from typing import Optional


class SecurityEventCreate(BaseModel):
    timestamp: Optional[datetime] = None
    event_type: str
    source: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    description: Optional[str] = None
    severity: str = "Low"

class TimelineEvent(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    source: str
    username: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    hostname: Optional[str] = None
    severity: str

 