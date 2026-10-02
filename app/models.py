from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from datetime import datetime

from app.database import Base

class IncidentAudit(Base):
    __tablename__ = "incident_audits"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(
        Integer,
        ForeignKey("incidents.id"),
        nullable=False
    )

    action = Column(
        String,
        nullable=False
    )

    old_value = Column(
        Text,
        nullable=True
    )

    new_value = Column(
        Text,
        nullable=True
    )

    performed_by = Column(
        String,
        default="SOC Analyst",
        nullable=False
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    event_type = Column(String, nullable=False)
    source = Column(String, nullable=False)
    username = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    destination_ip = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    description = Column(String, nullable=True)
    severity = Column(String, default="Low")


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    asset_name = Column(String, nullable=False, unique=True)
    asset_type = Column(String, nullable=False)
    criticality = Column(String, default="Medium")
    owner = Column(String, nullable=True)
    environment = Column(String, nullable=True)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="Medium")
    status = Column(String, default="Open")
    username = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)

    # Asset associated with this incident
    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=True)

    risk_score = Column(Integer, default=0)
    priority = Column(String, default="Medium")
    analyst_notes = Column(Text, nullable=True)
    escalation_status = Column(String, default="Not Escalated")
    created_at = Column(DateTime, default=datetime.utcnow)


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=False)


class EventTechniqueMapping(Base):
    __tablename__ = "event_technique_mappings"

    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("security_events.id"), nullable=False)
    technique_id = Column(String, nullable=False)
    technique_name = Column(String, nullable=False)
    description = Column(Text, nullable=True)