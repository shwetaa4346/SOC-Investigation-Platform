from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import engine, Base, SessionLocal
from app.models import (
    SecurityEvent,
    Asset,
    Incident,
    IncidentEvent,
    IncidentAudit,
    EventTechniqueMapping
)
from app.schemas import SecurityEventCreate, TimelineEvent
from pydantic import BaseModel


# Create database tables
Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="SOC Investigation & Incident Prioritization Platform"
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
@app.get("/dashboard", include_in_schema=False)
def dashboard():
    return FileResponse("dashboard.html")

# Database connection
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class IncidentCreate(BaseModel):
    title: str
    description: str | None = None
    severity: str = "Medium"
    status: str = "Open"
    username: str | None = None
    hostname: str | None = None
    source_ip: str | None = None


@app.get("/")
def home():
    return {
        "message": "SOC Investigation Platform is running",
        "status": "online"
    }


@app.post("/events")
def create_event(
    event: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    new_event = SecurityEvent(
        timestamp=event.timestamp,
        event_type=event.event_type,
        source=event.source,
        username=event.username,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        hostname=event.hostname,
        description=event.description,
        severity=event.severity
    )

    db.add(new_event)
    db.commit()
    db.refresh(new_event)

    return {
        "message": "Security event created successfully",
        "event_id": new_event.id
    }
@app.get("/events")
def get_events(db: Session = Depends(get_db)):
    events = db.query(SecurityEvent).all()

    return events
@app.post("/incidents")
def create_incident(
    incident: IncidentCreate,
    db: Session = Depends(get_db)
):
    new_incident = Incident(
        title=incident.title,
        description=incident.description,
        severity=incident.severity,
        status=incident.status,
        username=incident.username,
        hostname=incident.hostname,
        source_ip=incident.source_ip
    )

    db.add(new_incident)
    db.commit()
    db.refresh(new_incident)

    return {
        "message": "Incident created successfully",
        "incident_id": new_incident.id
    }

@app.get("/incidents")
def get_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).all()

    return incidents

@app.post("/incidents/1/events")
def add_event_to_incident(
    event_id: int,
    db: Session = Depends(get_db)
):
    # Check if the incident exists
    incident = db.query(Incident).filter(Incident.id == 1).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Check if the event exists
    event = db.query(SecurityEvent).filter(
        SecurityEvent.id == event_id
    ).first()

    if not event:
        return {
            "message": "Security event not found"
        }

    # Create the connection
    incident_event = IncidentEvent(
        incident_id=1,
        event_id=event_id
    )

    db.add(incident_event)
    db.commit()
    db.refresh(incident_event)

    return {
        "message": "Event linked to Incident #1 successfully",
        "incident_id": 1,
        "event_id": event_id
    }

@app.post("/incidents/1/events")
def add_event_to_incident(
    event_id: int,
    db: Session = Depends(get_db)
):
    # Check if Incident #1 exists
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Check if the security event exists
    event = db.query(SecurityEvent).filter(
        SecurityEvent.id == event_id
    ).first()

    if not event:
        return {
            "message": "Security event not found"
        }

    # Check if this event is already linked
    existing_link = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1,
        IncidentEvent.event_id == event_id
    ).first()

    if existing_link:
        return {
            "message": "Event is already linked to Incident #1",
            "incident_id": 1,
            "event_id": event_id
        }

    # Create the connection
    incident_event = IncidentEvent(
        incident_id=1,
        event_id=event_id
    )

    db.add(incident_event)
    db.commit()
    db.refresh(incident_event)

    return {
        "message": "Event linked to Incident #1 successfully",
        "incident_id": 1,
        "event_id": event_id
    }

@app.get("/incidents/1/events")
def get_incident_events(db: Session = Depends(get_db)):
    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    return links

@app.delete("/incidents/1/events/{link_id}")
def delete_incident_event(
    link_id: int,
    db: Session = Depends(get_db)
):
    link = db.query(IncidentEvent).filter(
        IncidentEvent.id == link_id,
        IncidentEvent.incident_id == 1
    ).first()

    if not link:
        return {
            "message": "Event link not found"
        }

    db.delete(link)
    db.commit()

    return {
        "message": "Event link deleted successfully",
        "link_id": link_id
    }

@app.post("/incidents/1/correlate")
def correlate_events_for_incident(
    db: Session = Depends(get_db)
):
    # Get Incident #1
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Find events related to the incident
    related_events = db.query(SecurityEvent).filter(
        SecurityEvent.username == incident.username,
        SecurityEvent.hostname == incident.hostname,
        SecurityEvent.source_ip == incident.source_ip
    ).all()

    linked_events = []
    already_linked = []

    for event in related_events:

        # Check whether the event is already linked
        existing_link = db.query(IncidentEvent).filter(
            IncidentEvent.incident_id == 1,
            IncidentEvent.event_id == event.id
        ).first()

        if existing_link:
            already_linked.append(event.id)
            continue

        # Create new incident-event relationship
        incident_event = IncidentEvent(
            incident_id=1,
            event_id=event.id
        )

        db.add(incident_event)
        linked_events.append(event.id)

    db.commit()

    return {
        "message": "Event correlation completed",
        "incident_id": 1,
        "newly_linked_events": linked_events,
        "already_linked_events": already_linked,
        "total_related_events": len(related_events)
    }

@app.get(
    "/incidents/1/timeline",
    response_model=list[TimelineEvent]
)
def get_incident_timeline(db: Session = Depends(get_db)):
    # Get all event links for Incident #1
    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    timeline = []

    # Get the actual security events
    for link in links:
        event = db.query(SecurityEvent).filter(
            SecurityEvent.id == link.event_id
        ).first()

        if event:
            timeline.append(event)

    # Sort events chronologically
    timeline.sort(
        key=lambda event: event.timestamp
    )

    return timeline

@app.post("/events/{event_id}/map-technique")
def map_event_to_mitre(
    event_id: int,
    db: Session = Depends(get_db)
):
    # Find the security event
    event = db.query(SecurityEvent).filter(
        SecurityEvent.id == event_id
    ).first()

    if not event:
        return {
            "message": "Security event not found"
        }

    # MITRE ATT&CK mapping based on event type
    mitre_mapping = {
        "PowerShell Execution": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "description": "Adversaries may abuse PowerShell to execute commands and scripts."
        },

        "Failed Login": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "description": "Repeated failed login attempts may indicate a brute-force authentication attack."
        },

        "Successful Login": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "description": "A successful login may indicate the use of valid credentials."
        },

        "Suspicious Network Connection": {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "description": "Suspicious network communication may indicate command-and-control or other malicious activity."
        }
    }

    # Check whether this event type has a mapping
    mapping = mitre_mapping.get(event.event_type)

    if not mapping:
        return {
            "message": "No MITRE ATT&CK mapping available for this event type",
            "event_id": event_id,
            "event_type": event.event_type
        }

    # Check whether mapping already exists
    existing_mapping = db.query(EventTechniqueMapping).filter(
        EventTechniqueMapping.event_id == event_id
    ).first()

    if existing_mapping:
        return {
            "message": "MITRE ATT&CK mapping already exists",
            "event_id": event_id,
            "technique_id": existing_mapping.technique_id,
            "technique_name": existing_mapping.technique_name
        }

    # Create the mapping
    new_mapping = EventTechniqueMapping(
        event_id=event.id,
        technique_id=mapping["technique_id"],
        technique_name=mapping["technique_name"],
        description=mapping["description"]
    )

    db.add(new_mapping)
    db.commit()
    db.refresh(new_mapping)

    return {
        "message": "MITRE ATT&CK technique mapped successfully",
        "event_id": event.id,
        "event_type": event.event_type,
        "technique_id": new_mapping.technique_id,
        "technique_name": new_mapping.technique_name,
        "description": new_mapping.description
    }

@app.post("/incidents/1/map-techniques")
def map_incident_events_to_mitre(
    db: Session = Depends(get_db)
):
    # Check whether Incident #1 exists
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Get all events linked to Incident #1
    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    if not links:
        return {
            "message": "No security events linked to Incident #1"
        }

    # MITRE ATT&CK mappings
    mitre_mapping = {
        "PowerShell Execution": {
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "description": "Adversaries may abuse PowerShell to execute commands and scripts."
        },

        "Failed Login": {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "description": "Repeated failed login attempts may indicate a brute-force authentication attack."
        },

        "Successful Login": {
            "technique_id": "T1078",
            "technique_name": "Valid Accounts",
            "description": "A successful login may indicate the use of valid credentials."
        },

        "Suspicious Network Connection": {
            "technique_id": "T1071",
            "technique_name": "Application Layer Protocol",
            "description": "Suspicious network communication may indicate command-and-control or other malicious activity."
        }
    }

    newly_mapped = []
    already_mapped = []
    no_mapping = []

    # Process every event linked to Incident #1
    for link in links:

        event = db.query(SecurityEvent).filter(
            SecurityEvent.id == link.event_id
        ).first()

        if not event:
            continue

        # Find MITRE mapping for this event type
        mapping = mitre_mapping.get(event.event_type)

        if not mapping:
            no_mapping.append({
                "event_id": event.id,
                "event_type": event.event_type
            })
            continue

        # Check if this event is already mapped
        existing_mapping = db.query(EventTechniqueMapping).filter(
            EventTechniqueMapping.event_id == event.id
        ).first()

        if existing_mapping:
            already_mapped.append({
                "event_id": event.id,
                "technique_id": existing_mapping.technique_id,
                "technique_name": existing_mapping.technique_name
            })
            continue

        # Create new MITRE mapping
        new_mapping = EventTechniqueMapping(
            event_id=event.id,
            technique_id=mapping["technique_id"],
            technique_name=mapping["technique_name"],
            description=mapping["description"]
        )

        db.add(new_mapping)

        newly_mapped.append({
            "event_id": event.id,
            "event_type": event.event_type,
            "technique_id": mapping["technique_id"],
            "technique_name": mapping["technique_name"]
        })

    # Save all new mappings
    db.commit()

    return {
        "message": "MITRE ATT&CK mapping completed for Incident #1",
        "incident_id": 1,
        "newly_mapped": newly_mapped,
        "already_mapped": already_mapped,
        "no_mapping_available": no_mapping,
        "total_events": len(links),
        "total_new_mappings": len(newly_mapped)
    }

@app.get("/incidents/1/techniques")
def get_incident_techniques(
    db: Session = Depends(get_db)
):
    # Check whether Incident #1 exists
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Get all events linked to Incident #1
    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    # Dictionary used to group duplicate techniques
    technique_groups = {}

    # Process each linked event
    for link in links:

        mappings = db.query(EventTechniqueMapping).filter(
            EventTechniqueMapping.event_id == link.event_id
        ).all()

        for mapping in mappings:

            # Create a unique key using technique ID
            technique_id = mapping.technique_id

            if technique_id not in technique_groups:

                technique_groups[technique_id] = {
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name,
                    "description": mapping.description,
                    "event_ids": []
                }

            # Add the event ID
            technique_groups[technique_id]["event_ids"].append(
                mapping.event_id
            )

    # Convert dictionary to list
    techniques = list(technique_groups.values())

    # Add occurrence count
    for technique in techniques:
        technique["event_count"] = len(
            technique["event_ids"]
        )

    return {
        "incident_id": 1,
        "total_unique_techniques": len(techniques),
        "techniques": techniques
    }

@app.post("/incidents/1/calculate-risk")
def calculate_incident_risk(
    db: Session = Depends(get_db)
):
    # Get Incident #1
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Get events linked to Incident #1
    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    if not links:
        return {
            "message": "No security events linked to Incident #1"
        }

    # Get actual security events
    events = []

    for link in links:
        event = db.query(SecurityEvent).filter(
            SecurityEvent.id == link.event_id
        ).first()

        if event:
            events.append(event)

    # --------------------------------------------------
    # Weighted Risk Model - 0 to 100
    # --------------------------------------------------

    risk_factors = []

    ASSET_WEIGHT = 0.25
    BEHAVIOR_WEIGHT = 0.25
    MITRE_WEIGHT = 0.20
    THREAT_INTEL_WEIGHT = 0.15
    VULNERABILITY_WEIGHT = 0.15

    # --------------------------------------------------
    # Factor 1: Asset Criticality
    # --------------------------------------------------

    asset_score = 0

    if incident.asset_id:
        asset = db.query(Asset).filter(
            Asset.id == incident.asset_id
        ).first()

        if asset:
            criticality_scores = {
                "Low": 25,
                "Medium": 50,
                "High": 75,
                "Critical": 100
            }

            asset_score = criticality_scores.get(
                asset.criticality,
                50
            )

            asset_weighted_score = (
                asset_score * ASSET_WEIGHT
            )

            risk_factors.append({
                "factor": "Asset criticality",
                "points": asset_score,
                "weighted_points": asset_weighted_score,
                "details": (
                    f"Affected asset '{asset.asset_name}' has "
                    f"{asset.criticality} criticality. "
                    f"Weighted contribution: "
                    f"{asset_score}/100 × 25% = "
                    f"{asset_weighted_score}"
                )
            })

    # --------------------------------------------------
    # Factor 2: Behavioral Evidence
    # --------------------------------------------------

    behavior_score = 0
    behavior_factors = []

    # Event severity
    high_severity_count = sum(
        1 for event in events
        if event.severity == "High"
    )

    medium_severity_count = sum(
        1 for event in events
        if event.severity == "Medium"
    )

    if high_severity_count > 0:
        points = min(
            high_severity_count * 20,
            40
        )

        behavior_score += points

        behavior_factors.append({
            "factor": "High severity events",
            "points": points,
            "details": (
                f"{high_severity_count} high severity "
                f"event(s)"
            )
        })

    if medium_severity_count > 0:
        points = min(
            medium_severity_count * 5,
            20
        )

        behavior_score += points

        behavior_factors.append({
            "factor": "Medium severity events",
            "points": points,
            "details": (
                f"{medium_severity_count} medium severity "
                f"event(s)"
            )
        })

    # Failed logins
    failed_login_count = sum(
        1 for event in events
        if event.event_type == "Failed Login"
    )

    if failed_login_count >= 3:
        points = 15
        behavior_score += points

        behavior_factors.append({
            "factor": "Multiple failed login attempts",
            "points": points,
            "details": (
                f"{failed_login_count} failed login "
                f"attempts detected"
            )
        })

    # Successful login
    successful_login_exists = any(
        event.event_type == "Successful Login"
        for event in events
    )

    if successful_login_exists:
        points = 15
        behavior_score += points

        behavior_factors.append({
            "factor": (
                "Successful login after suspicious "
                "authentication activity"
            ),
            "points": points,
            "details": (
                "Successful login detected in the "
                "incident timeline"
            )
        })

    # PowerShell
    powershell_exists = any(
        event.event_type == "PowerShell Execution"
        for event in events
    )

    if powershell_exists:
        points = 20
        behavior_score += points

        behavior_factors.append({
            "factor": "PowerShell execution",
            "points": points,
            "details": (
                "PowerShell execution detected"
            )
        })

    # Suspicious network connection
    network_connection_exists = any(
        event.event_type == "Suspicious Network Connection"
        for event in events
    )

    if network_connection_exists:
        points = 20
        behavior_score += points

        behavior_factors.append({
            "factor": "Suspicious network connection",
            "points": points,
            "details": (
                "Suspicious outbound network "
                "connection detected"
            )
        })

    behavior_score = min(
        behavior_score,
        100
    )

    risk_factors.extend(
        behavior_factors
    )

    # --------------------------------------------------
    # Factor 3: MITRE ATT&CK Context
    # --------------------------------------------------

    technique_ids = set()

    for event in events:

        mappings = db.query(
            EventTechniqueMapping
        ).filter(
            EventTechniqueMapping.event_id == event.id
        ).all()

        for mapping in mappings:
            technique_ids.add(
                mapping.technique_id
            )

    unique_technique_count = len(
        technique_ids
    )

    if unique_technique_count == 0:
        mitre_score = 0

    elif unique_technique_count == 1:
        mitre_score = 25

    elif unique_technique_count == 2:
        mitre_score = 50

    elif unique_technique_count == 3:
        mitre_score = 75

    else:
        mitre_score = 100

    risk_factors.append({
        "factor": "MITRE ATT&CK context",
        "points": mitre_score,
        "weighted_points": (
            mitre_score * MITRE_WEIGHT
        ),
        "details": (
            f"{unique_technique_count} unique "
            f"MITRE ATT&CK technique(s) identified"
        )
    })

    # --------------------------------------------------
    # Factor 4: Threat Intelligence / IOC Context
    # --------------------------------------------------

    threat_intel_score = 0

    suspicious_indicators = []

    for event in events:

        if event.destination_ip:
            suspicious_indicators.append(
                event.destination_ip
            )

    if suspicious_indicators:

        threat_intel_score = 50

        risk_factors.append({
            "factor": (
                "Threat intelligence / IOC context"
            ),
            "points": threat_intel_score,
            "weighted_points": (
                threat_intel_score *
                THREAT_INTEL_WEIGHT
            ),
            "details": (
                f"{len(suspicious_indicators)} "
                f"destination IP indicator(s) observed; "
                f"external threat-intelligence validation "
                f"is required"
            )
        })

    # --------------------------------------------------
    # Factor 5: Vulnerability Context
    # --------------------------------------------------

    vulnerability_score = 0

    high_vulnerability_count = sum(
        1 for event in events
        if event.severity == "High"
    )

    if high_vulnerability_count >= 3:
        vulnerability_score = 100

    elif high_vulnerability_count == 2:
        vulnerability_score = 75

    elif high_vulnerability_count == 1:
        vulnerability_score = 50

    else:
        vulnerability_score = 0

    if vulnerability_score > 0:

        risk_factors.append({
    "factor": "High-severity security event context",
    "points": vulnerability_score,
    "weighted_points": (
        vulnerability_score *
        VULNERABILITY_WEIGHT
    ),
    "details": (
        f"{high_vulnerability_count} "
        f"high-severity security event(s) "
        f"identified"
    )
})

    # --------------------------------------------------
    # Calculate Final Weighted Risk Score
    # --------------------------------------------------

    weighted_risk_score = (
        (asset_score * ASSET_WEIGHT)
        + (behavior_score * BEHAVIOR_WEIGHT)
        + (mitre_score * MITRE_WEIGHT)
        + (
            threat_intel_score *
            THREAT_INTEL_WEIGHT
        )
        + (
            vulnerability_score *
            VULNERABILITY_WEIGHT
        )
    )

    # --------------------------------------------------
    # Determine Priority
    # --------------------------------------------------

    if weighted_risk_score >= 75:
        priority = "Critical"

    elif weighted_risk_score >= 50:
        priority = "High"

    elif weighted_risk_score >= 25:
        priority = "Medium"

    else:
        priority = "Low"

    # --------------------------------------------------
    # Save Result
    # --------------------------------------------------

    incident.risk_score = round(
        weighted_risk_score
    )

    incident.priority = priority

    db.commit()
    db.refresh(incident)

    return {
        "message": (
            "Incident risk calculation completed"
        ),
        "incident_id": incident.id,
        "risk_score": incident.risk_score,
        "weighted_risk_score": round(
            weighted_risk_score,
            2
        ),
        "priority": incident.priority,
        "risk_factors": risk_factors,
        "unique_mitre_techniques": (
            unique_technique_count
        ),
        "total_events": len(events)
    }

@app.post("/assets")
def create_asset(
    asset_name: str,
    asset_type: str,
    criticality: str = "Medium",
    owner: str = None,
    environment: str = None,
    db: Session = Depends(get_db)
):
    existing_asset = db.query(Asset).filter(
        Asset.asset_name == asset_name
    ).first()

    if existing_asset:
        return {
            "message": "Asset already exists",
            "asset_id": existing_asset.id
        }

    asset = Asset(
        asset_name=asset_name,
        asset_type=asset_type,
        criticality=criticality,
        owner=owner,
        environment=environment
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    return {
        "message": "Asset created successfully",
        "asset_id": asset.id,
        "asset_name": asset.asset_name,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "environment": asset.environment
    }

@app.get("/assets")
def get_assets(
    db: Session = Depends(get_db)
):
    assets = db.query(Asset).all()

    return [
        {
            "id": asset.id,
            "asset_name": asset.asset_name,
            "asset_type": asset.asset_type,
            "criticality": asset.criticality,
            "owner": asset.owner,
            "environment": asset.environment
        }
        for asset in assets
    ]
@app.put("/incidents/1/asset")
def assign_asset_to_incident(
    asset_id: int,
    db: Session = Depends(get_db)
):
    # Find Incident #1
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Find the asset
    asset = db.query(Asset).filter(
        Asset.id == asset_id
    ).first()

    if not asset:
        return {
            "message": f"Asset #{asset_id} not found"
        }

    # Assign asset to incident
    incident.asset_id = asset.id

    db.commit()
    db.refresh(incident)

    return {
        "message": "Asset assigned to incident successfully",
        "incident_id": incident.id,
        "asset_id": asset.id,
        "asset_name": asset.asset_name,
        "asset_type": asset.asset_type,
        "criticality": asset.criticality,
        "owner": asset.owner,
        "environment": asset.environment
    }

@app.get("/incidents/1/analyst-summary")
def analyst_summary(
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    events = []

    for link in links:
        event = db.query(SecurityEvent).filter(
            SecurityEvent.id == link.event_id
        ).first()

        if event:
            events.append(event)

    # -----------------------------
    # Build observations
    # -----------------------------

    observations = []
    recommendations = []

    failed_logins = sum(
        1 for event in events
        if event.event_type == "Failed Login"
    )

    if failed_logins >= 3:
        observations.append(
            f"{failed_logins} failed login attempts were detected."
        )

        recommendations.append(
            "Investigate the source IP for possible brute-force activity."
        )

    successful_login = any(
        event.event_type == "Successful Login"
        for event in events
    )

    if successful_login and failed_logins >= 3:
        observations.append(
            "A successful login occurred after multiple failed login attempts."
        )

        recommendations.append(
            "Verify whether the successful login was legitimate and review account activity."
        )

    powershell = any(
        event.event_type == "PowerShell Execution"
        for event in events
    )

    if powershell:
        observations.append(
            "PowerShell execution was detected during the incident."
        )

        recommendations.append(
            "Review PowerShell commands and process execution for malicious activity."
        )

    network_activity = any(
        event.event_type == "Suspicious Network Connection"
        for event in events
    )

    if network_activity:
        observations.append(
            "Suspicious outbound network activity was detected."
        )

        recommendations.append(
            "Investigate the destination IP using threat-intelligence sources."
        )

    # -----------------------------
    # MITRE techniques
    # -----------------------------

    techniques = []

    for event in events:
        mappings = db.query(
            EventTechniqueMapping
        ).filter(
            EventTechniqueMapping.event_id == event.id
        ).all()

        for mapping in mappings:
            if mapping.technique_id not in [
                technique["technique_id"]
                for technique in techniques
            ]:
                techniques.append({
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name
                })

    # -----------------------------
    # Final analyst summary
    # -----------------------------

    if incident.priority == "Critical":
        priority_reason = (
            "The incident contains multiple correlated security events, "
            "authentication anomalies, PowerShell execution, suspicious "
            "network activity, and multiple MITRE ATT&CK techniques."
        )
    elif incident.priority == "High":
        priority_reason = (
            "The incident contains significant security activity "
            "requiring analyst investigation."
        )
    else:
        priority_reason = (
            "The incident currently has limited evidence of high-impact activity."
        )

    return {
        "incident_id": incident.id,
        "priority": incident.priority,
        "risk_score": incident.risk_score,
        "priority_reason": priority_reason,
        "observations": observations,
        "recommended_actions": recommendations,
        "mitre_techniques": techniques,
        "total_events": len(events)
    }

@app.get("/incidents/1/investigation")
def incident_investigation(
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    # Get assigned asset
    asset = None

    if incident.asset_id:
        asset = db.query(Asset).filter(
            Asset.id == incident.asset_id
        ).first()

    # Get linked events
    links = db.query(IncidentEvent).filter(
        IncidentEvent.incident_id == 1
    ).all()

    events = []

    for link in links:
        event = db.query(SecurityEvent).filter(
            SecurityEvent.id == link.event_id
        ).first()

        if event:
            events.append(event)

    # Sort events chronologically
    events.sort(
        key=lambda event: event.timestamp
    )

    # Get MITRE techniques
    techniques = []

    for event in events:
        mappings = db.query(
            EventTechniqueMapping
        ).filter(
            EventTechniqueMapping.event_id == event.id
        ).all()

        for mapping in mappings:
            if mapping.technique_id not in [
                technique["technique_id"]
                for technique in techniques
            ]:
                techniques.append({
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name
                })

    return {
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "username": incident.username,
            "hostname": incident.hostname,
            "source_ip": incident.source_ip
        },

        "asset": (
            {
                "id": asset.id,
                "name": asset.asset_name,
                "type": asset.asset_type,
                "criticality": asset.criticality,
                "owner": asset.owner,
                "environment": asset.environment
            }
            if asset else None
        ),

        "risk": {
            "score": incident.risk_score,
            "priority": incident.priority
        },

        "escalation": {
    "status": incident.escalation_status
},

        "timeline": [
            {
                "event_id": event.id,
                "timestamp": event.timestamp,
                "event_type": event.event_type,
                "source": event.source,
                "username": event.username,
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "hostname": event.hostname,
                "severity": event.severity
            }
            for event in events
        ],

        "mitre_attack": techniques,

        "summary": {
            "total_events": len(events),
            "unique_mitre_techniques": len(techniques)
        },
        "analyst_notes": incident.analyst_notes
    }

@app.put("/incidents/1/status")
def update_incident_status(
    status: str,
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    if status not in allowed_statuses:
        return {
            "message": "Invalid status",
            "allowed_statuses": allowed_statuses
        }

    # Store the previous status
    old_status = incident.status

    if old_status == status:
     return {
        "message": "Incident is already in this status",
        "incident_id": incident.id,
        "status": incident.status
    }

    # Update incident status
    incident.status = status

    # Create audit record
    audit = IncidentAudit(
        incident_id=incident.id,
        action="Status Changed",
        old_value=old_status,
        new_value=status,
        performed_by="SOC Analyst"
    )

    db.add(audit)

    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident status updated successfully",
        "incident_id": incident.id,
        "old_status": old_status,
        "status": incident.status
    }
@app.put("/incidents/1/notes")
def update_incident_notes(
    notes: str,
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {"message": "Incident #1 not found"}

    incident.analyst_notes = notes

    db.commit()
    db.refresh(incident)

    return {
        "message": "Analyst notes saved successfully",
        "incident_id": incident.id,
        "analyst_notes": incident.analyst_notes
    }

@app.put("/incidents/1/escalate")
def escalate_incident(
    db: Session = Depends(get_db)
):
    incident = db.query(Incident).filter(
        Incident.id == 1
    ).first()

    if not incident:
        return {
            "message": "Incident #1 not found"
        }

    incident.escalation_status = "Escalated"

    audit = IncidentAudit(
    incident_id=incident.id,
    action="Incident Escalated",
    old_value="Not Escalated",
    new_value="Escalated",
    performed_by="SOC Analyst"
)

    db.add(audit)

    db.commit()
    db.refresh(incident)

    return {
        "message": "Incident escalated successfully",
        "incident_id": incident.id,
        "escalation_status": incident.escalation_status
    }

@app.get("/incidents/1/audit")
def get_incident_audit(
    db: Session = Depends(get_db)
):
    audits = db.query(IncidentAudit).filter(
        IncidentAudit.incident_id == 1
    ).order_by(
        IncidentAudit.created_at.desc()
    ).all()

    return [
        {
            "id": audit.id,
            "incident_id": audit.incident_id,
            "action": audit.action,
            "old_value": audit.old_value,
            "new_value": audit.new_value,
            "performed_by": audit.performed_by,
            "created_at": audit.created_at
        }
        for audit in audits
    ]
