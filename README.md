\# SOC Investigation \& Incident Prioritization Platform



A SOC analyst-assistance platform designed to correlate security events, reconstruct incident timelines, map activities to MITRE ATT\&CK techniques, calculate contextual risk, and support investigation and response activities.



The platform provides a centralized view of an incident so that a SOC analyst can understand what happened, why the incident is risky, and what actions should be investigated.



\---



\## Project Overview



Security Operations Centers generate large amounts of security events and alerts. Investigating these events individually can make it difficult to understand the complete attack sequence.



This project addresses that problem by providing an investigation workflow that:



\- Correlates related security events into an incident

\- Reconstructs a chronological investigation timeline

\- Associates incidents with affected assets

\- Maps security events to MITRE ATT\&CK techniques

\- Calculates a contextual risk score

\- Assigns an incident priority

\- Generates analyst-oriented observations and recommended actions

\- Maintains analyst notes

\- Supports incident escalation

\- Tracks incident status changes through audit history

\- Provides a web-based SOC investigation dashboard



\---



\## Key Features



\### 1. Security Event Correlation



Related security events can be associated with an incident to provide a unified investigation view.



Example investigation sequence:



```text

Failed Login

&#x20;     ↓

Failed Login

&#x20;     ↓

Failed Login

&#x20;     ↓

Successful Login

&#x20;     ↓

PowerShell Execution

&#x20;     ↓

Suspicious Network Connection

2\. Incident Timeline



Correlated events are displayed chronologically to reconstruct the sequence of activity.



The timeline includes:



Timestamp

Event type

Source

Username

Source IP

Destination IP

Hostname

Severity

3\. Asset Context



An incident can be associated with an affected asset to provide additional investigation context.



Example:



Asset Name:     WORKSTATION-01

Asset Type:     Workstation

Criticality:    Medium

Owner:          IT Department

Environment:    Internal



Asset context contributes to the incident risk assessment.



4\. MITRE ATT\&CK Mapping



Security events are mapped to MITRE ATT\&CK techniques to help analysts understand the behavior associated with an incident.



Current demonstration mappings include:



Technique ID	Technique

T1110	Brute Force

T1078	Valid Accounts

T1059.001	PowerShell

T1071	Application Layer Protocol

5\. Contextual Risk Scoring



The platform calculates a weighted risk score using multiple contextual factors.



Risk Factor	Weight

Asset Context	25%

Behaviour Analysis	25%

MITRE ATT\&CK Context	20%

Threat Intelligence Context	15%

High-Severity Event Context	15%



The weighted result is converted into a risk score from 0–100.



Priority Thresholds

75–100  → Critical

50–74   → High

25–49   → Medium

0–24    → Low

Demonstration Result



The current demonstration incident produced:



Risk Score: 76 / 100

Priority:   Critical



Example factor contribution:



Asset Context               → 12.50

Behaviour Analysis          → 25.00

MITRE ATT\&CK Context        → 20.00

Threat Intelligence Context →  7.50

High-Severity Events        → 11.25

\------------------------------------

Weighted Total              → 76.25

Persisted Risk Score        → 76

Priority                    → Critical



The score is intended to provide contextual prioritization rather than relying only on the severity of an individual event.



6\. Analyst Assessment



The platform generates an analyst-oriented assessment containing:



Priority reason

Key observations

Recommended investigation actions

MITRE ATT\&CK techniques

Total correlated events



Example observations from the demonstration incident:



3 failed login attempts were detected.



A successful login occurred after multiple failed login attempts.



PowerShell execution was detected during the incident.



Suspicious outbound network activity was detected.



Example recommended actions include:



Investigate the source IP for possible brute-force activity.



Verify whether the successful login was legitimate and review account activity.



Review PowerShell commands and process execution for malicious activity.



Investigate the destination IP using threat-intelligence sources.

7\. Incident Response



The dashboard supports basic incident response actions:



Mark incident as Investigating

Mark incident as Resolved

Escalate incident

Add analyst notes

8\. Analyst Notes



SOC analysts can record investigation findings directly from the dashboard.



Example:



Reviewed authentication activity. Three failed login attempts were

followed by a successful login from the same source IP. PowerShell

execution and suspicious outbound network activity were subsequently

detected on WORKSTATION-01. Further investigation of account activity,

PowerShell execution, and destination IP is recommended.

9\. Audit History



Incident response actions are recorded in an audit history.



Each audit record contains:



Action

Previous value

New value

Performed by

Timestamp



Example:



Status Changed

Investigating → Resolved

Performed by: SOC Analyst



This provides traceability of analyst actions during an investigation.



Architecture

&#x20;                   SOC Investigation Dashboard

&#x20;                             │

&#x20;                             ▼

&#x20;                        FastAPI API

&#x20;                             │

&#x20;         ┌───────────────────┼───────────────────┐

&#x20;         │                   │                   │

&#x20;         ▼                   ▼                   ▼

&#x20;   Event Correlation    Risk Assessment    Analyst Assessment

&#x20;         │                   │                   │

&#x20;         ▼                   ▼                   ▼

&#x20;    Incident Data       Risk Factors       Investigation

&#x20;         │                   │                   │

&#x20;         └───────────────────┼───────────────────┘

&#x20;                             ▼

&#x20;                      MITRE ATT\&CK Mapping

&#x20;                             │

&#x20;                             ▼

&#x20;                      SQLite Database

Investigation Workflow

Security Events

&#x20;     │

&#x20;     ▼

Event Correlation

&#x20;     │

&#x20;     ▼

Incident Creation

&#x20;     │

&#x20;     ▼

Asset Association

&#x20;     │

&#x20;     ▼

Timeline Reconstruction

&#x20;     │

&#x20;     ▼

MITRE ATT\&CK Mapping

&#x20;     │

&#x20;     ▼

Contextual Risk Calculation

&#x20;     │

&#x20;     ▼

Priority Assignment

&#x20;     │

&#x20;     ▼

Analyst Assessment

&#x20;     │

&#x20;     ▼

Investigation / Escalation

&#x20;     │

&#x20;     ▼

Audit History

Technology Stack

Backend

Python

FastAPI

Uvicorn

SQLAlchemy

Pydantic

Database

SQLite

Frontend

HTML

CSS

JavaScript

Security Framework

MITRE ATT\&CK

Project Structure

SOC\_Investigation\_platform/

│

├── app/

│   ├── database.py

│   ├── main.py

│   ├── models.py

│   └── schemas.py

│

├── data/

│   └── soc.db

│

├── tests/

│

├── docs/

│   └── screenshots/

│       ├── dashboard-overview.png

│       ├── incident-timeline-part1.png

│       ├── incident-timeline-part2.png

│       ├── analyst-assessment.png

│       ├── incident-response.png

│       └── audit-history.png

│

├── dashboard.html

│

├── add\_assets.py

├── add\_analyst\_notes.py

├── add\_escalation\_status.py

├── add\_incident\_audit.py

├── add\_risk\_fields.py

├── check\_audit.py

│

├── requirements.txt

├── README.md

└── .gitignore



The local SQLite database and Python virtual environment are excluded from Git using .gitignore.



Installation

1\. Clone the Repository

git clone <YOUR-GITHUB-REPOSITORY-URL>

cd SOC\_Investigation\_platform

2\. Create a Virtual Environment

python -m venv venv

3\. Activate the Virtual Environment

Windows PowerShell

.\\venv\\Scripts\\Activate.ps1

Linux / macOS

source venv/bin/activate

4\. Install Dependencies

pip install -r requirements.txt

Running the Application



Start the FastAPI server:



uvicorn app.main:app --reload



The application will be available at:



http://127.0.0.1:8000

API Documentation



Open:



http://127.0.0.1:8000/docs

SOC Dashboard



Open:



http://127.0.0.1:8000/dashboard

API Endpoints



The following investigation and response endpoints have been verified in the current implementation:



Method	Endpoint	Purpose

GET	/incidents/1/investigation	Retrieve the complete investigation view

GET	/incidents/1/analyst-summary	Retrieve analyst assessment

PUT	/incidents/1/asset	Associate an asset with the incident

PUT	/incidents/1/status	Update incident status

PUT	/incidents/1/escalate	Escalate the incident

PUT	/incidents/1/notes	Save analyst notes

GET	/incidents/1/audit	Retrieve incident audit history



Additional event and incident functionality is implemented in the FastAPI application and can be explored through Swagger UI.



Swagger API Documentation

http://127.0.0.1:8000/docs

Demonstration Incident



The project includes a simulated investigation scenario involving a possible account compromise.



Incident

Title:

Possible Account Compromise

Description

Multiple failed login attempts were followed by a successful login

and suspicious activity on the same workstation.

Investigation Context

Username:       admin

Hostname:       WORKSTATION-01

Source IP:      192.168.1.50

Severity:       High



Risk Score:     76 / 100

Priority:       Critical

Status:         Resolved

Escalation:     Escalated

Correlated Events

1\. Failed Login

2\. Failed Login

3\. Failed Login

4\. Successful Login

5\. PowerShell Execution

6\. Suspicious Network Connection

MITRE ATT\&CK Techniques

T1110       Brute Force

T1078       Valid Accounts

T1059.001   PowerShell

T1071       Application Layer Protocol

Screenshots



The following screenshots demonstrate the working SOC investigation dashboard.



Dashboard Overview



Incident Timeline — Part 1



Incident Timeline — Part 2



Analyst Assessment



Incident Response



Audit History



Demo Flow



A project demonstration can be performed using the following sequence.



1\. Open the Dashboard



Open:



http://127.0.0.1:8000/dashboard



Explain that the dashboard provides a centralized view of the security investigation.



2\. Explain the Incident



Show:



Possible Account Compromise

Incident #1



Explain that multiple related security events have been associated with the incident.



3\. Show the Investigation Timeline



Walk through the sequence:



Failed Login

&#x20;      ↓

Failed Login

&#x20;      ↓

Failed Login

&#x20;      ↓

Successful Login

&#x20;      ↓

PowerShell Execution

&#x20;      ↓

Suspicious Network Connection



Explain how the timeline helps reconstruct the sequence of activity.



4\. Show Asset Context



Explain the affected asset:



WORKSTATION-01

Workstation

Medium Criticality

IT Department

Internal Environment

5\. Explain MITRE ATT\&CK Mapping



Show the four techniques:



T1110       Brute Force

T1078       Valid Accounts

T1059.001   PowerShell

T1071       Application Layer Protocol



Explain that the mapping provides additional behavioral context for the investigation.



6\. Explain Risk Scoring



Show:



Risk Score: 76 / 100

Priority: Critical



Explain that the risk score combines multiple contextual factors including:



Asset context

Behaviour analysis

MITRE ATT\&CK context

Threat intelligence context

High-severity event context

7\. Show Analyst Assessment



Demonstrate:



Why the incident received its priority

Key observations

Recommended investigation actions

MITRE ATT\&CK techniques

8\. Demonstrate Incident Response



Use the dashboard controls:



Mark as Investigating

Mark as Resolved

Escalate Incident

9\. Add Analyst Notes



Enter investigation notes into the Analyst Notes section and save them.



Explain that the notes remain associated with the incident for future investigation reference.



10\. Show Audit History



Open the Incident Audit History section.



Demonstrate that response actions are recorded with:



Action

Old Value

New Value

Performed By

Timestamp



This completes the investigation and response workflow.



Project Objective



The objective of this project is to demonstrate how security events can be transformed into a structured SOC investigation workflow.



Instead of simply displaying alerts, the platform provides additional context through:



Event Correlation

&#x20;     +

Timeline Reconstruction

&#x20;     +

Asset Context

&#x20;     +

MITRE ATT\&CK Mapping

&#x20;     +

Risk Prioritization

&#x20;     +

Analyst Assessment

&#x20;     +

Response Tracking

&#x20;     +

Audit History



The overall goal is to support a SOC analyst in understanding an incident, prioritizing its risk, and documenting investigation and response activities.



Future Enhancements



Possible future improvements include:



Multi-incident dashboard

Authentication and role-based access control

Real-time event ingestion

SIEM integration

Automated threat-intelligence enrichment

Advanced attack-chain detection

Automated alert deduplication

Email and notification integration

PostgreSQL support

Production deployment

Automated testing

CI/CD integration

Disclaimer



This project is developed for educational, cybersecurity training, and demonstration purposes.



The demonstration events and incident data are simulated and should not be interpreted as real security incidents.



Author



Shweta Tambe



Cybersecurity | VAPT | SOC | GRC

