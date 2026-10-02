import sqlite3

DB_PATH = "data/soc.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

try:
    cursor.execute("""
        CREATE TABLE incident_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT,
            performed_by TEXT NOT NULL DEFAULT 'SOC Analyst',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (incident_id) REFERENCES incidents(id)
        )
    """)

    conn.commit()

    print("incident_audits table created successfully")
    print("Incident audit migration completed successfully")

except sqlite3.OperationalError as e:
    print("Migration error:", e)

finally:
    conn.close()