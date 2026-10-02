import sqlite3

DB_PATH = "data/soc.db"

conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

try:
    cursor.execute("""
        ALTER TABLE incidents
        ADD COLUMN escalation_status TEXT DEFAULT 'Not Escalated'
    """)

    conn.commit()

    print("escalation_status column added successfully")
    print("Escalation status migration completed successfully")

except sqlite3.OperationalError as e:
    print("Migration error:", e)

finally:
    conn.close()
