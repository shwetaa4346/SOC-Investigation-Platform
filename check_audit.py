import sqlite3

conn = sqlite3.connect("data/soc.db")

cursor = conn.cursor()

cursor.execute("PRAGMA table_info(incident_audits)")

columns = cursor.fetchall()

print(columns)

conn.close()