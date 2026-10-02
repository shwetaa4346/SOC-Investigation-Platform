import sqlite3

db = sqlite3.connect("data/soc.db")

db.execute(
    "ALTER TABLE incidents ADD COLUMN risk_score INTEGER DEFAULT 0"
)

db.execute(
    "ALTER TABLE incidents ADD COLUMN priority TEXT DEFAULT 'Medium'"
)

db.commit()
db.close()

print("Risk fields added successfully")