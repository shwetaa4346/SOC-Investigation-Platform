import sqlite3

DB_PATH = "data/soc.db"

db = sqlite3.connect(DB_PATH)

columns = db.execute(
    "PRAGMA table_info(incidents)"
).fetchall()

column_names = [column[1] for column in columns]

if "analyst_notes" not in column_names:

    db.execute(
        "ALTER TABLE incidents ADD COLUMN analyst_notes TEXT"
    )

    print("analyst_notes column added to incidents table")

else:

    print("analyst_notes column already exists")

db.commit()
db.close()

print("Analyst notes migration completed successfully")