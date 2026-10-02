import sqlite3


DB_PATH = "data/soc.db"

db = sqlite3.connect(DB_PATH)


# --------------------------------------------------
# 1. Create assets table
# --------------------------------------------------

db.execute("""
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY,
    asset_name TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL,
    criticality TEXT DEFAULT 'Medium',
    owner TEXT,
    environment TEXT
)
""")


# --------------------------------------------------
# 2. Add asset_id to incidents table
# --------------------------------------------------

columns = db.execute(
    "PRAGMA table_info(incidents)"
).fetchall()

column_names = [column[1] for column in columns]


if "asset_id" not in column_names:
    db.execute("""
    ALTER TABLE incidents
    ADD COLUMN asset_id INTEGER
    """)

    print("asset_id column added to incidents table")
else:
    print("asset_id column already exists")


db.commit()
db.close()


print("Asset migration completed successfully")