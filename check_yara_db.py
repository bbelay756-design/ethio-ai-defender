from app.db.session import SessionLocal
from sqlalchemy import text

db = SessionLocal()
result = db.execute(text('SELECT sql FROM sqlite_master WHERE type="table" AND name="yara_rules"')).fetchall()
for row in result:
    print(row[0])