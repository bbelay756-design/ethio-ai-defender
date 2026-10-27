from app.db.session import SessionLocal, init_db
from sqlalchemy import text

init_db()
db = SessionLocal()
result = db.execute(text("SELECT id, name, namespace, version, is_active FROM yara_rules")).fetchall()
for row in result:
    print(f"id={row[0]}, name={row[1]}, ns={row[2]}, v={row[3]}, active={row[4]}")