from app.db.session import SessionLocal, init_db
from sqlalchemy import inspect

init_db()
db = SessionLocal()
inspector = inspect(db.bind)
tables = inspector.get_table_names()
for t in sorted(tables):
    print(f'{t}:')
    for c in inspector.get_columns(t):
        print(f'  {c["name"]}: {c["type"]}')