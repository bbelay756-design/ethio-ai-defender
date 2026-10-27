from app.db.session import SessionLocal, init_db
from sqlalchemy import inspect

init_db()
db = SessionLocal()
inspector = inspect(db.bind)
tables = inspector.get_table_names()
for t in sorted(tables):
    if 'yara' in t.lower() or 'risk' in t.lower() or 'ghidra' in t.lower():
        print(f'{t}:')
        cols = inspector.get_columns(t)
        for c in cols:
            print(f'  {c["name"]}: {c["type"]}')
        indexes = inspector.get_indexes(t)
        for idx in indexes:
            print(f'  Index: {idx["name"]} on {idx["column_names"]}')