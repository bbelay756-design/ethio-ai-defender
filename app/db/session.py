"""
Database Session and Engine Configuration Module

Configures SQLite database connection using SQLAlchemy 2.0.
Enforces SQLite foreign key constraints via event listener.
"""

from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings
from app.core.logger import logger

# Connect arguments for SQLite (check_same_thread=False for multi-threaded FastAPI)
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    future=True
)

# Enforce SQLite foreign key constraints
if settings.DATABASE_URL.startswith("sqlite"):
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Session factory
SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False
)

# Declarative Base
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that provides a transactional database session.
    Automatically commits on success or rolls back on unhandled exceptions.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """
    Initializes database tables and applies lightweight schema migrations.
    """
    import app.db.models  # Ensure all model classes are imported
    Base.metadata.create_all(bind=engine)

    # Lightweight migration check for newly added columns in SQLite
    if settings.DATABASE_URL.startswith("sqlite"):
        with engine.connect() as conn:
            cursor = conn.connection.cursor()
            cursor.execute("PRAGMA table_info(samples)")
            cols = [row[1] for row in cursor.fetchall()]
            if cols:
                if "user_id" not in cols:
                    cursor.execute("ALTER TABLE samples ADD COLUMN user_id INTEGER REFERENCES users(id)")
                if "sha1" not in cols:
                    cursor.execute("ALTER TABLE samples ADD COLUMN sha1 VARCHAR(40)")
                if "risk_score" not in cols:
                    cursor.execute("ALTER TABLE samples ADD COLUMN risk_score INTEGER DEFAULT 0")
                if "classification" not in cols:
                    cursor.execute("ALTER TABLE samples ADD COLUMN classification VARCHAR(32) DEFAULT 'LOW'")
                if "completed_at" not in cols:
                    cursor.execute("ALTER TABLE samples ADD COLUMN completed_at DATETIME")
                conn.connection.commit()

            cursor.execute("PRAGMA table_info(strings)")
            str_cols = [row[1] for row in cursor.fetchall()]
            if str_cols:
                if "encoding" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN encoding VARCHAR(16) DEFAULT 'ASCII'")
                if "offset" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN offset INTEGER")
                if "category" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN category VARCHAR(64) DEFAULT 'GENERAL'")
                if "suspicious" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN suspicious BOOLEAN DEFAULT 0")
                if "severity" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN severity VARCHAR(32) DEFAULT 'LOW'")
                if "confidence" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN confidence FLOAT DEFAULT 1.0")
                if "reason" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN reason TEXT")
                if "mitre_technique" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN mitre_technique VARCHAR(255)")
                if "created_at" not in str_cols:
                    cursor.execute("ALTER TABLE strings ADD COLUMN created_at DATETIME")
                conn.connection.commit()
            cursor.close()

    logger.info("Database tables initialized successfully.")
