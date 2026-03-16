"""
db/sqlite.py - SQLite engine creation and session management.

Uses SQLModel / SQLAlchemy under the hood.
Engine is created once at startup via init_engine().
get_session() is a FastAPI dependency that yields a Session per request.
"""

from __future__ import annotations

from pathlib import Path
from typing import Generator

from sqlalchemy import event
from sqlmodel import Session, SQLModel, create_engine

# Module-level engine; populated by init_engine()
_engine = None



def init_engine(db_path: str) -> None:
    """
    Initialize the global SQLite engine.
    Call once at application startup before any DB operations.
    """
    global _engine

    resolved_path = Path(db_path).expanduser().resolve()
    resolved_path.parent.mkdir(parents=True, exist_ok=True)

    connect_args = {"check_same_thread": False, "timeout": 5}
    _engine = create_engine(
        f"sqlite:///{resolved_path}",
        connect_args=connect_args,
        echo=False,
    )

    @event.listens_for(_engine, "connect")
    def _configure_sqlite(connection, _record):
        cursor = connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA busy_timeout=5000")
        cursor.close()



def get_engine():
    """Return the global engine. Raises RuntimeError if not initialized."""
    if _engine is None:
        raise RuntimeError("DB engine not initialized. Call init_engine() first.")
    return _engine



def create_tables() -> None:
    """Create all SQLModel tables. Safe to call multiple times (CREATE IF NOT EXISTS)."""
    SQLModel.metadata.create_all(get_engine())



def get_session() -> Generator[Session, None, None]:
    """
    FastAPI dependency: yields a database session per request.

    Usage:
        @router.post("/")
        def my_route(session: Session = Depends(get_session)): ...
    """
    with Session(get_engine()) as session:
        yield session
