"""SQLite persistence (WAL + foreign keys), mirroring the robust setup used
in sibling projects: the DB lives on a bind-mounted host directory so it
survives container rebuilds, and a snapshot is taken before schema work.
"""
from __future__ import annotations

import shutil
from datetime import datetime

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from . import config

config.DATA_DIR.mkdir(parents=True, exist_ok=True)
config.SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)

engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    connect_args={"check_same_thread": False},
    future=True,
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA journal_mode=WAL")
    cur.execute("PRAGMA foreign_keys=ON")
    cur.execute("PRAGMA synchronous=NORMAL")
    cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, future=True)
Base = declarative_base()


def snapshot(tag: str = "startup") -> None:
    """Copy the DB file before structural changes; keep the most recent 20."""
    if not config.DB_PATH.exists():
        return
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dst = config.SNAPSHOT_DIR / f"dagger-{ts}-{tag}.db"
    try:
        shutil.copy2(config.DB_PATH, dst)
    except OSError:
        return
    snaps = sorted(config.SNAPSHOT_DIR.glob("dagger-*.db"))
    for old in snaps[:-20]:
        old.unlink(missing_ok=True)


def init_db() -> None:
    from . import models  # noqa: F401  (register mappers)
    snapshot("startup")
    Base.metadata.create_all(engine)


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
