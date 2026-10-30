import os
from contextvars import ContextVar
from time import perf_counter

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is not set")

# Engine (connection pool handled automatically)
# engine = create_engine(
#     DATABASE_URL,
#     echo=True,
#     pool_pre_ping=True,
#     connect_args={
#         "options": "-c statement_timeout=30000"
#     },
#     execution_options={
#         "no_cache": True,
#         # "stream_results": True,
#     }
# )

# SessionLocal = sessionmaker(
#     autocommit=False,
#     autoflush=False,
#     bind=engine,
#     expire_on_commit=True  # ✅ expire objects after commit
# )
# Base = declarative_base()

# def get_db():
#     db = SessionLocal()
#     try:
#         yield db
#     except Exception:
#         db.rollback()
#         raise
#     finally:
#         db.close()


engine = create_engine(
    DATABASE_URL,
    echo=os.getenv("SQLALCHEMY_ECHO", "false").strip().lower() in {"1", "true", "yes", "on"},
    pool_pre_ping=True,
    execution_options={"no_cache": True}
)

request_db_metrics: ContextVar[dict[str, float] | None] = ContextVar(
    "request_db_metrics",
    default=None,
)


@event.listens_for(engine, "before_cursor_execute")
def start_request_db_timer(_connection, _cursor, _statement, _parameters, context, _executemany):
    context.request_db_started_at = perf_counter()


@event.listens_for(engine, "after_cursor_execute")
def record_request_db_duration(_connection, _cursor, _statement, _parameters, context, _executemany):
    metrics = request_db_metrics.get()
    started_at = getattr(context, "request_db_started_at", None)
    if metrics is not None and started_at is not None:
        metrics["duration_ms"] += (perf_counter() - started_at) * 1000


SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=True
)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
