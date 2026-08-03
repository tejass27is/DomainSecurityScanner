import os
from sqlalchemy import create_engine
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
    echo=True,
    pool_pre_ping=True,
    execution_options={"no_cache": True}
)

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
    except Exception:
        db.rollback()
        raise
    finally:
        db.rollback()
        db.close()
