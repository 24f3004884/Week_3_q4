from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
import os

os.makedirs("data", exist_ok=True)

DATABASE_URL = "sqlite:///data/incident.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={
        "check_same_thread": False
    }
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False
)

Base = declarative_base()