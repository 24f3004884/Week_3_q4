from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Text

from app.database import Base

class Run(Base):

    __tablename__ = "runs"

    run_id = Column(
        String,
        primary_key=True
    )

    state_json = Column(Text)