# backend/app/models/base.py
# app/models/base.py
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# Import all models here to ensure they're registered with SQLAlchemy
from .user import User  # noqa
from .network import NetworkEvent  # noqa
