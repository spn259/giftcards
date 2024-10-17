
from collections import OrderedDict

from sqlalchemy import (
    Column, Integer, String, Text, Boolean, ForeignKey,BigInteger, DateTime, func, text, ARRAY, Float, Index, types,
)
from sqlalchemy.dialects import postgresql
from sqlalchemy.dialects.postgresql import JSON, JSONB, UUID, BIGINT, TEXT, NUMERIC
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, validates
from sqlalchemy.orm.query import Query
from sqlalchemy.schema import Table
from sqlalchemy.sql import functions
from sqlalchemy.sql.elements import ColumnClause
from sqlalchemy.sql.selectable import FromClause, Alias, Lateral

Base = declarative_base()


class Cards(Base):
    __tablename__ = "cards"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    uuid = Column(String, nullable=False)
    added = Column(DateTime, nullable=False)


class Transactions(Base):
    __tablename__ = "transactions"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    card_id = Column(String, nullable=False)
    transaction_type = Column(String, nullable=False)
    amount = Column(Float)
    added = Column(DateTime, nullable=False)



# User Model linked to the 'users' table in the database
class User(Base):
    __tablename__ = 'users'

    id =Column(Integer, primary_key=True)
    username = Column(String(255), unique=True, nullable=False)
    password = Column(String(255), nullable=False)