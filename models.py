
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


from sqlalchemy import Column, Integer, String, Text, LargeBinary, DateTime
from sqlalchemy.ext.declarative import declarative_base
import datetime

Base = declarative_base()

class Photo(Base):
    __tablename__ = 'feedback'

    id = Column(Integer, primary_key=True)
    filename = Column(String(255))
    photo = Column(LargeBinary)  # Stores binary image data (BYTEA in PostgreSQL)
    feedback = Column(Text)
    added = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)

    def __repr__(self):
        return f"<Photo(id={self.id}, filename='{self.filename}', created_at={self.created_at})>"


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



class WorkerPin(Base):
    __tablename__ = "worker_pin"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    worker_name = Column(String, nullable=False)
    pin = Column(Integer, nullable=False)
    added = Column(DateTime, nullable=False)


class CustomerPin(Base):
    __tablename__ = "customer_pin"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    phone_number = Column(Integer, nullable=False)
    pin = Column(Integer, nullable=False)
    card_id = Column(String, nullable=False)
    added = Column(DateTime, nullable=False)

class Expenses(Base):
    __tablename__ = "expenses"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    vendor = Column(String, nullable=False)
    amount = Column(Float, nullable=False)
    details = Column(JSONB, nullable=False)
    transaction_date = Column(DateTime)
    submit_date = Column(DateTime)
    factura = Column(Boolean)
    reference_file_paths = Column(JSONB)


class PoloProducts(Base):
    __tablename__ = "polo_products"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_name = Column(String, nullable=False)
    description = Column(String)
    added = Column(DateTime)
    polo_id = Column(String)
 
class Menus(Base):
    __tablename__ = "menus"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_name = Column(String, nullable=False)
    description = Column(String)
    added = Column(DateTime)
    menu_version = Column(String)
    active = Column(Boolean)
    price = Column(String)


class ProductionCounts(Base):
    __tablename__ = "production_counts"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_name = Column(String, nullable=False)
    n_items = Column(Integer)
    added = Column(DateTime(timezone=False))
    dough_amount = Column(String)

class MermaCounts(Base):
    __tablename__ = "merma_counts"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_name = Column(String, nullable=False)
    n_items = Column(Integer)
    added = Column(DateTime(timezone=False))
   


