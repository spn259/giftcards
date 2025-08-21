
from collections import OrderedDict

from sqlalchemy import (
    Column, Integer,CheckConstraint, String, Text, Boolean, Enum, ForeignKey,BigInteger, DateTime, func, text, ARRAY, Float, Index, types,
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
from datetime import datetime
import pytz

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
    category = Column(String)
    biz_area = Column(String)
    payment_method = Column(String)
    username = Column(String)


class PoloProducts(Base):
    __tablename__ = "polo_products"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_name = Column(String, nullable=False)
    description = Column(String)
    added = Column(DateTime)
    polo_id = Column(String)
    modifier = Column(Boolean)
    fk_menu_ids = Column(JSONB)
 
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
    polo_product_ids = Column(JSONB)


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
   
class InventoryProducts(Base):
    __tablename__ = "inventory_products"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_area = Column(String, nullable=False)
    product_category = Column(String, nullable=False)
    product_name = Column(String)
    measure = Column(String)
    details = Column(String)
    username = Column(String)
    added = Column(DateTime(timezone=False))

class InventoryCounts(Base):
    __tablename__ = "inventory_counts"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    product_id = Column(BigInteger, nullable=False)
    value = Column(String, nullable=False)
    location = Column(String)
    username = Column(String)
    added = Column(DateTime(timezone=False))


from datetime import datetime
try:
    # Python 3.9 + (preferred)
    from zoneinfo import ZoneInfo          # built-in
    MX_TZ = ZoneInfo("America/Mexico_City")
except ImportError:
    # Fallback for older Python versions
    import pytz
    MX_TZ = pytz.timezone("America/Mexico_City")

class ChangeCount(Base):
    __tablename__ = "change_counts"

    id           = Column(Integer, primary_key=True)
    username     = Column(String, nullable=False)
    denomination = Column(Integer, nullable=False)
    added        = Column(DateTime(timezone=True),
        default=lambda: datetime.now(MX_TZ),   # ← local timestamp
        nullable=False
    )


MX_TZ = pytz.timezone("America/Mexico_City")

class InsumoRequest(Base):
    __tablename__  = "insumo_requests"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id          = Column(BigInteger, primary_key=True)
    employee    = Column(String(50),  nullable=False)
    name        = Column(String(80),  nullable=False)
    measure     = Column(String(10),  nullable=False)          # unidades, kg, g, etc.
    quantity    = Column(Float,       nullable=False)

    urgency     = Column(String)

    notes       = Column(Text)

    status      = Column(
        Enum(
            "pendiente",
            "asignado",
            "en progreso",
            "completado",
            "cancelado",
            name="insumo_status",
        ),
        default="pendiente",
        nullable=False,
    )

    assigned_to = Column(String(50))

    # ──────────────── TIMEZONE-AWARE «added» ──────────────────
    created_at = Column(
            DateTime(timezone=False),                          # <-- no tz
            server_default=text("timezone('America/Mexico_City', now())::timestamp"),
            nullable=False
        )
    # ───────────────────────────────────────────────────────────

class InsumoList(Base):
    __tablename__ = "insumo_list"
    __table_args__ = {"schema": "public", "extend_existing": True}

    id = Column(BigInteger, primary_key=True)
    insumo_name = Column(String, nullable=False)
    measure = Column(String, nullable=False)
    added = Column(DateTime, nullable=False)
    created_by = Column(String)
    area = Column(String)
    proveedor = Column(String)

from datetime import datetime
try:
    # Python 3.9 + (preferred)
    from zoneinfo import ZoneInfo          # built-in
    MX_TZ = ZoneInfo("America/Mexico_City")
except ImportError:
    # Fallback for older Python versions
    import pytz
    MX_TZ = pytz.timezone("America/Mexico_City")

class Survey(Base):
    __tablename__ = "survey"
    __table_args__ = {"schema": "public"}

    id = Column(BigInteger, primary_key=True)
    answers = Column(JSONB, nullable=False)
    added   = Column(
            DateTime(timezone=False),                          # <-- no tz
            server_default=text("timezone('America/Mexico_City', now())::timestamp"),
            nullable=False
        )
    
    
class LocationSuggestion(Base):
    __tablename__ = "location_suggestions"
    __table_args__ = (
        CheckConstraint("latitude BETWEEN -90 AND 90"),
        CheckConstraint("longitude BETWEEN -180 AND -(-180)"),  # same as BETWEEN -180 AND 180
        {"schema": "public"},
    )

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    email      = Column(Text, nullable=False)
    latitude   = Column(Float, nullable=False)   # maps to DOUBLE PRECISION
    longitude  = Column(Float, nullable=False)
    address    = Column(Text)
    place_id   = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)