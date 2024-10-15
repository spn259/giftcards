from db import PostgresDB
from models import Cards 
import os
import uuid 
from datetime import datetime, timezone

username = os.environ.get('username')
password = os.environ.get('password')
host = os.environ.get('host')
port = os.environ.get('port')
database = os.environ.get('database')
sslmode = os.environ.get('sslmode')

db = PostgresDB(
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
        sslmode=sslmode)


for i in range(0, 100):
    fi = Cards(uuid=(str(uuid.uuid4())), added=datetime.now(timezone.utc))
    db.session.add(fi)
db.session.commit()



