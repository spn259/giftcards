from db import PostgresDB
from models import Cards, Transactions
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


card_id = '217bfc2c-c464-493f-8971-9a7cb4992bda'

fi = Transactions(card_id=card_id, amount=100.0, transaction_type='add', added=datetime.now(timezone.utc))
db.session.add(fi)
db.session.commit()



