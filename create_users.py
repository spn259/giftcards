
from db import PostgresDB
from models import User
import os
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone


username = 'doadmin'
password = os.environ['PASSWORD']
host = os.environ['HOST']
port = os.environ['PORT']
database =os.environ['DATABASE']
sslmode = os.environ['SSLMODE']

db = PostgresDB(
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
        sslmode=sslmode)


new_user = User(username='cajero', password=generate_password_hash('adc123$'))
db.session.add(new_user)
db.session.commit()
