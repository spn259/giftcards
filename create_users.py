
from db import PostgresDB
from models import User
import os
from werkzeug.security import check_password_hash, generate_password_hash
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


new_user = User(username='steven', password=generate_password_hash('marigold'))
db.session.add(new_user)
db.session.commit()
