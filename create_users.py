
from db import PostgresDB
from app import User
import os
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime, timezone
from dotenv import load_dotenv
from pathlib import Path

# Force .env path based on script location
dotenv_path = Path(__file__).resolve().parent / '.env'
load_dotenv(dotenv_path=dotenv_path)

username = os.environ['dbusername']
password = os.environ['password']
host = os.environ['host']
port = 25060
database = os.environ['database']
sslmode = os.environ['sslmode']
spaces_access_key = os.environ['spaces_access_key']
spaces_key_id = os.environ['spaces_key_id']
spaces_bucket_endpoint = os.environ['spaces_bucket_endpoint']
spaces_bucket_name = os.environ['spaces_bucket_name']
openai_token = os.environ['openai_token']
db = PostgresDB(
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
        sslmode=sslmode)


new_user = User(username='romina', password=generate_password_hash('romina546'))
db.session.add(new_user)
db.session.commit()


