

from flask import (Flask, json, jsonify, redirect, render_template, request,
                   session, url_for, render_template_string, current_app)

from db import PostgresDB
from models import Cards, Transactions
import os
import uuid 
from datetime import datetime, timezone
import pandas as pd

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

app = Flask(__name__)

@app.route('/')
def landing():
    return render_template("landing.html")

@app.route('/scan')
def scan():
    print("Scanning.")
    return render_template("scan.html")


@app.route('/process_card/<card_id>',  methods=['GET', 'POST'])
def process_card(card_id):

    bal = pd.DataFrame(db.session.query(Transactions.amount)\
    .filter(Transactions.card_id == card_id).all(), columns=['amount'])
    print(bal)
    cur_bal = bal['amount'].sum()
    print("Scanning.")
    return render_template("cards.html", balance=cur_bal)

local = False
if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)

