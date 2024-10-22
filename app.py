from flask import (Flask, jsonify, redirect, render_template, request, session,
                   url_for, current_app, flash)
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from db import PostgresDB
from models import Cards, Transactions
import os
import uuid
from datetime import datetime, timezone
import pandas as pd

# Load environment variables
username = os.environ.get('username')
password = os.environ.get('password')
host = os.environ.get('host')
port = os.environ.get('port')
database = os.environ.get('database')
sslmode = os.environ.get('sslmode')

# db = PostgresDB(
#     username=username,
#     password=password,
#     host=host,
#     port=port,
#     database=database,
#     sslmode=sslmode)

app = Flask(__name__)

# Configuring SQLAlchemy to connect to your Postgres database
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{username}:{password}@{host}:{port}/{database}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'supersecretkey'


# Secret key for session management (you should use a secure random key)
app.secret_key = 'supersecretkey'

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# User Model linked to the 'users' table in the database
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

# Load the user from the database based on user ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Define User model for Flask-Login

# User loader callback (used by Flask-Login to reload users from session
# Routes
@app.route('/')
def landing():
    return render_template("landing.html")

from werkzeug.security import check_password_hash, generate_password_hash

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Query the database for the user
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and the password matches
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('scan'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/scan')
@login_required  # Require login to access this page
def scan():
    print("Scanning.")
    return render_template("scan.html")

@app.route('/process_card/<card_id>', methods=['GET', 'POST'])
def process_card(card_id):
    trans = pd.DataFrame(db.session.query(Transactions.amount, Transactions.transaction_type, Transactions.added)
                       .filter(Transactions.card_id == card_id).all(), columns=['amount', 'transaction_type', 'transaction_date'])
    
    if len(trans) == 0:
        return render_template("cards.html", balance=0, trans=dict(), card_id=card_id)
    t_d = list()
    for i, r in trans.iterrows():
        if r.transaction_type.strip() == 'add':
            t_type = 'Abono'
        else:
            t_type = 'Gasto'
        t_d.append({'type': t_type, 'amount': r.amount, 'transaction_date': r.transaction_date})

    cur_bal = trans['amount'].sum()
    print("Scanning.")
    return render_template("cards.html", balance=cur_bal, trans=t_d, card_id=card_id)

@app.route('/process_card_admin/<card_id>', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def process_card_admin(card_id):
    trans = pd.DataFrame(db.session.query(Transactions.amount, Transactions.transaction_type, Transactions.added)
                       .filter(Transactions.card_id == card_id).all(), columns=['amount', 'transaction_type', 'transaction_date'])
    
    if len(trans) == 0:
        return render_template("cards.html", balance=0, trans=dict(), card_id=card_id)
    t_d = list()
    for i, r in trans.iterrows():
        if r.transaction_type.strip() == 'add':
            t_type = 'Abono'
        else:
            t_type = 'Gasto'
        t_d.append({'type': t_type, 'amount': r.amount, 'transaction_date': r.transaction_date})

    cur_bal = trans['amount'].sum()
    print("Scanning.")
    return render_template("cards_admin.html", balance=cur_bal, trans=t_d, card_id=card_id)



@app.route('/add_transaction')
@login_required  # Require login to access this page
def add_transaction():
    print("Scanning.")
    return render_template("scan.html")

@app.route('/register_expense/', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def register_expense():
    card_id = request.args.get('card_id')
    print(card_id)

    return render_template("register_expense.html", card_id=card_id)

@app.route('/register_abono/', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def register_abono():
    card_id = request.args.get('card_id')
    print(card_id)

    return render_template("register_abono.html", card_id=card_id)

@app.route('/save_expense/', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def save_expense():
    card_id = request.form.get('card_id')
    amount = request.form.get('amount')
    amount = float(amount)
    amount = -amount
    fi = Transactions(card_id = card_id, transaction_type='expense',  added=datetime.now(timezone.utc), amount=amount)
    db.session.add(fi)
    db.session.commit()

    return redirect(url_for('process_card', card_id=card_id))  # Pass the ID as a parameter


# Run app locally
local =False
if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)
