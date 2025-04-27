

# routes.py
import json, logging
from flask import request, jsonify, current_app
from werkzeug.exceptions import BadRequest
# routes.py (or app.py)
import json, decimal, datetime
from sqlalchemy.exc import SQLAlchemyError

from flask import (Flask, jsonify, redirect, render_template, request, session,
                   url_for, current_app, flash, request, redirect, url_for, flash, jsonify)
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin

from models import Expenses     
from db import PostgresDB
from models import Cards, Transactions, WorkerPin, CustomerPin
import os
import uuid
from datetime import datetime, timezone
import pandas as pd

from flask import Flask, request, render_template, jsonify
import base64
import re
import os

username = os.environ['DBUSERNAME']
password = os.environ['PASSWORD']
host = os.environ['HOST']
port = 25060
database =os.environ['DATABASE']
sslmode = os.environ['SSLMODE']
spaces_access_key = os.environ['spaces_access_key']
spaces_key_id = os.environ['spaces_key_id']
spaces_bucket_endpoint = os.environ['spaces_bucket_endpoint']
spaces_bucket_name = os.environ['spaces_bucket_name']
OPENAI_TOKEN = os.environ['OPENAI_TOKEN']



# storage.py
import boto3, uuid, mimetypes
from pathlib import Path

_spaces = boto3.client(
    "s3",
    endpoint_url=spaces_bucket_endpoint,
    aws_access_key_id=spaces_key_id,
    aws_secret_access_key=spaces_access_key,
)

def upload_receipt(file_obj, expense_id: int) -> str:
    """
    Pushes `file_obj` to Spaces.
    Returns the S3 key (you can build the public URL from it later).
    """
    ext   = Path(file_obj.filename).suffix.lower() or ".bin"
    key   = f"expenses/{expense_id}/{uuid.uuid4().hex}{ext}"
    mime  = file_obj.mimetype or mimetypes.guess_type(ext)[0] or "application/octet-stream"

    _spaces.upload_fileobj(
        file_obj,
        spaces_bucket_name,
        key,
        ExtraArgs={"ContentType": mime, "ACL": "private"}   # or public-read
    )
    return key




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
    this_pin = db.session.query(CustomerPin.pin).filter(CustomerPin.card_id == card_id).all()
    if len(this_pin) > 0:
        has_pin = True
    else:
        has_pin = False
    if len(trans) == 0:
        return render_template("cards.html", balance=0, trans=dict(), card_id=card_id)
    t_d = list()
    for i, r in trans.iterrows():
        if r.transaction_type.strip().lower() == 'abono':
            t_type = 'Abono'
        else:
            t_type = 'Gasto'
        t_d.append({'type': t_type, 'amount': r.amount, 'transaction_date': r.transaction_date})

    cur_bal = trans['amount'].sum()
    print("Scanning.")
    return render_template("cards.html", balance=cur_bal, trans=t_d, card_id=card_id, pin_created=has_pin)

@app.route('/process_card_admin/<card_id>', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def process_card_admin(card_id):
    trans = pd.DataFrame(db.session.query(Transactions.amount, Transactions.transaction_type, Transactions.added)
                       .filter(Transactions.card_id == card_id).all(), columns=['amount', 'transaction_type', 'transaction_date'])
    
    if len(trans) == 0:
        return render_template("cards_admin.html", balance=0, trans=dict(), card_id=card_id)
    t_d = list()
    for i, r in trans.iterrows():
        if r.transaction_type.strip().lower() == 'abono':
            t_type = 'Abono'
        else:
            t_type = 'Gasto'
        t_d.append({'type': t_type, 'amount': r.amount, 'transaction_date': r.transaction_date})

    cur_bal = trans['amount'].sum()
    print("Scanning.")
    return render_template("cards_admin.html", balance=cur_bal, trans=t_d, card_id=card_id)



@app.route('/save_pin/', methods=['GET', 'POST'])
def save_pin():
    card_id = request.form.get('card_id')
    phone = request.form.get('phoneNumber')
    pin = request.form.get('pinNumber')
    fi = CustomerPin(phone_number=int(phone), pin=int(pin), card_id=card_id, added=datetime.now(timezone.utc))
    db.session.add(fi)
    db.session.commit()
    return redirect(url_for('process_card', card_id=card_id, pin_created=True))


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
    custo_pin = db.session.query(CustomerPin.pin).filter(CustomerPin.card_id == card_id).all()
    print(custo_pin)
    if len(custo_pin) > 0:
        has_pin = True
    else:
        has_pin = False

    trans = pd.DataFrame(db.session.query(Transactions.amount, Transactions.transaction_type, Transactions.added)
                    .filter(Transactions.card_id == card_id).all(), columns=['amount', 'transaction_type', 'transaction_date'])
  
    cur_bal = trans['amount'].sum()

    return render_template("register_expense.html", card_id=card_id, pin_created=has_pin, cur_bal=cur_bal)

@app.route('/register_abono/', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def register_abono():
    card_id = request.args.get('card_id')
    return render_template("register_abono.html", card_id=card_id, error=False)


@app.route('/save_abono/', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def save_abono():
    card_id = request.form.get('card_id')
    pin = request.form.get('pin')
    amount = request.form.get('amount')
    if pin is not None:
        pin = int(pin)
        all_pins = pd.DataFrame(db.session.query(WorkerPin.pin).all(), columns=['pin'])
        all_pins = [int(x) for x in all_pins.pin.tolist()]
        if pin not in all_pins:
            print(pin)
            return render_template("register_abono.html", card_id=card_id, error="true")
        else:
            amount = int(amount)
            fi = Transactions(card_id= card_id, transaction_type = 'Abono', added=datetime.now(timezone.utc), amount=amount)
            db.session.add(fi)
            db.session.commit()

            return redirect(url_for('process_card_admin', card_id=card_id))



    card_id = request.args.get('card_id')
    print(card_id)

    return render_template("register_abono.html", card_id=card_id)

@app.route('/save_expense/', methods=['GET', 'POST'])
@login_required  # Require login to access this page
def save_expense():
    card_id = request.form.get('card_id')
    amount = request.form.get('amount')
    trans = pd.DataFrame(db.session.query(Transactions.amount, Transactions.transaction_type, Transactions.added)
                    .filter(Transactions.card_id == card_id).all(), columns=['amount', 'transaction_type', 'transaction_date'])
  
    cur_bal = trans['amount'].sum()
    custo_pin = db.session.query(CustomerPin.pin).filter(CustomerPin.card_id == card_id).all()
    if len(custo_pin) > 0:
        pin = request.form.get('pin')
        if int(pin) != int(custo_pin[0][0]):
            return render_template("register_expense.html", card_id=card_id, error=True, pin_created=True, cur_bal=cur_bal)
        

    if float(amount) > cur_bal:
        return render_template("register_expense.html", card_id=card_id, error=False, bal_error=True, pin_created=True, cur_bal=cur_bal)

    amount = float(amount)
    amount = -amount
    fi = Transactions(card_id = card_id, transaction_type='Gasto',  added=datetime.now(timezone.utc), amount=amount)
    db.session.add(fi)
    db.session.commit()

    return redirect(url_for('process_card_admin', card_id=card_id))  # Pass the ID as a parameter

# Route that serves the feedback page
@app.route('/feedback')
def feedback():
    # You can serve a template here or return a string with HTML.
    return render_template('feedback.html')

# Route that receives the photo and feedback from the client
import re
import base64
from flask import request
from models import Photo  # Assuming your Photo model is defined in models.py

@app.route('/upload_photo', methods=['POST'])
def upload_photo():
    data = request.get_json()
    image_data = data.get('image')
    feedback = data.get('feedback', 'unknown')

    # Remove the data URL prefix (e.g., "data:image/png;base64,")
    image_data = re.sub('^data:image/.+;base64,', '', image_data)
    image_bytes = base64.b64decode(image_data)

    # Create a filename (you may include a timestamp or unique ID if needed)
    filename = f"{feedback}_photo.png"

    # Create an instance of the Photo model
    new_photo = Photo(
        filename=filename,
        photo=image_bytes,
        feedback=feedback
    )

    # Save the photo record to the database
    db.session.add(new_photo)
    db.session.commit()

    return "Photo received!", 200

import base64
from flask import render_template
from models import Photo

@app.route('/view_photos')
def view_photos():
    # Retrieve all photos from the database (ordering can be adjusted as needed)
    dphotos = db.session.query(Photo).all()

    # Convert each photo's binary data to a base64-encoded string for HTML display
    for dphoto in dphotos:
        if dphoto.photo:
            dphoto.base64 = base64.b64encode(dphoto.photo).decode('utf-8')
        else:
            dphoto.base64 = ""
    return render_template('view_photos.html', photos=dphotos)


@app.route('/thankyou')
def thankyou():
    return render_template('thankyou.html')


@app.route('/admin_log_expense', methods=['GET', 'POST'])
def admin_log_expense():
    return render_template('admin_registrar_gasto.html')

@app.post("/extract_receipt_api")
def extract_receipt_api():
    from receipt_utils import extract_receipts
    blobs = [f.read() for f in request.files.getlist("receipts")]
    if not blobs:
        return jsonify({"error": "no files"}), 400
    return jsonify(json.loads(extract_receipts(blobs)))


@app.route('/admin_registrar_gasto', methods=['GET', 'POST'])
def admin_registrar_gasto():
    """
    Handles the final form submit from the detailsSection.
    """
    try:
        # ── 1. Parse primitive fields ──────────────────────────────
        amount_raw = request.form.get("amount", "0").replace(",", "")
        amount     = float(decimal.Decimal(amount_raw))
        vendor     = request.form.get("vendor", "").strip()
        pay_meth   = request.form.get("payment_method")    # may be None
        factura    = request.form.get("factura") == "si"

        # From hidden input (add <input type=\"hidden\" name=\"raw_json\">)
        details_json = request.form.get("raw_json") or "{}"
        details      = json.loads(details_json)
        print(details)

        # Optional: allow manual date entry later
        txn_date = details.get("date") or request.form.get("transaction_date")
        txn_date = datetime.fromisoformat(txn_date) if txn_date else None

        # ── 2. Insert expense row ──────────────────────────────────
        expense = Expenses(
            vendor=vendor,
            amount=amount,
            details=details,
            transaction_date=txn_date,
            submit_date=datetime.utcnow(),
            factura=factura,
            reference_file_paths=[],       # fill after uploads
        )
        db.session.add(expense)
        db.session.flush()                 # get expense.id

        # ── 3. Upload every file to Spaces ─────────────────────────
        keys = []
        for f in request.files.getlist("receipts"):
            if not f or f.filename == "":
                continue
            key = upload_receipt(f, expense.id)
            keys.append(key)

        # ── 4. Update row with file paths & commit ─────────────────
        expense.reference_file_paths = keys
        db.session.commit()

        print("Gasto guardado ✅", "success")
        return redirect(url_for("admin_log_expense"))

    except (ValueError, decimal.InvalidOperation):
        db.session.rollback()
        print("Monto inválido", "danger")
        return redirect(url_for("admin_log_expense"))

    except SQLAlchemyError:
        db.session.rollback()
        app.logger.exception("DB error saving expense")
        print("Error de base de datos", "danger")
        return redirect(url_for("admin_log_expense"))

    except Exception as e:
        db.session.rollback()
        app.logger.exception("Unexpected error")
        return jsonify({"error": "server_error", "details": str(e)}), 500



# Run app locally
local = False
if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)
