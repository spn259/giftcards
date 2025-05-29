

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
from models import Cards, Transactions, WorkerPin, CustomerPin, PoloProducts, Menus, ProductionCounts, MermaCounts
import os
import uuid
from datetime import datetime, timezone
import pandas as pd

from flask import Flask, request, render_template, jsonify
import base64
import re
import os
from product_utils import grab_week_year
from datetime import datetime
import pytz

local = False
if local:
    from dotenv import load_dotenv
    from pathlib import Path

    # Force .env path based on script location
    dotenv_path = Path(__file__).resolve().parent / '.env'
    load_dotenv(dotenv_path=dotenv_path)

# Load the .env file from the current directory


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

@app.route('/main_landing', methods=['GET', 'POST'])
def main_landing():
    return render_template("main_landing.html")

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

from polo_utils import pull_polo_products

@app.route('/refresh_products', methods=['GET', 'POST'])
def refresh_products():
    from polo_utils import pull_polo_mods
    cur_prods = pd.DataFrame(db.session.query(PoloProducts.id, PoloProducts.product_name, PoloProducts.polo_id, PoloProducts.description).all())
    polo_prods = pull_polo_products()
    polo_prods = pd.DataFrame(polo_prods, columns=['name', 'description', 'polo_id'])
    polo_prods['modifier'] = False
    polo_mods = pull_polo_mods()
    polo_mods = pd.DataFrame(polo_mods, columns=['name', 'description', 'polo_id'])
    polo_mods['modifier'] = True

    polo_prods = pd.concat([polo_prods, polo_mods]).reset_index(drop=True)

    for i, r in polo_prods.iterrows():
        if r.polo_id not in cur_prods.polo_id.tolist():
            fi = PoloProducts(product_name=r['name'], description=r.description, polo_id=r.polo_id, modifier=r.modifier, added=datetime.utcnow())
            db.session.add(fi)
        db.session.commit()
    return jsonify({"added": True})

@app.route('/upload_menu', methods=['GET', 'POST'])
def upload_menu():
    return render_template('scan_menu.html')

@app.route('/extract_menu_api', methods=['POST'])
def extract_menu_api():
    from product_utils import extract_products

    blobs = [f.read() for f in request.files.getlist("menu_files")]
    if not blobs:
        return jsonify({"error": "no files"}), 400
    return jsonify(json.loads(extract_products(blobs)))
    
    # Extract product data from uploaded files
    # Return JSON: {"products": [{"name": ..., "description": ..., "price": ...}, ...]}
    pass
@app.route('/save_menu_products', methods=['POST'])
def save_menu_products():

    wy = grab_week_year()

    form_data = request.form

    # Step 2: Extract all product indices
    from collections import defaultdict
    products = defaultdict(dict)

    for full_key in form_data:
        if full_key.startswith("products["):
            # Example: products[0][name] ➜ index = 0, field = name
            parts = full_key.replace("products[", "").replace("]", "").split("[")
            if len(parts) == 2:
                index, field = parts
                products[int(index)][field] = form_data[full_key]

    # Step 3: Convert defaultdict to regular list
    product_list = [products[i] for i in sorted(products)]

    # Optional: parse raw_json if needed
    raw_json = form_data.get("raw_json")

    db.session.query(Menus).update({'active': False})
    db.session.commit()

    # Example: print or save to DB
    for product in product_list:
        fi = Menus(product_name=product.get('name'), description = product.get('description'), 
                   price=product.get('price'), added=datetime.utcnow(), menu_version=wy, active=True)
        db.session.add(fi)
    db.session.commit()
    return "Products received"


@app.route('/enter_production_counts', methods=['GET', 'POST'])
def enter_production_counts():
    menu_items = pd.DataFrame(db.session.query(Menus.product_name, Menus.id).filter(Menus.active == True).all())
    d = list()
    for i, r in menu_items.iterrows():
        d.append({'product_name': r.product_name, 'id': r.id})

    print(d)

    return render_template('production_counts.html', menu_items=d)

@app.route('/save_production_counts', methods=['GET', 'POST'])
def save_production_counts():
    masa_global = request.form.get('masa_global', type=int, default=1)
    


    cst = pytz.timezone("America/Mexico_City")
    now_cst = datetime.now(cst)

    naive_cst = now_cst.replace(tzinfo=None)
    menu_items = pd.DataFrame(db.session.query(Menus.id, Menus.product_name).filter(Menus.active == True).all())
    id_to_prod = dict(zip(menu_items.id.tolist(), menu_items.product_name.tolist()))
    if request.method == "POST":
        counts_by_name = {}

        # 1. Extract all form fields of the form counts[<product_name>]
        for full_key, val in request.form.items():
            if full_key.startswith('counts[') and full_key.endswith(']'):
                # slice out what's between the brackets
                name = full_key[len('counts['):-1]  
                try:
                    qty = int(val)
                except (ValueError, TypeError):
                    qty = 0
                counts_by_name[int(name)] = qty
            # Handle saving logic here
        
        for k, v in counts_by_name.items():
            n = id_to_prod.get(k)
            fi = ProductionCounts(product_name=n, n_items=v, added=naive_cst, dough_amount= masa_global)
            db.session.add(fi)
        
        db.session.commit()
        

        return "Products received"
    

@app.route('/enter_merma_counts', methods=['GET', 'POST'])
def enter_merma_counts():
    menu_items = pd.DataFrame(db.session.query(Menus.product_name, Menus.id).filter(Menus.active == True).all())
    d = list()
    for i, r in menu_items.iterrows():
        d.append({'product_name': r.product_name, 'id': r.id})

    print(d)

    return render_template('merma_counts.html', menu_items=d)

@app.route('/save_merma_counts', methods=['GET', 'POST'])
def save_merma_counts():
    
    import pytz
    from datetime import datetime



    cst = pytz.timezone("America/Mexico_City")
    now_cst = datetime.now(cst)

    naive_cst = now_cst.replace(tzinfo=None)

    menu_items = pd.DataFrame(db.session.query(Menus.id, Menus.product_name).filter(Menus.active == True).all())
    id_to_prod = dict(zip(menu_items.id.tolist(), menu_items.product_name.tolist()))
    if request.method == "POST":
        merma_counts = {}

        # 1) Extract all form fields like "merma[15]" → {15: qty}
        for key, val in request.form.items():
            if key.startswith('merma[') and key.endswith(']'):
                # pull out the ID between the brackets
                id_str = key[len('merma['):-1]
                try:
                    item_id = int(id_str)
                    qty     = int(val)
                except (ValueError, TypeError):
                    continue
                merma_counts[item_id] = qty
        
        for k, v in merma_counts.items():
            n = id_to_prod.get(k)
            fi = MermaCounts(product_name=n, n_items=v, added=naive_cst)
            db.session.add(fi)
        
        db.session.commit()
        

        return "Products received"    
def pull_mods(order_id, box_id='aaf6eb61-bc43-4f5c-bf7e-086778897930'):
    import requests
    from polo_utils import HEADERS
    per_order_url = 'https://api.polotab.com/api/v1/restaurants/cd7d0f22-eb20-450e-b185-5ce412a3a8ea/orders/{}'.format(order_id)
    ord_res = requests.get(per_order_url, headers=HEADERS)
    all_mods = list()
    for item in ord_res.json()['orderItems']:
        if item['cartItem']['productId'] == box_id:
            mods = [(x['modifier']['id'], x['quantity']) for x in item['cartItem']['cartItemModifiers']]
            all_mods.extend(mods)
    return all_mods

@app.route('/merma_dashboard')
def merma_dashboard():

    from datetime import datetime, timedelta
    from polo_utils import pull_polo_sales

    # ---------- 1. Parse date parameters ----------
    # Expect YYYY-MM-DD strings; if missing, default to today
    today_str = datetime.now().strftime("%Y-%m-%d")

    start_str = request.args.get("start_date", today_str)
    end_str   = request.args.get("end_date", start_str)  # default: same day

    try:
        start_date = datetime.strptime(start_str, "%Y-%m-%d").date()
    except ValueError:
        start_date = datetime.today().date()

    try:
        end_date = datetime.strptime(end_str, "%Y-%m-%d").date()
    except ValueError:
        print("rror conversion...")
        end_date = start_date

    # start_dt → 00:00 local CST, naive
    start_dt = datetime.combine(start_date, datetime.min.time())

    # end_dt  → 00:00 of day AFTER end_date (exclusive upper bound)
    end_dt   = datetime.combine(end_date + timedelta(days=1), datetime.min.time())
    print(start_str, end_str)
    # Example
    resp = pull_polo_sales(start_str, end_str)
    od = dict()
    # Example
    box_id = 'aaf6eb61-bc43-4f5c-bf7e-086778897930'
    d = dict()
    for order in resp.json()['orders']:
        for prod in order['orderItems']:
            prod_id = prod['cartItem']['productId']
            if prod_id == box_id:
                mods = pull_mods(prod['orderId'])
                for item in mods:
                    prod_id, q = item
                    if not d.get(prod_id):
                        d[prod_id] = q
                    else:
                        d[prod_id] =  d[prod_id]+q
                        
            q = prod['cartItem']['quantity']
            if not d.get(prod_id):
                d[prod_id] = q
            else:
                d[prod_id] =  d[prod_id]+q
    all_prods = pd.DataFrame(db.session.query(Menus.product_name, Menus.description, Menus.id, Menus.polo_product_ids).filter(Menus.active == True).all())
    all_polo = pd.DataFrame(db.session.query(PoloProducts.product_name, PoloProducts.modifier, PoloProducts.description, PoloProducts.id, PoloProducts.polo_id).all())
    polo_to_uuid = dict(zip(all_polo.id.tolist(), all_polo.polo_id.tolist()))
    polo_to_adc = dict()
    for i, r in all_prods.iterrows():
        for item in r.polo_product_ids:
            uu = polo_to_uuid.get(item)
            polo_to_adc[uu] = r['product_name']
    final_polo_res = {x: 0 for x in all_prods.product_name.tolist()}
    for k, v in d.items():
        prod_name = polo_to_adc.get(k)
        if pd.notnull(prod_name):
            final_polo_res[prod_name]+= v
            
    l = list()
    for k, v in final_polo_res.items():
        l.append((k, v))
        
    polo_df = pd.DataFrame(l, columns=['product_name', 'n_items'])



    # ---------- 2. Query DB ----------
    prod_df = pd.DataFrame(
        db.session.query(
            ProductionCounts.product_name,
            ProductionCounts.n_items.label("n_prod")
        )
        .filter(ProductionCounts.added.between(start_dt, end_dt))
        .all()
    )

    merma_df = pd.DataFrame(
        db.session.query(
            MermaCounts.product_name,
            MermaCounts.n_items.label("n_merma"),
            MermaCounts.added
        )
        .filter(MermaCounts.added.between(start_dt, end_dt))
        .all()
    )
   


    # ---------- 3. Deduplicate merma by day ----------
    if not merma_df.empty:
        merma_df["date_hour"] = merma_df["added"].dt.floor("H")     # e.g. 2025-05-29 14:00:00

    # 2️⃣  keep the last row for each (product, hour) combo
        merma_df = (
            merma_df.sort_values(["product_name", "added"])         # latest is last after sort
                    .drop_duplicates(subset=["product_name", "date_hour"], keep="last")
                    [["product_name", "n_merma"]]                  # final tidy columns
        )
        print(merma_df)
    
    data = list()
    for i, r in polo_df.iterrows():
        if len(merma_df) > 0:
            tmp_merma= merma_df[merma_df.product_name == r.product_name]
            if len(tmp_merma) > 0:
                # n_merma = tmp_merma.iloc[0]['n_merma']
                n_merma = tmp_merma['n_merma'].sum()
            else:
                n_merma = -1
        else:
            n_merma = 0 
        if len(prod_df) > 0:
            tmp_prod = prod_df[prod_df.product_name == r.product_name]
            if len(tmp_prod) > 0:
                n_prod = tmp_prod.iloc[0]['n_prod']
                n_prod = tmp_prod['n_prod'].sum()
            else:
                n_prod = -1
        else:
            n_prod = 0 
       
        data.append({'product_name':r.product_name, 
                     'merma_count': n_merma, 
                     'production_count': n_prod, 
                     'sales_count': r.n_items}
                    )
       
        


    return render_template("merma_dashboard.html", data=data)

@app.route('/expenses_dashboard')
def expenses_dashboard():
    # 1) Set up pytz CST zone and “now”
    from datetime import datetime, time
    import pytz
    cst = pytz.timezone("America/Mexico_City")
    now_cst = datetime.now(cst)

    # 2) Compute defaults in CST
    default_start = now_cst.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    default_end   = now_cst.replace(hour=23, minute=59, second=59, microsecond=999999)

    # 3) Read query‐params
    start_str = request.args.get('start_date')
    end_str   = request.args.get('end_date')

    # 4) Parse or fall back
    if start_str:
        try:
            dt = datetime.strptime(start_str, "%Y-%m-%d")
            start_dt = cst.localize(datetime.combine(dt.date(), time.min))
        except ValueError:
            start_dt = default_start
    else:
        start_dt = default_start

    if end_str:
        try:
            dt = datetime.strptime(end_str, "%Y-%m-%d")
            end_dt = cst.localize(datetime.combine(dt.date(), time.max))
        except ValueError:
            end_dt = default_end
    else:
        end_dt = default_end

    # 5) Query between those datetimes
    expenses = (
        db.session.query(Expenses)
        .filter(
            Expenses.transaction_date >= start_dt,
            Expenses.transaction_date <= end_dt
        )
        .order_by(Expenses.transaction_date)
        .all()
    )

    # 6) Compute total
    total_amount = sum(e.amount for e in expenses)

    # 7) Render, passing back the ISO‐dates for the form
    return render_template(
        'expense_dashboard.html',
        data=expenses,
        total_amount=total_amount,
        start_date=start_dt.date().isoformat(),
        end_date=end_dt.date().isoformat()
    )


@app.route('/match_polo_products', methods=['GET', 'POST'])
def match_polo_products():
    all_prods = pd.DataFrame(db.session.query(Menus.product_name, Menus.description, Menus.id).filter(Menus.active == True).all())
    all_polo = pd.DataFrame(db.session.query(PoloProducts.product_name, PoloProducts.modifier, PoloProducts.description, PoloProducts.id).all())

    polo_d = list()
    for i, r in all_polo.iterrows():
        polo_d.append({'product_name': r.product_name, 'modifier': r.modifier, 'description': r.description, 'id': r['id']})
        
    prod_d = list()
    for i, r in all_prods.iterrows():
        prod_d.append({'product_name': r.product_name, 'description': r.description, 'id': r['id']})

    prompt = """
    For each product in the list Menu Items, try to match one or more products from the list Polo Products, 
    output your matches as JSON list:

    for example
    "GLASEADA ORIGINAL": [{{name: name, id: id, modifier: modifier}}, {{name: name, id: id, modifier: modifier}}]

    Most will have two matches, one non-modifier and one modifier, return the 3 best matches.

    In the matches, include the polo id, and whether it is a modifier or not and name as keys

    Polo products: {}
    Menu products: {}


    """

    system_prompt = """Out put your answer as json
    product: [{{"product_name": name}}, {{"product_id": prod_id}}]"""

    this_prompt = prompt.format(polo_d, prod_d)
    pull = True
    if pull:

        MODEL = "gpt-4.1-2025-04-14"
        from openai import OpenAI
        client = OpenAI(api_key=openai_token) 
        kw = {"response_format": {"type": "json_object"}}

        # Call the LLMclient.chat.completions.create
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": this_prompt}
            ],
            **kw
        )

        resp = json.loads(response.model_dump_json())
        content = resp['choices'][0]['message']['content']
        res = json.loads(content)
    else:
        res = {'GLASEADA ORIGINAL': [{'name': 'Dona Glaseada Original', 'id': 209, 'modifier': False}, {'name': 'Dona Glaseada Original', 'id': 234, 'modifier': True}], 'MAPLE TOCINO': [{'name': 'Dona de Maple Tocino', 'id': 176, 'modifier': False}, {'name': 'Maple Tocino', 'id': 242, 'modifier': True}], 'CHOCOLATE': [{'name': 'Dona de Chocolate', 'id': 156, 'modifier': False}, {'name': 'Dona de Chocolate', 'id': 240, 'modifier': True}], 'BLUEBERRY': [{'name': 'Dona con Glaseado de Blueberry', 'id': 52, 'modifier': False}, {'name': 'Dona con Glaseado de Blueberry', 'id': 239, 'modifier': True}], 'NUTELLA': [{'name': 'Dona Rellena Nutella', 'id': 44, 'modifier': False}, {'name': 'Dona Rellena Nutella', 'id': 237, 'modifier': True}], 'ZARZAMORA': [{'name': 'Dona Rellena Zarzamora', 'id': 152, 'modifier': False}, {'name': 'Dona Rellena Zarzamora', 'id': 227, 'modifier': True}], 'MATCHA': [{'name': 'Dona Rellena de Matcha', 'id': 31, 'modifier': False}, {'name': 'Dona Rellena de Matcha', 'id': 235, 'modifier': True}], 'CANELA TWIST': [{'name': 'Canela Twist', 'id': 162, 'modifier': False}, {'name': 'Canela Twist', 'id': 233, 'modifier': True}], 'OLD FASHION ZANAHORIA': [{'name': 'Old Fashion Zanahoria', 'id': 143, 'modifier': False}, {'name': 'Old Fashion Zanahoria', 'id': 230, 'modifier': True}], 'OLD FASHION CHOCOLATE': [{'name': 'Dona Old Fashion Chocolate', 'id': 105, 'modifier': False}, {'name': 'Dona Old Fashion Chocolate', 'id': 228, 'modifier': True}], 'APPLE FRITTER': [{'name': 'Apple Fritter', 'id': 57, 'modifier': False}, {'name': 'Apple Fritter', 'id': 238, 'modifier': True}], 'LONGJOHN MAPLE': [{'name': 'Maple Long John (Rellena de Crema)', 'id': 64, 'modifier': False}, {'name': 'Maple Long John (Rellena de Crema)', 'id': 229, 'modifier': True}], 'LONGJOHN CHOCOLATE': [{'name': 'Chocolate Long John (Rellena de Crema)', 'id': 45, 'modifier': False}, {'name': 'Chocolate Long John (Rellena de Crema)', 'id': 236, 'modifier': True}], 'PIZZA PUFF': [{'name': 'Pizza Puff', 'id': 231, 'modifier': True}, {'name': 'Pizza Dona', 'id': 83, 'modifier': False}], 'BEARCLAW MANZANA': [{'name': 'Bear Claw Manzana', 'id': 21, 'modifier': False}, {'name': 'Bearclaw Manzana', 'id': 241, 'modifier': True}]}


    return render_template('match_polo_products.html', options=res)
BRACKET_RE = re.compile(r"^modifiers\[(.+?)\]\[\]$")

@app.route("/save_modifiers", methods=["POST"])
def save_modifiers():
    """
    Build a dict:
        {
            "GLASEADA ORIGINAL": [209, 234],
            "CHOCOLATE":        [240],  # etc.
        }
    from the check-box form.
    """
    selected = {}                       # product_name -> list[int]

    # request.form is a MultiDict; iterate over keys
    for field, values in request.form.lists():
        m = BRACKET_RE.match(field)
        if not m:
            continue                    # skip unrelated fields (CSRF token…)

        product_name = m.group(1)       # text inside the [ ... ]
        # values is already a list of strings; convert to int
        selected[product_name] = [int(v) for v in values if v.strip()]

    # ---- do whatever you need with `selected` dict ----
    # e.g. save to DB, log, etc.
    print("User picked:", selected)

    for k, v in selected.items():
        db.session.query(Menus)\
        .filter(Menus.product_name == k.strip())\
        .filter(Menus.active == True)\
        .update({'polo_product_ids': v})
    db.session.commit()

    flash("Modificadores guardados.", "success")
    return "Products received"    

# ── imports ────────────────────────────────────────────────────────
from flask import render_template, abort, current_app
import json, os, mimetypes, re
import boto3
from botocore.client import Config

# db, login_required already imported elsewhere
# routes.py  (add near your other routes)
import io, os, json, mimetypes
from flask import send_file, abort
from botocore.exceptions import ClientError

# --------------------------------------------
#  Clean the key exactly as stored in DB
# --------------------------------------------
def clean_key(raw: str) -> str:
    raw = raw.strip().lstrip("/")
    if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
        raw = raw[1:-1]
    return raw

from flask import Response, stream_with_context
# ... existing imports ...

@app.route("/expense/<int:expense_id>/receipt/<int:index>")
@login_required
def expense_receipt(expense_id: int, index: int):
    """Stream one receipt (image or PDF). PDFs are forced inline."""
    exp = db.session.get(Expenses, expense_id) or abort(404)

    keys = exp.reference_file_paths or []
    if isinstance(keys, str):
        keys = json.loads(keys)

    try:
        key = clean_key(keys[index])
    except IndexError:
        abort(404)

    # Grab object from Spaces
    try:
        obj = _spaces.get_object(Bucket=spaces_bucket_name, Key=key)
    except _spaces.exceptions.NoSuchKey:
        abort(404)

    # Detect type from file-extension *only*
    ext   = os.path.splitext(key)[1].lower()
    is_pdf = ext == ".pdf"
    mime   = "application/pdf" if is_pdf else \
             mimetypes.guess_type(key)[0] or "application/octet-stream"

    # Stream body so large files don’t sit in memory
    body_iter = stream_with_context(obj["Body"].iter_chunks())

    headers = {
        "Content-Type":        mime,
        "Content-Disposition": f'inline; filename="{os.path.basename(key)}"',
        "Content-Length":      obj["ContentLength"],
    }

    # Build plain Response instead of send_file → full header control
    return Response(body_iter, headers=headers)


# ── route ──────────────────────────────────────────────────────────
@app.route("/expense/<int:expense_id>")
@login_required
def expense_detail(expense_id: int):
    exp = db.session.get(Expenses, expense_id)
    if exp is None:
        abort(404)

    # 1. parse JSONB safely
    details = exp.details if isinstance(exp.details, dict) else json.loads(exp.details or "{}")
    items   = (details.get("receipts", [{}])[0]).get("items", [])

    # 2. collect object paths
    raw_keys = exp.reference_file_paths or []
    if isinstance(raw_keys, str):
        raw_keys = json.loads(raw_keys)

    files = []
    for i, raw in enumerate(raw_keys):
        key  = clean_key(raw)
        ext  = os.path.splitext(key)[1].lower()
        mime = mimetypes.guess_type(key)[0] or ""
        kind = "pdf" if mime == "application/pdf" else "image"
        files.append({"idx": i, "kind": kind})

    # Force correct MIME for PDFs
    ext  = os.path.splitext(key)[1].lower()
    mime = "application/pdf" if ext == ".pdf" else mimetypes.guess_type(key)[0] or "application/octet-stream"

    obj  = _spaces.get_object(Bucket=spaces_bucket_name, Key=key)
    data = io.BytesIO(obj["Body"].read())
    # 3. render page
    return render_template(
        "expense_detail.html",
        expense=exp,
        details=details,
        items=items,
        files=files,
    )


# Run app locally
if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)
