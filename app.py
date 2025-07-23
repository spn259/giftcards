
import os, io, re, json, uuid, time, base64, calendar, logging, decimal, mimetypes
from pathlib import Path
from datetime import datetime, timedelta, date, timezone
from threading import Lock
from zoneinfo import ZoneInfo
from collections import defaultdict

# ── Third-party libs ────────────────────────────────────────────────
import boto3, pandas as pd, pytz
from botocore.client import Config
from botocore.exceptions import ClientError
from pywebpush import webpush, WebPushException
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import BadRequest
from flask import (
    Flask, request, jsonify, redirect, render_template, url_for, flash,
    abort, Response, stream_with_context, current_app, session, send_file, 
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required,
    logout_user, login_required, current_user
)
from flask_caching import Cache
from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import func, cast, Numeric
from sqlalchemy.exc import SQLAlchemyError
from models import (
    Cards, ChangeCount, InsumoRequest, Transactions, WorkerPin,
    CustomerPin, PoloProducts, Menus, ProductionCounts, MermaCounts,
    InventoryProducts, InventoryCounts, Expenses, Photo
)
from db import PostgresDB
from events import assignment_event_stream, push_assignment_event
from product_utils import grab_week_year
from sqlalchemy.dialects.postgresql import JSONB  # add this
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash

MX_TZ = ZoneInfo("America/Mexico_City")
from pusher_push_notifications import PushNotifications



local = False
if local:
    from dotenv import load_dotenv
    from pathlib import Path
    dotenv_path = Path(__file__).resolve().parent / ".env"
    load_dotenv(dotenv_path=dotenv_path)


username = os.environ["dbusername"]
password = os.environ["password"]
host = os.environ["host"]
port = 25060
database = os.environ["database"]
sslmode = os.environ["sslmode"]
spaces_access_key = os.environ["spaces_access_key"]
spaces_key_id = os.environ["spaces_key_id"]
spaces_bucket_endpoint = os.environ["spaces_bucket_endpoint"]
spaces_bucket_name = os.environ["spaces_bucket_name"]
openai_token = os.environ["openai_token"]
BEAMS_INSTANCE_ID = os.environ["BEAMS_INSTANCE_ID"]
BEAMS_SECRET_KEY = os.environ["BEAMS_SECRET_KEY"]

local = True
if local:
    from my_secrets import env_vars

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
    ext = Path(file_obj.filename).suffix.lower() or ".bin"
    key = f"expenses/{expense_id}/{uuid.uuid4().hex}{ext}"
    mime = (
        file_obj.mimetype or mimetypes.guess_type(ext)[0] or "application/octet-stream"
    )
    _spaces.upload_fileobj(
        file_obj,
        spaces_bucket_name,
        key,
        ExtraArgs={"ContentType": mime, "ACL": "private"},  # or public-read
    )
    return key

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"postgresql://{username}:{password}@{host}:{port}/{database}"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.secret_key = "supersecretkey"

app.secret_key = "supersecretkey"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.remember_cookie_duration = timedelta(days=30)  # example: 30 d

app.config["CACHE_TYPE"] = "simple"
app.config["CACHE_DEFAULT_TIMEOUT"] = 165  # seconds
cache = Cache(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    push_subscription = db.Column(JSONB)  # JSONB now imported

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ALLOWED_USERS = {"steven", "romina"}
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)
app.config.update(
    REMEMBER_COOKIE_SECURE=True,  # HTTPS only
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
)


def username_required(view_func):
    """Allow the route only for specific usernames."""

    @wraps(view_func)
    @login_required  # must be logged in first
    def wrapped_view(*args, **kwargs):
        if current_user.username not in ALLOWED_USERS:
            abort(403)  # Forbidden
        return view_func(*args, **kwargs)

    return wrapped_view


@username_required
@login_required  # 👈 just stack it above your view
@app.route("/main_landing", methods=["GET", "POST"])
def main_landing():
    return render_template("main_landing.html")

app.config['BEAMS_INSTANCE_ID'] = BEAMS_INSTANCE_ID
beams_client = PushNotifications(
    instance_id=BEAMS_INSTANCE_ID,
    secret_key=BEAMS_SECRET_KEY,
)

@app.route("/pusher/beams-auth", methods=["GET"])
@login_required                         # 🔒 user must be logged-in
def beams_auth():
    """
    Pusher Beams auth endpoint.
    The Web-SDK calls it with ?user_id=<id>; we make sure that id
    matches the logged-in user, then return a signed JWT.
    """
    requested_id = request.args.get("user_id") 
    print(requested_id)         # from query-string
    actual_id    = str(current_user.id)    
                 # from Flask-Login

    if requested_id != actual_id:
        abort(401, description="Inconsistent request")

    # one positional argument – the user_id
    beams_token = beams_client.generate_token(actual_id)
    print(beams_token)

    return jsonify(beams_token)  

def push_message(user_id: int, message: str) -> None:
    beams_client.publish_to_users(
        user_ids=[str(user_id)],                 # ← use the real user-id
        publish_body={
            "web": {
                "notification": {                # ONLY Web-Notification fields here
                    "title": "Pedido nuevo",
                    "body":  message,
                    "icon":  "https://lionfish-app-zpcxb.ondigitalocean.app/static/logo-128.png"
                },
                # Extra Beams-specific keys go **next to** notification
                "deep_link": "https://lionfish-app-zpcxb.ondigitalocean.app/admin/insumos"
            },
            # (Optional) native payloads:
            # "fcm": {...},
            # "apns": {...},
        },
    )


@app.route("/employee_landing", methods=["GET", "POST"])
def employee_landing():
    push_message('1', 'You have hit the employee landing page.')
    return render_template("employee_landing.html")

@app.route("/")
@login_required
def landing():
    try:
        if current_user.username not in ALLOWED_USERS:
            print("NOt allowed")
            return render_template("landing.html")
    except:
        return url_for("login")

    else:
        return render_template("main_landing.html")
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=True)
            flash("Login successful!", "success")

            # NEW: honour ?next= if it is a safe relative URL
            next_page = request.args.get("next")
            if not next_page or not next_page.startswith("/"):

                next_page = url_for("scan")
                if current_user.username in ALLOWED_USERS:
                    next_page = url_for("main_landing")

            return redirect(next_page)
        else:
            flash("Invalid credentials. Please try again.", "danger")

    # GET or failed POST
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

@app.route("/scan")
@login_required  # Require login to access this page
def scan():
    return render_template("scan.html")

@app.route("/process_card/<card_id>", methods=["GET", "POST"])
def process_card(card_id):
    trans = pd.DataFrame(
        db.session.query(
            Transactions.amount, Transactions.transaction_type, Transactions.added
        )
        .filter(Transactions.card_id == card_id)
        .all(),
        columns=["amount", "transaction_type", "transaction_date"],
    )
    this_pin = (
        db.session.query(CustomerPin.pin).filter(CustomerPin.card_id == card_id).all()
    )
    if len(this_pin) > 0:
        has_pin = True
    else:
        has_pin = False
    if len(trans) == 0:
        return render_template("cards.html", balance=0, trans=dict(), card_id=card_id)
    t_d = list()
    for i, r in trans.iterrows():
        if r.transaction_type.strip().lower() == "abono":
            t_type = "Abono"
        else:
            t_type = "Gasto"
        t_d.append(
            {"type": t_type, "amount": r.amount, "transaction_date": r.transaction_date}
        )

    cur_bal = trans["amount"].sum()
    print("Scanning.")
    return render_template(
        "cards.html", balance=cur_bal, trans=t_d, card_id=card_id, pin_created=has_pin
    )


@app.route("/process_card_admin/<card_id>", methods=["GET", "POST"])
@login_required  # Require login to access this page
def process_card_admin(card_id):
    trans = pd.DataFrame(
        db.session.query(
            Transactions.amount, Transactions.transaction_type, Transactions.added
        )
        .filter(Transactions.card_id == card_id)
        .all(),
        columns=["amount", "transaction_type", "transaction_date"],
    )

    if len(trans) == 0:
        return render_template(
            "cards_admin.html", balance=0, trans=dict(), card_id=card_id
        )
    t_d = list()
    for i, r in trans.iterrows():
        if r.transaction_type.strip().lower() == "abono":
            t_type = "Abono"
        else:
            t_type = "Gasto"
        t_d.append(
            {"type": t_type, "amount": r.amount, "transaction_date": r.transaction_date}
        )

    cur_bal = trans["amount"].sum()
    print("Scanning.")
    return render_template(
        "cards_admin.html", balance=cur_bal, trans=t_d, card_id=card_id
    )


@app.route("/save_pin/", methods=["GET", "POST"])
def save_pin():
    card_id = request.form.get("card_id")
    phone = request.form.get("phoneNumber")
    pin = request.form.get("pinNumber")
    fi = CustomerPin(
        phone_number=int(phone),
        pin=int(pin),
        card_id=card_id,
        added=datetime.now(timezone.utc),
    )
    db.session.add(fi)
    db.session.commit()
    return redirect(url_for("process_card", card_id=card_id, pin_created=True))


@app.route("/add_transaction")
@login_required  # Require login to access this page
def add_transaction():
    print("Scanning.")
    return render_template("scan.html")


@app.route("/register_expense/", methods=["GET", "POST"])
@login_required  # Require login to access this page
def register_expense():
    card_id = request.args.get("card_id")
    print(card_id)
    custo_pin = (
        db.session.query(CustomerPin.pin).filter(CustomerPin.card_id == card_id).all()
    )
    print(custo_pin)
    if len(custo_pin) > 0:
        has_pin = True
    else:
        has_pin = False

    trans = pd.DataFrame(
        db.session.query(
            Transactions.amount, Transactions.transaction_type, Transactions.added
        )
        .filter(Transactions.card_id == card_id)
        .all(),
        columns=["amount", "transaction_type", "transaction_date"],
    )

    cur_bal = trans["amount"].sum()

    return render_template(
        "register_expense.html", card_id=card_id, pin_created=has_pin, cur_bal=cur_bal
    )


@app.route("/register_abono/", methods=["GET", "POST"])
@login_required  # Require login to access this page
def register_abono():
    card_id = request.args.get("card_id")
    return render_template("register_abono.html", card_id=card_id, error=False)


@app.route("/save_abono/", methods=["GET", "POST"])
@login_required  # Require login to access this page
def save_abono():
    card_id = request.form.get("card_id")
    pin = request.form.get("pin")
    amount = request.form.get("amount")
    if pin is not None:
        pin = int(pin)
        all_pins = pd.DataFrame(db.session.query(WorkerPin.pin).all(), columns=["pin"])
        all_pins = [int(x) for x in all_pins.pin.tolist()]
        if pin not in all_pins:
            print(pin)
            return render_template("register_abono.html", card_id=card_id, error="true")
        else:
            amount = int(amount)
            fi = Transactions(
                card_id=card_id,
                transaction_type="Abono",
                added=datetime.now(timezone.utc),
                amount=amount,
            )
            db.session.add(fi)
            db.session.commit()

            return redirect(url_for("process_card_admin", card_id=card_id))

    card_id = request.args.get("card_id")
    print(card_id)

    return render_template("register_abono.html", card_id=card_id)


@app.route("/save_expense/", methods=["GET", "POST"])
@login_required  # Require login to access this page
def save_expense():
    card_id = request.form.get("card_id")
    amount = request.form.get("amount")
    trans = pd.DataFrame(
        db.session.query(
            Transactions.amount, Transactions.transaction_type, Transactions.added
        )
        .filter(Transactions.card_id == card_id)
        .all(),
        columns=["amount", "transaction_type", "transaction_date"],
    )

    cur_bal = trans["amount"].sum()
    custo_pin = (
        db.session.query(CustomerPin.pin).filter(CustomerPin.card_id == card_id).all()
    )
    if len(custo_pin) > 0:
        pin = request.form.get("pin")
        if int(pin) != int(custo_pin[0][0]):
            return render_template(
                "register_expense.html",
                card_id=card_id,
                error=True,
                pin_created=True,
                cur_bal=cur_bal,
            )

    if float(amount) > cur_bal:
        return render_template(
            "register_expense.html",
            card_id=card_id,
            error=False,
            bal_error=True,
            pin_created=True,
            cur_bal=cur_bal,
        )

    amount = float(amount)
    amount = -amount
    fi = Transactions(
        card_id=card_id,
        transaction_type="Gasto",
        added=datetime.now(timezone.utc),
        amount=amount,
    )
    db.session.add(fi)
    db.session.commit()

    return redirect(
        url_for("process_card_admin", card_id=card_id)
    )  # Pass the ID as a parameter


@login_required
@app.route("/admin_log_expense", methods=["GET", "POST"])
def admin_log_expense():
    return render_template("admin_registrar_gasto.html")


@app.post("/extract_receipt_api")
def extract_receipt_api():
    from receipt_utils import extract_receipts

    blobs = [f.read() for f in request.files.getlist("receipts")]
    if not blobs:
        return jsonify({"error": "no files"}), 400
    return jsonify(json.loads(extract_receipts(blobs)))


@app.route("/admin_registrar_gasto", methods=["GET", "POST"])
def admin_registrar_gasto():
    # ------------------------------------------------------------------ POST
    if request.method == "POST":
        try:
            amount_raw = (request.form.get("amount", "0") or "0").replace(",", "")
            amount = float(decimal.Decimal(amount_raw))

            vendor = request.form.get("vendor", "").strip()
            pay_meth = request.form.get("payment_method")
            factura = request.form.get("factura") == "si"

            expense_cat = request.form.get("expense_category")

            details_json = request.form.get("raw_json") or "{}"
            details = json.loads(details_json)

            txn_date = details.get("date") or request.form.get("transaction_date")
            txn_date = datetime.fromisoformat(txn_date) if txn_date else None

            username = getattr(current_user, "username", None)

            expense = Expenses(
                vendor=vendor,
                amount=amount,
                details=details,
                transaction_date=txn_date,
                submit_date=datetime.utcnow(),
                factura=factura,
                payment_method=pay_meth,
                category=expense_cat,
                biz_area=None,
                reference_file_paths=[],
                username=username,
            )
            db.session.add(expense)
            db.session.flush()  # get expense.id for uploads

            keys = []
            for f in request.files.getlist("receipts"):
                if f and f.filename:
                    keys.append(upload_receipt(f, expense.id))
            expense.reference_file_paths = keys
            db.session.commit()

            flash("Gasto guardado correctamente.", "success")
        except (ValueError, decimal.InvalidOperation):
            db.session.rollback()
            flash("Datos inválidos: verifica monto y categorías.", "danger")
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception("DB error saving expense")
            flash("Error de base de datos.", "danger")
        except Exception as e:
            db.session.rollback()
            app.logger.exception("Unexpected error")
            return jsonify({"error": "server_error", "details": str(e)}), 500

        return redirect(url_for("admin_registrar_gasto"))  # stay on page

    cst = pytz.timezone("America/Mexico_City")
    now = datetime.now(cst)
    start_of_month = now.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    ).replace(tzinfo=None)
    end_of_today = now.replace(
        hour=23, minute=59, second=59, microsecond=999999
    ).replace(tzinfo=None)

    # 2) fetch expenses
    rows = (
        db.session.query(Expenses)
        .filter(
            Expenses.transaction_date >= start_of_month,
            Expenses.transaction_date <= end_of_today,
        )
        .order_by(Expenses.transaction_date.desc())
        .all()
    )

    total_amount = sum(r.amount for r in rows)

    # 3) render the same template you already use to create expenses
    return render_template(
        "admin_registrar_gasto.html",
        data=rows,
        total_amount=total_amount,
        start_date=start_of_month.date().isoformat(),
        end_date=end_of_today.date().isoformat(),
    )


from polo_utils import pull_polo_products

@app.route("/match_polo_products", methods=["GET", "POST"])
def match_polo_products():
    return jsonify({'hello'})

@app.route("/refresh_products", methods=["GET", "POST"])
def refresh_products():
    from polo_utils import pull_polo_mods

    cur_prods = pd.DataFrame(
        db.session.query(
            PoloProducts.id,
            PoloProducts.product_name,
            PoloProducts.polo_id,
            PoloProducts.description,
        ).all()
    )
    polo_prods = pull_polo_products()
    polo_prods = pd.DataFrame(polo_prods, columns=["name", "description", "polo_id"])
    polo_prods["modifier"] = False
    polo_mods = list()
    mod_ids = [
        "ed59a5bf-f9b6-4d72-b98e-11ba9b47d8e6",
        "55e38e78-53cd-4b18-a9c8-5d5daf487433",
    ]
    for mod in mod_ids:
        these_mods = pull_polo_mods(prod_id=mod)
        polo_mods.extend(these_mods)
    polo_mods = pd.DataFrame(polo_mods, columns=["name", "description", "polo_id"])
    polo_mods["modifier"] = True

    polo_prods = pd.concat([polo_prods, polo_mods]).reset_index(drop=True)
    print(polo_mods)
    for i, r in polo_prods.iterrows():
        if r.polo_id not in cur_prods.polo_id.tolist():
            fi = PoloProducts(
                product_name=r["name"],
                description=r.description,
                polo_id=r.polo_id,
                modifier=r.modifier,
                added=datetime.utcnow(),
            )
            db.session.add(fi)
        db.session.commit()
    return jsonify({"added": True})


@app.route("/upload_menu", methods=["GET", "POST"])
def upload_menu():
    return render_template("scan_menu.html")


@app.route("/extract_menu_api", methods=["POST"])
def extract_menu_api():
    from product_utils import extract_products

    blobs = [f.read() for f in request.files.getlist("menu_files")]
    if not blobs:
        return jsonify({"error": "no files"}), 400
    return jsonify(json.loads(extract_products(blobs)))


@app.route("/save_menu_products", methods=["POST"])
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

    db.session.query(Menus).update({"active": False})
    db.session.commit()

    # Example: print or save to DB
    for product in product_list:
        fi = Menus(
            product_name=product.get("name"),
            description=product.get("description"),
            price=product.get("price"),
            added=datetime.utcnow(),
            menu_version=wy,
            active=True,
        )
        db.session.add(fi)
    db.session.commit()
    return "Products received"

@app.route("/enter_production_counts", methods=["GET", "POST"])
def enter_production_counts():
    menu_items = pd.DataFrame(
        db.session.query(Menus.product_name, Menus.id)
        .filter(Menus.active == True)
        .all()
    )
    d = list()
    for i, r in menu_items.iterrows():
        d.append({"product_name": r.product_name, "id": r.id})

    return render_template(
        "production_counts.html", menu_items=d, selected_date=date.today().isoformat()
    )


@app.route("/save_production_counts", methods=["GET", "POST"])
def save_production_counts():
    # ── 1.  Constants / helpers ─────────────────────────────────
    cst_tz = pytz.timezone("America/Mexico_City")

    # ── 2.  Read scalar form fields ─────────────────────────────
    masa_global = request.form.get("masa_global", type=int, default=1)

    # Pick the user-selected date or default to today
    report_date_str = request.form.get("report_date", "")  # '' if missing
    if report_date_str:
        try:
            report_date = datetime.strptime(report_date_str, "%Y-%m-%d").date()
        except ValueError:
            report_date = date.today()  # bad format → today
    else:
        report_date = date.today()

    added_dt = datetime.combine(report_date, time.min)  # 00:00
    added_dt_naive = cst_tz.localize(added_dt).replace(tzinfo=None)

    # ── 3.  Look-up helpers ────────────────────────────────────
    menu_items = pd.DataFrame(
        db.session.query(Menus.id, Menus.product_name)
        .filter(Menus.active == True)
        .all()
    )
    id_to_prod = dict(zip(menu_items.id.tolist(), menu_items.product_name.tolist()))

    # ── 4.  POST: persist counts ───────────────────────────────
    if request.method == "POST":
        counts_by_id = {}
        for key, val in request.form.items():
            if key.startswith("counts[") and key.endswith("]"):
                prod_id = int(key[len("counts[") : -1])
                try:
                    qty = int(val)
                except (ValueError, TypeError):
                    qty = 0
                counts_by_id[prod_id] = qty

        for prod_id, qty in counts_by_id.items():
            product_name = id_to_prod.get(prod_id)
            db.session.add(
                ProductionCounts(
                    product_name=product_name,
                    n_items=qty,
                    added=added_dt_naive,
                    dough_amount=masa_global,
                )
            )

        db.session.commit()

        return "Products received"


@app.route("/enter_merma_counts", methods=["GET", "POST"])
def enter_merma_counts():
    menu_items = pd.DataFrame(
        db.session.query(Menus.product_name, Menus.id)
        .filter(Menus.active == True)
        .all()
    )
    d = list()
    for i, r in menu_items.iterrows():
        d.append({"product_name": r.product_name, "id": r.id})

    print(d)

    return render_template("merma_counts.html", menu_items=d)


@app.route("/save_merma_counts", methods=["GET", "POST"])
def save_merma_counts():
    cst = pytz.timezone("America/Mexico_City")
    now_cst = datetime.now(cst)

    naive_cst = now_cst.replace(tzinfo=None)

    menu_items = pd.DataFrame(
        db.session.query(Menus.id, Menus.product_name)
        .filter(Menus.active == True)
        .all()
    )
    id_to_prod = dict(zip(menu_items.id.tolist(), menu_items.product_name.tolist()))
    if request.method == "POST":
        merma_counts = {}

        # 1) Extract all form fields like "merma[15]" → {15: qty}
        for key, val in request.form.items():
            if key.startswith("merma[") and key.endswith("]"):
                # pull out the ID between the brackets
                id_str = key[len("merma[") : -1]
                try:
                    item_id = int(id_str)
                    qty = int(val)
                except (ValueError, TypeError):
                    continue
                merma_counts[item_id] = qty

        for k, v in merma_counts.items():
            n = id_to_prod.get(k)
            fi = MermaCounts(product_name=n, n_items=v, added=naive_cst)
            db.session.add(fi)

        db.session.commit()

        return "Products received"

@app.route("/merma_dashboard")
def merma_dashboard():

    today_str = datetime.now().strftime("%Y-%m-%d")

    start_str = request.args.get("start_date", today_str)
    end_str = request.args.get("end_date", start_str)  # default: same day

    try:
        start_date = datetime.strptime(start_str, "%Y-%m-%d").date()
    except ValueError:
        print("Defaulting to today")
        start_date = datetime.today().date()

    try:
        end_date = datetime.strptime(end_str, "%Y-%m-%d").date()
    except ValueError:
        print("rror conversion...")
        end_date = start_date

    start_dt = datetime.combine(start_date, datetime.min.time())

    end_dt = datetime.combine(end_date, datetime.max.time())

    prod_df = pd.DataFrame(
        db.session.query(
            ProductionCounts.product_name,
            ProductionCounts.n_items.label("n_prod"),
            ProductionCounts.added,
        )
        .filter(ProductionCounts.added.between(start_dt, end_dt))
        .all()
    )

    merma_df = pd.DataFrame(
        db.session.query(
            MermaCounts.product_name,
            MermaCounts.n_items.label("n_merma"),
            MermaCounts.added,
        )
        .filter(MermaCounts.added.between(start_dt, end_dt))
        .all()
    )

    if not merma_df.empty:
        merma_df["date"] = merma_df["added"].dt.normalize()  # 2025-05-29 00:00:00
        merma_df = merma_df.sort_values(
            ["product_name", "added"]
        ).drop_duplicates(  # newest row goes last
            subset=["product_name", "date"], keep="last"
        )[
            ["product_name", "n_merma"]
        ]  # final tidy columns

    # ---------- 2.  Deduplicate PRODUCCIÓN by product + day ----------
    if not prod_df.empty:
        prod_df["date"] = prod_df["added"].dt.normalize()
        prod_df = prod_df.sort_values(["product_name", "added"]).drop_duplicates(
            subset=["product_name", "date"], keep="last"
        )[["product_name", "n_prod", "date"]]

    prods = prod_df.drop_duplicates(subset=["product_name"]).reset_index(drop=True)
    data = list()
    for i, r in prods.iterrows():
        if len(merma_df) > 0:
            tmp_merma = merma_df[merma_df.product_name == r.product_name]
            if len(tmp_merma) > 0:
                # n_merma = tmp_merma.iloc[0]['n_merma']
                n_merma = tmp_merma["n_merma"].sum()
            else:
                n_merma = -1
        else:
            n_merma = 0
        if len(prod_df) > 0:
            tmp_prod = prod_df[prod_df.product_name == r.product_name]
            if len(tmp_prod) > 0:
                n_prod = tmp_prod.iloc[0]["n_prod"]
                n_prod = tmp_prod["n_prod"].sum()
            else:
                n_prod = 0
        else:
            n_prod = 0

        data.append(
            {
                "product_name": r.product_name,
                "merma_count": n_merma,
                "production_count": n_prod,
                "sales_count": 0,
            }
        )

    return render_template("merma_dashboard.html", data=data)

@app.route("/expenses_dashboard")
def expenses_dashboard():
    # ── 1) Zona UTC y fecha/hora “ahora” ─────────────────────────────
    utc = pytz.utc
    now_utc = datetime.utcnow().replace(tzinfo=utc)

    # ── 2) Límites por defecto: 1 de mes-actual 00:00 → último día 23:59 ─
    first_of_month = now_utc.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    _, days_in_month = calendar.monthrange(now_utc.year, now_utc.month)
    last_of_month = now_utc.replace(
        day=days_in_month, hour=23, minute=59, second=59, microsecond=999999
    )

    default_start = first_of_month
    default_end = last_of_month

    # ── 3) Leer query-params (YYYY-MM-DD) ────────────────────────────
    start_str = request.args.get("start_date")
    end_str = request.args.get("end_date")

    # ── 4) Parsear fechas o caer en los defaults ─────────────────────
    if start_str:
        try:
            dt = datetime.strptime(start_str, "%Y-%m-%d")
            start_dt = utc.localize(datetime.combine(dt.date(), time.min))
        except ValueError:
            start_dt = default_start
    else:
        start_dt = default_start

    if end_str:
        try:
            dt = datetime.strptime(end_str, "%Y-%m-%d")
            end_dt = utc.localize(datetime.combine(dt.date(), time.max))
        except ValueError:
            end_dt = default_end
    else:
        end_dt = default_end

    # ── 5) Consultar la BD ───────────────────────────────────────────
    expenses = (
        db.session.query(Expenses)
        .filter(
            Expenses.transaction_date >= start_dt, Expenses.transaction_date <= end_dt
        )
        .order_by(Expenses.transaction_date)
        .all()
    )

    # ── 6) Total y render ────────────────────────────────────────────
    total_amount = sum(e.amount for e in expenses)

    return render_template(
        "expense_dashboard.html",
        data=expenses,
        total_amount=total_amount,
        start_date=start_dt.date().isoformat(),
        end_date=end_dt.date().isoformat(),
    )

def clean_key(raw: str) -> str:
    raw = raw.strip().lstrip("/")
    if (raw.startswith('"') and raw.endswith('"')) or (
        raw.startswith("'") and raw.endswith("'")
    ):
        raw = raw[1:-1]
    return raw

@app.route("/expense/<int:expense_id>/receipt/<int:index>")
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
    ext = os.path.splitext(key)[1].lower()
    is_pdf = ext == ".pdf"
    mime = (
        "application/pdf"
        if is_pdf
        else mimetypes.guess_type(key)[0] or "application/octet-stream"
    )

    # Stream body so large files don’t sit in memory
    body_iter = stream_with_context(obj["Body"].iter_chunks())

    headers = {
        "Content-Type": mime,
        "Content-Disposition": f'inline; filename="{os.path.basename(key)}"',
        "Content-Length": obj["ContentLength"],
    }
    return Response(body_iter, headers=headers)

@app.route("/expense/<int:expense_id>")
def expense_detail(expense_id: int):
    exp = db.session.get(Expenses, expense_id)
    if exp is None:
        abort(404)

    # 1. parse JSONB safely
    details = (
        exp.details
        if isinstance(exp.details, dict)
        else json.loads(exp.details or "{}")
    )
    items = (details.get("receipts", [{}])[0]).get("items", [])

    raw_keys = exp.reference_file_paths or []
    if isinstance(raw_keys, str):
        raw_keys = json.loads(raw_keys)

    files = []
    for i, raw in enumerate(raw_keys):
        key = clean_key(raw)
        ext = os.path.splitext(key)[1].lower()
        mime = mimetypes.guess_type(key)[0] or ""
        kind = "pdf" if mime == "application/pdf" else "image"
        files.append({"idx": i, "kind": kind})

    # Force correct MIME for PDFs
    ext = os.path.splitext(key)[1].lower()
    mime = (
        "application/pdf"
        if ext == ".pdf"
        else mimetypes.guess_type(key)[0] or "application/octet-stream"
    )

    obj = _spaces.get_object(Bucket=spaces_bucket_name, Key=key)
    data = io.BytesIO(obj["Body"].read())
    # 3. render page
    return render_template(
        "expense_detail.html",
        expense=exp,
        details=details,
        items=items,
        files=files,
    )

@app.post("/delete_expense/<int:expense_id>")
def delete_expense(expense_id: int):
    db.session.query(Expenses).filter(Expenses.id == expense_id).delete()
    db.session.commit()
    return redirect(url_for("expenses_dashboard"))

@app.route("/create_inventory_item", methods=["GET", "POST"])
@login_required
def create_inventory_item():
    return render_template("create_inventory_item.html")

@app.post("/save_inventory_item")
@login_required
def save_inventory_item():
    """
    Accepts:
      • JSON: sent by the single-page dashboard (Content-Type: application/json)
      • Form data: fallback for the old <form method="POST"> page
    Returns:
      JSON describing the newly created product
    """

    # ---------- 1. Read input (JSON first, else form) ----------
    if request.is_json:
        data = request.get_json(silent=True) or {}
        product_area = data.get("product_area")
        product_category = data.get("product_category")
        product_name = (data.get("product_name") or "").strip()
        measure = data.get("measure")
        details = data.get("details", "")
    else:
        # legacy form fields
        product_area = request.form.get("product_area")
        product_category = (
            request.form.get("product_category") == "_new"
            and request.form.get("new_category")
            or request.form.get("product_category")
        )
        measure = (
            request.form.get("measure") == "_new"
            and request.form.get("new_measure")
            or request.form.get("measure")
        )
        product_name = request.form.get("product_name", "").strip()
        details = request.form.get("details", "")

    # ---------- 2. Basic validation ----------
    if not all([product_area, product_category, product_name, measure]):
        abort(400, "Missing required fields")

    # ---------- 3. Create DB row ----------
    username = getattr(current_user, "username", None)
    new = InventoryProducts(
        product_area=product_area.lower(),
        product_category=product_category.lower(),
        product_name=product_name,
        measure=measure.lower(),
        details=details,
        username=username,
        added=datetime.now(),
    )
    db.session.add(new)
    db.session.commit()

    # flash only for classic form submits
    if not request.is_json:
        flash("Artículo guardado.", "success")

    # ---------- 4. JSON response for front-end ----------
    return (
        jsonify(
            id=new.id,
            area=new.product_area,
            category=new.product_category,
            name=new.product_name,
            measure=new.measure,
            details=new.details,
            tienda=None,
            bodega=None,
        ),
        201,
    )
    return redirect(url_for("create_inventory_item"))

def build_inventory():
    # 1. products ---------------------------------------------------
    prows = db.session.query(
        InventoryProducts.id,
        InventoryProducts.product_area,
        InventoryProducts.product_category,
        InventoryProducts.product_name,
        InventoryProducts.details,
        InventoryProducts.measure,
        InventoryProducts.added,  # ← new
        InventoryProducts.username,  # ← new
    ).all()

    # 2. summed counts ---------------------------------------------
    crows = (
        db.session.query(
            InventoryCounts.product_id,
            InventoryCounts.location,
            func.sum(cast(InventoryCounts.value, Numeric)).label("total"),
        )
        .group_by(InventoryCounts.product_id, InventoryCounts.location)
        .all()
    )
    counts = defaultdict(dict)
    for pid, loc, total in crows:
        counts[pid][loc] = total

    # 3. merge ------------------------------------------------------
    inventory = []
    for r in prows:
        pid = r.id
        inventory.append(
            dict(
                id=pid,
                area=r.product_area,
                category=r.product_category,
                name=r.product_name,
                measure=r.measure,
                details=r.details,
                added=r.added.strftime("%d/%m/%Y %H:%M"),  # → “05/06/2025 13:45”
                user=r.username or "—",
                tienda=counts.get(pid, {}).get("tienda"),
                bodega=counts.get(pid, {}).get("bodega"),
            )
        )
    return inventory

@app.get("/inventory_dashboard")
@login_required
def inventory_dashboard():
    inventory = build_inventory()  # your existing helper
    return render_template("inventory_dashboard.html", inventory=inventory)

@app.post("/inventory/<int:item_id>/value")
@login_required
def save_inventory_value(item_id: int):
    """
    Receives JSON: {"value": 12.5}
    Saves that numeric value for the given inventory item.
    """
    item = db.session.get(InventoryProducts, item_id) or abort(404)

    data = request.get_json(silent=True) or {}
    try:
        val = float(data["value"])
        if val < 0:
            raise ValueError
    except (KeyError, ValueError, TypeError):
        return {"error": "invalid_value"}, 400

    location = data.get("location", "tienda").lower()
    if location not in {"tienda", "bodega"}:
        return {"error": "invalid_location"}, 400
    username = getattr(current_user, "username", None)

    # Example: insert a movement / update stock
    mv = InventoryCounts(
        product_id=item.id,
        value=val,
        location=location,
        username=username,
        added=datetime.now(),
    )
    db.session.add(mv)
    db.session.commit()
    return {"ok": True}, 201


@app.post("/update_inventory_item/<int:item_id>")
@login_required
def update_inventory_item(item_id):
    data = request.get_json(silent=True) or {}
    item = db.session.get(InventoryProducts, item_id) or abort(404)

    for fld in (
        "product_area",
        "product_category",
        "product_name",
        "measure",
        "details",
    ):
        if fld in data and data[fld] is not None:
            setattr(
                item,
                fld,
                (
                    data[fld].strip().lower()
                    if fld != "product_name"
                    else data[fld].strip()
                ),
            )

    item.username = getattr(current_user, "username", None)
    item.added = datetime.now()
    db.session.commit()

    return jsonify(
        id=item.id,
        area=item.product_area,
        category=item.product_category,
        name=item.product_name,
        measure=item.measure,
        details=item.details,
        added=item.added.strftime("%d/%m/%Y %H:%M"),
        user=item.username,
    )


@app.route("/cash_count")
def cash_count():
    return render_template("cash_count.html")

@app.route("/save_cash_count", methods=["POST"])
def save_cash_count():
    print("HR")
    cashier = (request.form.get("cashier") or "").strip()
    if not cashier:
        flash("El nombre del cajero es obligatorio.", "danger")
        return redirect(request.referrer or "/")

    # ── NEW: one shared timestamp for this submission ──
    batch_time = datetime.now(MX_TZ)

    rows = []
    for key, raw_qty in request.form.items():
        if key.startswith("counts[") and key.endswith("]"):
            try:
                denom = int(key[7:-1])
                qty = int(raw_qty or 0)
            except ValueError:
                continue

            if qty > 0:
                rows.extend(
                    ChangeCount(
                        username=cashier, denomination=denom, added=batch_time
                    )  # ← same for every row
                    for _ in range(qty)
                )

    if not rows:
        flash("No se ingresaron cantidades mayores a 0.", "warning")
        return redirect(request.referrer or "/")
    print(rows)
    db.session.add_all(rows)
    db.session.commit()
    flash("Conteo guardado correctamente.", "success")
    return redirect("/")

@login_required
@username_required
@app.route("/cash_count_registers", methods=["GET"])
def cash_count_registers():
    """
    Overview page – one row per submission with the summed total.
    """
    raw = (
        db.session.query(
            ChangeCount.username,
            ChangeCount.added,
            func.sum(ChangeCount.denomination).label("total_mxn"),
        )
        .group_by(ChangeCount.username, ChangeCount.added)
        .order_by(ChangeCount.added.desc())
        .all()
    )

    registers = [
        {
            "username": r.username,
            "added_local": r.added.astimezone(MX_TZ),
            "added_iso": r.added.isoformat(),  # key for URL
            "total_mxn": int(r.total_mxn),
        }
        for r in raw
    ]

    return render_template("cash_count_registers.html", registers=registers)


@login_required
@username_required
@app.route("/cash_count_register/<username>/<path:added_iso>", methods=["GET"])
def cash_count_register_detail(username, added_iso):
    """
    Detail page for a single register (submission).
    URL carries <username> and <added_iso> (the exact timestamp string).
    """
    try:
        added_dt = datetime.fromisoformat(added_iso)
    except ValueError:
        abort(404)

    rows = (
        db.session.query(ChangeCount.denomination, func.count().label("qty"))
        .filter(ChangeCount.username == username, ChangeCount.added == added_dt)
        .group_by(ChangeCount.denomination)
        .order_by(ChangeCount.denomination)
        .all()
    )

    if not rows:
        abort(404)

    detail = [
        {"denom": r.denomination, "qty": r.qty, "subtotal": r.denomination * r.qty}
        for r in rows
    ]
    total = sum(d["subtotal"] for d in detail)

    return render_template(
        "cash_count_register_detail.html",
        username=username,
        added_local=added_dt.astimezone(MX_TZ),
        detail=detail,
        total=total,
    )


# routes.py ― employee view
@app.route("/insumos/request_form", methods=["GET"])
def insumo_form():
    push_message('1', 'You have hit the insumos page.')
    employees = ["Karina", "Andy", "Paco", "David", "Fanny", "Tony", "Otro"]
    return render_template("insumo_request.html", employees=employees)


# routes.py  – imports near the top of the file
from concurrent.futures import ThreadPoolExecutor
from app import app, db



# one shared pool (4 workers is plenty for a few pushes per request)
push_pool = ThreadPoolExecutor(max_workers=4)

def _send_webpush(subscription: dict, payload: dict):
    return True


# ─────────── Route ───────────────────────────────────────
@app.post("/insumos/request")
def create_insumo_request():
    """Create a new InsumoRequest and kick off web-pushes asynchronously."""
    data = request.get_json(force=True)

    # 1.  Create + commit the request
    req = InsumoRequest(
        employee = data["employee"],
        name     = data["insumo"],
        measure  = data["measure"],
        quantity = float(data["quantity"]),
        urgency  = data["urgency"],
        notes    = data.get("notes"),
    )
    db.session.add(req)
    db.session.commit()

    # 2.  Prepare  payload once
    payload = {
        "title":   "Nueva solicitud de insumo",
        "body":    f"{req.employee} pidió {req.quantity} {req.measure} de {req.name}",
        "urgency": req.urgency,
        "id":      req.id,
    }

    # 3.  Enqueue pushes (non-blocking)
    recipients = ["steven", "andre", "adriana", "romina"]
    for username in recipients:
        user = db.session.execute(
            db.select(User).filter_by(username=username)
        ).scalar_one_or_none()

        if user and user.push_subscription:
            push_pool.submit(_send_webpush, user.push_subscription, payload)

    # 4.  Immediate 204 → front-end shows success without delay
    return ("", 204)

@app.route("/admin/insumos")
@login_required
def admin_insumos():
    reqs = (
        db.session.query(InsumoRequest).order_by(InsumoRequest.created_at.desc()).all()
    )
    employees = ["steven", "adriana", "andre", "romina"]
    return render_template("admin_insumos.html", reqs=reqs, employees=employees)

@app.route("/insumo/events")
def insumo_events():
    return Response(
        stream_with_context(assignment_event_stream()), mimetype="text/event-stream"
    )


@app.post("/admin/insumos/<int:req_id>/assign")
@login_required
def assign_insumo(req_id: int):
    """Assign an insumo request to an employee and send a push alert."""
    # ── 1. Find the request row ────────────────────────────────────────────
    req = db.session.get(InsumoRequest, req_id)
    if req is None:
        abort(404, description="Solicitud no encontrada")

    # ── 2. Get assignee from form (came from the modal) ────────────────────
    assignee = request.form.get("assigned_to", "").strip()
    if not assignee:
        flash("Debes seleccionar un empleado.", "danger")
        return redirect(url_for("admin_insumos"))

    user = db.session.execute(
        select(User).filter_by(username=assignee)
    ).scalar_one_or_none()
    if user is None:
        flash("Empleado no encontrado.", "danger")
        return redirect(url_for("admin_insumos"))

    # ── 3. Update DB row ───────────────────────────────────────────────────
    req.assigned_to = assignee
    req.status      = "asignado"        # keep in sync with the ENUM
    db.session.commit()
    emp_id = db.session.query(User.id).filter(User.username == assignee).one()
    print(emp_id[0])
    push_message(str(emp_id[0]), 'Te asignaron un insumo')

    # ── 4. Push notification (fire-and-forget) ────────────────────────────
    payload = {
        "title": f"Insumo asignado: {req.name}",
        "body":  f"{req.quantity} {req.measure} — urgencia {req.urgency}",
        "url":   "/admin/insumos"
    }
    # send_push_insumo(user, payload)     # wrap in try/except inside helper

    flash("Insumo asignado correctamente.", "success")
    return redirect(url_for("admin_insumos"))





from flask import send_from_directory, make_response

@app.route("/service-worker.js")
def service_worker():
    static_dir = Path(app.root_path) / "static"
    response   = send_from_directory(
        static_dir,
        "service_worker.js",
        mimetype="text/javascript"
    )
    # Optional: force re-fetch on each deploy
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"]        = "no-cache"
    response.headers["Expires"]       = "0"
    return response

# routes.py  – replace the old update_insumo_status function
from flask import request, redirect, flash, url_for, current_app, abort
from flask_login import login_required
from sqlalchemy import select

from app import db
from models import InsumoRequest          # adjust path as needed


@app.route("/admin/insumos/<int:req_id>/status", methods=["POST"])
@login_required
def update_insumo_status(req_id: int):
    """
    Update the status of an InsumoRequest.
    Works with vanilla SQLAlchemy (no Model.query helper).
    """
    # ── 1. fetch or 404 ──────────────────────────────────────────
    stmt = select(InsumoRequest).where(InsumoRequest.id == req_id)
    req  = db.session.scalar(stmt)        # returns None if not found
    if req is None:
        abort(404)

    # ── 2. validate new status ───────────────────────────────────
    new_status = request.form.get("status", "").strip().lower()
    allowed = current_app.config.get(
        "INSUMO_STATUSES",
        ["pendiente", "en progreso", "completado", "cancelado"]
    )
    if new_status not in allowed:
        flash("Estado no válido.", "danger")
        return redirect(request.referrer or url_for("insumos_admin"))

    # ── 3. apply + commit ────────────────────────────────────────
    if new_status != req.status:
        req.status = new_status
        db.session.commit()
        flash(f"Estado actualizado a «{new_status}».", "success")
    else:
        flash("El estado ya estaba actualizado.", "info")

    return redirect(request.referrer or url_for("insumos_admin"))

if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)
