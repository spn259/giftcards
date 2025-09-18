
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
GOOGLE_MAPS_API_KEY = os.environ["GOOGLE_MAPS_API_KEY"]
AUSTIN_DONUT_API_KEY =  os.environ["AUSTIN_DONUT_API_KEY"]


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
    
    @property
    def is_employee(self): return False
    @property
    def is_admin(self):    return True
    

@login_manager.user_loader
def load_user(user_id: str):
    """Restore the correct user object from the session cookie."""
    # ── ① admin ids are plain integers ───────────────────────────
    if user_id.isdigit():
        return User.query.get(int(user_id))

    # ── ② employee ids are “emp-<int>” ──────────────────────────
    if user_id.startswith("emp-"):
        try:
            worker_id = int(user_id.split("-", 1)[1])   # "emp-6" → 6
        except (IndexError, ValueError):
            return None
        row = db.session.get(WorkerPin, worker_id)
        return EmployeeProxy(row) if row else None

    # anything else → anonymous
    return None


ALLOWED_USERS = {"steven", "romina", "adriana", "andre"}
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)
app.config.update(
    REMEMBER_COOKIE_SECURE=True,  # HTTPS only
    REMEMBER_COOKIE_HTTPONLY=True,
    REMEMBER_COOKIE_SAMESITE="Lax",
)

class EmployeeProxy(UserMixin):
    """Wraps a WorkerPin row so Flask-Login can track it."""
    def __init__(self, row: WorkerPin):
        self._row = row
        self.id   = f"emp-{row.id}"          # unique session id
        self.name = row.worker_name
    
    def get_id(self):           # override for clarity
        return self.id  

    # flags for convenience
    @property
    def is_employee(self): return True
    @property
    def is_admin(self):    return False

from functools import wraps
from flask import request, redirect, url_for, abort
from flask_login import current_user

def employee_required(view):
    """Only allow authenticated employees."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        # ① not signed in → go to the employee login page
        if not current_user.is_authenticated:
            return redirect(url_for("employee_login", next=request.url))

        # ② signed in but wrong role
        if not getattr(current_user, "is_employee", False):
            return abort(403)

        # ③ all good
        return view(*args, **kwargs)

    return wrapped

from flask import render_template, request, flash

@app.route("/employee_login", methods=["GET", "POST"])
def employee_login():
    # # already logged in as employee ⇒ skip form
    # if current_user.is_authenticated and current_user.is_employee:
    #     return redirect(url_for("employee_landing"))
    
    if current_user.is_authenticated and getattr(current_user, "is_employee", False):
        return redirect(url_for("employee_landing"))


    if request.method == "POST":
        pin = request.form.get("pin", "").strip()
        worker = db.session.query(WorkerPin).filter_by(pin=int(pin)).first()
        print(worker)
        if worker:
            print("OOGGING")
            login_user(
                EmployeeProxy(worker),
                remember=True,
                duration=timedelta(hours=2)   # 2-hour “remember me”
            )
            return redirect(request.args.get("next") or
                            url_for("employee_landing"))

        flash("Invalid PIN.", "danger")

    return render_template("employee_login.html")


def username_required(view_func):
    """Allow the route only for specific usernames."""

    @wraps(view_func)
    @login_required  # must be logged in first
    def wrapped_view(*args, **kwargs):
        try:
            if current_user.username not in ALLOWED_USERS:
                return redirect(url_for("employee_login", next=request.url))
        except:
            url_for("login", next=request.url)

        return view_func(*args, **kwargs)

    return wrapped_view


@app.route("/main_landing", methods=["GET", "POST"])
@login_required                         # ensures login
@username_required                      # then checks allowed list
def main_landing():
    return render_template("main_landing.html")

@app.route("/employee_landing", methods=["GET", "POST"])
@employee_required
@username_required          # o @login_required / @admin_required                      # <─ now Flask wraps it too
def employee_landing():
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
    print("DON")

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

from openai import OpenAI
from polo_utils import pull_polo_products
import json, re
from collections import defaultdict
from flask import request, render_template, flash, redirect, url_for
# assume `db`, `Menus`, `PoloProducts` already imported

import json, re
import numpy as np
import pandas as pd
from collections import defaultdict
from flask import request, flash, redirect, url_for, render_template

BRACKET_RE = re.compile(r"^matches\[(.+?)\]\[\]$")

# ---- Embedding config ----
EMBED_MODEL = "text-embedding-3-small"   # for quality use "text-embedding-3-large"
TOP_K = 5                               # how many Polo candidates to hand to the LLM per Menu item
EMBED_BATCH = 128

def _to_openai_text_list(seq):
    """
    Coerce a sequence into a list[str] suitable for OpenAI embeddings.
    - Converts None / NaN / pd.NA to a single space (avoid empty strings).
    - Decodes bytes.
    - Ensures plain str for everything else.
    """
    out = []
    for x in seq:
        # Handle pandas / numpy NA, None, and NaN
        if x is None or (isinstance(x, float) and math.isnan(x)) or (pd.isna(x) if 'pd' in globals() else False):
            s = " "
        elif isinstance(x, (bytes, bytearray)):
            s = x.decode("utf-8", errors="ignore") or " "
        else:
            s = str(x)
            if not s.strip():
                s = " "
        out.append(s)
    return out



def _normalize(mat: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(mat, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return mat / norms

def _embed(client: OpenAI, texts, model=EMBED_MODEL, batch_size=EMBED_BATCH) -> np.ndarray:
    """Return np.array of shape (len(texts), dim). Uses OpenAI embeddings with robust input sanitization."""
    out = []
    for i in range(0, len(texts), batch_size):
        raw_chunk = texts[i:i+batch_size]
        # Ensure a plain list[str] with no None/NaN/bytes/empties
        chunk = _to_openai_text_list(raw_chunk)

        # Defensive: avoid sending an empty batch (shouldn't happen but cheap to guard)
        if not chunk:
            continue

        # Call OpenAI
        resp = client.embeddings.create(model=model, input=chunk)

        # Preserve order using the returned index
        ordered = [None] * len(chunk)
        for d in resp.data:
            ordered[d.index] = d.embedding
        # If something weird came back, filter any None (shouldn't happen)
        out.extend(e for e in ordered if e is not None)

    return np.array(out, dtype=np.float32)


@app.route("/match_polo_products", methods=["GET", "POST"])
def match_polo_products():
    if request.method == "POST":
        # Which groups were displayed?
        rendered_groups = set(request.form.getlist("groups[]"))

        # Build { group_name: [ids...] } from matches[<group>][]
        selected = defaultdict(list)
        for field, values in request.form.lists():
            m = BRACKET_RE.match(field)
            if not m:
                continue
            group = m.group(1)
            for v in values:
                v = (v or "").strip()
                if not v:
                    continue
                try:
                    selected[group].append(int(v))
                except ValueError:
                    pass

        # Dedup + sort
        selected = {g: sorted(set(ids)) for g, ids in selected.items()}

        # Persist: for every rendered group, set polo_product_ids to chosen list (or empty)
        for group in rendered_groups:
            ids = selected.get(group, [])
            (db.session.query(Menus)
               .filter(Menus.product_name == group.strip(), Menus.active.is_(True))
               .update({"polo_product_ids": ids}))
        db.session.commit()

        flash("Emparejamientos guardados.", "success")
        return redirect(url_for("match_polo_products"))

    from openai import OpenAI
    client = OpenAI(api_key=openai_token)

    # Pull source data (ensure named columns)
    all_prods = pd.DataFrame(
        db.session.query(Menus.product_name, Menus.description, Menus.id)
        .filter(Menus.active.is_(True))
        .all(),
        columns=["product_name", "description", "id"],
    )
    all_polo = pd.DataFrame(
        db.session.query(
            PoloProducts.product_name,
            PoloProducts.modifier,
            PoloProducts.description,
            PoloProducts.id,
        )
        .filter(PoloProducts.modifier != True)
        .all(),
        columns=["product_name", "modifier", "description", "id"],
    )

    # If either table is empty, bail early
    if all_prods.empty or all_polo.empty:
        return render_template("match_polo_products.html", options={})

    # Build texts for embeddings
    polo_texts = [
        r.product_name
        for _, r in all_polo.iterrows()
    ]
    menu_texts = [
        r.product_name
        for _, r in all_prods.iterrows()
    ]
    # print(polo_texts)
    # print(menu_texts)

    # Compute (or load cached) embeddings
    # TIP: cache polo embeddings in DB (e.g., pgvector) to avoid recompute on every request.
    polo_embeds = _normalize(_embed(client, polo_texts))
    menu_embeds = _normalize(_embed(client, menu_texts))

    # Similarity search: for each menu item, pick top-K polo candidates
    Np = len(all_polo)
    k = min(TOP_K, Np)
    polo_T = polo_embeds.T  # (dim, Np)

    candidate_map = {}  # menu_idx -> {"menu_name": str, "candidates": [ {name,id}, ... ]}
    for i, (_, mr) in enumerate(all_prods.iterrows()):
        sims = menu_embeds[i].dot(polo_T)  # (Np,)
        # Get top-k indices fast
        idx = np.argpartition(-sims, k - 1)[:k]
        idx = idx[np.argsort(-sims[idx])]  # sort by score descending

        cands = []
        for j in idx:
            pr = all_polo.iloc[int(j)]
            cands.append({"name": pr.product_name, "id": int(pr.id)})
        candidate_map[i] = {"menu_name": mr.product_name, "candidates": cands}

    # Call the LLM only on reduced candidate lists
    options = {}
    system_prompt = (
        "Output only a JSON object mapping the Menu Item name to a list of up to 5 Polo matches. "
        "Each match is an object with keys: name (string), id (integer). No extra commentary."
    )
    MODEL = "gpt-4.1-2025-04-14"  # keep your existing model
    response_format = {"type": "json_object"}

    for i, payload in candidate_map.items():
        menu_name = payload["menu_name"]
        cands = payload["candidates"]
        user_prompt = (
            f'For the Menu Item "{menu_name}", choose up to 5 best matches from these Polo Products '
            f'(objects with keys "name" and "id"). '
            f'Respond as: "{menu_name}": [{{"name": "...","id": 123}}, ...]\n\n'
            f"Candidates: {json.dumps(cands, ensure_ascii=False)}"
        )

        try:
            resp = client.chat.completions.create(
                model=MODEL,
                messages=[{"role": "system", "content": system_prompt},
                          {"role": "user", "content": user_prompt}],
                response_format=response_format,
            )
            content = resp.choices[0].message.content
            options.update(json.loads(content))
        except Exception:
            # Fallback: top-5 by similarity if the LLM response fails/parses badly
            options[menu_name] = cands[:5]

    return render_template("match_polo_products.html", options=options)



@app.route("/refresh_products", methods=["GET", "POST"])
def refresh_products():
    all_polo = pd.DataFrame(db.session.query(PoloProducts.product_name, PoloProducts.polo_id, PoloProducts.modifier, PoloProducts.description, PoloProducts.id).all())

    bearer_token = get_restaurant_token(API_KEY, RESTAURANT_ID)

    prods = requests.get(
        "https://api.polotab.com/menus/v1/items",
        headers={"Authorization": f"Bearer {bearer_token}"},
        timeout=15,
    )
    prods.raise_for_status()

    all_prods = prods.json()
    cur_polo = all_polo.polo_id.tolist()
    from datetime import datetime
    for item in all_prods:
        if item['id'] not in cur_polo:
            fi = PoloProducts(product_name=item['name'], description=item['description'], added=datetime.utcnow(), polo_id=item['id'])
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
    from datetime import datetime, time   # time is now the class, not the module
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
    import pandas as pd
    from datetime import datetime, timedelta
    from zoneinfo import ZoneInfo

    MX  = ZoneInfo("America/Mexico_City")
    UTC = ZoneInfo("UTC")

    # ---------- Parse UI dates ----------
    today_str = datetime.now(MX).strftime("%Y-%m-%d")
    start_str = request.args.get("start_date", today_str)
    end_str   = request.args.get("end_date", start_str)

    def parse_ymd(s, fallback_date):
        try:
            return datetime.strptime(s, "%Y-%m-%d").date()
        except Exception:
            return fallback_date

    start_date = parse_ymd(start_str, datetime.now(MX).date())
    end_date   = parse_ymd(end_str, start_date)
    if end_date < start_date:
        end_date = start_date

    # ---------- Build local closed–open window [start 00:00, next 00:00) ----------
    start_local = datetime.combine(start_date, datetime.min.time(), tzinfo=MX)
    end_local   = datetime.combine(end_date,   datetime.min.time(), tzinfo=MX) + timedelta(days=1)

    # UTC bounds for UTC-stored columns
    start_utc = start_local.astimezone(UTC)
    end_utc   = end_local.astimezone(UTC)

    # Naive local bounds (for timestamp-without-time-zone columns like ProductionCounts.added)
    start_local_naive = start_local.replace(tzinfo=None)
    end_local_naive   = end_local.replace(tzinfo=None)

    # ---------- Pull data ----------
    # Menus (active)
    menu = pd.DataFrame(
        db.session.query(Menus.product_name, Menus.polo_product_ids)
        .filter(Menus.active.is_(True))
        .all(),
        columns=["product_name", "polo_product_ids"],
    )

    # Sales (UTC bounds)
    sales_df = pd.DataFrame(
        db.session.query(
            PoloOrders.order_id,
            PoloOrders.id,
            PoloOrders.item_id,
            PoloOrders.created_at,
            PoloOrders.quantity,
            PoloOrders.status,
        )
        .filter(PoloOrders.status == "completed")
        .filter(PoloOrders.created_at >= start_utc)
        .filter(PoloOrders.created_at <  end_utc)
        .all(),
        columns=["order_id", "id", "item_id", "created_at", "quantity", "status"],
    )

    # Production (LOCAL NAIVE bounds because `added` is naive/local)
    prod_df = pd.DataFrame(
        db.session.query(
            ProductionCounts.product_name,
            ProductionCounts.n_items.label("n_prod"),
            ProductionCounts.added,
        )
        .filter(ProductionCounts.added >= start_local_naive)
        .filter(ProductionCounts.added <  end_local_naive)
        .all(),
        columns=["product_name", "n_prod", "added"],
    )

    # Merma (UTC bounds)
    merma_df = pd.DataFrame(
        db.session.query(
            MermaCounts.product_name,
            MermaCounts.n_items.label("n_merma"),
            MermaCounts.added,
        )
        .filter(MermaCounts.added >= start_utc)
        .filter(MermaCounts.added <  end_utc)
        .all(),
        columns=["product_name", "n_merma", "added"],
    )

    # ---------- Standardize time columns to UTC in pandas ----------
    if not sales_df.empty:
        # created_at already UTC in DB; ensure tz-aware UTC in pandas
        sales_df["created_at"] = pd.to_datetime(sales_df["created_at"], errors="coerce", utc=True)

    if not prod_df.empty:
        # prod_df.added is naive local → localize MX then convert to UTC
        prod_df["added"] = pd.to_datetime(prod_df["added"], errors="coerce")
        if pd.api.types.is_datetime64tz_dtype(prod_df["added"]):
            prod_df["added"] = prod_df["added"].dt.tz_convert("UTC")
        else:
            prod_df["added"] = prod_df["added"].dt.tz_localize("America/Mexico_City").dt.tz_convert("UTC")

    if not merma_df.empty:
        # If stored as UTC (tz-aware or naive UTC), normalize to tz-aware UTC
        merma_df["added"] = pd.to_datetime(merma_df["added"], errors="coerce", utc=True)

    # ---------- Map Polo product → ADC menu name ----------
    polo_prods = pd.DataFrame(
        db.session.query(PoloProducts.id, PoloProducts.product_name, PoloProducts.polo_id).all(),
        columns=["id", "product_name", "polo_id"],
    )

    polo_to_name = {}
    for _, r in menu.iterrows():
        ids = r["polo_product_ids"] or []
        if not ids:
            continue
        t = polo_prods[polo_prods["id"].isin(ids)]
        for _, row in t.iterrows():
            polo_to_name[row["polo_id"]] = r["product_name"]

    # Aggregate sales to ADC names
    name_to_sales = {name: 0 for name in set(polo_to_name.values())}
    if not sales_df.empty:
        sales_df["adc_name"] = [polo_to_name.get(x) for x in sales_df["item_id"].tolist()]
        for _, r in sales_df.iterrows():
            name = r["adc_name"]
            if name:
                name_to_sales[name] = name_to_sales.get(name, 0) + (r["quantity"] or 0)

    # ---------- Dedupe/sum by LOCAL day for production and merma ----------
    if not prod_df.empty:
        prod_df["date_local"] = prod_df["added"].dt.tz_convert(MX).dt.normalize()
        prod_df = (
            prod_df.sort_values(["product_name", "added"])
                   .drop_duplicates(subset=["product_name", "date_local"], keep="last")
                   .groupby("product_name", as_index=False)["n_prod"].sum()
        )

    if not merma_df.empty:
        merma_df["date_local"] = merma_df["added"].dt.tz_convert(MX).dt.normalize()
        merma_df = (
            merma_df.sort_values(["product_name", "added"])
                    .drop_duplicates(subset=["product_name", "date_local"], keep="last")
                    .groupby("product_name", as_index=False)["n_merma"].sum()
        )

    # ---------- Assemble final payload ----------
    base_names = (
        prod_df["product_name"].drop_duplicates().tolist()
        if not prod_df.empty else list(name_to_sales.keys())
    )

    data = []
    for pname in base_names:
        sales_count = name_to_sales.get(pname, 0)

        n_prod = 0
        if not prod_df.empty:
            tmp = prod_df[prod_df["product_name"] == pname]
            n_prod = int(tmp["n_prod"].sum()) if not tmp.empty else 0

        n_merma = 0
        if not merma_df.empty:
            tmp = merma_df[merma_df["product_name"] == pname]
            n_merma = int(tmp["n_merma"].sum()) if not tmp.empty else 0

        data.append(
            {
                "product_name": pname,
                "merma_count": n_merma,
                "production_count": n_prod,
                "sales_count": sales_count,
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
@employee_required                      # <─ now Flask wraps it too
@app.route("/insumos/request_form", methods=["GET"])
def insumo_form():
    from models import InsumoList
    try:
        employee_name = current_user.name
    except:
        return redirect(url_for("employee_login"))

    # ── consulta ───────────────────────────────────────────────────────────
    # Devuelve dict { "Harina": "KG", ... }  y lista ordenada de nombres
    insumos_dict = dict(
        db.session.query(InsumoList.insumo_name, InsumoList.measure).all()
    )
    insumo_names = sorted(insumos_dict.keys(), key=str.lower)

    # ── render ─────────────────────────────────────────────────────────────
    return render_template(
        "insumo_request.html",
        employee_name=employee_name,
        insumos=insumos_dict,          # dict Jinja
        insumo_names=insumo_names      # lista para datalist
    )
 

def send_insumo_ntfy(req):
    import requests

    # Texto principal (cuerpo del push)
    body = f"{req.employee} pidió {req.quantity} {req.measure} de {req.name}"

    # Cabecera Title del push
    title = f"Nuevo insumo: {req.status.capitalize()} ({req.urgency})"

    # Cabecera Priority según urgencia ntfy (1-5). Ajusta a tu gusto.
    prio_map = {"ahora": "5", "hoy": "4", "manana": "3", "proximos_dias": "2"}
    priority = prio_map.get(req.urgency, "3")

    requests.post(
        "https://ntfy.sh/adc-alerts-insumos",
        data=body.encode("utf-8"),          # cuerpo en UTF-8
        headers={
            "Title":     title,             # título con acentos
            "Priority":  priority,          # prioridad opcional
            "Click":     "https://lionfish-app-zpcxb.ondigitalocean.app/admin/insumos",
            "Content-Type": "text/plain; charset=utf-8"  # ¡importante!
        },
        timeout=5
    )


@employee_required                      # <─ now Flask wraps it too
@app.post("/insumos/request")
def create_insumo_request():
    """Create a new InsumoRequest and kick off web-pushes asynchronously."""
    data = request.get_json(force=True)

    # 1.  Create + commit the request
    req = InsumoRequest(
        employee = data["employee"],
        name     = data["insumo"].upper(),
        measure  = data["measure"],
        quantity = float(data["quantity"]),
        urgency  = data["urgency"],
        notes    = data.get("notes"),
    )
    db.session.add(req)
    db.session.commit()
    send_insumo_ntfy(req)
    
    return ("", 204)

# routes.py

@app.route("/admin/insumos")
@login_required
def admin_insumos():
    from models import InsumoList
    # solicitudes (más recientes primero)
    reqs = (
        db.session.query(InsumoRequest)
        .order_by(InsumoRequest.created_at.desc())
        .all()
    )

    # nombres existentes en el catálogo
    catalogo = {
        x.insumo_name.strip().lower(): x        # objeto InsumoList
        for x in db.session.query(InsumoList).all()
    }

    # añade a cada solicitud un flag y datos del catálogo
    for r in reqs:
        key              = (r.name or "").strip().lower()
        r.in_catalog     = key in catalogo
        r.catalog_item   = catalogo.get(key)    # None si no existe
        # ejemplo extra: medida en catálogo
        r.catalog_measure = r.catalog_item.measure if r.catalog_item else None

    employees = ["steven", "adriana", "andre", "romina"]
    return render_template(
        "admin_insumos.html",
        reqs=reqs,
        employees=employees
    )


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
    import requests 
    req.assigned_to = assignee
    req.status      = "asignado"        # keep in sync with the ENUM
    db.session.commit()
    requests.post("https://ntfy.sh/adc-alerts-{}".format(assignee),
    data=f"""{assignee}: Te asignaron un insumo: {req.name}.""".encode('utf-8'),
        headers={
            "Click": "https://lionfish-app-zpcxb.ondigitalocean.app/admin/insumos"
        })
    emp_id = db.session.query(User.id).filter(User.username == assignee).one()


    flash("Insumo asignado correctamente.", "success")
    return redirect(url_for("admin_insumos"))



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


# solo usuarios con el rol adecuado
@username_required          # o @login_required / @admin_required
@app.route("/insumos/create", methods=["GET", "POST"])
def create_insumo():
    from models import InsumoList
    medidas = ["pz", "kg", "g", "l", "ml"]
    areas   = ["cocina", "barra", "limpieza"]

    # ------------- POST: guardar -----------------------------------------
    if request.method == "POST":
        name      = request.form.get("name", "").strip().upper()
        measure   = request.form.get("measure")
        area      = request.form.get("area")
        proveedor = request.form.get("proveedor", "").strip()

        # validación simple
        if not name or not measure or not area:
            flash("Nombre, unidad y área son obligatorios.", "danger")
            return redirect(request.url)

        # evitar duplicados exactos (opcional)
        exists = db.session.query(
            db.exists().where(
                (InsumoList.insumo_name.ilike(name)) &
                (InsumoList.measure == measure)
            )
        ).scalar()

        if exists:
            flash("Ese insumo ya existe.", "warning")
            next_url = request.args.get("next") or url_for("admin_insumos")
            return redirect(next_url)

        try:
            nuevo = InsumoList(
                insumo_name = name.upper(),
                measure     = measure,
                area        = area,
                proveedor   = proveedor or None

            )
            db.session.add(nuevo)
            db.session.commit()
            flash("Insumo creado exitosamente ✅", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error al guardar: {e}", "danger")

        # volver a la página previa o al admin
        next_url = request.args.get("next") or url_for("admin_insumos")
        return redirect(next_url)

    # ------------- GET: formulario ---------------------------------------
    prefill_name    = request.args.get("prefill", "")
    prefill_measure = request.args.get("measure", "").lower()

    return render_template(
        "create_insumo.html",
        medidas        = medidas,
        areas          = areas,
        prefill_name   = prefill_name,
        prefill_measure= prefill_measure
    )

@app.route("/insumos")
@login_required
def view_insumos():
    insumos = db.session.execute(
        text("SELECT id, insumo_name, measure, added, proveedor, area "
             "FROM public.insumo_list ORDER BY insumo_name")
    ).mappings()    # o usa tu modelo SQLAlchemy

    return render_template("insumos_table.html", insumos=insumos)


import requests
from datetime import datetime
try:
    from zoneinfo import ZoneInfo
    MX_TZ = ZoneInfo("America/Mexico_City")
except ImportError:
    import pytz
    MX_TZ = pytz.timezone("America/Mexico_City")


def send_survey_ntfy(survey_row):
    """
    Push a Survey row to ntfy.sh/adc-alerts-feedback.
    Works on any Python 3.x without unicode-header issues.
    """
    a = survey_row.answers
    worst = min(a.values())     # 1 bad · 3 good

    # ── Title (ASCII-only) ───────────────────────────────
    title_map = {1: "Nuevo feedback (Malo)",
                 2: "Nuevo feedback (Regular)",
                 3: "Nuevo feedback (Bueno)"}
    title = f"{title_map[worst]} - ID {survey_row.id}"

    # ── Body (can contain emoji freely) ─────────────────
    face_map = {1: "❌", 2: "⚠️", 3: "✅"}
    fmt_val = lambda v: f"{v} {face_map[v]}"
    body_lines = [
        f"Comida   : {fmt_val(a['comida'])}",
        f"Servicio : {fmt_val(a['servicio'])}",
        f"Limpieza : {fmt_val(a['limpieza'])}",
        "",
        "Hora local: " + survey_row.added.astimezone(MX_TZ).strftime("%Y-%m-%d %H:%M")
    ]
    body = "\n".join(body_lines)

    # ── Priority ────────────────────────────────────────
    priority = "5" if worst == 1 else "4" if worst == 2 else "3"

    # ── POST ────────────────────────────────────────────
    requests.post(
        "https://ntfy.sh/adc-alerts-feedback",
        data=body.encode("utf-8"),
        headers={
            "Title"       : title,          # ASCII → always safe
            "Priority"    : priority,
            "Click"       : "https://lionfish-app-zpcxb.ondigitalocean.app/survey/feedback",
            "Content-Type": "text/plain; charset=utf-8"
        },
        timeout=5
    )

def _clean_key(raw: str) -> str:
    """
    Ensure the key does NOT start with a slash or with the bucket name.
    """
    key = raw.lstrip("/")                     # kill leading slash
    prefix = f"{spaces_bucket_name}/"
    if key.startswith(prefix):
        key = key[len(prefix):]               # strip duplicated bucket
    return key

@app.route("/feedback", methods=["GET", "POST"])
def feedback():
    return render_template('feedback.html')

@app.route("/survey/submit", methods=["POST"])
def submit_survey():
    """
    Expects JSON:
        {
          "comida": 1|2|3,
          "servicio": …,
          "limpieza": …,
          "photo_base64": "data:image/png;base64,AAAA…"
        }
    """

    import uuid, io, base64, mimetypes
    from flask import request, jsonify, abort
    from sqlalchemy.exc import SQLAlchemyError
    from models import Survey

    data = request.get_json(silent=True) or {}
    photo_b64 = data.pop("photo_base64", None)         # strip out the image
    expected = {"comida", "servicio", "limpieza"}

    # --- basic validation ---------------------------------------------------
    if not expected.issubset(data):
        abort(400, "Campos incompletos.")
    try:
        answers = {k: int(data[k]) for k in expected}
    except (TypeError, ValueError):
        abort(400, "Valores inválidos.")

    # --- upload snapshot, if any -------------------------------------------
    if photo_b64:
        try:
            header, b64 = photo_b64.split(",", 1)
            mime = header.split(":")[1].split(";")[0]           # e.g. image/png
            ext  = mimetypes.guess_extension(mime) or ".png"
            # key  = f"survey_photos/{uuid.uuid4()}{ext}"
            key = _clean_key(f"survey_photos/{uuid.uuid4()}{ext}")
            file_bytes = base64.b64decode(b64)                  # ← decode here

            _spaces.upload_fileobj(
                io.BytesIO(file_bytes),
                spaces_bucket_name,                             # e.g. "recibos"
                key,
                ExtraArgs={"ContentType": mime, "ACL": "private"}
            )
            answers["photo_key"] = key
        except Exception as e:
            app.logger.error(f"Upload snapshot failed: {e}")

    # --- save survey --------------------------------------------------------
    try:
        row = Survey(answers=answers)                  # server_default NOW()
        db.session.add(row)
        db.session.commit()
        send_survey_ntfy(row)
        return jsonify({"status": "ok", "id": row.id}), 201
    except SQLAlchemyError as e:
        db.session.rollback()
        abort(500, "Error al guardar la encuesta.")


        # your helper

# 1-hour links are plenty for a dashboard refresh
URL_TTL_SEC = 3600


from flask import render_template, url_for
from sqlalchemy import func

@app.route("/survey/feedback", methods=["GET"])
def view_feedback():
    from models import Survey
    rows = (
        db.session.query(Survey.id, Survey.answers, Survey.added)
                  .order_by(Survey.added.desc())
                  .all()
    )

    enriched = []
    for r in rows:
        d = dict(id=r.id, answers=r.answers, added=r.added)
        key = r.answers.get("photo_key")
        d["photo_url"] = (
            url_for("survey_photo", survey_id=r.id) if key else None
        )
        enriched.append(d)

    return render_template("survey_feedback.html", surveys=enriched)


# utils/storage.py  (or wherever you keep helpers)
def clean_key(raw: str) -> str:
    """Strip leading slash and duplicated bucket prefix."""
    key = raw.lstrip("/")
    prefix = f"{spaces_bucket_name}/"
    if key.startswith(prefix):
        key = key[len(prefix):]
    return key


@app.route("/survey/<int:survey_id>/photo")
def survey_photo(survey_id: int):
    from models import Survey
    print("HR")
    """Stream the snapshot attached to a survey row."""
    row = db.session.get(Survey, survey_id) or abort(404)
    key = clean_key(row.answers.get("photo_key", "")) or abort(404)

    # fetch from Spaces
    try:
        obj = _spaces.get_object(Bucket=spaces_bucket_name, Key=key)
    except _spaces.exceptions.NoSuchKey:
        abort(404)

    # mime type by extension
    ext  = os.path.splitext(key)[1].lower()
    mime = mimetypes.guess_type(key)[0] or "application/octet-stream"

    headers = {
        "Content-Type": mime,
        "Content-Disposition": f'inline; filename="{os.path.basename(key)}"',
        "Content-Length": obj["ContentLength"]
    }
    body_iter = stream_with_context(obj["Body"].iter_chunks())
    return Response(body_iter, headers=headers)


@app.route("/survey-location", methods=["GET", "POST"])
def survey_location():
    from models import LocationSuggestion
    next_url = request.values.get("next") or "/"

    if request.method == "POST":
        email    = (request.form.get("email") or "").strip()
        lat_str  = request.form.get("lat")
        lng_str  = request.form.get("lng")
        address  = request.form.get("address") or None
        place_id = request.form.get("place_id") or None

        # Basic validation
        if not email or not lat_str or not lng_str:
            return render_template(
                "survey_location.html",
                google_maps_api_key=GOOGLE_MAPS_API_KEY,
                next_url=next_url,
                error="Please enter your email and pick a spot on the map.",
                candidate_pins=[],
            ), 400

        # Parse & range-check coordinates (friendlier than letting DB constraint fail)
        try:
            lat = float(lat_str)
            lng = float(lng_str)
        except (TypeError, ValueError):
            return render_template(
                "survey_location.html",
                google_maps_api_key=GOOGLE_MAPS_API_KEY,
                next_url=next_url,
                error="Coordinates look invalid — try selecting the pin again.",
                candidate_pins=[],
            ), 400

        if not (-90.0 <= lat <= 90.0 and -180.0 <= lng <= 180.0):
            return render_template(
                "survey_location.html",
                google_maps_api_key=GOOGLE_MAPS_API_KEY,
                next_url=next_url,
                error="Coordinates out of range — please pick a valid place.",
                candidate_pins=[],
            ), 400

        # Persist via SQLAlchemy
        try:
            suggestion = LocationSuggestion(
                email=email,
                latitude=lat,
                longitude=lng,
                address=address,
                place_id=place_id,
            )
            db.session.add(suggestion)
            db.session.commit()
        except Exception:
            db.session.rollback()
            return render_template(
                "survey_location.html",
                google_maps_api_key=GOOGLE_MAPS_API_KEY,
                next_url=next_url,
                error="Couldn’t save your suggestion. Please try again.",
                candidate_pins=[],
            ), 500
        token = _reward_serializer().dumps({"sid": suggestion.id})
        print(token)
        return redirect(url_for("survey_thanks", c=token))

    # GET — render page
    candidate_pins = []  # optionally pre-seed choices
    return render_template(
        "survey_location.html",
        google_maps_api_key=GOOGLE_MAPS_API_KEY,
        next_url=next_url,
        candidate_pins=candidate_pins,
    )

# routes_quicklook.py (or drop into your app.py)

                               # ← adjust to your project
from models import LocationSuggestion           # ← adjust import
from sqlalchemy import and_
MX = ZoneInfo("America/Mexico_City")

def _parse_dates():
    """
    Parse start/end from ?start=YYYY-MM-DD&end=YYYY-MM-DD&days=NN
    If not provided, default to last 30 days (local MX time).
    Returns (start_dt_inclusive, end_dt_exclusive, dedup_bool)
    """
    dedup = request.args.get("dedup", "0") == "1"
    days  = request.args.get("days", type=int)

    start_s = request.args.get("start", "").strip() or None
    end_s   = request.args.get("end", "").strip() or None

    today = date.today()
    if not start_s and not end_s:
        # default: last 30 days
        end_local   = today
        start_local = today - timedelta(days=29)
    else:
        # If only one is given, fill the other with sensible default
        if end_s and not start_s:
            end_local   = datetime.strptime(end_s, "%Y-%m-%d").date()
            start_local = end_local - timedelta(days=(days or 30) - 1)
        elif start_s and not end_s:
            start_local = datetime.strptime(start_s, "%Y-%m-%d").date()
            end_local   = start_local + timedelta(days=(days or 30) - 1)
        else:
            start_local = datetime.strptime(start_s, "%Y-%m-%d").date()
            end_local   = datetime.strptime(end_s, "%Y-%m-%d").date()

    # Inclusive start at 00:00, exclusive end at next day 00:00 (local MX tz)
    start_dt = datetime.combine(start_local, datetime.min.time(), MX)
    end_dt   = datetime.combine(end_local + timedelta(days=1), datetime.min.time(), MX)
    return start_local, end_local, start_dt, end_dt, dedup

def _fetch_suggestions(start_dt, end_dt, dedup=False):
    q = (
        db.session.query(LocationSuggestion)
        .filter(
            and_(
                LocationSuggestion.created_at >= start_dt,
                LocationSuggestion.created_at <  end_dt,
            )
        )
        .order_by(LocationSuggestion.created_at.desc())
    )
    rows = q.all()

    if dedup:
        seen = set()
        unique_rows = []
        for r in rows:
            if r.email not in seen:
                unique_rows.append(r)
                seen.add(r.email)
        rows = unique_rows

    return rows

@app.route("/survey-location/quick-look")
def survey_quick_look():
    start_local, end_local, start_dt, end_dt, dedup = _parse_dates()
    rows = _fetch_suggestions(start_dt, end_dt, dedup=dedup)

    # Summaries
    total_points   = len(rows)
    unique_emails  = len({r.email for r in rows})
    last_added_iso = rows[0].created_at.astimezone(MX).isoformat() if rows else None

    suggestions = [
        {
            "id": r.id,
            "email": r.email,
            "lat": float(r.latitude),
            "lng": float(r.longitude),
            "address": r.address or "",
            "place_id": r.place_id or "",
            "created_at": r.created_at.astimezone(MX).isoformat(),
        }
        for r in rows
    ]

    return render_template(
        "survey_quick_look.html",
        GOOGLe_maps_api_key=GOOGLE_MAPS_API_KEY,
        suggestions=suggestions,
        # filter echo
        start_value=start_local.strftime("%Y-%m-%d"),
        end_value=end_local.strftime("%Y-%m-%d"),
        dedup=dedup,
        # stats
        total_points=total_points,
        unique_emails=unique_emails,
        last_added_iso=last_added_iso,
    )

@app.route("/survey-location/export.csv")
def survey_quick_look_export():
    _, _, start_dt, end_dt, dedup = _parse_dates()
    rows = _fetch_suggestions(start_dt, end_dt, dedup=dedup)

    def gen():
        yield "id,email,latitude,longitude,address,place_id,created_at\n"
        for r in rows:
            # Escape quotes and commas in address safely
            addr = (r.address or "").replace('"', '""')
            line = f'{r.id},"{r.email}",{r.latitude:.6f},{r.longitude:.6f},"{addr}","{r.place_id or ""}",{r.created_at.astimezone(MX).isoformat()}\n'
            yield line

    filename = f"location_suggestions_{start_dt.date()}_{(end_dt - timedelta(days=1)).date()}{'_dedup' if dedup else ''}.csv"
    return Response(gen(), mimetype="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})

# Optional: handy JSON feed for debugging or hooking up a BI tool
@app.route("/survey-location/admin.json")
def survey_quick_look_json():
    _, _, start_dt, end_dt, dedup = _parse_dates()
    rows = _fetch_suggestions(start_dt, end_dt, dedup=dedup)
    return {
        "count": len(rows),
        "dedup": dedup,
        "results": [
            {
                "id": r.id,
                "email": r.email,
                "latitude": float(r.latitude),
                "longitude": float(r.longitude),
                "address": r.address,
                "place_id": r.place_id,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ],
    }

# --- imports necesarios (si no los tienes ya) ---
from itsdangerous import BadSignature, SignatureExpired
# Ajusta estos imports a tu estructura


# Si no tienes este helper aún, agrégalo (usa tu SECRET_KEY):
from itsdangerous import URLSafeTimedSerializer
def _reward_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="survey-reward")

@app.route("/survey-location/thanks")
def survey_thanks():
    """
    Muestra un mensaje simple de agradecimiento y el email registrado.
    Valida el token y busca el registro en la BD para extraer el email.
    """
    token = request.args.get("c")
    if not token:
        abort(400)

    try:
        data = _reward_serializer().loads(token, max_age=60*60*24*90)  # válido 90 días
        sid = data.get("sid")
    except SignatureExpired:
        return "⏰ El código expiró. Por favor envía una nueva sugerencia.", 400
    except BadSignature:
        return "❌ Código inválido.", 400

    # Buscar el registro para obtener el email
    sug = db.session.query(LocationSuggestion).filter_by(id=sid).first()
    email = sug.email if sug else "—"

    return render_template("survey_thanks.html", email=email)

import os
from typing import Dict, Any, Iterable, List, Optional
from tasks.utils import get_restaurant_token, pull_order_details
from sqlalchemy import text
from models import PoloTickets, PoloOrders

RESTAURANT_ID  = os.getenv("RESTAURANT_ID", "cd7d0f22-eb20-450e-b185-5ce412a3a8ea")
API_KEY        = os.getenv("AUSTIN_DONUT_API_KEY", None)  # store securely in env
BASE_URL       = "https://api.polotab.com"  # ← replace with the real base URL

# ─── auth: exchange API key → restaurant bearer token ──────────────────────────

# app_bootstrap.py (or wherever you init Flask)
from concurrent.futures import ThreadPoolExecutor
import secrets
from datetime import timezone
from sqlalchemy import func
import httpx
import logging

executor = ThreadPoolExecutor(max_workers=2)  # 1–2 is plenty for this job
JOB_STATE = {}  # in-memory progress tracker: {job_id: {status, fetched, error}}


def _try_lock(key: int = 942001) -> bool:
    return db.session.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar()

def _unlock(key: int = 942001) -> None:
    db.session.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})

import requests
RESTAURANT_ID  = os.getenv("RESTAURANT_ID", "cd7d0f22-eb20-450e-b185-5ce412a3a8ea")

executor = ThreadPoolExecutor(max_workers=2)  # 1–2 is plenty for this job
JOB_STATE = {}  # in-memory progress tracker: {job_id: {status, fetched, error}}

# routes.py
from flask import jsonify, request
from datetime import timezone

PULL_URL = "https://api.polotab.com/orders/v1/orders"

def _safe_iso(dt):
    # Convert to ISO8601 with timezone if you have a naive UTC timestamp in DB
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()

def _pull_orders_job(job_id: str):
    from sqlalchemy.dialects.postgresql import insert

    """Runs in a background thread. Must manage its own app context + DB session."""
    with app.app_context():
        try:
            JOB_STATE[job_id] = {"status": "running", "fetched": 0}

            if not _try_lock():
                JOB_STATE[job_id] = {"status": "skipped", "fetched": 0}
                return

            bearer_token = get_restaurant_token(API_KEY, RESTAURANT_ID)

            # Get newest 'started_at' we already have so we only pull new stuff.
            last_started = db.session.query(PoloTickets.order_id).order_by(PoloTickets.started_at.desc()).limit(1).one()[0]
            params = {"limit": 100}
            if last_started:
                params["created_after"] = last_started

            # Use a persistent client (keep-alive) + sensible timeouts
            timeout = httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=30.0)
            limits = httpx.Limits(max_connections=10, max_keepalive_connections=5)

            total_fetched = 0
            cursor = None

            with httpx.Client(timeout=timeout, limits=limits) as client:
                done = False
                while True:
                    p = dict(params)
                    
                    resp = client.get(
                        PULL_URL,
                        headers={"Authorization": f"Bearer {bearer_token}"},
                        params=p,
                    )
                    resp.raise_for_status()
                    orders = resp.json()

                    if not orders:
                        break

                    # Bulk-insert tickets fast
                    ticket_rows = []
                    for item in orders:
                        if item['id'] == last_started:
                            done = True
                            break
                        ticket_rows.append(dict(
                            order_id     = item["id"],
                            started_at   = item["startedAt"],   # if ISO8601, psycopg can parse
                            finished_at  = item.get("finishedAt"),
                            total_amount = item.get("totalAmount"),
                            order_type   = item.get("type"),
                            status       = item.get("status"),
                        ))
                    # Faster than many .add()
                    try:
                        stmt = insert(PoloTickets).values(ticket_rows).on_conflict_do_nothing(index_elements=["order_id"])
                        db.session.execute(stmt)
                        db.session.commit()     
                    except:
                        db.session.rollback()


                    # Pull order details for each order (sequential; see optional concurrency below)
                    order_rows = []
                    for od in orders:
                        # If possible: pass the httpx client to reuse connection inside pull_order_details
                        dets = pull_order_details(od["id"], bearer_token)
                        for r in dets:
                            (
                                item_id, one_time_id, name, n_items, order_id, started_at,
                                order_type, modifier, total_amount, platform, status
                            ) = r
                            if od['id'] == last_started:
                                break
                            order_rows.append(dict(
                                item_id      = item_id,
                                one_time_id = one_time_id,
                                quantity     = n_items,
                                product_name = name,
                                order_id     = od["id"],
                                created_at   = started_at,
                                order_type   = order_type,
                                modifier     = modifier,
                                price        = total_amount,
                                platform     = platform,
                                status       = status,
                            ))

                    if order_rows:
                        try:
                            stmt = insert(PoloOrders).values(order_rows).on_conflict_do_nothing(index_elements=["one_time_id"])
                            db.session.execute(stmt)
                            db.session.commit()
                        except:
                            db.session.rollback()

                    total_fetched += len(orders)
                    JOB_STATE[job_id]["fetched"] = total_fetched
                    if done:
                        break
            JOB_STATE[job_id]["status"] = "done"

        except Exception as e:
            db.session.rollback()
            JOB_STATE[job_id] = {"status": "error", "error": str(e), "fetched": JOB_STATE.get(job_id, {}).get("fetched", 0)}
            logging.exception("pull-external failed")
        finally:
            db.session.remove()  # important when using threads
            _unlock()            # release your one-at-a-time guard
# routes.py (HTTP endpoints)
@app.route("/pull_orders", methods=["POST", "GET"])
def enqueue_pull_orders():
    # QUICK return. Do NOT do the heavy work here.
    job_id = secrets.token_hex(8)
    JOB_STATE[job_id] = {"status": "queued", "fetched": 0}

    # Important: acquire the lock in the worker (not here), so skipped state can be reported.
    executor.submit(_pull_orders_job, job_id)
    return jsonify({"accepted": True, "job_id": job_id}), 202

@app.route("/pull_orders/status/<job_id>", methods=["GET"])
def pull_orders_status(job_id):
    return jsonify(JOB_STATE.get(job_id, {"status": "unknown"})), 200





if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)
