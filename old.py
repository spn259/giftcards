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

    Most will have two matches, one non-modifier and one modifier, return the 5 best matches.

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

from datetime import datetime
from flask import request, jsonify, flash, abort
from flask_login import login_required, current_user

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
        product_area      = data.get("product_area")
        product_category  = data.get("product_category")
        product_name      = (data.get("product_name") or "").strip()
        measure           = data.get("measure")
        details           = data.get("details", "")
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
        details      = request.form.get("details", "")

    # ---------- 2. Basic validation ----------
    if not all([product_area, product_category, product_name, measure]):
        abort(400, "Missing required fields")

    # ---------- 3. Create DB row ----------
    username = getattr(current_user, "username", None)
    new = InventoryProducts(
        product_area     = product_area.lower(),
        product_category = product_category.lower(),
        product_name     = product_name,
        measure          = measure.lower(),
        details          = details,
        username         = username,
        added            = datetime.now()
    )
    db.session.add(new)
    db.session.commit()

    # flash only for classic form submits
    if not request.is_json:
        flash("Artículo guardado.", "success")

    # ---------- 4. JSON response for front-end ----------
    return (
        jsonify(
            id       = new.id,
            area     = new.product_area,
            category = new.product_category,
            name     = new.product_name,
            measure  = new.measure,
            details  = new.details,
            tienda   = None,
            bodega   = None,
        ),
        201,
    )

    return redirect(url_for("create_inventory_item"))

from pandas import DataFrame

# app.py
from collections import defaultdict
from sqlalchemy import func
import pandas as pd

# app.py
from collections import defaultdict
from sqlalchemy import func, cast, Numeric        #  ← add cast + Numeric
import pandas as pd

# @app.route("/show_inventory_item", methods=["GET", "POST"])
# @login_required
from collections import defaultdict
from sqlalchemy import func, cast, Numeric

def build_inventory():
    # 1. products ---------------------------------------------------
    prows = db.session.query(
        InventoryProducts.id,
        InventoryProducts.product_area,
        InventoryProducts.product_category,
        InventoryProducts.product_name,
        InventoryProducts.details,
        InventoryProducts.measure,
        InventoryProducts.added,        # ← new
        InventoryProducts.username      # ← new
    ).all()

    # 2. summed counts ---------------------------------------------
    crows = (
        db.session.query(
            InventoryCounts.product_id,
            InventoryCounts.location,
            func.sum(cast(InventoryCounts.value, Numeric)).label("total")
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
                id       = pid,
                area     = r.product_area,
                category = r.product_category,
                name     = r.product_name,
                measure  = r.measure,
                details  = r.details,
                added    = r.added.strftime("%d/%m/%Y %H:%M"),  # → “05/06/2025 13:45”
                user     = r.username or "—",
                tienda   = counts.get(pid, {}).get("tienda"),
                bodega   = counts.get(pid, {}).get("bodega"),
            )
        )
    return inventory


@app.get("/inventory_dashboard")
@login_required
def inventory_dashboard():
    # `inventory` must already contain tienda & bodega counts (or None)
    inventory = build_inventory()          # your existing helper
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
    mv = InventoryCounts(product_id=item.id,
                           value=val,
                           location=location,
                           username=username, 
                           added=datetime.now())
    db.session.add(mv)
    db.session.commit()
    return {"ok": True}, 201

@app.post("/update_inventory_item/<int:item_id>")
@login_required
def update_inventory_item(item_id):
    data = request.get_json(silent=True) or {}
    item = db.session.get(InventoryProducts, item_id) or abort(404)

    for fld in ("product_area", "product_category",
                "product_name", "measure", "details"):
        if fld in data and data[fld] is not None:
            setattr(item, fld, data[fld].strip().lower() if fld != "product_name" else data[fld].strip())

    item.username = getattr(current_user, "username", None)
    item.added = datetime.now()
    db.session.commit()

    return jsonify(
        id=item.id, area=item.product_area, category=item.product_category,
        name=item.product_name, measure=item.measure, details=item.details,
        added=item.added.strftime("%d/%m/%Y %H:%M"), user=item.username
    )
