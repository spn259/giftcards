from app import db, app, jsonify, logging
from models import * 

import os
import requests
from typing import Dict, Any, Iterable, List, Optional
from utils import get_restaurant_token

RESTAURANT_ID  = os.getenv("RESTAURANT_ID", "cd7d0f22-eb20-450e-b185-5ce412a3a8ea")
API_KEY        = os.getenv("AUSTIN_DONUT_API_KEY", None)  # store securely in env
BASE_URL       = "https://api.polotab.com"  # ← replace with the real base URL

# ─── auth: exchange API key → restaurant bearer token ──────────────────────────


def _try_lock(key: int = 942001) -> bool:
    return db.session.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar()

def _unlock(key: int = 942001) -> None:
    db.session.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})

@app.route("/pull_orders", methods=["GET", "POST"])
def tasks_pull_external():
    bearer_token = get_restaurant_token(API_KEY, RESTAURANT_ID)

   
    # 2) one-at-a-time guard across processes/instances
    if not _try_lock():
        # another run in progress → skip quietly
        return jsonify({"skipped": True}), 202

    try:
        last = db.session.query(PoloTickets.order_id).order_by(PoloTickets.started_at.desc()).limit(1)
        params = dict()
        params['limit'] = 100
        params["created_before"] = last

        ords = requests.get("https://api.polotab.com/orders/v1/orders",
            headers={
            "Authorization": "Bearer {}".format(bearer_token)
            }, 
            params = params
        )
        ords = ords.json()
        for item in ords:
            fi = PoloTickets(order_id=item['id'], started_at=item['startedAt'], finished_at=item['finishedAt'], total_amount=item['totalAmount'], 
                            order_type=item['type'], status=item['status'])
            db.session.add(fi)
        db.session.commit()
           
        return jsonify({"ok": True, "fetched": True})
    except Exception as e:
        db.session.rollback()
        logging.logger.exception("pull-external failed")
        return jsonify({"error": str(e)}), 500
    finally:
        _unlock()
