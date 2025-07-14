# polo_api.py  ← renamed for clarity
import os
from datetime import datetime, time, timedelta
import requests
import pytz
import dateutil.parser

# ─────────────────────────── CONFIG ────────────────────────────
BACKOFFICE_TOKEN: str = os.getenv("backoffice_token", "").strip()

if not BACKOFFICE_TOKEN:
    raise RuntimeError(
        "BACKOFFICE_TOKEN is missing. "
        "Set it in your environment, e.g.:\n"
        "   export BACKOFFICE_TOKEN='eyJhbGciOi...'"
    )

COOKIE_HEADER = f"backofficeUserCookie={BACKOFFICE_TOKEN}"
COOKIE_DICT   = {"backofficeUserCookie": BACKOFFICE_TOKEN}

CST = pytz.timezone("America/Mexico_City")

# ─────────────────────────── Productos ─────────────────────────
def pull_polo_products():
    url = (
        "https://api.polotab.com/api/v1/chains/"
        "d01b50da-d2cb-4eb3-a446-1441b09723cd/products"
    )

    headers = {
        "Host": "api.polotab.com",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) "
            "Gecko/20100101 Firefox/137.0"
        ),
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://admin.polotab.com/",
        "Content-Type": "application/json",
        "Origin": "https://admin.polotab.com",
        "Connection": "keep-alive",
        "Cookie": COOKIE_HEADER,
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Priority": "u=4",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
    }

    r = requests.get(url, headers=headers, timeout=120)
    r.raise_for_status()
    return [(it["name"], it["description"], it["id"]) for it in r.json()]


# ─────────────────────────── Modificadores ─────────────────────
def pull_polo_mods(prod_id: str):
    url = (
        "https://api.polotab.com/api/v1/chains/"
        "d01b50da-d2cb-4eb3-a446-1441b09723cd/modifier_sets/"
        f"{prod_id}?allChannels=false"
    )

    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Accept-Language": "en-US,en;q=0.5",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        "Content-Type": "application/json",
        "Origin": "https://admin.polotab.com",
        "Referer": "https://admin.polotab.com/",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "TE": "trailers",
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) "
            "Gecko/20100101 Firefox/137.0"
        ),
    }

    r = requests.get(url, headers=headers, cookies=COOKIE_DICT, timeout=120)
    r.raise_for_status()
    j = r.json()
    return [(m["name"], None, m["id"]) for m in j["modifiers"]]


# ─────────────────────────── Ventas ────────────────────────────
API_URL = (
    "https://api.polotab.com/api/v1/restaurants/"
    "cd7d0f22-eb20-450e-b185-5ce412a3a8ea/orders/"
    "?page=0&perpage=1000&startDate={start}&endDate={end}&sortdir=DESC"
)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) "
        "Gecko/20100101 Firefox/137.0"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Referer": "https://admin.polotab.com/",
    "Content-Type": "application/json",
    "Origin": "https://admin.polotab.com",
    "Connection": "keep-alive",
    "Cookie": COOKIE_HEADER,
}

# ── helpers ────────────────────────────────────────────────────
def _cst_midnight(day: datetime) -> datetime:
    return CST.localize(datetime.combine(day.date(), time.min))

def cst_range_to_utc_ms(start_day: datetime, end_day: datetime):
    start_mid = _cst_midnight(start_day)
    end_nextmid = _cst_midnight(end_day) + timedelta(days=1)
    start_ms = int(start_mid.astimezone(pytz.utc).timestamp() * 1000)
    end_ms = int(end_nextmid.astimezone(pytz.utc).timestamp() * 1000) - 1
    return start_ms, end_ms

# ── main fetch ─────────────────────────────────────────────────
def pull_polo_sales(
    start_date_str: str | None = None,
    end_date_str: str | None = None,
) -> requests.Response:
    if start_date_str:
        start_dt = dateutil.parser.parse(start_date_str)
    else:
        start_dt = datetime.now(CST)
    if end_date_str:
        end_dt = dateutil.parser.parse(end_date_str)
    else:
        end_dt = start_dt

    for var in ("start_dt", "end_dt"):
        dt = locals()[var]
        locals()[var] = CST.localize(dt) if dt.tzinfo is None else dt.astimezone(CST)

    if start_dt > end_dt:
        start_dt, end_dt = end_dt, start_dt

    start_ms, end_ms = cst_range_to_utc_ms(start_dt, end_dt)
    print(start_ms, end_ms)
    url = API_URL.format(start=start_ms, end=end_ms)
    return requests.get(url, headers=HEADERS, timeout=1200)


# ─── demo ──────────────────────────────────────────────────────
if __name__ == "__main__":
    # export BACKOFFICE_TOKEN=... before running
    sales = pull_polo_sales("2025-05-01", "2025-05-03")
    print(sales.status_code, sales.json()[:1])
