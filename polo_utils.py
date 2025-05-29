import requests

def pull_polo_products():

    url = "https://api.polotab.com/api/v1/chains/d01b50da-d2cb-4eb3-a446-1441b09723cd/products"

    headers = {
        "Host": "api.polotab.com",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://admin.polotab.com/",
        "Content-Type": "application/json",
        "Origin": "https://admin.polotab.com",
        "Connection": "keep-alive",
        "Cookie": "backofficeUserCookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNjYzA2NWIxLTFmOWMtNDg5ZC04MWRjLTEzOTM2ODRmMmY2YSIsImlhdCI6MTc0NjAyOTM3MCwiZXhwIjoxNzUxMjEzMzcwfQ.gkKcvpgXKBdEVi8xVxEXgkEwfm1a9K9NGT4B5Ghe1l4",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-site",
        "Priority": "u=4",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache"
    }

    response = requests.get(url, headers=headers)

    results = list()
    for item in response.json():
        results.append((item['name'], item['description'], item['id']))
    return results

def pull_polo_mods():

    # Base URL and query parameters
    url = "https://api.polotab.com/api/v1/chains/d01b50da-d2cb-4eb3-a446-1441b09723cd/modifier_sets/ed59a5bf-f9b6-4d72-b98e-11ba9b47d8e6?allChannels=false"


    # Headers and cookie from your example request
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
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
    }

    cookies = {
        "backofficeUserCookie": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNjYzA2NWIxLTFmOWMtNDg5ZC04MWRjLTEzOTM2ODRmMmY2YSIsImlhdCI6MTc0NjI4Nzk2NSwiZXhwIjoxNzUxNDcxOTY1fQ.ggFPFoF3Vbp6oOMFlOkyejKLceYAa3D_jnP2l6akZ_M"
    }

    # Perform the GET request
    response = requests.get(url, headers=headers, cookies=cookies)
    j = response.json()
    mods = [(x['name'], None, x['id']) for x in j['modifiers']]
    return mods 

 
import requests, json, pytz, dateutil.parser
from datetime import datetime, time, timedelta

CST = pytz.timezone("America/Mexico_City")
API_URL = ("https://api.polotab.com/api/v1/restaurants/"
           "cd7d0f22-eb20-450e-b185-5ce412a3a8ea/orders/"
           "?page=0&perpage=1000&startDate={start}&endDate={end}&sortdir=DESC")

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Referer": "https://admin.polotab.com/",
    "Content-Type": "application/json",
    "Origin": "https://admin.polotab.com",
    "Connection": "keep-alive",
    # 👇 your auth / session cookie
    "Cookie": "backofficeUserCookie=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImNjYzA2NWIxLTFmOWMtNDg5ZC04MWRjLTEzOTM2ODRmMmY2YSIsImlhdCI6MTc0NjAyOTM3MCwiZXhwIjoxNzUxMjEzMzcwfQ.gkKcvpgXKBdEVi8xVxEXgkEwfm1a9K9NGT4B5Ghe1l4"

}

from datetime import datetime, time, timedelta
import dateutil.parser
import pytz, requests

# ── constants you already have ────────────────────────────────────────────────
# API_URL = "https://api.polotab.com/v1/orders?start={start}&end={end}"
# HEADERS = {"Authorization": "Bearer …"}
CST     = pytz.timezone("America/Mexico_City")          # Central Standard/Daylight

# ── helpers ───────────────────────────────────────────────────────────────────
def _cst_midnight(day: datetime) -> datetime:
    """Return this calendar day’s midnight in CST (aware datetime)."""
    return CST.localize(datetime.combine(day.date(), time.min))

def cst_range_to_utc_ms(start_day: datetime, end_day: datetime):
    """
    Return (start_ms, end_ms) for an **inclusive** CST date range.
    `start_day` and `end_day` may contain a time part; only the dates matter.
    """
    start_mid   = _cst_midnight(start_day)
    end_nextmid = _cst_midnight(end_day) + timedelta(days=1)

    start_ms = int(start_mid.astimezone(pytz.utc).timestamp() * 1000)
    end_ms   = int(end_nextmid.astimezone(pytz.utc).timestamp() * 1000) - 1
    return start_ms, end_ms

# ── main function ─────────────────────────────────────────────────────────────
def pull_polo_sales(start_date_str: str | None = None,
                    end_date_str:   str | None = None) -> requests.Response:
    """
    Fetch PoloTab orders between two CST calendar dates **inclusive**.

    Parameters
    ----------
    start_date_str : str | None
        ISO-like date (e.g. "2025-05-01").  If None, defaults to **today**.
    end_date_str   : str | None
        ISO-like date.  If None, defaults to `start_date_str`
        (→ single-day query identical to the old behaviour).

    Returns
    -------
    requests.Response
        Raw response from the PoloTab API.
    """
    # 1.  Parse → aware datetimes in CST
    if start_date_str:
        start_dt = dateutil.parser.parse(start_date_str)
    else:                                   # missing → today
        start_dt = datetime.now(CST)

    if end_date_str:
        end_dt = dateutil.parser.parse(end_date_str)
    else:                                   # missing → same as start
        end_dt = start_dt

    # normalise to CST
    for var in ("start_dt", "end_dt"):
        dt = locals()[var]
        if dt.tzinfo is None:
            locals()[var] = CST.localize(dt)
        else:
            locals()[var] = dt.astimezone(CST)

    # swap if user reversed them
    if start_dt > end_dt:
        start_dt, end_dt = end_dt, start_dt

    # 2.  UTC millisecond bounds
    start_ms, end_ms = cst_range_to_utc_ms(start_dt, end_dt)

    # 3.  Call the API
    url = API_URL.format(start=start_ms, end=end_ms)
    return requests.get(url, headers=HEADERS)

# ── example usage ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    # 2025-05-01 through 2025-05-07, inclusive
    r = pull_polo_sales("2025-05-01", "2025-05-07")
    print(r.status_code, r.json()[:2])      # peek at first two records


