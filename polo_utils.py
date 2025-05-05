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

def cst_day_to_utc_ms(day):
    """Return (start_ms, end_ms) UTC epoch-ms for a CST calendar date."""
    # strip any time part, keep only date
    cst_midnight = CST.localize(datetime.combine(day.date(), time.min))
    cst_next_mid = cst_midnight + timedelta(days=1)

    start_ms = int(cst_midnight.astimezone(pytz.utc).timestamp() * 1000)
    end_ms   = int(cst_next_mid.astimezone(pytz.utc).timestamp() * 1000) - 1
    return start_ms, end_ms

def pull_polo_sales(date_str):
    """
    Query PoloTab orders for a given CST calendar day (default: today CST)
    and return the raw `requests.Response`.
    """
    # ── 1. pick the target day in CST ──
    if date_str:
        dt = dateutil.parser.parse(date_str)
        if dt.tzinfo is None:
            dt = CST.localize(dt)       # naive → CST
        else:
            dt = dt.astimezone(CST)     # convert whatever → CST
    else:
        dt = datetime.now(CST)

    # ── 2. convert to UTC millisecond bounds ──
    start_ms, end_ms = cst_day_to_utc_ms(dt)

    # ── 3. hit the API ──
    url = API_URL.format(start=start_ms, end=end_ms)
    return requests.get(url, headers=HEADERS)


