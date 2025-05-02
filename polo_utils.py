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