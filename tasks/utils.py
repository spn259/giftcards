import requests 

BASE_URL       = "https://api.polotab.com"  # ← replace with the real base URL


def get_restaurant_token(api_key: str, restaurant_id: str) -> str:
    """
    POST /auth/v1/restaurants/token
    Header: Authorization: Bearer <API_KEY>
    Body:   { "restaurantId": "<id>" }
    Returns: bearer token (valid ~7 days)
    """
    url = f"{BASE_URL}/auth/v1/restaurants/token"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {"restaurantId": restaurant_id}
    resp = requests.post(url, json=payload, headers=headers, timeout=30)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        raise RuntimeError(f"Token request failed: {resp.status_code} {resp.text}") from e

    data = resp.json()
    # Adjust this if the API wraps the token differently (e.g., {"token": "..."}).
    token = data.get("token") or data.get("access_token") or data.get("bearerToken")
    if not token:
        raise ValueError(f"Token field not found in response: {data}")
    return token


def pull_order_details(order_id, bearer_token):
    resp = requests.get(
    "https://api.polotab.com/orders/v1/orders/{}".format(order_id),
    headers={
      "Content-Type": "application/json",
      "Authorization": "Bearer {}".format(bearer_token)
    })
    this_order = resp.json()

    res = list()
    platform = None
    
    for item in this_order['orderItems']:
        status = item['status']
        name = item['item']['name']
        n_items = item['quantity']
        if this_order['type'] == 'delivery':
            platform = this_order['payments'][0]['app']['name']
            
        res.append((item['itemId'], name, n_items, order_id, this_order['startedAt'], this_order['type'], False, item['totalAmount'], platform, status))
        mods = item.get('orderItemModifiers')
        if mods:
            for mod in mods:
                item_x = mod['item']
                has_name = item_x.get('name')
                mod_price = mod['price']['amount']
                res.append((mod['itemId'], has_name, mod['quantity'], order_id, this_order['startedAt'], this_order['type'], True, mod_price, platform, status))
            
            
        
    return res