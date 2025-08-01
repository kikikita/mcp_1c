import requests
from requests.auth import HTTPBasicAuth

# === Connection parameters ===
BASE_URL = "http://192.168.18.113/TEST19/odata/standard.odata/Catalog_Контрагенты?$format=json"
USERNAME = "nikita"
PASSWORD = "password"

# === Request parameters ===

try:
    response = requests.get(
        BASE_URL,
        auth=HTTPBasicAuth(USERNAME, PASSWORD),
        timeout=10
    )

    print("Status code:", response.status_code)

    if response.status_code == 200:
        print("Server response:")
        print(response.text)  # or response.json() if the response is JSON
    else:
        print("Error:", response.text)

except requests.exceptions.RequestException as e:
    print("Connection error:", e)
