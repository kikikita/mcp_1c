import requests
from requests.auth import HTTPBasicAuth
import logging

from log_config import setup_logging

setup_logging()
logger = logging.getLogger(__name__)

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

    logger.info("Status code: %s", response.status_code)

    if response.status_code == 200:
        logger.debug("Server response: %s", response.text)  # or response.json() if the response is JSON
    else:
        logger.error("Error: %s", response.text)

except requests.exceptions.RequestException as e:
    logger.exception("Connection error: %s", e)
