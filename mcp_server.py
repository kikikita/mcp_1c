import os
import logging
from typing import Annotated, List, Dict, Any, Optional

import httpx
from fastapi import HTTPException
from pydantic import Field
from mcp.server.fastmcp import FastMCP
from onec_client import (
    get_metadata as oc_get_metadata,
    search_nomenclature as oc_search_nomenclature,
    create_nomenclature as oc_create_nomenclature,
    search_contractor as oc_search_contractor,
    create_contractor as oc_create_contractor,
)


# Base URL of real 1C instance. If not provided, dummy in-memory data will be used.
API_BASE_URL = os.getenv("MCP_1C_BASE")
ONEC_USERNAME = os.getenv("ONEC_USERNAME")
ONEC_PASSWORD = os.getenv("ONEC_PASSWORD")

logger = logging.getLogger(__name__)

mcp = FastMCP("mcp_1c")
app = mcp.streamable_http_app

# --- Dummy storage for local testing ---
_dummy_db: Dict[str, Dict[str, Dict]] = {}
_metadata: Dict[str, Dict] = {}


def _error_status(message: str) -> int:
    """Map common 1C error messages to HTTP status codes."""
    msg = message.lower()
    if "не найден" in msg:
        return 404
    if "уже существует" in msg or "существует" in msg:
        return 409
    if "некоррект" in msg or "ошибка" in msg:
        return 400
    if "недопуст" in msg or "валид" in msg:
        return 422
    if "не авториз" in msg or "доступ" in msg:
        return 401
    return 500


async def _forward(method: str, url: str, **kwargs):
    """Forward request to real 1C if base URL is configured."""
    if not API_BASE_URL:
        raise RuntimeError("Real 1C base URL not configured")
    auth = None
    if ONEC_USERNAME and ONEC_PASSWORD:
        auth = httpx.BasicAuth(ONEC_USERNAME, ONEC_PASSWORD)
    async with httpx.AsyncClient(base_url=API_BASE_URL, auth=auth) as client:
        resp = await client.request(method, url, **kwargs)
    if resp.status_code >= 400:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
        logger.exception("1C returned error: %s", detail)
        status = _error_status(str(detail))
        raise HTTPException(status_code=status, detail=detail)
    if resp.content:
        return resp.json()
    return None


# ---------------------------------------------------------------------------
# API ENDPOINTS
# ---------------------------------------------------------------------------

@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}", methods=["GET"])
async def list_items(type: str, name: str, filter: Optional[str] = None) -> List[Dict]:
    """Получить список объектов указанного типа."""
    if API_BASE_URL:
        params = {"filter": filter} if filter else None
        return await _forward("GET", f"/{type}/{name}", params=params)
    data = list(_dummy_db.get(f"{type}/{name}", {}).values())
    if filter:
        data = [d for d in data if filter.lower() in str(d).lower()]
    return data


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}/{id}", methods=["GET"])
async def get_item(type: str, name: str, id: str) -> Dict:
    """Получить объект по идентификатору."""
    if API_BASE_URL:
        return await _forward("GET", f"/{type}/{name}/{id}")
    item = _dummy_db.get(f"{type}/{name}", {}).get(id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    return item


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}", methods=["POST"])
async def create_item(type: str, name: str, payload: Dict[str, Any]) -> Dict:
    """Создать новый объект."""
    if API_BASE_URL:
        return await _forward("POST", f"/{type}/{name}", json=payload)
    obj_store = _dummy_db.setdefault(f"{type}/{name}", {})
    new_id = str(len(obj_store) + 1)
    if any(p.get("name") == payload.get("name") for p in obj_store.values()):
        raise HTTPException(status_code=409, detail="already exists")
    obj_store[new_id] = {**payload, "id": new_id, "posted": False}
    return obj_store[new_id]


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}/{id}", methods=["PATCH"])
async def update_item(type: str, name: str, id: str, payload: Dict[str, Any]) -> Dict:
    """Обновить существующий объект."""
    if API_BASE_URL:
        return await _forward("PATCH", f"/{type}/{name}/{id}", json=payload)
    store = _dummy_db.setdefault(f"{type}/{name}", {})
    if id not in store:
        raise HTTPException(status_code=404, detail="not found")
    store[id].update(payload)
    return store[id]


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}/{id}", methods=["DELETE"])
async def delete_item(type: str, name: str, id: str) -> Dict:
    """Удалить объект."""
    if API_BASE_URL:
        return await _forward("DELETE", f"/{type}/{name}/{id}")
    store = _dummy_db.setdefault(f"{type}/{name}", {})
    if id not in store:
        raise HTTPException(status_code=404, detail="not found")
    return store.pop(id)


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}/{id}/post", methods=["POST"])
async def post_item(type: str, name: str, id: str) -> Dict:
    """Провести документ в 1К."""
    if API_BASE_URL:
        return await _forward("POST", f"/{type}/{name}/{id}/post")
    store = _dummy_db.setdefault(f"{type}/{name}", {})
    item = store.get(id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    if item.get("posted"):
        raise HTTPException(status_code=409, detail="already posted")
    item["posted"] = True
    return item


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}/{id}/unpost", methods=["POST"])
async def unpost_item(type: str, name: str, id: str) -> Dict:
    """Отменить проведение документа."""
    if API_BASE_URL:
        return await _forward("POST", f"/{type}/{name}/{id}/unpost")
    store = _dummy_db.setdefault(f"{type}/{name}", {})
    item = store.get(id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    if not item.get("posted"):
        raise HTTPException(status_code=409, detail="not posted")
    item["posted"] = False
    return item


@mcp.tool()
async def get_credit(
    account: Annotated[str, Field(description="Код счёта")],
    period_start: Annotated[str, Field(description="Дата начала периода dd-mm-yyyy")],
    period_end: Annotated[str, Field(description="Дата конца периода dd-mm-yyyy")],
) -> List[Dict]:
    """Получить сумму кредитовых оборотов по счёту за указанный период."""
    params = {"account": account, "periodStart": period_start, "periodEnd": period_end}
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"{API_BASE_URL}/turnover", params=params)
        resp.raise_for_status()
        data = resp.json()
    result = []
    for row in data:
        analytics = ", ".join(filter(None, [
            row.get("Субконто1Представление"),
            row.get("Субконто2Представление"),
            row.get("Субконто3Представление"),
        ]))
        result.append({"account": row["СчетКод"], "analytics": analytics, "amount": row["СуммаОборотКт"]})
    return result


@mcp.tool()
async def find_objects(obj_type: str, params: Dict[str, Any] | None = None):
    """Поиск объектов произвольного типа."""
    return await oc_find_objects(obj_type, params)


@mcp.tool()
async def get_object(obj_type: str, obj_id: str):
    """Получение объекта по идентификатору."""
    return await oc_get_object(obj_type, obj_id)


@mcp.tool()
async def create_object(obj_type: str, data: Dict[str, Any]):
    """Создание объекта указанного типа."""
    return await oc_create_object(obj_type, data)


@mcp.tool()
async def update_object(obj_type: str, obj_id: str, data: Dict[str, Any]):
    """Обновление существующего объекта."""
    return await oc_update_object(obj_type, obj_id, data)


@mcp.tool()
async def delete_object(obj_type: str, obj_id: str):
    """Удаление объекта."""
    await oc_delete_object(obj_type, obj_id)


@mcp.tool()
async def post_document(doc_type: str, doc_id: str):
    """Проведение документа."""
    return await oc_post_document(doc_type, doc_id)


@mcp.tool()
async def unpost_document(doc_type: str, doc_id: str):
    """Отмена проведения документа."""
    return await oc_unpost_document(doc_type, doc_id)


@mcp.tool()
async def search_nomenclature(name: str) -> List[Dict]:
    """Найти номенклатуру по части названия."""
    return await oc_search_nomenclature(name)


@mcp.tool()
async def create_nomenclature(data: Dict[str, Any]) -> Dict:
    """Создать новую номенклатуру."""
    return await oc_create_nomenclature(data)


@mcp.tool()
async def search_contractor(inn: str) -> List[Dict]:
    """Найти контрагента по ИНН."""
    return await oc_search_contractor(inn)


@mcp.tool()
async def create_contractor(data: Dict[str, Any]) -> Dict:
    """Создать контрагента."""
    return await oc_create_contractor(data)


@mcp.tool()
async def create_payment(data: Dict[str, Any]) -> Dict:
    """Создать платёжное поручение."""
    return await oc_create_payment(data)


@mcp.tool()
async def get_metadata():
    """Получить метаданные базы 1С."""
    return await oc_get_metadata()


if __name__ == "__main__":
    mcp.run()
