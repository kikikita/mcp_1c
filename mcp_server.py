import httpx
from typing import Annotated, List, Dict, Any

import httpx
from fastapi import HTTPException, Request
from mcp.server.fastmcp import FastMCP
from .onec_client import (
    find_objects as oc_find_objects,
    get_object as oc_get_object,
    create_object as oc_create_object,
    update_object as oc_update_object,
    delete_object as oc_delete_object,
    post_document as oc_post_document,
    unpost_document as oc_unpost_document,
    get_metadata as oc_get_metadata,
)


# Base URL of real 1C instance. If not provided, dummy in-memory data will be used.
API_BASE_URL = os.getenv("MCP_1C_BASE")

mcp = FastMCP("mcp_1c")

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
    return 500


async def _forward(method: str, url: str, **kwargs):
    """Forward request to real 1C if base URL is configured."""
    if not API_BASE_URL:
        raise RuntimeError("Real 1C base URL not configured")
    async with httpx.AsyncClient(base_url=API_BASE_URL) as client:
        resp = await client.request(method, url, **kwargs)
    if resp.status_code >= 400:
        try:
            detail = resp.json()
        except Exception:
            detail = resp.text
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
    """List objects from 1C."""
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
    """Get object by ID."""
    if API_BASE_URL:
        return await _forward("GET", f"/{type}/{name}/{id}")
    item = _dummy_db.get(f"{type}/{name}", {}).get(id)
    if not item:
        raise HTTPException(status_code=404, detail="not found")
    return item


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}", methods=["POST"])
async def create_item(request: Request, type: str, name: str) -> Dict:
    """Create a new object."""
    payload = await request.json()
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
async def update_item(request: Request, type: str, name: str, id: str) -> Dict:
    """Update existing object."""
    payload = await request.json()
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
    """Delete object."""
    if API_BASE_URL:
        return await _forward("DELETE", f"/{type}/{name}/{id}")
    store = _dummy_db.setdefault(f"{type}/{name}", {})
    if id not in store:
        raise HTTPException(status_code=404, detail="not found")
    return store.pop(id)


@mcp.tool()
@mcp.custom_route("/mcp/{type}/{name}/{id}/post", methods=["POST"])
async def post_item(type: str, name: str, id: str) -> Dict:
    """Post object in 1C."""
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
    """Unpost object in 1C."""
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
async def get_metadata():
    """Получить метаданные базы 1С."""
    return await oc_get_metadata()


if __name__ == "__main__":
    mcp.run()
