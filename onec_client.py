import os
from typing import Any, Dict, Optional

import httpx


_BASE_URL = os.environ.get("ONEC_BASE_URL", "http://localhost:9000/1c")
_USERNAME = os.environ.get("ONEC_USERNAME", "")
_PASSWORD = os.environ.get("ONEC_PASSWORD", "")

_AUTH = httpx.BasicAuth(_USERNAME, _PASSWORD)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=_BASE_URL, auth=_AUTH)


async def find_objects(obj_type: str, params: Optional[Dict[str, Any]] = None) -> Any:
    """Search for objects of the given type."""
    async with _client() as client:
        resp = await client.get(f"/{obj_type}", params=params)
        resp.raise_for_status()
        return resp.json()


async def get_object(obj_type: str, obj_id: str) -> Any:
    """Retrieve a single object by id."""
    async with _client() as client:
        resp = await client.get(f"/{obj_type}/{obj_id}")
        resp.raise_for_status()
        return resp.json()


async def create_object(obj_type: str, data: Dict[str, Any]) -> Any:
    """Create a new object."""
    async with _client() as client:
        resp = await client.post(f"/{obj_type}", json=data)
        resp.raise_for_status()
        return resp.json()


async def update_object(obj_type: str, obj_id: str, data: Dict[str, Any]) -> Any:
    """Update an existing object."""
    async with _client() as client:
        resp = await client.put(f"/{obj_type}/{obj_id}", json=data)
        resp.raise_for_status()
        return resp.json()


async def delete_object(obj_type: str, obj_id: str) -> None:
    """Delete an object."""
    async with _client() as client:
        resp = await client.delete(f"/{obj_type}/{obj_id}")
        resp.raise_for_status()


async def post_document(doc_type: str, doc_id: str) -> Any:
    """Post (close) a document."""
    async with _client() as client:
        resp = await client.post(f"/{doc_type}/{doc_id}/post")
        resp.raise_for_status()
        return resp.json()


async def unpost_document(doc_type: str, doc_id: str) -> Any:
    """Unpost (reopen) a document."""
    async with _client() as client:
        resp = await client.post(f"/{doc_type}/{doc_id}/unpost")
        resp.raise_for_status()
        return resp.json()


async def search_nomenclature(name: str) -> Any:
    """Поиск номенклатуры по части наименования."""
    params = {"$filter": f"contains(Description,'{name}')", "$top": 10}
    async with _client() as client:
        resp = await client.get("/Catalog_Номенклатура", params=params)
        resp.raise_for_status()
        return resp.json()


async def create_nomenclature(data: Dict[str, Any]) -> Any:
    """Создание нового элемента номенклатуры."""
    async with _client() as client:
        resp = await client.post("/Catalog_Номенклатура", json=data)
        resp.raise_for_status()
        return resp.json()


async def search_contractor(inn: str) -> Any:
    """Поиск контрагента по ИНН."""
    params = {"$filter": f"ИНН eq '{inn}'", "$top": 10}
    async with _client() as client:
        resp = await client.get("/Catalog_Контрагенты", params=params)
        resp.raise_for_status()
        return resp.json()


async def create_contractor(data: Dict[str, Any]) -> Any:
    """Создание нового контрагента."""
    async with _client() as client:
        resp = await client.post("/Catalog_Контрагенты", json=data)
        resp.raise_for_status()
        return resp.json()


async def create_payment(data: Dict[str, Any]) -> Any:
    """Создание платёжного поручения."""
    async with _client() as client:
        resp = await client.post("/payments", json=data)
        resp.raise_for_status()
        return resp.json()


async def get_metadata() -> Any:
    """Возвратить описание метаданных 1К."""
    async with _client() as client:
        resp = await client.get("/$metadata")
        resp.raise_for_status()
        return resp.text
