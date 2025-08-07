"""MCP server exposing 1C OData operations as callable tools for LLM agents.

The :class:`MCPServer` class provides a thin abstraction over
:class:`~odata_client.ODataClient`.  Functions defined at module level and
decorated with :func:`mcp.tool <mcp.server.fastmcp.FastMCP.tool>` expose these
operations to Model Context Protocol (MCP) clients.  Tools are intentionally
atomic so that a language model can compose complex business workflows from
simple primitives.
"""

from __future__ import annotations

import asyncio
import os
import json
import re
from typing import Any, Dict, List, Optional, Union

from mcp.server.fastmcp import FastMCP
from odata_client import ODataClient, _is_guid


class MCPServer:
    """Encapsulates business level operations on top of the OData client."""

    def __init__(self, base_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 30, verify_ssl: bool = False) -> None:
        self.client = ODataClient(base_url, username=username, password=password,
                                  timeout=timeout, verify_ssl=verify_ssl)

    # ------------------------------------------------------------------
    # Helper methods
    # ------------------------------------------------------------------

    @staticmethod
    def _build_filter(filters: Union[Dict[str, Any], List[str], None]) -> Optional[str]:
        """Convert a dictionary or list of conditions into an OData filter string.

        The simplest form accepts a mapping of field names to literal values and
        joins them with ``and``.  String values are quoted, GUIDs are wrapped
        using the ``guid'...'`` literal and numeric/boolean values are passed
        through.  You can also pass a list of raw filter expressions which
        will be joined with ``and`` verbatim.  If ``filters`` is already a
        string it is returned unchanged.
        """
        if filters is None:
            return None
        # If user provides a string just return it
        if isinstance(filters, str):
            return filters
        # If a list is provided treat each element as a complete expression
        if isinstance(filters, list):
            return " and ".join(filt for filt in filters if filt)
        if isinstance(filters, dict):
            exprs: List[str] = []
            for key, value in filters.items():
                if value is None:
                    exprs.append(f"{key} eq null")
                elif isinstance(value, bool):
                    exprs.append(f"{key} eq {'true' if value else 'false'}")
                elif isinstance(value, (int, float)):
                    exprs.append(f"{key} eq {value}")
                elif isinstance(value, str):
                    # If the value looks like an expression (contains space or operator) then use as is
                    if re.search(r"\s(and|or|eq|ne|gt|lt|ge|le)\s", value, re.IGNORECASE):
                        exprs.append(f"{key} {value}")
                    elif _is_guid(value):
                        exprs.append(f"{key} eq guid'{value}'")
                    else:
                        # Escape single quotes by doubling them
                        safe = value.replace("'", "''")
                        exprs.append(f"{key} eq '{safe}'")
                else:
                    # Fallback to string conversion
                    exprs.append(f"{key} eq '{value}'")
            return " and ".join(exprs)
        return None

    @staticmethod
    def _parse_result(response, client: ODataClient) -> Dict[str, Any]:
        """Return a unified result dictionary from an ODataResponse."""
        return {
            "http_code": client.get_http_code(),
            "http_message": client.get_http_message(),
            "odata_error_code": client.get_error_code(),
            "odata_error_message": client.get_error_message(),
            "last_id": client.get_last_id(),
            "data": response.values() if hasattr(response, "values") else None,
        }

    # ------------------------------------------------------------------
    # Tool implementations
    # ------------------------------------------------------------------

    def list_objects(self, object_name: str, filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
                      top: Optional[int] = None, expand: Optional[str] = None) -> Dict[str, Any]:
        """Return a list of entities from the specified entity set.

        :param object_name: Name of the entity set (e.g. ``Catalog_Номенклатура``).
        :param filters: Optional filter specification.  See :meth:`_build_filter`.
        :param top: Optional maximum number of records to return.
        :param expand: Optional comma separated list of navigation properties to expand.
        :return: Dictionary containing metadata and the list under the ``data`` key.
        """
        builder = getattr(self.client, object_name)
        # Apply query options
        if expand:
            builder = builder.expand(expand)
        if top is not None:
            builder = builder.top(int(top))
        if filters:
            filt = self._build_filter(filters)
            if filt:
                builder = builder.filter(filt)
        response = builder.get()
        return self._parse_result(response, self.client)

    def find_object(self, object_name: str, filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
                    expand: Optional[str] = None) -> Dict[str, Any]:
        """Return the first entity that matches the given filter.

        :param object_name: Name of the entity set.
        :param filters: Filter specification.  See :meth:`_build_filter`.
        :param expand: Optional navigation properties to expand.
        :return: Result dictionary.  The ``data`` key will contain either a
            single record or be ``None`` if nothing matched.
        """
        builder = getattr(self.client, object_name)
        if expand:
            builder = builder.expand(expand)
        if filters:
            filt = self._build_filter(filters)
            if filt:
                builder = builder.filter(filt)
        # Only request one record by default
        builder = builder.top(1)
        response = builder.get()
        result = self._parse_result(response, self.client)
        vals = result.get("data") or []
        result["data"] = vals[0] if vals else None
        return result

    def create_object(self, object_name: str, data: Dict[str, Any], expand: Optional[str] = None) -> Dict[str, Any]:
        """Create a new entity and return its identifier.

        :param object_name: Name of the entity set.
        :param data: Dictionary of field names and values to populate on the new entity.
        :param expand: Optional navigation properties to expand in the returned payload.
        :return: Result dictionary.  ``last_id`` will contain the new Ref_Key.
        """
        builder = getattr(self.client, object_name)
        if expand:
            builder = builder.expand(expand)
        response = builder.create(data)
        return self._parse_result(response, self.client)

    def update_object(self, object_name: str, object_id: Union[str, Dict[str, str]], data: Dict[str, Any],
                      expand: Optional[str] = None) -> Dict[str, Any]:
        """Update an existing entity.

        :param object_name: Name of the entity set.
        :param object_id: GUID or composite key identifying the entity.
        :param data: Dictionary of fields to update.
        :param expand: Optional navigation properties to expand in the returned payload.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        if expand:
            builder = builder.expand(expand)
        response = builder.update(data=data)
        return self._parse_result(response, self.client)

    def delete_object(self, object_name: str, object_id: Union[str, Dict[str, str]],
                      physical_delete: bool = False) -> Dict[str, Any]:
        """Delete an entity by marking it or removing it entirely.

        :param object_name: Name of the entity set.
        :param object_id: GUID or composite key.
        :param physical_delete: If ``True`` perform a physical deletion via
            HTTP DELETE.  Otherwise perform a logical deletion by setting
            ``DeletionMark`` to ``true`` via :meth:`update_object`.
        :return: Result dictionary.
        """
        if physical_delete:
            builder = getattr(self.client, object_name).id(object_id)
            response = builder.delete()
            return self._parse_result(response, self.client)
        # Logical delete
        return self.update_object(object_name, object_id, {"DeletionMark": True})

    def post_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        """Conduct (post) a document.

        :param object_name: Name of the document entity set (e.g. ``Document_ПлатежноеПоручение``).
        :param object_id: GUID identifying the document.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Post")  # invoke Post action
        return self._parse_result(response, self.client)

    def unpost_document(self, object_name: str, object_id: Union[str, Dict[str, str]]) -> Dict[str, Any]:
        """Reverse (unpost) a document.

        :param object_name: Name of the document entity set.
        :param object_id: GUID identifying the document.
        :return: Result dictionary.
        """
        builder = getattr(self.client, object_name).id(object_id)
        response = builder("Unpost")
        return self._parse_result(response, self.client)

    def get_schema(self, object_name: str) -> Dict[str, Any]:
        """Return the metadata for the specified entity set.

        The returned dictionary contains the entity type and a mapping of
        property names to their EDM types.
        """
        meta = self.client.get_metadata()
        es = meta.get("entity_sets", {}).get(object_name)
        return {
            "http_code": self.client.get_http_code(),
            "http_message": self.client.get_http_message(),
            "odata_error_code": self.client.get_error_code(),
            "odata_error_message": self.client.get_error_message(),
            "schema": es,
        }


# ---------------------------------------------------------------------------
# FastMCP integration
# ---------------------------------------------------------------------------

# Environment configuration is read once at import time.  The server will fail
# later during requests if a mandatory parameter (e.g. ``MCP_1C_BASE``) is
# missing, which keeps module import lightweight.
BASE_URL = os.getenv("MCP_1C_BASE", "")
USERNAME = os.getenv("ONEC_USERNAME")
PASSWORD = os.getenv("ONEC_PASSWORD")
VERIFY_SSL = os.getenv("ONEC_VERIFY_SSL", "false").lower() not in {"false", "0", "no"}

_server = MCPServer(BASE_URL, username=USERNAME, password=PASSWORD, verify_ssl=VERIFY_SSL)

# FastMCP application instance used to expose tools to the LLM agent.
mcp = FastMCP("mcp_1c")


@mcp.tool()
async def list_objects(
    object_name: str,
    filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    top: Optional[int] = None,
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a list of entities from the specified entity set."""
    return await asyncio.to_thread(_server.list_objects, object_name, filters, top, expand)


@mcp.tool()
async def find_object(
    object_name: str,
    filters: Optional[Union[str, Dict[str, Any], List[str]]] = None,
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Return the first entity matching the filter from the specified entity set."""
    return await asyncio.to_thread(_server.find_object, object_name, filters, expand)


@mcp.tool()
async def create_object(
    object_name: str,
    data: Dict[str, Any],
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new entity in the specified entity set."""
    return await asyncio.to_thread(_server.create_object, object_name, data, expand)


@mcp.tool()
async def update_object(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
    data: Dict[str, Any],
    expand: Optional[str] = None,
) -> Dict[str, Any]:
    """Update fields of an existing entity."""
    return await asyncio.to_thread(_server.update_object, object_name, object_id, data, expand)


@mcp.tool()
async def delete_object(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
    physical_delete: bool = False,
) -> Dict[str, Any]:
    """Delete an entity (logical by default)."""
    return await asyncio.to_thread(_server.delete_object, object_name, object_id, physical_delete)


@mcp.tool()
async def post_document(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
) -> Dict[str, Any]:
    """Conduct (post) a document."""
    return await asyncio.to_thread(_server.post_document, object_name, object_id)


@mcp.tool()
async def unpost_document(
    object_name: str,
    object_id: Union[str, Dict[str, str]],
) -> Dict[str, Any]:
    """Reverse a previously posted document."""
    return await asyncio.to_thread(_server.unpost_document, object_name, object_id)


@mcp.tool()
async def get_schema(object_name: str) -> Dict[str, Any]:
    """Retrieve metadata (properties and types) for the specified entity set."""
    return await asyncio.to_thread(_server.get_schema, object_name)


# Expose ASGI application for uvicorn/ASGI servers.
app = mcp.streamable_http_app()


if __name__ == "__main__":
    mcp.run("streamable-http")

