"""
Python OData client for interacting with 1C via its standard OData interface.

This module defines a lightweight, stateful client that mirrors much of the
behaviour found in the original PHP implementation (see `odata_php/OData/Client.php`).
It allows you to build requests dynamically by chaining attribute accessors
(e.g. ``client.Catalog_Номенклатура``) and then invoking one of the high level
methods such as ``get``, ``create``, ``update`` or ``delete``.  Query options
like ``$filter``, ``$expand`` and ``$top`` are supported via the corresponding
``filter``, ``expand`` and ``top`` methods.  Documents can be posted/unposted
through the ``__call__`` mechanism (e.g. ``client.Document_ПлатежноеПоручение.id(guid).Post()``).

The client uses the ``requests`` library under the hood and implements basic
error handling.  After each request the client captures HTTP and OData error
codes/messages which can be inspected via ``get_http_code()``,
``get_http_message()`` and ``get_error_message()``.  A convenience method
``is_ok()`` is provided to quickly check if the previous request succeeded.

Key robustness changes:
- Ephemeral sessions per request (opt-in by default) to avoid reusing stale
  keep-alive sockets that servers (IIS/1C) often reset.
- ``Connection: close`` header by default.
- Retries on transient network/status errors.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import quote, urlencode


# ---------------------------- Response wrapper ----------------------------

class ODataResponse:
    """Wrapper around requests.Response providing helpers for 1C OData payloads."""

    def __init__(self, client: "ODataClient", response: requests.Response) -> None:
        self._client = client
        self._response = response
        self._json: Optional[Dict[str, Any]] = None

    @property
    def raw(self) -> requests.Response:
        return self._response

    def to_array(self) -> Dict[str, Any]:
        if self._json is None:
            try:
                self._json = self._response.json()
            except ValueError:
                self._json = {}
        return self._json

    def values(self) -> List[Dict[str, Any]]:
        """
        Normalize collection results across formats:
        - Modern: {"value": [...]}
        - Verbose v2/v3: {"d":{"results":[...]}} or {"d":{<entity>}}
        - Single entity: {"Ref_Key": "..."}
        """
        data = self.to_array()
        # Modern
        if isinstance(data, dict) and isinstance(data.get("value"), list):
            return data["value"]
        # Verbose
        if isinstance(data, dict) and "d" in data:
            d = data["d"]
            if isinstance(d, dict):
                if isinstance(d.get("results"), list):
                    return d["results"]
                if "Ref_Key" in d:
                    return [d]
            elif isinstance(d, list):
                return d
        # Single entity
        if isinstance(data, dict) and "Ref_Key" in data:
            return [data]
        return []

    def first(self) -> Optional[Dict[str, Any]]:
        vals = self.values()
        return vals[0] if vals else None


# ----------------------------- Request state ------------------------------

class _RequestState:
    """Mutable state shared across a fluent endpoint chain."""

    def __init__(self, segments: Optional[List[str]] = None) -> None:
        self.segments: List[str] = segments or []
        self.entity_id: Optional[Union[str, Dict[str, str]]] = None
        self.query_params: Dict[str, Any] = {}
        self.is_invocation: bool = False
        self.invocation_name: Optional[str] = None

    def clone(self) -> "_RequestState":
        new = _RequestState(self.segments.copy())
        new.entity_id = self.entity_id
        new.query_params = self.query_params.copy()
        new.is_invocation = self.is_invocation
        new.invocation_name = self.invocation_name
        return new


# ---------------------------- Endpoint builder ----------------------------

class ODataEndpoint:
    """Represents a specific OData entity set or path built from chained attributes."""

    def __init__(self, client: "ODataClient", state: _RequestState) -> None:
        self._client = client
        self._state = state

    # ---------- state builders (no I/O) ----------

    def id(self, value: Optional[Union[str, Dict[str, str]]] = None) -> "ODataEndpoint":
        """Set entity key (GUID string or composite dict)."""
        self._state.entity_id = value
        return self

    def expand(self, fields: str) -> "ODataEndpoint":
        self._state.query_params["$expand"] = fields
        return self

    def top(self, count: int) -> "ODataEndpoint":
        self._state.query_params["$top"] = int(count)
        return self

    def filter(self, expression: str) -> "ODataEndpoint":
        self._state.query_params["$filter"] = expression
        return self

    # ---------- terminal operations (do I/O) ----------

    def get(
        self,
        id: Optional[Union[str, Dict[str, str]]] = None,
        filter: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> ODataResponse:
        if id is not None:
            self._state.entity_id = id
        if filter is not None:
            self._state.query_params["$filter"] = filter
        return self._request("GET", options or {})

    def create(self, data: Dict[str, Any], options: Optional[Dict[str, Any]] = None) -> ODataResponse:
        return self.update(None, data, options or {})

    def update(
        self,
        id: Optional[Union[str, Dict[str, str]]] = None,
        data: Optional[Dict[str, Any]] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> ODataResponse:
        if id is not None:
            self._state.entity_id = id
        method = "PATCH" if self._state.entity_id else "POST"
        if options is None:
            options = {}
        if data is not None and "json" not in options:
            options = options.copy()
            options["json"] = data
        return self._request(method, options)

    def delete(
        self,
        id: Optional[Union[str, Dict[str, str]]] = None,
        filter: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> ODataResponse:
        if id is not None:
            self._state.entity_id = id
        if filter is not None:
            self._state.query_params["$filter"] = filter
        return self._request("DELETE", options or {})

    # ---------- actions / function imports ----------

    def __call__(self, name: str) -> ODataResponse:
        """Invoke a bound action (e.g. 'Post'). Requires prior .id(...)."""
        self._state.is_invocation = True
        self._state.invocation_name = name
        return self._request("POST", {})

    # Sugar for common document actions
    def Post(self) -> ODataResponse:
        self._state.is_invocation = True
        self._state.invocation_name = "Post"
        return self._request("POST", {})

    def Unpost(self) -> ODataResponse:
        self._state.is_invocation = True
        self._state.invocation_name = "Unpost"
        return self._request("POST", {})

    # ---------- internals ----------

    def _build_path(self) -> str:
        # URL-encode each path segment; keep underscores as-is
        encoded_segments: List[str] = [quote(seg, safe="_") for seg in self._state.segments]

        # Append entity key if present
        if self._state.entity_id:
            if isinstance(self._state.entity_id, dict):
                parts = []
                for k, v in self._state.entity_id.items():
                    if _is_guid(v):
                        parts.append(f"{k}=guid'{v}'")
                    else:
                        parts.append(f"{k}='{v}'")
                encoded_segments[-1] += "(" + ",".join(parts) + ")"
            else:
                v = self._state.entity_id
                if _is_guid(v):
                    encoded_segments[-1] += f"(guid'{v}')"
                else:
                    encoded_segments[-1] += f"('{v}')"

        # Append invocation name (Post/Unpost/etc.)
        if self._state.is_invocation and self._state.invocation_name:
            encoded_segments.append(self._state.invocation_name)

        return "/".join(encoded_segments)

    def _request(self, method: str, options: Dict[str, Any]) -> ODataResponse:
        self._client._reset_state()

        # Build base URL (path already encoded)
        path = self._build_path()
        base = f"{self._client.base_url}/{path}"

        # Merge query params; enforce $format=json for 1C
        params = self._state.query_params.copy()
        params.setdefault("$format", "json")
        if "params" in options and options["params"]:
            params.update(options["params"])

        # Build querystring manually so spaces become %20 (not '+') and OData tokens stay intact
        if params:
            qs = urlencode(params, doseq=True, quote_via=quote, safe="(),$'=:")
            url = f"{base}?{qs}"
        else:
            url = base

        # Use ephemeral session for this request (prevents stale keep-alive reuse)
        sess = self._client._get_session_for_request()

        req_options: Dict[str, Any] = {
            "timeout": self._client.timeout,
            "verify": self._client.verify_ssl,
            "headers": self._client._merge_headers(options.get("headers")),
            "allow_redirects": True,
        }
        if "data" in options and options["data"] is not None:
            req_options["data"] = options["data"]
        if "json" in options and options["json"] is not None:
            req_options["json"] = options["json"]

        try:
            # Save debug info
            self._client._last_url = url
            self._client._last_params = params.copy() if params else None

            response = sess.request(method, url, **req_options)
            self._client._record_response(response)
        except requests.RequestException as exc:
            self._client.http_code = getattr(exc.response, "status_code", None) or 0
            self._client.http_message = str(exc)
            self._client.odata_code = None
            self._client.odata_message = None
            if self._client.use_ephemeral_session:
                try:
                    sess.close()
                except Exception:
                    pass
            raise
        finally:
            # Reset state for next chain
            self._state.is_invocation = False
            self._state.invocation_name = None
            self._state.entity_id = None
            self._state.query_params = {}

        # Close ephemeral session immediately after the request
        if self._client.use_ephemeral_session:
            try:
                sess.close()
            except Exception:
                pass

        return ODataResponse(self._client, response)

    # Build nested segments: client.Catalog_Номенклатура.TablePart ...
    def __getattr__(self, name: str) -> "ODataEndpoint":
        if name.startswith("_"):
            raise AttributeError(name)
        new_state = self._state.clone()
        new_state.segments.append(name)
        return ODataEndpoint(self._client, new_state)


# ------------------------------- Utilities --------------------------------

def _is_guid(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        )
    )


# --------------------------------- Client ---------------------------------

def _make_retry() -> Retry:
    """Create a Retry object compatible with different urllib3 versions."""
    methods = frozenset(["GET", "POST", "PATCH", "DELETE", "PUT", "OPTIONS"])
    try:
        # Newer urllib3
        return Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.2,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=methods,
        )
    except TypeError:
        # Older urllib3 uses method_whitelist
        return Retry(
            total=3,
            connect=3,
            read=3,
            backoff_factor=0.2,
            status_forcelist=(429, 500, 502, 503, 504),
            method_whitelist=methods,  # type: ignore[arg-type]
        )


class ODataClient:
    """Top level client object used to access entity sets exposed by the 1C OData endpoint."""

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
        # Robustness toggles:
        use_ephemeral_session: bool = True,   # separate session per request
        force_close: bool = True,             # add Connection: close
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.use_ephemeral_session = use_ephemeral_session
        self.force_close = force_close

        # Reference session: NOT shared across threads; used as a template
        self.session = requests.Session()
        self.session.trust_env = False  # ignore system proxies (deterministic behavior)
        if username is not None and password is not None:
            self.session.auth = (username, password)

        headers = {"Accept": "application/json; charset=utf-8"}
        if extra_headers:
            headers.update(extra_headers)
        if self.force_close:
            headers["Connection"] = "close"
        self.session.headers.update(headers)

        # Small pool + retries on the reference session
        retry = _make_retry()
        adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        # Last request/response info
        self.http_code: Optional[int] = None
        self.http_message: Optional[str] = None
        self.odata_code: Optional[str] = None
        self.odata_message: Optional[str] = None
        self._last_id: Optional[str] = None

        # Metadata cache
        self._metadata_cache: Optional[Dict[str, Any]] = None

        # Debug: last request URL/params
        self._last_url: Optional[str] = None
        self._last_params: Optional[Dict[str, Any]] = None

    # ----- debug -----

    def get_last_request(self) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
        """Return (url, params) of the last HTTP request for debugging."""
        return self._last_url, self._last_params

    # ----- internal state tracking -----

    def _reset_state(self) -> None:
        self.http_code = None
        self.http_message = None
        self.odata_code = None
        self.odata_message = None
        self._last_id = None

    def _record_response(self, response: requests.Response) -> None:
        self.http_code = response.status_code
        self.http_message = response.reason

        # Parse JSON body to extract OData error/Ref_Key if available
        try:
            data = response.json()
        except ValueError:
            data = None

        if isinstance(data, dict):
            err = data.get("odata.error") or data.get("error") or None
            if isinstance(err, dict):
                code = err.get("code") or (err.get("error") if isinstance(err.get("error"), str) else None)
                msg_obj = err.get("message")
                message = None
                if isinstance(msg_obj, dict):
                    message = msg_obj.get("value") or msg_obj.get("Message")
                elif isinstance(msg_obj, str):
                    message = msg_obj
                self.odata_code = code
                self.odata_message = message

            if "Ref_Key" in data and isinstance(data["Ref_Key"], str):
                self._last_id = data["Ref_Key"]

        # Fallback: parse GUID from Location header
        loc = response.headers.get("Location")
        if not self._last_id and loc:
            m = re.search(r"\(guid'([0-9a-fA-F-]{36})'\)", loc)
            if m:
                self._last_id = m.group(1)

    # ----- session helpers -----

    def _new_ephemeral_session(self) -> requests.Session:
        s = requests.Session()
        s.trust_env = False
        s.headers.update(self.session.headers)  # copy Accept/Connection/etc.
        s.auth = self.session.auth
        retry = _make_retry()
        adapter = HTTPAdapter(max_retries=retry, pool_connections=1, pool_maxsize=1)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _get_session_for_request(self) -> requests.Session:
        return self._new_ephemeral_session() if self.use_ephemeral_session else self.session

    def _merge_headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        headers = dict(self.session.headers)
        if self.force_close:
            headers["Connection"] = "close"
        if extra:
            headers.update(extra)
        return headers

    # ----- public API -----

    def __getattr__(self, name: str) -> ODataEndpoint:
        if name.startswith("_"):
            raise AttributeError(name)
        state = _RequestState([name])
        return ODataEndpoint(self, state)

    def is_ok(self) -> bool:
        return (self.http_code is not None and 200 <= self.http_code < 300 and self.odata_code is None)

    def get_http_code(self) -> Optional[int]:
        return self.http_code

    def get_http_message(self) -> Optional[str]:
        return self.http_message

    def get_error_code(self) -> Optional[str]:
        return self.odata_code

    def get_error_message(self) -> Optional[str]:
        return self.odata_message

    def get_last_id(self) -> Optional[str]:
        return self._last_id

    # ----- metadata -----

    def get_metadata(self) -> Dict[str, Any]:
        """
        Retrieve and cache OData metadata (EDMX v2/v3/v4 or service document).
        Returns dict: {Name: entity_type or None}
        """
        if self._metadata_cache is not None and (self._metadata_cache.get("entity_sets") or {}):
            # Return only entity_sets as {Name: entity_type or None}
            return {k: v.get("entity_type") for k, v in self._metadata_cache["entity_sets"].items()}

        url = f"{self.base_url.strip()}/$metadata"
        headers = self._merge_headers({"Accept": "application/xml"})

        entity_sets: Dict[str, Optional[str]] = {}

        # 1) request $metadata
        sess = self._get_session_for_request()
        try:
            resp = sess.get(url, timeout=self.timeout, verify=self.verify_ssl, headers=headers, allow_redirects=True)
            self._record_response(resp)
            raw = resp.text
        except requests.RequestException as exc:
            self.http_code = getattr(exc.response, "status_code", None) or 0
            self.http_message = str(exc)
            self.odata_code = None
            self.odata_message = None
            self._metadata_cache = {"entity_sets": {}}
            if self.use_ephemeral_session:
                try:
                    sess.close()
                except Exception:
                    pass
            return {}
        finally:
            if self.use_ephemeral_session:
                try:
                    sess.close()
                except Exception:
                    pass

        parsed = False

        # 2) Try EDMX parse (namespace-agnostic)
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(raw)

            # 2.1 read EntitySet(s) from any EntityContainer
            for node in root.iter():
                if node.tag.endswith("EntityContainer"):
                    for es in list(node):
                        if es.tag.endswith("EntitySet"):
                            name = es.get("Name")
                            etype = es.get("EntityType")
                            if name:
                                entity_sets[name] = etype
            parsed = bool(entity_sets)

            # 3) If nothing found, try APP service document
            if not parsed:
                ns_app = {"app": "http://www.w3.org/2007/app"}
                for coll in root.findall(".//app:collection", ns_app):
                    href = coll.get("href")
                    if href:
                        entity_sets[href] = None
                parsed = bool(entity_sets)
        except Exception:
            parsed = False

        # 4) Fallback: GET base_url as APP service document
        if not parsed:
            sess2 = self._get_session_for_request()
            try:
                resp2 = sess2.get(self.base_url.strip(), timeout=self.timeout, verify=self.verify_ssl, headers=headers, allow_redirects=True)
                self._record_response(resp2)
                try:
                    import xml.etree.ElementTree as ET

                    root2 = ET.fromstring(resp2.text)
                    ns_app = {"app": "http://www.w3.org/2007/app"}
                    for coll in root2.findall(".//app:collection", ns_app):
                        href = coll.get("href")
                        if href:
                            entity_sets[href] = None
                except Exception:
                    entity_sets = {}
            except requests.RequestException as exc:
                self.http_code = getattr(exc.response, "status_code", None) or 0
                self.http_message = str(exc)
                self.odata_code = None
                self.odata_message = None
            finally:
                if self.use_ephemeral_session:
                    try:
                        sess2.close()
                    except Exception:
                        pass

        self._metadata_cache = {"entity_sets": {k: {"entity_type": v} for k, v in entity_sets.items()}}
        # Return only entity_sets as {Name: entity_type or None}
        return {k: v for k, v in entity_sets.items()}

    # ----- table parts helpers -----

    def _build_entity_uri(self, parent_name: str, parent_id: Union[str, Dict[str, str]]) -> str:
        if isinstance(parent_id, dict):
            key_parts = []
            for k, v in parent_id.items():
                if _is_guid(v):
                    key_parts.append(f"{k}=guid'{v}'")
                else:
                    key_parts.append(f"{k}='{v}'")
            key = "(" + ",".join(key_parts) + ")"
        else:
            key = f"(guid'{parent_id}')" if _is_guid(parent_id) else f"('{parent_id}')"
        # URL-encode the parent_name (Cyrillic)
        return f"{self.base_url}/{quote(parent_name, safe='_')}{key}"

    def add_table_part_rows(
        self,
        parent_name: str,
        parent_id: Union[str, Dict[str, str]],
        table_name: str,
        rows: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        POST rows to table part:
            <base>/<parent_name>(...)/<table_name>
        Returns brief result per row.
        """
        uri = f"{self._build_entity_uri(parent_name, parent_id)}/{quote(table_name)}"
        results: List[Dict[str, Any]] = []
        for row in rows or []:
            sess = self._get_session_for_request()
            try:
                r = sess.post(
                    uri,
                    json=row,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    headers=self._merge_headers(None),
                    allow_redirects=True,
                )
                self._record_response(r)
                ok = 200 <= r.status_code < 300
                results.append(
                    {
                        "http_code": r.status_code,
                        "http_message": r.reason,
                        "ok": ok,
                        "row": row,
                    }
                )
            except requests.RequestException as exc:
                results.append(
                    {
                        "http_code": getattr(exc.response, "status_code", 0) or 0,
                        "http_message": str(exc),
                        "ok": False,
                        "row": row,
                    }
                )
            finally:
                if self.use_ephemeral_session:
                    try:
                        sess.close()
                    except Exception:
                        pass
        return results

    def get_table_part(
        self,
        parent_name: str,
        parent_id: Union[str, Dict[str, str]],
        table_name: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> ODataResponse:
        base = f"{self._build_entity_uri(parent_name, parent_id)}/{quote(table_name)}"
        if params:
            qs = urlencode(params, doseq=True, quote_via=quote, safe="(),$'=:")
            url = f"{base}?{qs}"
        else:
            url = base

        sess = self._get_session_for_request()
        try:
            r = sess.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                headers=self._merge_headers(None),
                allow_redirects=True,
            )
            self._record_response(r)
            return ODataResponse(self, r)
        finally:
            if self.use_ephemeral_session:
                try:
                    sess.close()
                except Exception:
                    pass
