"""
Python OData client for interacting with 1C via its standard OData interface.
FIXED VERSION with optimized connection management and proper session pool usage.

Key improvements:
- Fixed session pool usage (don't close pooled sessions)
- Better Ref_Key capture from verbose payloads
- Improved error handling and resource cleanup
"""

from __future__ import annotations

import re
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
import threading
import time

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import quote, urlencode

logger = logging.getLogger(__name__)


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
            qs = urlencode(params, doseq=True, quote_via=quote, safe="(),=:")
            url = f"{base}?{qs}"
        else:
            url = base

        # Use appropriate session strategy
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
            # Return session to pool even on exception
            self._client._return_session_to_pool(sess)
            raise
        finally:
            # Reset state for next chain
            self._state.is_invocation = False
            self._state.invocation_name = None
            self._state.entity_id = None
            self._state.query_params = {}

        # Always return session to pool (it will handle main session properly)
        self._client._return_session_to_pool(sess)
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
            total=2,  # Reduced retries for faster failure
            connect=2,
            read=2,
            backoff_factor=0.1,  # Faster backoff
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=methods,
        )
    except TypeError:
        # Older urllib3 uses method_whitelist
        return Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.1,
            status_forcelist=(429, 500, 502, 503, 504),
            method_whitelist=methods,  # type: ignore[arg-type]
        )


class ODataClient:
    """
    Top level client object for 1C OData endpoint.
    FIXED VERSION with better session management and proper pool usage.
    """

    def __init__(
        self,
        base_url: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: int = 30,
        verify_ssl: bool = False,
        extra_headers: Optional[Dict[str, str]] = None,
        # Session management strategy
        use_session_pool: bool = True,      # Use session pool for better performance
        max_pool_size: int = 5,             # Maximum sessions in pool
        session_ttl: int = 300,             # Session time-to-live in seconds
        force_close: bool = False,          # Only force close for problematic servers
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.use_session_pool = use_session_pool
        self.max_pool_size = max_pool_size
        self.session_ttl = session_ttl
        self.force_close = force_close

        # Session pool for reuse
        self._session_pool: List[Tuple[requests.Session, float]] = []
        self._pool_lock = threading.Lock()

        # Main session as fallback
        self.session = self._create_session(username, password, extra_headers)

        # Last request/response info
        self.http_code: Optional[int] = None
        self.http_message: Optional[str] = None
        self.odata_code: Optional[str] = None
        self.odata_message: Optional[str] = None
        self._last_id: Optional[str] = None

        # Metadata cache with TTL
        self._metadata_cache: Optional[Dict[str, Any]] = None
        self._metadata_cache_time: float = 0
        self._metadata_cache_ttl: int = 3600  # 1 hour

        # Debug: last request URL/params
        self._last_url: Optional[str] = None
        self._last_params: Optional[Dict[str, Any]] = None

    def _create_session(self, username: Optional[str], password: Optional[str], extra_headers: Optional[Dict[str, str]]) -> requests.Session:
        """Create a new session with standard configuration."""
        session = requests.Session()
        session.trust_env = False  # ignore system proxies
        
        if username is not None and password is not None:
            session.auth = (username, password)

        headers = {"Accept": "application/json; charset=utf-8"}
        if extra_headers:
            headers.update(extra_headers)
        if self.force_close:
            headers["Connection"] = "close"
        session.headers.update(headers)

        # Optimized retry configuration
        retry = _make_retry()
        adapter = HTTPAdapter(
            max_retries=retry, 
            pool_connections=self.max_pool_size, 
            pool_maxsize=self.max_pool_size * 2
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session

    def _get_session_from_pool(self) -> Optional[requests.Session]:
        """Get a session from the pool if available and not expired."""
        if not self.use_session_pool:
            return None
            
        with self._pool_lock:
            current_time = time.time()
            # Clean expired sessions
            expired_sessions = []
            valid_sessions = []
            
            for sess, created in self._session_pool:
                if current_time - created < self.session_ttl:
                    valid_sessions.append((sess, created))
                else:
                    expired_sessions.append(sess)
            
            self._session_pool = valid_sessions
            
            # Close expired sessions
            for sess in expired_sessions:
                try:
                    sess.close()
                except Exception:
                    pass
            
            if self._session_pool:
                return self._session_pool.pop(0)[0]
        return None

    def _return_session_to_pool(self, session: requests.Session) -> None:
        """Return a session to the pool if there's space, or close it."""
        # Don't pool the main session
        if session == self.session:
            return
            
        if not self.use_session_pool:
            try:
                session.close()
            except Exception:
                pass
            return
            
        with self._pool_lock:
            if len(self._session_pool) < self.max_pool_size:
                self._session_pool.append((session, time.time()))
            else:
                # Pool is full, close the session
                try:
                    session.close()
                except Exception:
                    pass

    def _get_session_for_request(self) -> requests.Session:
        """Get appropriate session for request."""
        if self.use_session_pool:
            pooled_session = self._get_session_from_pool()
            if pooled_session:
                return pooled_session
            
            # Create new session for pool
            return self._create_session(
                self.session.auth[0] if self.session.auth else None,
                self.session.auth[1] if self.session.auth else None,
                None
            )
        
        # Use main session
        return self.session

    def _merge_headers(self, extra: Optional[Dict[str, str]]) -> Dict[str, str]:
        headers = dict(self.session.headers)
        if self.force_close:
            headers["Connection"] = "close"
        if extra:
            headers.update(extra)
        return headers

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
        """Record response details and extract Ref_Key from various payload formats."""
        self.http_code = response.status_code
        self.http_message = response.reason

        # Log response details for debugging
        if response.status_code >= 400:
            logger.warning(f"HTTP {response.status_code} {response.reason} for {response.url}")
            logger.warning(f"Response headers: {dict(response.headers)}")
            if response.text:
                logger.warning(f"Response body (first 500 chars): {response.text[:500]}")

        # Parse JSON body to extract OData error/Ref_Key if available
        try:
            data = response.json()
        except ValueError:
            data = None

        if isinstance(data, dict):
            # Parse OData errors
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
                
                if code or message:
                    logger.error(f"OData error - Code: {code}, Message: {message}")

            # Extract Ref_Key from various response formats
            if "Ref_Key" in data and isinstance(data["Ref_Key"], str):
                self._last_id = data["Ref_Key"]
            elif "d" in data:
                # Handle verbose OData format
                d = data["d"]
                if isinstance(d, dict):
                    if "Ref_Key" in d:
                        self._last_id = d["Ref_Key"]
                    elif isinstance(d.get("results"), list) and d["results"]:
                        # Extract from first result in collection
                        first_result = d["results"][0]
                        if isinstance(first_result, dict) and "Ref_Key" in first_result:
                            self._last_id = first_result["Ref_Key"]

        # Fallback: parse GUID from Location header
        if not self._last_id:
            loc = response.headers.get("Location")
            if loc:
                m = re.search(r"\(guid'([0-9a-fA-F-]{36})'\)", loc)
                if m:
                    self._last_id = m.group(1)

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

    # ----- metadata with caching -----

    def get_metadata(self) -> Dict[str, Any]:
        """
        Retrieve and cache OData metadata with TTL.
        Returns dict: {"raw": <xml>, "entity_sets": {Name: {"entity_type": str|None, "properties": {...}}}}
        """
        current_time = time.time()
        
        # Check if cache is still valid
        if (self._metadata_cache is not None and 
            self._metadata_cache.get("entity_sets") and
            current_time - self._metadata_cache_time < self._metadata_cache_ttl):
            return self._metadata_cache

        url = f"{self.base_url.strip()}/$metadata"
        headers = self._merge_headers({"Accept": "application/xml"})

        metadata: Dict[str, Any] = {"raw": "", "entity_sets": {}}

        # Get session for metadata request
        sess = self._get_session_for_request()
        
        try:
            resp = sess.get(url, timeout=self.timeout, verify=self.verify_ssl, headers=headers, allow_redirects=True)
            self._record_response(resp)
            metadata["raw"] = resp.text
        except requests.RequestException as exc:
            self.http_code = getattr(exc.response, "status_code", None) or 0
            self.http_message = str(exc)
            self.odata_code = None
            self.odata_message = None
            self._return_session_to_pool(sess)
            return metadata
        finally:
            self._return_session_to_pool(sess)

        parsed = False

        # Try EDMX parse (namespace-agnostic)
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(metadata["raw"])

            # Map EntityType -> properties and navigation properties
            etype_props: Dict[str, Dict[str, Any]] = {}
            for node in root.iter():
                if node.tag.endswith("EntityType"):
                    et_name = node.get("Name")
                    if not et_name:
                        continue
                    props: Dict[str, Dict[str, Any]] = {}
                    nav_props: Dict[str, Dict[str, Any]] = {}
                    for child in list(node):
                        if child.tag.endswith("Property"):
                            pname = child.get("Name")
                            ptype = child.get("Type")
                            nullable = (child.get("Nullable", "true").lower() == "true")
                            if pname:
                                props[pname] = {"type": ptype, "nullable": nullable}
                        elif child.tag.endswith("NavigationProperty"):
                            pname = child.get("Name")
                            ptype = child.get("Type")
                            if pname:
                                nav_props[pname] = {"type": ptype}
                    etype_props[et_name] = {
                        "properties": props,
                        "navigation_properties": nav_props,
                    }

            # Read EntitySet(s) from any EntityContainer
            entity_sets: Dict[str, Dict[str, Any]] = {}
            for node in root.iter():
                if node.tag.endswith("EntityContainer"):
                    for es in list(node):
                        if es.tag.endswith("EntitySet"):
                            name = es.get("Name")
                            etype = es.get("EntityType")
                            if not name:
                                continue
                            et_short = (etype or "").split(".")[-1]
                            et_info = etype_props.get(et_short, {})
                            entity_sets[name] = {
                                "entity_type": etype,
                                "properties": et_info.get("properties", {}),
                                "navigation_properties": et_info.get("navigation_properties", {}),
                            }

            if entity_sets:
                metadata["entity_sets"] = entity_sets
                parsed = True

        except Exception:
            parsed = False

        # Fallback: try APP service document if EDMX parsing failed
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
                            metadata["entity_sets"][href] = {"entity_type": None, "properties": {}}
                except Exception:
                    metadata["entity_sets"] = {}
            except requests.RequestException as exc:
                self.http_code = getattr(exc.response, "status_code", None) or 0
                self.http_message = str(exc)
                self.odata_code = None
                self.odata_message = None
            finally:
                self._return_session_to_pool(sess2)

        # Cache the result
        metadata = metadata.get("entity_sets")
        self._metadata_cache = metadata
        self._metadata_cache_time = current_time
        return metadata

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
        POST rows to table part: <base>/<parent_name>(...)/<table_name>
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
                results.append({
                    "http_code": r.status_code,
                    "http_message": r.reason,
                    "ok": ok,
                    "row": row,
                })
            except requests.RequestException as exc:
                results.append({
                    "http_code": getattr(exc.response, "status_code", 0) or 0,
                    "http_message": str(exc),
                    "ok": False,
                    "row": row,
                })
            finally:
                self._return_session_to_pool(sess)
                    
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
            qs = urlencode(params, doseq=True, quote_via=quote, safe="(),=:")
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
            self._return_session_to_pool(sess)

    def __del__(self):
        """Cleanup sessions when client is destroyed."""
        try:
            # Close main session
            if hasattr(self, 'session'):
                self.session.close()
            
            # Close pooled sessions
            if hasattr(self, '_session_pool'):
                with self._pool_lock:
                    for session, _ in self._session_pool:
                        try:
                            session.close()
                        except Exception:
                            pass
                    self._session_pool.clear()
        except Exception:
            pass