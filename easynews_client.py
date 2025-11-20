"""
Easynews API-like client (unofficial) to perform searches and download NZB files.

This client mimics the webapp behavior by calling:
- GET /2.0/search/solr-search for search results (JSON)
- POST /2.0/api/dl-nzb to create/download NZB for selected items

Authentication is cookie-based via username/password POST to the login endpoint.
You'll need a valid Easynews account. Use responsibly and per Easynews TOS.
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests
from requests.exceptions import RequestException
import logging

logger = logging.getLogger(__name__)


EASYNEWS_BASE = "https://members.easynews.com"


class EasynewsError(Exception):
    pass


@dataclass
class SearchItem:
    id: Optional[str]
    hash: str
    filename: str
    ext: str
    sig: Optional[str]
    type: str
    raw: Dict[str, Any]

    @property
    def value_token(self) -> str:
        """
        Build the value string Easynews expects for checkbox selections:
        format: "{hash}|{b64(filename)}:{b64(ext)}"
        As seen in members.js createNZB -> it reads from input[checkbox].value
        """
        fn_b64 = base64.b64encode(self.filename.encode()).decode().replace("=", "")
        ext_b64 = base64.b64encode(self.ext.encode()).decode().replace("=", "")
        return f"{self.hash}|{fn_b64}:{ext_b64}"


class EasynewsClient:
    def __init__(self, username: str, password: str, session: Optional[requests.Session] = None):
        self.username = username
        self.password = password
        self.s = session or requests.Session()
        # Default headers
        self.s.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EasynewsClient/1.0",
            "Accept": "application/json, text/javascript, */*; q=0.9",
        })
        # Use HTTP Basic Auth for endpoints that support it
        self.s.auth = (self.username, self.password)

    def login(self) -> None:
        """
        Prime session and validate credentials using a quick authenticated call.
        This relies on HTTP Basic Auth configured on the session.
        """
        try:
            # perform a quick GET to prime the session
            self.s.get(f"{EASYNEWS_BASE}/2.0/", timeout=10)
            check = self.s.get(
                f"{EASYNEWS_BASE}/2.0/search/solr-search/?fly=2&gps=test&sb=1&pno=1&pby=1&u=1&chxu=1&chxgx=1&st=basic&s1=dtime&s1d=-&sS=3&vv=1&fty%5B%5D=VIDEO",
                allow_redirects=True,
                timeout=15,
            )
        except RequestException as e:
            # Wrap network-level errors in EasynewsError so callers can handle uniformly
            # Record the full exception traceback for diagnostics
            logger.exception("Network error during Easynews login")
            raise EasynewsError(f"Network error during Easynews login: {e}") from e

        if check.status_code in (401, 403):
            raise EasynewsError("Unauthorized; check username/password")

    def search(
        self,
        query: str,
        file_type: str = "VIDEO",
        page: int = 1,
        per_page: int = 50,
        sort_field: Optional[str] = "dtime",
        sort_dir: str = "-",
        safe_off: int = 0,
    ) -> Dict[str, Any]:
        """
        Call the same Solr-backed endpoint used by the site.
        Returns the raw JSON dict, including data and pagination fields.
        """
        if file_type != "VIDEO":
            # Enforce VIDEO only as requested
            file_type = "VIDEO"

        params = {
            # Backend selector, 1 = solr-search
            "fly": "2",
            "sb": "1",
            "pno": str(page),
            "pby": str(per_page),
            "u": "1",
            "chxu": "1",
            "chxgx": "1",
            "st": "basic",
            "gps": query,
            "vv": "1",  # for VIDEO hover/preview data
            "safeO": str(safe_off),
        }
        if sort_field:
            params["s1"] = sort_field
            params["s1d"] = sort_dir

        # fty[] is a repeated parameter
        url = f"{EASYNEWS_BASE}/2.0/search/solr-search/"
        # Manually build query string to include array param
        query_params = "&".join([f"{k}={requests.utils.quote(v)}" for k, v in params.items()]) + f"&fty%5B%5D={requests.utils.quote(file_type)}"
        full_url = f"{url}?{query_params}"

        try:
            r = self.s.get(full_url, timeout=30)
            r.raise_for_status()
            return r.json()
        except RequestException as e:
            logger.exception("Search request failed for query '%s'", query)
            raise EasynewsError(f"Search request failed: {e}") from e

    @staticmethod
    def _collect_items(json_data: Dict[str, Any]) -> List[SearchItem]:
        items: List[SearchItem] = []
        for it in json_data.get("data", []):
            hash_id = ""
            filename_no_ext = ""
            ext = ""
            sig: Optional[str] = None
            typ = ""
            item_id: Optional[str] = None

            if isinstance(it, list):
                if len(it) >= 12:
                    hash_id = it[0]
                    filename_no_ext = it[10]
                    ext = it[11]
            elif isinstance(it, dict):
                # Some APIs may return dict with numeric keys as strings
                if "0" in it:
                    hash_id = it.get("0", "")
                if "10" in it:
                    filename_no_ext = it.get("10", "")
                if "11" in it:
                    ext = it.get("11", "")
                sig = it.get("sig")
                typ = it.get("type", "")
                item_id = it.get("id")

            if not hash_id or not ext:
                # Skip malformed entries
                continue

            items.append(SearchItem(
                id=item_id,
                hash=hash_id,
                filename=filename_no_ext,
                ext=ext,
                sig=sig,
                type=typ,
                raw=it if isinstance(it, dict) else {},
            ))
        return items

    def build_nzb_payload(
        self,
        items: List[SearchItem],
        name: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Build the form-encoded payload expected by /2.0/api/dl-nzb.
        Emulates createNZB() from members.js which submits hidden inputs of the checked items.
        Keys look like "{index}&sig={sig}" and value is value_token.
        We'll just use sequential indexes starting at 0.
        """
        data: Dict[str, str] = {"autoNZB": "1"}
        for idx, it in enumerate(items):
            key = str(idx)
            if it.sig:
                key = f"{idx}&sig={it.sig}"
            data[key] = it.value_token
        if name:
            data["nameZipQ0"] = name
        # The site posts to /2.0/api/dl-nzb and returns the NZB file content (application/x-nzb or xml)
        return data

    def download_nzb(self, payload: Dict[str, str], out_path: str) -> str:
        url = f"{EASYNEWS_BASE}/2.0/api/dl-nzb"
        try:
            r = self.s.post(url, data=payload, stream=True, timeout=60)
        except RequestException as e:
            logger.exception("NZB download request failed")
            raise EasynewsError(f"NZB download request failed: {e}") from e

        if r.status_code != 200:
            raise EasynewsError(f"NZB creation failed: HTTP {r.status_code}")

        content_type = r.headers.get("Content-Type", "")
        if "xml" not in content_type and "nzb" not in content_type:
            # Sometimes returns text/html with a redirect page; still try to save
            pass

        content = r.content.replace(b'date=""', b'date="0"')  # normalize empty NZB date fields
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(content)
        return out_path

    def search_and_nzb(
        self,
        query: str,
        file_type: str = "VIDEO",
        max_items: int = 5,
        nzb_name: Optional[str] = None,
        out_path: str = "download.nzb",
    ) -> str:
        data = self.search(query=query, file_type=file_type)
        items = self._collect_items(data)
        if not items:
            raise EasynewsError("No results found for query")
        sel = items[:max_items]
        payload = self.build_nzb_payload(sel, name=nzb_name)
        return self.download_nzb(payload, out_path)


__all__ = ["EasynewsClient", "EasynewsError", "SearchItem"]
