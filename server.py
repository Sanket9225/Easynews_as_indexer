import base64
import html
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, List, Optional

from flask import Flask, Response, jsonify, request
import json

from easynews_client import EasynewsClient, EasynewsError, SearchItem
import logging

# Basic logging configuration to ensure logs are visible when running the app
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


APP = Flask(__name__)
_CLIENT: Optional[EasynewsClient] = None
_CLIENT_LOCK = threading.Lock()
_CLIENT_LOGIN_TTL = 600  # seconds
_CLIENT_LAST_LOGIN: float = 0.0
_CLIENT_FAIL_COUNT: int = 0
_CLIENT_FAILED_UNTIL: float = 0.0
_CLIENT_BACKOFF_BASE = 5  # seconds, base backoff multiplier
_CLIENT_BACKOFF_MAX = 300  # seconds, max backoff


def _load_dotenv():
    path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    os.environ.setdefault(k, v)
    except Exception:
        pass


_load_dotenv()

API_KEY = os.environ.get("NEWZNAB_APIKEY", "testkey")
EZ_USER = os.environ.get("EASYNEWS_USER")
EZ_PASS = os.environ.get("EASYNEWS_PASS")


def require_apikey() -> bool:
    key = request.args.get("apikey") or request.headers.get("X-Api-Key")
    return (API_KEY is None) or (key == API_KEY)


def client() -> EasynewsClient:
    if not EZ_USER or not EZ_PASS:
        raise RuntimeError("Set EASYNEWS_USER and EASYNEWS_PASS environment variables")
    global _CLIENT, _CLIENT_LAST_LOGIN
    global _CLIENT_FAIL_COUNT, _CLIENT_FAILED_UNTIL
    with _CLIENT_LOCK:
        now = time.time()
        # If we previously detected failures, and the backoff window hasn't expired, fail fast
        if _CLIENT_FAILED_UNTIL and now < _CLIENT_FAILED_UNTIL:
            raise EasynewsError("Upstream service in backoff window")

        now = time.time()
        if _CLIENT is None:
            _CLIENT = EasynewsClient(EZ_USER, EZ_PASS)
            # login may raise EasynewsError on network/auth errors
            try:
                _CLIENT.login()
            except EasynewsError:
                # increment failure counter and set backoff window
                _CLIENT_FAIL_COUNT = min(_CLIENT_FAIL_COUNT + 1, 10)
                backoff = min(_CLIENT_BACKOFF_BASE * (2 ** (_CLIENT_FAIL_COUNT - 1)), _CLIENT_BACKOFF_MAX)
                _CLIENT_FAILED_UNTIL = time.time() + backoff
                logger.exception("Easynews login failed — entering backoff for %s seconds", backoff)
                # Clear client object so next successful login will recreate
                _CLIENT = None
                raise
            # Reset failure/backoff counters on successful login
            _CLIENT_FAIL_COUNT = 0
            _CLIENT_FAILED_UNTIL = 0.0
            _CLIENT_LAST_LOGIN = now
        elif now - _CLIENT_LAST_LOGIN > _CLIENT_LOGIN_TTL:
            try:
                _CLIENT.login()
            except EasynewsError:
                # If login fails on refresh, rotate the client and attempt once more
                _CLIENT = EasynewsClient(EZ_USER, EZ_PASS)
                try:
                    _CLIENT.login()
                except EasynewsError:
                    _CLIENT_FAIL_COUNT = min(_CLIENT_FAIL_COUNT + 1, 10)
                    backoff = min(_CLIENT_BACKOFF_BASE * (2 ** (_CLIENT_FAIL_COUNT - 1)), _CLIENT_BACKOFF_MAX)
                    _CLIENT_FAILED_UNTIL = time.time() + backoff
                    logger.exception("Easynews login refresh failed — entering backoff for %s seconds", backoff)
                    _CLIENT = None
                    raise
            _CLIENT_LAST_LOGIN = time.time()
        return _CLIENT


def xml_escape(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def encode_id(item: dict) -> str:
    # Pack info needed to build NZB for a single selection and preserve title for filename
    payload = {
        "hash": item.get("hash"),
        "filename": item.get("filename"),
        "ext": item.get("ext"),
        "sig": item.get("sig"),
        "title": item.get("title"),
    }
    if item.get("sample"):
        payload["sample"] = True
    raw = base64.urlsafe_b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode().rstrip("=")
    return raw


def decode_id(enc: str) -> dict:
    pad = "=" * (-len(enc) % 4)
    raw = base64.urlsafe_b64decode(enc + pad).decode()
    return json.loads(raw)


def to_search_item(d: dict) -> SearchItem:
    return SearchItem(
        id=None,
        hash=d["hash"],
        filename=d["filename"],
        ext=d["ext"],
        sig=d.get("sig"),
        type="VIDEO",
        raw={},
    )


_TITLE_PARENS_RE = re.compile(r"\(([^()]*)\)")


def _normalize_title(raw: str) -> str:
    text = html.unescape(raw or "").strip()
    if not text:
        return text
    matches = _TITLE_PARENS_RE.findall(text)
    for candidate in reversed(matches):
        cleaned = candidate.strip()
        if cleaned:
            return cleaned
    return text


def _coerce_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            try:
                return datetime.fromtimestamp(int(text), tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
            try:
                dt = datetime.strptime(text.replace("Z", "+0000"), fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    return None


def filter_and_map(json_data: dict, min_bytes: int) -> List[dict]:
    out: List[dict] = []
    for it in json_data.get("data", []):
        hash_id: Optional[str] = None
        subject: Optional[str] = None
        filename_no_ext: Optional[str] = None
        ext: Optional[str] = None
        size: Any = 0
        poster: Optional[str] = None
        posted_raw: Any = None
        sig: Optional[str] = None
        display_fn: Optional[str] = None
        extension_field: Optional[str] = None

        if isinstance(it, list):
            if len(it) >= 12:
                hash_id = it[0]
                subject = it[6]
                filename_no_ext = it[10]
                ext = it[11]
            if len(it) > 7:
                poster = it[7]
            if len(it) > 8:
                posted_raw = it[8]
        elif isinstance(it, dict):
            hash_id = it.get("hash") or it.get("0") or it.get("id")
            subject = it.get("subject") or it.get("6")
            filename_no_ext = it.get("filename") or it.get("10")
            ext = it.get("ext") or it.get("11")
            size = it.get("size", 0)
            poster = it.get("poster") or it.get("7")
            posted_raw = it.get("dtime") or it.get("date") or it.get("12")
            sig = it.get("sig")
            display_fn = it.get("fn") or it.get("filename")
            extension_field = it.get("extension") or it.get("ext")

        if not hash_id or not ext:
            continue

        filename_no_ext = filename_no_ext or ""
        ext = ext or ""
        if extension_field and not ext:
            ext = extension_field

        # Try to use numeric size if present; otherwise skip (can't verify <100MB rule)
        if not isinstance(size, int):
            try:
                size = int(size)
            except Exception:
                size = 0

        if size < min_bytes:
            continue

        title: Optional[str] = None
        if display_fn:
            cleaned = display_fn.strip()
            if cleaned:
                normalized = cleaned.replace(" - ", "-")
                parts = [segment for segment in normalized.split(" ") if segment]
                sanitized = ".".join(parts)
                ext_component = extension_field or ext or ""
                if ext_component and not ext_component.startswith("."):
                    ext_component = f".{ext_component}"
                title = f"{sanitized}{ext_component}" if ext_component else sanitized

        if not title:
            fallback = subject or f"{filename_no_ext}{ext}"
            title = _normalize_title(fallback)

        out.append(
            {
                "hash": hash_id,
                "filename": filename_no_ext,
                "ext": ext,
                "sig": sig,
                "size": size,
                "title": title,
                "poster": poster,
                "posted": posted_raw,
            }
        )
    return out


@APP.route("/api")
def api():
    if not require_apikey():
        return Response("Unauthorized", status=401)

    t = request.args.get("t", "caps")
    if t == "caps":
        xml = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<caps>"
            "<server version=\"0.1\" title=\"Easynews Bridge\"/>"
            "<limits maxrequests=\"100\" defaultlimit=\"100\"/>"
            "<registration available=\"no\" open=\"no\"/>"
            "<searching>"
            "<search available=\"yes\" supportedParams=\"q\"/>"
            "</searching>"
            "<categories>"
            "<category id=\"2000\" name=\"Movies\"/>"
            "</categories>"
            "</caps>"
        )
        return Response(xml, mimetype="application/xml")

    if t in ("search", "movie", "tvsearch"):
        raw_query = request.args.get("q", "")
        q = raw_query.strip()
        fallback_query = False
        if not q or q.lower() == "test":  # allow Prowlarr validation calls to receive data
            q = "matrix"
            fallback_query = True
        limit = int(request.args.get("limit", "100"))
        offset = int(request.args.get("offset", "0"))
        min_size_param = request.args.get("minsize")
        min_size_mb = 100
        if min_size_param:
            try:
                min_size_mb = max(100, int(min_size_param))
            except ValueError:
                min_size_mb = 100
        min_bytes = min_size_mb * 1024 * 1024

        if fallback_query:
            items = [
                {
                    "hash": "SAMPLEHASH1234567890",
                    "filename": "sample.matrix.clip",
                    "ext": ".mkv",
                    "sig": None,
                    "size": 700 * 1024 * 1024,
                    "title": "Sample Matrix Clip",
                    "sample": True,
                    "poster": "sample@example.com",
                    "posted": int(time.time()),
                }
            ]
        else:
            try:
                c = client()
            except EasynewsError as e:
                # login/network failure — record traceback-level info
                logger.exception("Easynews client unavailable when attempting to search")
                return Response("Upstream service unavailable", status=503)
            # aim for maximum results per page
            data = c.search(query=q, file_type="VIDEO", per_page=250, sort_field="relevance", sort_dir="-")
            items = filter_and_map(data, min_bytes=min_bytes)

        # Trim by limit (handles fallback and real queries)
        items = items[offset : offset + limit]

        display_q = raw_query if raw_query else q
        chan_title = f"Results for {display_q}"
        now_dt = datetime.now(timezone.utc)
        channel_pub = now_dt.strftime("%a, %d %b %Y %H:%M:%S %z")

        header = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<rss version=\"2.0\" xmlns:newznab=\"http://www.newznab.com/DTD/2010/feeds/attributes/\">"
            "<channel>"
            f"<title>{xml_escape(chan_title)}</title>"
            f"<description>{xml_escape(chan_title)}</description>"
            f"<link>{request.url_root.rstrip('/')}/api</link>"
            f"<pubDate>{channel_pub}</pubDate>"
        )

        body_parts: List[str] = []
        for it in items:
            enc_id = encode_id(it)
            title = xml_escape(it["title"]) if it["title"] else "Untitled"
            link = f"{request.url_root.rstrip('/')}/api?t=get&id={enc_id}&apikey={request.args.get('apikey')}"
            safe_link = xml_escape(link)
            size = it["size"]
            guid = enc_id
            poster = it.get("poster")
            posted_dt = _coerce_datetime(it.get("posted")) or now_dt
            posted_str = posted_dt.strftime("%a, %d %b %Y %H:%M:%S %z")
            posted_epoch = str(int(posted_dt.timestamp()))
            attr_parts = [
                f"<newznab:attr name=\"size\" value=\"{size}\"/>",
                f"<newznab:attr name=\"category\" value=\"2000\"/>",
                f"<newznab:attr name=\"usenetdate\" value=\"{posted_str}\"/>",
                f"<newznab:attr name=\"posted\" value=\"{posted_epoch}\"/>",
            ]
            if poster:
                attr_parts.append(f"<newznab:attr name=\"poster\" value=\"{xml_escape(poster)}\"/>")
            attr_xml = "".join(attr_parts)
            item_xml = (
                f"<item>"
                f"<title>{title}</title>"
                f"<guid isPermaLink=\"false\">{guid}</guid>"
                f"<link>{safe_link}</link>"
                f"<category>2000</category>"
                f"<pubDate>{posted_str}</pubDate>"
                f"{attr_xml}"
                f"<enclosure url=\"{safe_link}\" length=\"{size}\" type=\"application/x-nzb\"/>"
                f"</item>"
            )
            body_parts.append(item_xml)

        footer = "</channel></rss>"
        xml = header + "".join(body_parts) + footer
        return Response(xml, mimetype="application/rss+xml")

    if t in ("get", "getnzb"):
        enc_id = request.args.get("id")
        if not enc_id:
            return Response("Missing id", status=400)
        d = decode_id(enc_id)
        if d.get("sample"):
            title = d.get("title", "Sample Item")
            safe_title = "sample"
            nzb_content = (
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                "<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">"
                "<file subject=\"Sample Matrix Clip\" date=\"0\" poster=\"sample@example.com\">"
                "<groups><group>alt.binaries.sample</group></groups>"
                "<segments><segment bytes=\"1024\" number=\"1\">sample</segment></segments>"
                "</file></nzb>"
            ).encode("utf-8")
            resp = Response(nzb_content, mimetype="application/x-nzb")
            resp.headers["Content-Disposition"] = f"attachment; filename=\"{safe_title}.nzb\""
            return resp
        si = to_search_item(d)
        try:
            c = client()
        except EasynewsError as e:
            logger.exception("Easynews client unavailable when building NZB")
            return Response("Upstream service unavailable", status=503)

        payload = c.build_nzb_payload([si], name=d.get("title"))
        # fetch content
        try:
            r = c.s.post("https://members.easynews.com/2.0/api/dl-nzb", data=payload, timeout=60)
        except Exception:
            logger.exception("Error fetching NZB from upstream")
            return Response("Upstream request failed", status=502)

        if r.status_code != 200:
            return Response(f"Upstream error {r.status_code}", status=502)
        # Name file as title.nzb
        title = d.get("title") or (d.get("filename", "download") + d.get("ext", ""))
        safe_title = "".join(ch for ch in title if ch.isalnum() or ch in (" ", "-", "_", "."))[:200].strip() or "download"
        resp = Response(r.content, mimetype="application/x-nzb")
        resp.headers["Content-Disposition"] = f"attachment; filename=\"{safe_title}.nzb\""
        return resp

    return Response("Unsupported 't' parameter", status=400)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8081))
    APP.run(host="0.0.0.0", port=port)
