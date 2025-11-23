import base64
import html
import os
import re
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set
from urllib.parse import quote

from flask import Flask, Response, jsonify, request
import json

from easynews_client import EasynewsClient, EasynewsError, SearchItem


APP = Flask(__name__)
_CLIENT: Optional[EasynewsClient] = None
_CLIENT_LOCK = threading.Lock()
_CLIENT_LOGIN_TTL = 600  # seconds
_CLIENT_LAST_LOGIN: float = 0.0


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
    with _CLIENT_LOCK:
        now = time.time()
        if _CLIENT is None:
            _CLIENT = EasynewsClient(EZ_USER, EZ_PASS)
            _CLIENT.login()
            _CLIENT_LAST_LOGIN = now
        elif now - _CLIENT_LAST_LOGIN > _CLIENT_LOGIN_TTL:
            try:
                _CLIENT.login()
            except EasynewsError:
                _CLIENT = EasynewsClient(EZ_USER, EZ_PASS)
                _CLIENT.login()
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


_ALLOWED_VIDEO_EXTENSIONS = {
    ".mkv",
    ".mp4",
    ".m4v",
    ".avi",
    ".ts",
    ".mov",
    ".wmv",
    ".mpg",
    ".mpeg",
    ".flv",
    ".webm",
}

_STOPWORDS = {
    "the",
    "a",
    "an",
    "and",
    "of",
    "in",
    "for",
    "on",
}

_MIN_DURATION_SECONDS = 60
_TOKEN_SPLIT_RE = re.compile(r"[^\w]+", re.UNICODE)
_QUALITY_RE = re.compile(r"(2160|1440|1080|720|480|360)\s*(p|i)?", re.IGNORECASE)
_YEAR_RE = re.compile(r"(19|20)\d{2}")
_SEASON_EP_RE = re.compile(r"(?:s(?P<season>\d{1,2})e(?P<episode>\d{1,2})|(?P<season2>\d{1,2})x(?P<episode2>\d{1,2}))", re.IGNORECASE)
_SANITIZE_SYMBOLS_RE = re.compile(r"[\.\-_:\s]+")
_NON_ALNUM_RE = re.compile(r"[^\w\sÀ-ÿ]")


def _parse_duration_seconds(raw: Any) -> Optional[int]:
    if raw is None:
        return None
    if isinstance(raw, (int, float)):
        if raw <= 0:
            return None
        return int(raw)
    text = str(raw).strip().lower()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    total = 0
    matched = False
    for label, multiplier in (("h", 3600), ("m", 60), ("s", 1)):
        for part in re.findall(rf"(\d+)\s*{label}", text):
            total += int(part) * multiplier
            matched = True
    if matched:
        return total
    if ":" in text:
        try:
            pieces = [int(p) for p in text.split(":")]
            if len(pieces) == 3:
                h, m, s = pieces
            elif len(pieces) == 2:
                h = 0
                m, s = pieces
            else:
                return None
            return h * 3600 + m * 60 + s
        except ValueError:
            return None
    return None


def _as_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _tokenize(text: str) -> List[str]:
    if not text:
        return []
    normalized = _TOKEN_SPLIT_RE.sub(" ", text.lower())
    tokens = [tok for tok in normalized.split() if len(tok) > 1 and tok not in _STOPWORDS]
    return tokens


def _sanitize_phrase(text: str) -> str:
    if not text:
        return ""
    working = text.replace("&", " and ")
    working = _SANITIZE_SYMBOLS_RE.sub(" ", working)
    working = _NON_ALNUM_RE.sub("", working)
    return working.lower().strip()


def _is_flagged_item(item: Any, ext: str, duration_seconds: Optional[int]) -> bool:
    passwd = False
    virus = False
    file_type = ""
    if isinstance(item, dict):
        passwd = bool(item.get("passwd") or item.get("password"))
        virus = bool(item.get("virus"))
        file_type = str(item.get("type") or item.get("file_type") or "").upper()
    if passwd or virus:
        return True
    if file_type and file_type != "VIDEO":
        return True
    if ext and ext.lower() not in _ALLOWED_VIDEO_EXTENSIONS:
        return True
    if duration_seconds is not None and duration_seconds < _MIN_DURATION_SECONDS:
        return True
    return False


def _format_duration(seconds: Optional[int]) -> Optional[str]:
    if seconds is None:
        return None
    if seconds <= 0:
        return None
    td = timedelta(seconds=seconds)
    total_seconds = int(td.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    return f"{hours:02}:{minutes:02}:{secs:02}"


def _extract_quality(*texts: Optional[str]) -> Optional[str]:
    for text in texts:
        if not text:
            continue
        lowered = text.lower()
        if "4k" in lowered:
            return "2160p"
        match = _QUALITY_RE.search(lowered)
        if match:
            value = match.group(1)
            suffix = match.group(2) or "p"
            return f"{value}{suffix.lower()}"
        if "uhd" in lowered:
            return "2160p"
        if "fhd" in lowered:
            return "1080p"
    return None


def _build_thumbnail_url(base: Optional[str], hash_id: Optional[str], slug: Optional[str]) -> Optional[str]:
    if not base or not hash_id:
        return None
    base = base.rstrip("/") + "/"
    prefix = hash_id[:3]
    safe_slug = quote((slug or hash_id).replace("/", "_"))
    return f"{base}{prefix}/pr-{hash_id}.jpg/th-{safe_slug}.jpg"


def _extract_release_markers(text: str, quality_hint: Optional[str] = None) -> Dict[str, Optional[Any]]:
    info: Dict[str, Optional[Any]] = {}
    if not text:
        return info
    season_match = _SEASON_EP_RE.search(text)
    if season_match:
        season = season_match.group("season") or season_match.group("season2")
        episode = season_match.group("episode") or season_match.group("episode2")
        if season:
            info["season"] = int(season)
        if episode:
            info["episode"] = int(episode)
    year_match = _YEAR_RE.search(text)
    if year_match:
        info["year"] = int(year_match.group(0))
    quality = quality_hint or _extract_quality(text)
    if quality:
        info["quality"] = quality
    return info


def _matches_strict(title: str, strict_phrase: Optional[str]) -> bool:
    if not strict_phrase:
        return True
    candidate = _sanitize_phrase(title)
    if not candidate:
        return False
    if candidate == strict_phrase:
        return True
    candidate_tokens = candidate.split()
    phrase_tokens = strict_phrase.split()
    if not phrase_tokens:
        return True
    for idx in range(0, max(1, len(candidate_tokens) - len(phrase_tokens) + 1)):
        if candidate_tokens[idx : idx + len(phrase_tokens)] == phrase_tokens:
            return True
    return False


def filter_and_map(
    json_data: dict,
    min_bytes: int,
    query_tokens: Optional[List[str]] = None,
    query_meta: Optional[Dict[str, Optional[Any]]] = None,
    strict_phrase: Optional[str] = None,
    strict_match: bool = False,
) -> List[dict]:
    token_set: Set[str] = set(query_tokens or [])
    thumb_base = json_data.get("thumbURL") or json_data.get("thumbUrl")
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
        duration_raw: Any = None
        fullres: Optional[str] = None

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
            if len(it) > 14:
                duration_raw = it[14]
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
            duration_raw = it.get("14") or it.get("duration") or it.get("len")
            fullres = it.get("fullres") or it.get("resolution")

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

        duration_seconds = _parse_duration_seconds(duration_raw)

        if _is_flagged_item(it, ext, duration_seconds):
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

        quality = _extract_quality(title, fullres)
        title_meta = _extract_release_markers(title, quality)
        if not quality and title_meta.get("quality"):
            quality = title_meta.get("quality")

        if strict_match and not _matches_strict(title, strict_phrase):
            continue

        if query_meta:
            q_year = query_meta.get("year")
            q_season = query_meta.get("season")
            q_episode = query_meta.get("episode")
            q_quality = query_meta.get("quality")
            t_year = title_meta.get("year")
            t_season = title_meta.get("season")
            t_episode = title_meta.get("episode")
            t_quality = quality or title_meta.get("quality")
            if q_year and t_year and q_year != t_year:
                continue
            if q_season and t_season and q_season != t_season:
                continue
            if q_episode and t_episode and q_episode != t_episode:
                continue
            if q_quality and t_quality and q_quality.lower() != t_quality.lower():
                continue

        if token_set:
            title_tokens = set(_tokenize(title))
            if not title_tokens or not token_set.issubset(title_tokens):
                continue

        duration_formatted = _format_duration(duration_seconds)
        thumbnail_url = _build_thumbnail_url(thumb_base, hash_id, filename_no_ext)
        year = title_meta.get("year")

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
                "duration": duration_seconds,
                "duration_hms": duration_formatted,
                "quality": quality,
                "thumbnail": thumbnail_url,
                "year": year,
                "season": title_meta.get("season"),
                "episode": title_meta.get("episode"),
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
            "<movie-search available=\"yes\" supportedParams=\"q,year\"/>"
            "<tv-search available=\"yes\" supportedParams=\"q,season,ep\"/>"
            "</searching>"
            "<categories>"
            "<category id=\"2000\" name=\"Movies\"/>"
            "</categories>"
            "</caps>"
        )
        return Response(xml, mimetype="application/xml")

    if t in ("search", "movie", "tvsearch"):
        base_query = (request.args.get("q") or "").strip()
        season_param = request.args.get("season") or request.args.get("seasonnum")
        episode_param = request.args.get("ep") or request.args.get("epnum") or request.args.get("episode")
        year_param = request.args.get("year") or request.args.get("yr")
        season_int = _as_int(season_param)
        episode_int = _as_int(episode_param)
        year_int = _as_int(year_param)

        search_components: List[str] = []
        if base_query:
            search_components.append(base_query)

        if t == "movie":
            if year_int and str(year_int) not in base_query:
                search_components.append(str(year_int))
        elif t == "tvsearch":
            if season_int is not None and episode_int is not None:
                search_components.append(f"S{season_int:02}E{episode_int:02}")
            elif season_int is not None:
                search_components.append(f"S{season_int:02}")
            if year_int and str(year_int) not in base_query:
                search_components.append(str(year_int))

        search_label = " ".join(part for part in search_components if part).strip()
        raw_query = search_label or base_query
        q = raw_query.strip()
        fallback_query = False
        if not q or q.lower() == "test":  # allow Prowlarr validation calls to receive data
            q = "matrix"
            fallback_query = True
        query_tokens = _tokenize(raw_query)
        query_meta = _extract_release_markers(raw_query)
        if year_int:
            query_meta["year"] = year_int
        if season_int is not None:
            query_meta["season"] = season_int
        if episode_int is not None:
            query_meta["episode"] = episode_int
        strict_param = request.args.get("strict")
        strict_requested = t == "movie"
        if strict_param is not None:
            strict_requested = strict_param.strip().lower() not in {"0", "false", "no", "off"}
        strict_phrase = _sanitize_phrase(raw_query) if strict_requested else None
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
            c = client()
            # aim for maximum results per page
            data = c.search(query=q, file_type="VIDEO", per_page=250, sort_field="relevance", sort_dir="-")
            if fallback_query:
                items = filter_and_map(data, min_bytes=min_bytes)
            else:
                items = filter_and_map(
                    data,
                    min_bytes=min_bytes,
                    query_tokens=query_tokens,
                    query_meta=query_meta,
                    strict_phrase=strict_phrase,
                    strict_match=strict_requested,
                )

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
            duration_hms = it.get("duration_hms")
            quality = it.get("quality")
            thumb = it.get("thumbnail")
            year = it.get("year")
            season = it.get("season")
            episode = it.get("episode")
            attr_parts = [
                f"<newznab:attr name=\"size\" value=\"{size}\"/>",
                f"<newznab:attr name=\"category\" value=\"2000\"/>",
                f"<newznab:attr name=\"usenetdate\" value=\"{posted_str}\"/>",
                f"<newznab:attr name=\"posted\" value=\"{posted_epoch}\"/>",
            ]
            if poster:
                attr_parts.append(f"<newznab:attr name=\"poster\" value=\"{xml_escape(poster)}\"/>")
            if quality:
                attr_parts.append(f"<newznab:attr name=\"quality\" value=\"{xml_escape(quality)}\"/>")
            if duration_hms:
                attr_parts.append(f"<newznab:attr name=\"duration\" value=\"{duration_hms}\"/>")
            if thumb:
                attr_parts.append(f"<newznab:attr name=\"thumb\" value=\"{xml_escape(thumb)}\"/>")
            if year:
                attr_parts.append(f"<newznab:attr name=\"year\" value=\"{year}\"/>")
            if season:
                attr_parts.append(f"<newznab:attr name=\"season\" value=\"{season}\"/>")
            if episode:
                attr_parts.append(f"<newznab:attr name=\"episode\" value=\"{episode}\"/>")
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
        c = client()
        payload = c.build_nzb_payload([si], name=d.get("title"))
        # fetch content
        url = f"https://members.easynews.com/2.0/api/dl-nzb"
        r = c.s.post(url, data=payload)
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
