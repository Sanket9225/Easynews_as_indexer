import base64
import os
import time
from datetime import datetime, timezone
from typing import List, Tuple

from flask import Flask, Response, jsonify, request
import json

from easynews_client import EasynewsClient, SearchItem


APP = Flask(__name__)


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
    return EasynewsClient(EZ_USER, EZ_PASS)


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


def filter_and_map(json_data: dict, min_bytes: int) -> List[dict]:
    out: List[dict] = []
    for it in json_data.get("data", []):
        # Extract core fields
        # it may be list-like
        try:
            hash_id = it[0]
            subject = it[6]
            filename_no_ext = it[10]
            ext = it[11]
            size = it.get("size", 0) if isinstance(it, dict) else (it["size"] if isinstance(it, dict) and "size" in it else 0)
        except Exception:
            # dict-like numeric keys as strings
            hash_id = it.get("0") if isinstance(it, dict) else None
            subject = it.get("6") if isinstance(it, dict) else None
            filename_no_ext = it.get("10") if isinstance(it, dict) else None
            ext = it.get("11") if isinstance(it, dict) else None
            size = it.get("size", 0) if isinstance(it, dict) else 0

        if not hash_id or not ext:
            continue

        # Try to use numeric size if present; otherwise skip (can't verify <100MB rule)
        if not isinstance(size, int):
            try:
                size = int(size)
            except Exception:
                size = 0

        if size < min_bytes:
            continue

        title = subject or (filename_no_ext + ext)
        sig = it.get("sig") if isinstance(it, dict) else None

        out.append(
            {
                "hash": hash_id,
                "filename": filename_no_ext,
                "ext": ext,
                "sig": sig,
                "size": size,
                "title": title,
                # Time fields: try index 7 or expires if available
                "pub": it[7] if (isinstance(it, list) and len(it) > 7) else (it.get("7") if isinstance(it, dict) else None),
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
        if not q or q.lower() == "test":  # allow Prowlarr test ping to pass with sample data
            q = "matrix"
            fallback_query = True
        limit = int(request.args.get("limit", "100"))
        min_size_mb = int(request.args.get("minsize", "100"))
        min_bytes = min_size_mb * 1024 * 1024
        if fallback_query:
            min_bytes = min(10 * 1024 * 1024, min_bytes)  # ensure sample data not filtered out

        c = client()
        c.login()
        # aim for maximum results per page
        data = c.search(query=q, file_type="VIDEO", per_page=250, sort_field="relevance", sort_dir="-")
        items = filter_and_map(data, min_bytes=min_bytes)
        # Trim by limit
        items = items[:limit]

        display_q = raw_query if raw_query else q
        chan_title = f"Results for {display_q}"
        now = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S %z")

        header = (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            "<rss version=\"2.0\" xmlns:newznab=\"http://www.newznab.com/DTD/2010/feeds/attributes/\">"
            "<channel>"
            f"<title>{xml_escape(chan_title)}</title>"
            f"<description>{xml_escape(chan_title)}</description>"
            f"<link>{request.url_root.rstrip('/')}/api</link>"
            f"<pubDate>{now}</pubDate>"
        )

        body_parts: List[str] = []
        for it in items:
            enc_id = encode_id(it)
            title = xml_escape(it["title"]) if it["title"] else "Untitled"
            link = f"{request.url_root.rstrip('/')}/api?t=get&id={enc_id}&apikey={request.args.get('apikey')}"
            safe_link = xml_escape(link)
            size = it["size"]
            guid = enc_id
            pub = it.get("pub") or now
            item_xml = (
                f"<item>"
                f"<title>{title}</title>"
                f"<guid isPermaLink=\"false\">{guid}</guid>"
                f"<link>{safe_link}</link>"
                f"<category>2000</category>"
                f"<pubDate>{pub}</pubDate>"
                f"<newznab:attr name=\"size\" value=\"{size}\"/>"
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
        si = to_search_item(d)
        c = client()
        c.login()
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
    # Local dev server
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8081)))
