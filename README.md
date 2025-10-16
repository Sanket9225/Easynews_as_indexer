# Easynews Newznab-like server

Flask server that bridges Easynews search to a Newznab-like API so you can add it to Prowlarr as a custom indexer and download NZBs. Video-only, sorts by relevance, returns as many results as possible, and filters files smaller than 100 MB.

## Setup

1. Create and activate a Python 3.11+ virtual environment:

```
# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1

# Linux / macOS (bash/zsh)
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```
pip install -r requirements.txt
```

3. Configure credentials and API key. Create a `.env` file in the repo root:

```
EASYNEWS_USER=your_easynews_username
EASYNEWS_PASS=your_easynews_password
NEWZNAB_APIKEY=testkey
```

4. Run the server:

```
python server.py
```

It starts on `http://127.0.0.1:8081`.

## Endpoints

- Caps: `GET /api?t=caps&apikey=<key>`
- Search (video-only): `GET /api?t=search&q=<query>&apikey=<key>&limit=<n>&minsize=<MB>`
	- Default `limit=100`, `minsize=100` (MB)
	- Also supports `t=movie` and `t=tvsearch`
- Download NZB: `GET /api?t=get&id=<encoded>&apikey=<key>`
	- Filename equals the item title

## Prowlarr integration

Add a Newznab (custom) indexer in Prowlarr:
- URL: `http://127.0.0.1:8081`
- API Key: the same key in your `.env` (e.g., `testkey`)
- Categories: Movies (2000)

## Notes
- Unofficial client: endpoints/params mirror the Easynews web app and may change.
- Use your own Easynews account per their Terms of Service.