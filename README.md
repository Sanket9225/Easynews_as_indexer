# [☕ Please support my work on Buy Me a Coffee](https://buymeacoffee.com/gaikwadsank)

# Easynews Newznab-like server

Flask server that bridges Easynews search to a Newznab-like API so you can add it to Prowlarr as a custom indexer and download NZBs. Video-only, sorts by relevance, returns as many results as possible, and filters files smaller than 100 MB.

## Setup (Local)

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

## Setup (Docker)


### Pull from GitHub Container Registry

```
docker pull ghcr.io/sanket9225/easynews_as_indexer:latest
```

Run the published image (Linux/macOS shells):

```
docker run --rm -d -p 8081:8081 \
	-e EASYNEWS_USER=your_easynews_username \
	-e EASYNEWS_PASS=your_easynews_password \
	-e NEWZNAB_APIKEY=testkey \
	-e PORT=8081 \
	ghcr.io/sanket9225/easynews_as_indexer:latest
```

> The published image currently includes `linux/amd64` and `linux/arm64` manifests.

Windows PowerShell equivalent:

```
docker run --rm -d -p 8081:8081 ^
	-e EASYNEWS_USER=your_easynews_username ^
	-e EASYNEWS_PASS=your_easynews_password ^
	-e NEWZNAB_APIKEY=testkey ^
	-e PORT=8081 ^
	ghcr.io/sanket9225/easynews_as_indexer:latest
```

To tail logs from the detached container run `docker logs -f <container-id>`.

## Endpoints

- Caps: `GET /api?t=caps&apikey=<key>`
- Search (video-only): `GET /api?t=search&q=<query>&apikey=<key>&limit=<n>&minsize=<MB>`
	- Default `limit=100`, `minsize=100` (MB)
	- Also supports `t=movie` and `t=tvsearch`
	- Optional `strict=0|1` overrides title matching strictness (`movie` defaults to strict)
	- Movie search accepts `year=<YYYY>` to bias results; TV search accepts `season=<NN>` and `ep=<NN>` (automatically appended as `SxxEyy` in the Easynews query)
- Download NZB: `GET /api?t=get&id=<encoded>&apikey=<key>`
	- Filename equals the item title

## Prowlarr integration

Add a Newznab (generic) indexer in Prowlarr:
- URL: `http://127.0.0.1:8081`
- API Key: the same key in your `.env` (e.g., `testkey`)

---

## [☕ If this project helps you, consider buying me a coffee](https://buymeacoffee.com/gaikwadsank)
