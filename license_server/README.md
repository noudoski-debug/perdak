# EncoreDLC key system starter

A starter license backend + admin page + client UI preview.

## Included
- FastAPI + SQLite license API.
- Durations: 7, 14, 20, 30, 60, 90, 180, 360 days, or lifetime.
- Admin key creation/list/revoke.
- A polished client key-entry screen with an on-screen keyboard.
- Demo key `1234567` seeded for local development only.

## Not included
This project intentionally does not download or execute remote `.sh` scripts or binaries. A shell script is executable code, and trying to make it impossible to inspect while downloading it is not a security boundary. For production distribution, package a signed APK/build artifact, verify its signature/hash, and use Android's normal install/update flow.

## Run backend
Python 3.10+ recommended.

```bash
cd backend
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -r requirements.txt
export ENDLC_ADMIN_TOKEN='replace-with-a-long-random-secret'
export ENDLC_DB_PATH='./endldlc.sqlite3'
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/admin` for the admin panel and `http://127.0.0.1:8000/` for the client UI preview.
For LAN/device testing, bind to `0.0.0.0` only behind HTTPS/reverse proxy and firewall rules. Do not expose the development server directly to the public internet.

## API
- `POST /api/v1/license/validate` JSON: `{"key":"1234567","device_id":"demo-device"}`
- `POST /api/v1/admin/keys` header `X-Admin-Token: ...`; JSON: `{"duration_days":30,"label":"customer"}`
  - `duration_days` can be one of 7,14,20,30,60,90,180,360 or `null` for lifetime.
- `GET /api/v1/admin/keys` header `X-Admin-Token`
- `POST /api/v1/admin/keys/{id}/revoke` header `X-Admin-Token`

## Important production notes
- Put the API behind HTTPS.
- Store `ENDLC_ADMIN_TOKEN` in a secret manager/environment, never in an APK.
- Replace the demo key, enable rate limiting, and add audit logging.
- Bind a license to a server-generated account or device identity only after documenting reset/rebind rules. Device IDs supplied by clients can be spoofed.
- The demo client UI is a web preview that can be placed in an Android WebView. It is not a compiled APK.
