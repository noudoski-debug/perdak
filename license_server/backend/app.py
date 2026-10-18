from __future__ import annotations

import os
import secrets
import time
import threading
from collections import defaultdict, deque
import psycopg
from psycopg.rows import dict_row
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ADMIN_TOKEN = os.environ.get("ENDLC_ADMIN_TOKEN", "DaValhjaDV#$24+%").strip()
ONLINE_WINDOW_SECONDS = max(60, int(os.environ.get("ENDLC_ONLINE_WINDOW_SECONDS", "150")))
_failed_attempts = defaultdict(deque)
_failed_lock = threading.Lock()
ALLOWED_DURATIONS = {7, 14, 20, 30, 60, 90, 180, 360}

app = FastAPI(title="EncoreDLC License API", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not set. Add the Render PostgreSQL Internal Database URL to the web service environment.")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def init_db() -> None:
    with connect() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id BIGSERIAL PRIMARY KEY,
            license_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            label TEXT NOT NULL DEFAULT '',
            revoked INTEGER NOT NULL DEFAULT 0,
            device_id TEXT,
            session_expires_at TEXT,
            shared INTEGER NOT NULL DEFAULT 0,
            last_seen_at TEXT
        )
        """)
        con.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS session_expires_at TEXT")
        con.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS shared INTEGER NOT NULL DEFAULT 0")
        con.execute("ALTER TABLE licenses ADD COLUMN IF NOT EXISTS last_seen_at TEXT")
        con.execute("CREATE INDEX IF NOT EXISTS idx_licenses_last_seen ON licenses(last_seen_at)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_licenses_device_id ON licenses(device_id)")
        con.execute("""CREATE TABLE IF NOT EXISTS client_presence (
            device_id TEXT PRIMARY KEY, license_id BIGINT NOT NULL, last_seen_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS admin_audit (
            id BIGSERIAL PRIMARY KEY, created_at TEXT NOT NULL, action TEXT NOT NULL,
            license_id BIGINT, detail TEXT NOT NULL DEFAULT '', remote_ip TEXT NOT NULL DEFAULT '')""")


def require_admin(token: Optional[str], request: Request) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Admin disabled: set ENDLC_ADMIN_TOKEN")
    ip = request.client.host if request.client else "unknown"
    now = time.monotonic()
    with _failed_lock:
        attempts = _failed_attempts[ip]
        while attempts and now - attempts[0] > 300:
            attempts.popleft()
        if len(attempts) >= 12:
            raise HTTPException(status_code=429, detail="Too many failed admin authentication attempts. Try again later.")
        if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
            attempts.append(now)
            raise HTTPException(status_code=401, detail="Invalid admin token")
        _failed_attempts.pop(ip, None)


def audit(con, request: Request, action: str, license_id: Optional[int] = None, detail: str = "") -> None:
    ip = request.client.host if request.client else "unknown"
    con.execute("INSERT INTO admin_audit (created_at, action, license_id, detail, remote_ip) VALUES (%s, %s, %s, %s, %s)",
                (utc_now().isoformat(), action, license_id, detail[:500], ip[:100]))


def parse_dt(value):
    if not value: return None
    try:
        dt = datetime.fromisoformat(value)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError): return None


def is_live(row, now):
    seen, session, expiry = parse_dt(row.get("last_seen_at")), parse_dt(row.get("session_expires_at")), parse_dt(row.get("expires_at"))
    return bool(not row.get("revoked") and seen and (now-seen).total_seconds() <= ONLINE_WINDOW_SECONDS
                and session and now < session and (not expiry or now < expiry))


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") or request.url.path == "/admin" else "no-cache"
    if request.url.scheme == "https": response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


def generate_key() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "ENDLC-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


class ValidateRequest(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    device_id: str = Field(min_length=1, max_length=200)


class CreateKeyRequest(BaseModel):
    duration_days: Optional[int] = None
    label: str = Field(default="", max_length=200)
    shared: bool = False


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", response_class=HTMLResponse)
def client_page() -> str:
    return (WEB_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/admin", response_class=HTMLResponse)
def admin_page() -> str:
    return (WEB_DIR / "admin.html").read_text(encoding="utf-8")


@app.get("/api/v1/health")
def health() -> dict:
    return {"ok": True, "service": "EncoreDLC License API"}


@app.post("/api/v1/license/validate")
def validate_license(body: ValidateRequest, request: Request) -> dict:
    key = body.key.strip()
    device_id = body.device_id.strip()
    if not key or not device_id:
        raise HTTPException(status_code=400, detail="key and device_id are required")
    with connect() as con:
        row = con.execute("SELECT * FROM licenses WHERE license_key = %s", (key,)).fetchone()
        if row is None:
            return {"valid": False, "reason": "invalid_key"}
        if row["revoked"]:
            return {"valid": False, "reason": "revoked"}
        expires = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
        if expires and utc_now() >= expires:
            return {"valid": False, "reason": "expired"}
        # First successful activation binds the key to this device ID.
        if not row["shared"] and row["device_id"] and row["device_id"] != device_id:
            return {"valid": False, "reason": "device_mismatch"}
        if not row["shared"] and not row["device_id"]:
            con.execute("UPDATE licenses SET device_id = %s WHERE id = %s", (device_id, row["id"]))
        # Server-side one-hour session. No session token/expiry is stored on the client.
        session_expiry = utc_now() + timedelta(hours=1)
        seen_at = utc_now().isoformat()
        con.execute("UPDATE licenses SET session_expires_at = %s, last_seen_at = %s WHERE id = %s", (session_expiry.isoformat(), seen_at, row["id"]))
        con.execute("INSERT INTO client_presence (device_id, license_id, last_seen_at) VALUES (%s, %s, %s) ON CONFLICT (device_id) DO UPDATE SET license_id = EXCLUDED.license_id, last_seen_at = EXCLUDED.last_seen_at", (device_id, row["id"], seen_at))
        return {"valid": True, "expires_at": row["expires_at"], "session_expires_at": session_expiry.isoformat(), "label": row["label"]}


class SessionRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=200)


@app.post("/api/v1/license/session")
def check_session(body: SessionRequest) -> dict:
    device_id = body.device_id.strip()
    if not device_id:
        return {"valid": False, "reason": "missing_device"}
    now = utc_now()
    with connect() as con:
        row = con.execute("""SELECT * FROM licenses
            WHERE device_id = %s AND revoked = 0 AND session_expires_at IS NOT NULL
            ORDER BY id DESC LIMIT 1""", (device_id,)).fetchone()
        if row is None:
            return {"valid": False, "reason": "no_session"}
        expires = datetime.fromisoformat(row["session_expires_at"])
        license_expires = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
        if now >= expires or (license_expires and now >= license_expires):
            return {"valid": False, "reason": "session_expired"}
        con.execute("UPDATE licenses SET last_seen_at = %s WHERE id = %s", (now.isoformat(), row["id"]))
        con.execute("INSERT INTO client_presence (device_id, license_id, last_seen_at) VALUES (%s, %s, %s) ON CONFLICT (device_id) DO UPDATE SET license_id = EXCLUDED.license_id, last_seen_at = EXCLUDED.last_seen_at", (device_id, row["id"], now.isoformat()))
        return {"valid": True, "session_expires_at": row["session_expires_at"]}


@app.get("/api/v1/admin/stats")
def admin_stats(request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    now = utc_now()
    with connect() as con:
        rows = con.execute("SELECT id, expires_at, revoked, session_expires_at, last_seen_at FROM licenses").fetchall()
        total = con.execute("SELECT COUNT(*) AS n FROM licenses").fetchone()["n"]
        revoked = con.execute("SELECT COUNT(*) AS n FROM licenses WHERE revoked = 1").fetchone()["n"]
        created = con.execute("SELECT COUNT(*) AS n FROM licenses WHERE created_at >= %s", ((now-timedelta(hours=24)).isoformat(),)).fetchone()["n"]
        online = con.execute("""SELECT COUNT(DISTINCT p.device_id) AS n FROM client_presence p
            JOIN licenses l ON l.id = p.license_id
            WHERE p.last_seen_at >= %s AND l.revoked = 0
            AND (l.expires_at IS NULL OR l.expires_at > %s)
            AND (l.session_expires_at IS NULL OR l.session_expires_at > %s)""",
            ((now-timedelta(seconds=ONLINE_WINDOW_SECONDS)).isoformat(), now.isoformat(), now.isoformat())).fetchone()["n"]
    expired = sum(1 for r in rows if r["expires_at"] and parse_dt(r["expires_at"]) and parse_dt(r["expires_at"]) <= now)
    active = sum(1 for r in rows if not r["revoked"] and (not r["expires_at"] or (parse_dt(r["expires_at"]) and parse_dt(r["expires_at"]) > now)))
    return {"total_keys": int(total or 0), "revoked_keys": int(revoked or 0), "active_keys": active, "expired_keys": expired,
            "online_users": int(online or 0), "created_last_24h": int(created or 0),
            "online_window_seconds": ONLINE_WINDOW_SECONDS, "server_time": now.isoformat()}


@app.get("/api/v1/admin/activity")
def admin_activity(request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        rows = con.execute("SELECT id, created_at, action, license_id, detail, remote_ip FROM admin_audit ORDER BY id DESC LIMIT 50").fetchall()
    return {"activity": [dict(r) for r in rows]}


@app.post("/api/v1/admin/keys/{license_id}/unrevoke")
def unrevoke_key(license_id: int, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        cur = con.execute("UPDATE licenses SET revoked = 0 WHERE id = %s", (license_id,))
        if cur.rowcount == 0: raise HTTPException(status_code=404, detail="License not found")
        audit(con, request, "key_unrevoked", license_id)
    return {"ok": True, "id": license_id}


@app.post("/api/v1/admin/keys")
def create_key(body: CreateKeyRequest, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    if body.duration_days is not None and body.duration_days not in ALLOWED_DURATIONS:
        raise HTTPException(status_code=400, detail="duration_days must be 7, 14, 20, 30, 60, 90, 180, 360 or null for lifetime")
    expires = utc_now() + timedelta(days=body.duration_days) if body.duration_days else None
    with connect() as con:
        for _ in range(10):
            key = generate_key()
            try:
                cur = con.execute(
                    "INSERT INTO licenses (license_key, created_at, expires_at, label, shared) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                    (key, utc_now().isoformat(), to_iso(expires), body.label.strip(), int(body.shared)),
                )
                inserted = cur.fetchone()
                audit(con, request, "key_created", inserted["id"], f"label={body.label.strip()}; duration_days={body.duration_days}; shared={body.shared}")
                return {"id": inserted["id"], "key": key, "created_at": utc_now().isoformat(), "expires_at": to_iso(expires), "label": body.label}
            except psycopg.IntegrityError:
                continue
    raise HTTPException(status_code=500, detail="Could not generate unique key")


@app.get("/api/v1/admin/keys")
def list_keys(request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        rows = con.execute("SELECT id, license_key, created_at, expires_at, label, revoked, device_id, shared, last_seen_at, session_expires_at FROM licenses ORDER BY id DESC LIMIT 2000").fetchall()
    now = utc_now()
    result = []
    for row in rows:
        item = dict(row); item["online"] = is_live(item, now); result.append(item)
    return {"keys": result}


@app.post("/api/v1/admin/keys/{license_id}/revoke")
def revoke_key(license_id: int, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        cur = con.execute("UPDATE licenses SET revoked = 1, session_expires_at = NULL WHERE id = %s", (license_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="License not found")
        audit(con, request, "key_revoked", license_id)
    return {"ok": True, "id": license_id}


@app.post("/api/v1/admin/keys/{license_id}/unbind")
def unbind_device(license_id: int, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        cur = con.execute("UPDATE licenses SET device_id = NULL WHERE id = %s", (license_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="License not found")
        audit(con, request, "device_unbound", license_id)
    return {"ok": True, "id": license_id}


@app.delete("/api/v1/admin/keys/{license_id}")
def delete_key(license_id: int, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        row = con.execute("SELECT license_key FROM licenses WHERE id = %s", (license_id,)).fetchone()
        if row is None: raise HTTPException(status_code=404, detail="License not found")
        audit(con, request, "key_deleted", license_id, f"key={row['license_key']}")
        con.execute("DELETE FROM licenses WHERE id = %s", (license_id,))
    return {"ok": True, "id": license_id}


class AdjustDaysRequest(BaseModel):
    days: int = Field(ge=-36500, le=36500)


@app.post("/api/v1/admin/keys/{license_id}/days")
def adjust_days(license_id: int, body: AdjustDaysRequest, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        row = con.execute("SELECT expires_at FROM licenses WHERE id = %s", (license_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="License not found")
        if row["expires_at"] is None:
            raise HTTPException(status_code=400, detail="Lifetime key has no expiration to adjust")
        current = datetime.fromisoformat(row["expires_at"])
        updated = current + timedelta(days=body.days)
        if updated <= utc_now():
            con.execute("UPDATE licenses SET expires_at = %s, session_expires_at = NULL WHERE id = %s", (updated.isoformat(), license_id))
        else:
            con.execute("UPDATE licenses SET expires_at = %s WHERE id = %s", (updated.isoformat(), license_id))
        audit(con, request, "expiration_changed", license_id, f"days={body.days}; expires_at={updated.isoformat()}")
    return {"ok": True, "id": license_id, "expires_at": updated.isoformat()}
