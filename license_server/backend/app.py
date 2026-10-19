from __future__ import annotations

import os
import secrets
import time
import threading
import base64
import json
import hashlib
import hmac
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ADMIN_TOKEN = os.environ.get("ENDLC_ADMIN_TOKEN", "DaValhjaDV#$24+%").strip()
TOKEN_TTL_SECONDS = max(60, min(900, int(os.environ.get("ENDLC_TOKEN_TTL_SECONDS", "300"))))
SIGNING_PRIVATE_KEY_B64 = os.environ.get("ENDLC_SIGNING_PRIVATE_KEY_B64", "").strip()
RATE_WINDOW_SECONDS = max(60, int(os.environ.get("ENDLC_RATE_WINDOW_SECONDS", "300")))
RATE_MAX_IP = max(5, int(os.environ.get("ENDLC_RATE_MAX_IP", "30")))
RATE_MAX_KEY = max(3, int(os.environ.get("ENDLC_RATE_MAX_KEY", "10")))
ONLINE_WINDOW_SECONDS = max(60, int(os.environ.get("ENDLC_ONLINE_WINDOW_SECONDS", "150")))
_failed_attempts = defaultdict(deque)
_failed_lock = threading.Lock()
ALLOWED_DURATIONS = {1, 3, 7, 14, 20, 30, 60, 90, 180, 360}

# ── защита клиента ──
# 1 = требовать от клиента build_hash + подпись (включать ПОСЛЕ выпуска обновлённого клиента)
ENFORCE_CLIENT = os.environ.get("ENDLC_ENFORCE_CLIENT", "1") == "1"
# общий секрет для HMAC-подписи запроса (зашивается в клиент при сборке)
CLIENT_HMAC_KEY = os.environ.get("ENDLC_CLIENT_HMAC_KEY", "A2mzpAVFXIkc37yRVWGB7NHkr").strip()
# белый список официальных билдов (sha256), через запятую; плюс можно добавлять через /admin/builds
ENV_BUILDS = {x.strip().lower() for x in os.environ.get("ENDLC_OFFICIAL_BUILDS", "").split(",") if x.strip()}
# 1 = автоматически банить устройство при поддельном/неофициальном клиенте
AUTOBAN = os.environ.get("ENDLC_AUTOBAN", "1") == "1"

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
        con.execute("""CREATE TABLE IF NOT EXISTS security_events (
            id BIGSERIAL PRIMARY KEY, created_at TEXT NOT NULL, event TEXT NOT NULL,
            ip_hash TEXT NOT NULL, key_hash TEXT NOT NULL DEFAULT '', device_hash TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '')""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_security_events_time ON security_events(created_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS official_builds (
            build_hash TEXT PRIMARY KEY, version TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS banned_devices (
            device_hash TEXT PRIMARY KEY, reason TEXT NOT NULL DEFAULT '', license_id BIGINT, created_at TEXT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS challenges (
            nonce TEXT PRIMARY KEY, device_hash TEXT NOT NULL, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0)""")
        con.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id BIGSERIAL PRIMARY KEY, created_at TEXT NOT NULL, kind TEXT NOT NULL, license_id BIGINT,
            label TEXT NOT NULL DEFAULT '', key_masked TEXT NOT NULL DEFAULT '', device_hash TEXT NOT NULL DEFAULT '',
            build_hash TEXT NOT NULL DEFAULT '', client_version TEXT NOT NULL DEFAULT '', ip_hash TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '', handled INTEGER NOT NULL DEFAULT 0)""")
        con.execute("CREATE INDEX IF NOT EXISTS idx_alerts_dedupe ON alerts(kind, device_hash, created_at)")



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


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def signing_key() -> Ed25519PrivateKey:
    # Must be supplied as base64url/base64 raw 32-byte Ed25519 private key.
    if not SIGNING_PRIVATE_KEY_B64:
        raise HTTPException(status_code=503, detail="License signing is not configured")
    try:
        raw = base64.urlsafe_b64decode(SIGNING_PRIVATE_KEY_B64 + "=" * (-len(SIGNING_PRIVATE_KEY_B64) % 4))
        if len(raw) != 32:
            raise ValueError("expected 32 raw bytes")
        return Ed25519PrivateKey.from_private_bytes(raw)
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Invalid license signing key configuration") from exc


def issue_token(license_id: int, device_id: str, expires_at: Optional[str]) -> str:
    now = int(time.time())
    claims = {"iss": "EncoreDLC", "aud": "EncoreDLC-client", "sub": str(license_id),
              "did": hashlib.sha256(device_id.encode()).hexdigest(),
              "iat": now, "nbf": now, "exp": now + TOKEN_TTL_SECONDS,
              "license_exp": expires_at}
    header = {"alg": "EdDSA", "typ": "JWT"}
    signing_input = b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode()) + "." + b64u(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    sig = signing_key().sign(signing_input.encode("ascii"))
    return signing_input + "." + b64u(sig)


def security_event(con, request: Request, event: str, key: str = "", device_id: str = "", detail: str = "") -> None:
    ip = request.client.host if request.client else "unknown"
    # Hash identifiers in logs; don't store submitted license keys or raw device IDs.
    con.execute("INSERT INTO security_events (created_at,event,ip_hash,key_hash,device_hash,detail) VALUES (%s,%s,%s,%s,%s,%s)",
        (utc_now().isoformat(), event, hashlib.sha256(ip.encode()).hexdigest(),
         hashlib.sha256(key.strip().upper().encode()).hexdigest() if key else "",
         hashlib.sha256(device_id.encode()).hexdigest() if device_id else "", detail[:250]))


def enforce_validate_rate_limit(con, request: Request, key: str) -> None:
    ip = request.client.host if request.client else "unknown"
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()
    key_hash = hashlib.sha256(key.strip().upper().encode()).hexdigest()
    cutoff = (utc_now() - timedelta(seconds=RATE_WINDOW_SECONDS)).isoformat()
    row = con.execute("SELECT COUNT(*) AS n FROM security_events WHERE created_at >= %s AND ip_hash = %s AND event = 'validate_attempt'",
                      (cutoff, ip_hash)).fetchone()
    if int(row["n"] or 0) >= RATE_MAX_IP:
        security_event(con, request, "rate_limited_ip", key, detail="license validation rate limit")
        raise HTTPException(status_code=429, detail="Too many validation attempts; retry later")
    row = con.execute("SELECT COUNT(*) AS n FROM security_events WHERE created_at >= %s AND key_hash = %s AND event = 'validate_attempt'",
                      (cutoff, key_hash)).fetchone()
    if int(row["n"] or 0) >= RATE_MAX_KEY:
        security_event(con, request, "rate_limited_key", key, detail="license validation rate limit")
        raise HTTPException(status_code=429, detail="Too many attempts for this key; retry later")
    security_event(con, request, "validate_attempt", key)


def generate_key() -> str:
    # Numeric-only keys; zero-padding preserves a fixed 10-digit format.
    return f"{secrets.randbelow(10**10):010d}"


class ValidateRequest(BaseModel):
    key: str = Field(min_length=1, max_length=100)
    device_id: str = Field(min_length=1, max_length=200)
    client_version: str = Field(default="", max_length=40)
    build_hash: str = Field(default="", max_length=128)
    nonce: str = Field(default="", max_length=100)
    proof: str = Field(default="", max_length=128)


class CreateKeyRequest(BaseModel):
    duration_days: Optional[int] = None
    label: str = Field(default="", max_length=200)
    shared: bool = False


# ───────────────────────── ЗАЩИТА КЛИЕНТА / ТРЕВОГИ ─────────────────────────
def dev_hash_of(device_id: str) -> str:
    return hashlib.sha256(device_id.strip().encode()).hexdigest()


def mask_key(k: str) -> str:
    k = k or ""
    return (k[:6] + "…" + k[-4:]) if len(k) > 12 else "***"


def build_allowed(con, build_hash: str) -> bool:
    h = build_hash.strip().lower()
    if h in ENV_BUILDS:
        return True
    return con.execute("SELECT 1 FROM official_builds WHERE build_hash = %s AND active = 1", (h,)).fetchone() is not None


def kick_license(con, license_id: int) -> None:
    con.execute("UPDATE licenses SET session_expires_at = NULL WHERE id = %s", (license_id,))


def ban_device(con, device_hash: str, reason: str, license_id: Optional[int] = None) -> None:
    con.execute("""INSERT INTO banned_devices (device_hash, reason, license_id, created_at) VALUES (%s,%s,%s,%s)
        ON CONFLICT (device_hash) DO NOTHING""", (device_hash, reason[:200], license_id, utc_now().isoformat()))
    if license_id:
        kick_license(con, license_id)


def raise_alert(con, request: Request, kind: str, row, device_hash: str, build_hash: str = "",
                client_version: str = "", detail: str = "", window_min: int = 10) -> Optional[int]:
    """Создаёт тревогу для бота. Одинаковые (kind + устройство) не чаще раза в window_min минут."""
    cutoff = (utc_now() - timedelta(minutes=window_min)).isoformat()
    if con.execute("SELECT 1 FROM alerts WHERE kind = %s AND device_hash = %s AND created_at >= %s LIMIT 1",
                   (kind, device_hash, cutoff)).fetchone():
        return None
    ip = request.client.host if request.client else "unknown"
    r = con.execute("""INSERT INTO alerts (created_at, kind, license_id, label, key_masked, device_hash, build_hash,
        client_version, ip_hash, detail) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
        (utc_now().isoformat(), kind, row["id"] if row else None, (row["label"] if row else "") or "",
         mask_key(row["license_key"]) if row else "", device_hash, build_hash[:128], client_version[:40],
         hashlib.sha256(ip.encode()).hexdigest(), detail[:250])).fetchone()
    return r["id"]


def check_client_integrity(con, body, device_id: str) -> Optional[str]:
    """None — клиент в порядке; иначе код причины."""
    if not ENFORCE_CLIENT:
        return None
    if not (body.build_hash and body.client_version):
        return "missing_attestation"
    if CLIENT_HMAC_KEY:
        if not body.nonce or not body.proof:
            return "missing_attestation"
        used = con.execute("""UPDATE challenges SET used = 1 WHERE nonce = %s AND device_hash = %s
            AND used = 0 AND expires_at >= %s RETURNING nonce""",
            (body.nonce, dev_hash_of(device_id), utc_now().isoformat())).fetchone()
        if not used:
            return "bad_nonce"
        msg = f"{body.nonce}|{device_id.strip()}|{body.build_hash.strip().lower()}|{body.client_version}".encode()
        expected = hmac.new(CLIENT_HMAC_KEY.encode(), msg, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, body.proof.strip().lower()):
            return "bad_proof"
    if not build_allowed(con, body.build_hash):
        return "unofficial_build"
    return None


class ChallengeRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=200)


@app.post("/api/v1/license/challenge")
def license_challenge(body: ChallengeRequest, request: Request) -> dict:
    """Клиент берёт одноразовый nonce, подписывает его и отправляет в /validate."""
    ip = request.client.host if request.client else "unknown"
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()
    now = utc_now()
    with connect() as con:
        cutoff = (now - timedelta(seconds=RATE_WINDOW_SECONDS)).isoformat()
        n = con.execute("SELECT COUNT(*) AS n FROM security_events WHERE created_at >= %s AND ip_hash = %s AND event = 'challenge'",
                        (cutoff, ip_hash)).fetchone()["n"]
        if int(n or 0) >= RATE_MAX_IP * 3:
            raise HTTPException(status_code=429, detail="Too many requests")
        security_event(con, request, "challenge")
        con.execute("DELETE FROM challenges WHERE expires_at < %s", (now.isoformat(),))
        nonce = secrets.token_urlsafe(24)
        con.execute("INSERT INTO challenges (nonce, device_hash, expires_at) VALUES (%s,%s,%s)",
                    (nonce, dev_hash_of(body.device_id), (now + timedelta(seconds=60)).isoformat()))
    return {"nonce": nonce, "expires_in": 60}


def parse_bearer(authorization: Optional[str]):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    parts = authorization[7:].strip().split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        signed = (parts[0] + "." + parts[1]).encode("ascii")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        signing_key().public_key().verify(signature, signed)
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        now = int(time.time())
        if claims.get("iss") != "EncoreDLC" or claims.get("aud") != "EncoreDLC-client":
            raise ValueError("iss/aud")
        if int(claims.get("exp", 0)) <= now or int(claims.get("nbf", 0)) > now:
            raise ValueError("time")
        return int(claims["sub"]), str(claims["did"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


class ReportRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=40)
    detail: str = Field(default="", max_length=200)
    build_hash: str = Field(default="", max_length=128)
    client_version: str = Field(default="", max_length=40)


REPORT_KINDS = {"tamper", "debugger", "hook", "integrity", "unofficial_build"}


@app.post("/api/v1/license/report")
def client_report(body: ReportRequest, request: Request, authorization: Optional[str] = Header(default=None)) -> dict:
    """Клиент сообщает о вмешательстве. Сессия сразу обрывается, админу уходит тревога."""
    license_id, device_hash = parse_bearer(authorization)
    kind = body.kind if body.kind in REPORT_KINDS else "tamper"
    with connect() as con:
        row = con.execute("SELECT id, label, license_key FROM licenses WHERE id = %s", (license_id,)).fetchone()
        if row is None:
            return {"ok": True, "action": "terminate"}
        raise_alert(con, request, kind, row, device_hash, body.build_hash, body.client_version, body.detail)
        kick_license(con, license_id)
        if AUTOBAN:
            ban_device(con, device_hash, f"client report: {kind}", license_id)
    return {"ok": True, "action": "terminate"}


@app.get("/api/v1/admin/alerts")
def admin_alerts(request: Request, after_id: int = 0, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        rows = con.execute("""SELECT id, created_at, kind, license_id, label, key_masked, device_hash, build_hash,
            client_version, detail, handled FROM alerts WHERE id > %s ORDER BY id ASC LIMIT 50""", (after_id,)).fetchall()
    return {"alerts": [dict(r) for r in rows]}


@app.post("/api/v1/admin/alerts/{alert_id}/handle")
def admin_alert_handle(alert_id: int, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        con.execute("UPDATE alerts SET handled = 1 WHERE id = %s", (alert_id,))
        audit(con, request, "alert_handled", None, f"alert={alert_id}")
    return {"ok": True}


class BanRequest(BaseModel):
    device_hash: Optional[str] = Field(default=None, max_length=128)
    license_id: Optional[int] = None
    reason: str = Field(default="", max_length=200)


@app.post("/api/v1/admin/devices/ban")
def admin_ban_device(body: BanRequest, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        dh = (body.device_hash or "").strip().lower()
        if not dh and body.license_id:
            row = con.execute("SELECT device_id FROM licenses WHERE id = %s", (body.license_id,)).fetchone()
            if row and row["device_id"]:
                dh = dev_hash_of(row["device_id"])
        if not dh:
            raise HTTPException(status_code=400, detail="device_hash or license_id with bound device required")
        ban_device(con, dh, body.reason or "admin", body.license_id)
        audit(con, request, "device_banned", body.license_id, f"device={dh[:16]}; reason={body.reason}")
    return {"ok": True, "device_hash": dh}


class UnbanRequest(BaseModel):
    device_hash: str = Field(min_length=8, max_length=128)


@app.post("/api/v1/admin/devices/unban")
def admin_unban_device(body: UnbanRequest, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        # допускаем префикс хэша (бот показывает короткий вид)
        cur = con.execute("DELETE FROM banned_devices WHERE device_hash LIKE %s", (body.device_hash.strip().lower() + "%",))
        audit(con, request, "device_unbanned", None, f"device={body.device_hash[:16]}")
    return {"ok": True, "removed": cur.rowcount}


@app.get("/api/v1/admin/devices/banned")
def admin_banned_devices(request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        rows = con.execute("SELECT device_hash, reason, license_id, created_at FROM banned_devices ORDER BY created_at DESC LIMIT 100").fetchall()
    return {"devices": [dict(r) for r in rows]}


class BuildRequest(BaseModel):
    build_hash: str = Field(min_length=16, max_length=128)
    version: str = Field(default="", max_length=40)
    note: str = Field(default="", max_length=200)


@app.post("/api/v1/admin/builds")
def admin_add_build(body: BuildRequest, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        con.execute("""INSERT INTO official_builds (build_hash, version, note, active, created_at) VALUES (%s,%s,%s,1,%s)
            ON CONFLICT (build_hash) DO UPDATE SET version = EXCLUDED.version, note = EXCLUDED.note, active = 1""",
            (body.build_hash.strip().lower(), body.version, body.note, utc_now().isoformat()))
        audit(con, request, "build_added", None, f"{body.version}; {body.build_hash[:16]}")
    return {"ok": True}


@app.get("/api/v1/admin/builds")
def admin_list_builds(request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        rows = con.execute("SELECT build_hash, version, note, active, created_at FROM official_builds ORDER BY created_at DESC").fetchall()
    return {"builds": [dict(r) for r in rows], "env_builds": sorted(ENV_BUILDS), "enforce": ENFORCE_CLIENT}


@app.post("/api/v1/admin/builds/{build_hash}/deactivate")
def admin_deactivate_build(build_hash: str, request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        cur = con.execute("UPDATE official_builds SET active = 0 WHERE build_hash LIKE %s", (build_hash.strip().lower() + "%",))
        audit(con, request, "build_deactivated", None, build_hash[:16])
    return {"ok": True, "updated": cur.rowcount}


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


@app.get("/api/v1/license/public-key")
def license_public_key() -> dict:
    # Public key is safe to embed in the native client for offline signature verification.
    pub = signing_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    return {"algorithm": "Ed25519", "public_key_b64url": b64u(pub)}


@app.post("/api/v1/license/check")
def check_license_key(body: dict, request: Request) -> dict:
    """Read-only portal check. Does not activate/bind a device or issue a client token."""
    raw_key = body.get("key", "") if isinstance(body, dict) else ""
    key = str(raw_key).strip()
    if not key.isdigit() or not (1 <= len(key) <= 12):
        return {"valid": False, "reason": "invalid_format"}
    with connect() as con:
        enforce_validate_rate_limit(con, request, key)
        row = con.execute("SELECT id, expires_at, revoked FROM licenses WHERE license_key = %s", (key,)).fetchone()
        if row is None:
            security_event(con, request, "validate_denied", key, detail="portal key check: invalid key")
            return {"valid": False, "reason": "invalid_key"}
        if row["revoked"]:
            security_event(con, request, "validate_denied", key, detail="portal key check: revoked")
            return {"valid": False, "reason": "revoked"}
        expires = parse_dt(row["expires_at"])
        if expires and utc_now() >= expires:
            security_event(con, request, "validate_denied", key, detail="portal key check: expired")
            return {"valid": False, "reason": "expired"}
        security_event(con, request, "validate_success", key, detail="portal status check only; no activation")
        return {"valid": True, "expires_at": row["expires_at"], "activation_required": True}


@app.post("/api/v1/license/validate")
def validate_license(body: ValidateRequest, request: Request) -> dict:
    key = body.key.strip()
    device_id = body.device_id.strip()
    if not key or not device_id:
        raise HTTPException(status_code=400, detail="key and device_id are required")
    with connect() as con:
        enforce_validate_rate_limit(con, request, key)
        dev_hash = dev_hash_of(device_id)
        if con.execute("SELECT 1 FROM banned_devices WHERE device_hash = %s", (dev_hash,)).fetchone():
            security_event(con, request, "validate_denied", key, device_id, "device banned")
            brow = con.execute("SELECT id, label, license_key FROM licenses WHERE license_key = %s", (key,)).fetchone()
            raise_alert(con, request, "banned_device", brow, dev_hash, body.build_hash, body.client_version,
                        "попытка входа с заблокированного устройства", window_min=60)
            return {"valid": False, "reason": "device_banned", "kick": True}
        row = con.execute("SELECT * FROM licenses WHERE license_key = %s", (key,)).fetchone()
        if row is None:
            security_event(con, request, "validate_denied", key, device_id, "invalid key")
            return {"valid": False, "reason": "invalid_key"}
        bad = check_client_integrity(con, body, device_id)
        if bad:
            security_event(con, request, "validate_denied", key, device_id, bad)
            raise_alert(con, request, bad, row, dev_hash, body.build_hash, body.client_version,
                        f"{bad}; version={body.client_version[:20] or '-'}")
            if row["device_id"] == device_id:
                kick_license(con, row["id"])  # выкидываем активную сессию с этого устройства
            if AUTOBAN and bad in ("unofficial_build", "bad_proof"):
                ban_device(con, dev_hash, bad, row["id"])
            return {"valid": False, "reason": "unofficial_client", "kick": True}
        if row["revoked"]:
            security_event(con, request, "validate_denied", key, device_id, "revoked")
            return {"valid": False, "reason": "revoked"}
        expires = parse_dt(row["expires_at"])
        now = utc_now()
        if expires and now >= expires:
            security_event(con, request, "validate_denied", key, device_id, "expired")
            return {"valid": False, "reason": "expired"}
        if not row["shared"] and row["device_id"] and row["device_id"] != device_id:
            security_event(con, request, "validate_denied", key, device_id, "device mismatch")
            return {"valid": False, "reason": "device_mismatch"}
        if not row["shared"] and not row["device_id"]:
            cur = con.execute("UPDATE licenses SET device_id = %s WHERE id = %s AND device_id IS NULL",
                              (device_id, row["id"]))
            if cur.rowcount == 0:
                current = con.execute("SELECT device_id FROM licenses WHERE id = %s", (row["id"],)).fetchone()
                if current and current["device_id"] != device_id:
                    security_event(con, request, "validate_denied", key, device_id, "activation race/device mismatch")
                    return {"valid": False, "reason": "device_mismatch"}
        session_expiry = now + timedelta(seconds=TOKEN_TTL_SECONDS)
        seen_at = now.isoformat()
        con.execute("UPDATE licenses SET session_expires_at = %s, last_seen_at = %s WHERE id = %s",
                    (session_expiry.isoformat(), seen_at, row["id"]))
        con.execute("""INSERT INTO client_presence (device_id, license_id, last_seen_at)
            VALUES (%s, %s, %s) ON CONFLICT (device_id) DO UPDATE SET
            license_id = EXCLUDED.license_id, last_seen_at = EXCLUDED.last_seen_at""",
            (device_id, row["id"], seen_at))
        token = issue_token(int(row["id"]), device_id, row["expires_at"])
        security_event(con, request, "validate_success", key, device_id, "signed token issued")
        return {"valid": True, "expires_at": row["expires_at"], "session_expires_at": session_expiry.isoformat(),
                "token": token, "token_type": "Bearer", "token_expires_in": TOKEN_TTL_SECONDS,
                "label": row["label"]}


class SessionRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=200)


@app.post("/api/v1/license/session")
def check_session(request: Request, authorization: Optional[str] = Header(default=None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Bearer token required")
    parts = authorization[7:].strip().split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid token")
    try:
        public_key = signing_key().public_key()
        signed = (parts[0] + "." + parts[1]).encode("ascii")
        signature = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
        public_key.verify(signature, signed)
        claims = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
        now = int(time.time())
        if claims.get("iss") != "EncoreDLC" or claims.get("aud") != "EncoreDLC-client":
            raise ValueError("wrong issuer/audience")
        if int(claims.get("exp", 0)) <= now or int(claims.get("nbf", 0)) > now:
            raise ValueError("expired/not-yet-valid")
        license_id, device_hash = int(claims["sub"]), str(claims["did"])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    with connect() as con:
        row = con.execute("SELECT * FROM licenses WHERE id = %s", (license_id,)).fetchone()
        if row is None or row["revoked"]:
            raise HTTPException(status_code=401, detail="License revoked or unavailable")
        if con.execute("SELECT 1 FROM banned_devices WHERE device_hash = %s", (device_hash,)).fetchone():
            raise HTTPException(status_code=401, detail="Device banned")
        if row["session_expires_at"] is None:
            raise HTTPException(status_code=401, detail="Session terminated")
        expiry = parse_dt(row["expires_at"])
        if expiry and utc_now() >= expiry:
            raise HTTPException(status_code=401, detail="License expired")
        if not row["shared"] and (not row["device_id"] or hashlib.sha256(row["device_id"].encode()).hexdigest() != device_hash):
            raise HTTPException(status_code=401, detail="Device binding mismatch")
        con.execute("UPDATE licenses SET last_seen_at = %s WHERE id = %s", (utc_now().isoformat(), license_id))
        return {"valid": True, "license_expires_at": row["expires_at"], "token_expires_at": claims["exp"]}


@app.get("/api/v1/admin/security-events")
def admin_security_events(request: Request, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token, request)
    with connect() as con:
        rows = con.execute("""SELECT id, created_at, event, ip_hash, key_hash, device_hash, detail
            FROM security_events ORDER BY id DESC LIMIT 200""").fetchall()
    return {"events": [dict(r) for r in rows]}


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
        raise HTTPException(status_code=400, detail="duration_days must be one of 1, 3, 7, 14, 20, 30, 60, 90, 180, 360 or null for lifetime")
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
