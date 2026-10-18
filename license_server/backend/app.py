from __future__ import annotations

import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
DB_PATH = Path(os.environ.get("ENDLC_DB_PATH", str(Path(__file__).resolve().parent / "endldlc.sqlite3")))
ADMIN_TOKEN = os.environ.get("ENDLC_ADMIN_TOKEN", "admin")
ALLOWED_DURATIONS = {7, 14, 20, 30, 60, 90, 180, 360}

app = FastAPI(title="EncoreDLC License API", version="1.0.0")
app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def connect() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect() as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_key TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            label TEXT NOT NULL DEFAULT '',
            revoked INTEGER NOT NULL DEFAULT 0,
            device_id TEXT,
            session_expires_at TEXT,
            shared INTEGER NOT NULL DEFAULT 0
        )
        """)
        # Migrate existing databases without losing license records.
        columns = {row[1] for row in con.execute("PRAGMA table_info(licenses)").fetchall()}
        if "session_expires_at" not in columns:
            con.execute("ALTER TABLE licenses ADD COLUMN session_expires_at TEXT")
        if "shared" not in columns:
            con.execute("ALTER TABLE licenses ADD COLUMN shared INTEGER NOT NULL DEFAULT 0")
        # Development-only sample key; remove/replace before deployment.
        exists = con.execute("SELECT id FROM licenses WHERE license_key = ?", ("1234567",)).fetchone()
        if not exists:
            con.execute(
                "INSERT INTO licenses (license_key, created_at, expires_at, label) VALUES (?, ?, ?, ?)",
                ("1234567", utc_now().isoformat(), (utc_now() + timedelta(days=7)).isoformat(), "DEMO ONLY — remove before production"),
            )


def require_admin(token: Optional[str]) -> None:
    if not ADMIN_TOKEN:
        raise HTTPException(status_code=503, detail="Admin disabled: set ENDLC_ADMIN_TOKEN")
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        raise HTTPException(status_code=401, detail="Invalid admin token")


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
    custom_key: Optional[str] = Field(default=None, min_length=4, max_length=100)


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
        row = con.execute("SELECT * FROM licenses WHERE license_key = ?", (key,)).fetchone()
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
            con.execute("UPDATE licenses SET device_id = ? WHERE id = ?", (device_id, row["id"]))
        # Server-side one-hour session. No session token/expiry is stored on the client.
        session_expiry = utc_now() + timedelta(hours=1)
        con.execute("UPDATE licenses SET session_expires_at = ? WHERE id = ?", (session_expiry.isoformat(), row["id"]))
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
            WHERE device_id = ? AND revoked = 0 AND session_expires_at IS NOT NULL
            ORDER BY id DESC LIMIT 1""", (device_id,)).fetchone()
        if row is None:
            return {"valid": False, "reason": "no_session"}
        expires = datetime.fromisoformat(row["session_expires_at"])
        license_expires = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
        if now >= expires or (license_expires and now >= license_expires):
            return {"valid": False, "reason": "session_expired"}
        return {"valid": True, "session_expires_at": row["session_expires_at"]}


@app.post("/api/v1/admin/keys")
def create_key(body: CreateKeyRequest, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token)
    if body.duration_days is not None and body.duration_days not in ALLOWED_DURATIONS:
        raise HTTPException(status_code=400, detail="duration_days must be 7, 14, 20, 30, 60, 90, 180, 360 or null for lifetime")
    expires = utc_now() + timedelta(days=body.duration_days) if body.duration_days else None
    custom_key = body.custom_key.strip() if body.custom_key else ""
    if custom_key and not re.fullmatch(r"[A-Za-z0-9_-]{4,100}", custom_key):
        raise HTTPException(status_code=400, detail="Custom key may contain only A-Z, a-z, 0-9, underscore and hyphen (4-100 chars)")
    key = custom_key or generate_key()
    with connect() as con:
        try:
            cur = con.execute(
                "INSERT INTO licenses (license_key, created_at, expires_at, label, shared) VALUES (?, ?, ?, ?, ?)",
                (key, utc_now().isoformat(), to_iso(expires), body.label.strip(), int(body.shared)),
            )
            return {"id": cur.lastrowid, "key": key, "created_at": utc_now().isoformat(), "expires_at": to_iso(expires), "label": body.label}
        except sqlite3.IntegrityError:
            if custom_key:
                raise HTTPException(status_code=409, detail="This custom key already exists")
    raise HTTPException(status_code=500, detail="Could not generate unique key")


@app.get("/api/v1/admin/keys")
def list_keys(x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token)
    with connect() as con:
        rows = con.execute("SELECT id, license_key, created_at, expires_at, label, revoked, device_id, shared FROM licenses ORDER BY id DESC").fetchall()
    return {"keys": [dict(r) for r in rows]}


@app.post("/api/v1/admin/keys/{license_id}/revoke")
def revoke_key(license_id: int, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token)
    with connect() as con:
        cur = con.execute("UPDATE licenses SET revoked = 1 WHERE id = ?", (license_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="License not found")
    return {"ok": True, "id": license_id}


@app.post("/api/v1/admin/keys/{license_id}/unbind")
def unbind_device(license_id: int, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token)
    with connect() as con:
        cur = con.execute("UPDATE licenses SET device_id = NULL WHERE id = ?", (license_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="License not found")
    return {"ok": True, "id": license_id}


@app.delete("/api/v1/admin/keys/{license_id}")
def delete_key(license_id: int, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token)
    with connect() as con:
        cur = con.execute("DELETE FROM licenses WHERE id = ?", (license_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="License not found")
    return {"ok": True, "id": license_id}


class AdjustDaysRequest(BaseModel):
    days: int = Field(ge=-36500, le=36500)


@app.post("/api/v1/admin/keys/{license_id}/days")
def adjust_days(license_id: int, body: AdjustDaysRequest, x_admin_token: Optional[str] = Header(default=None)) -> dict:
    require_admin(x_admin_token)
    with connect() as con:
        row = con.execute("SELECT expires_at FROM licenses WHERE id = ?", (license_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="License not found")
        if row["expires_at"] is None:
            raise HTTPException(status_code=400, detail="Lifetime key has no expiration to adjust")
        current = datetime.fromisoformat(row["expires_at"])
        updated = current + timedelta(days=body.days)
        if updated <= utc_now():
            con.execute("UPDATE licenses SET expires_at = ?, session_expires_at = NULL WHERE id = ?", (updated.isoformat(), license_id))
        else:
            con.execute("UPDATE licenses SET expires_at = ? WHERE id = ?", (updated.isoformat(), license_id))
    return {"ok": True, "id": license_id, "expires_at": updated.isoformat()}
