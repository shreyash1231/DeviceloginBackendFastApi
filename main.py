from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import sqlite3
from typing import List
import time
import jwt
import requests

# Simple FastAPI app that tracks active sessions per user in a local SQLite DB.
# It expects the frontend to provide an Auth0 id_token (JWT) in the Authorization header (Bearer <id_token>).
# For production, verify tokens properly against Auth0 JWKS. This example performs a minimal signature-less decode for demo.

DB = "sessions.db"
N_DEFAULT = 3  # default concurrent devices allowed; can be overridden via query param in requests for testing.

app = FastAPI(title="N-device Auth0 demo backend")
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000","https://n-device-frotend-o3xe.vercel.app"],  # frontend URL
    allow_credentials=True,
    allow_methods=["*"],  # allow all HTTP methods
    allow_headers=["*"],  # allow all headers
)

class RegisterRequest(BaseModel):
    device_id: str
    device_name: str

def init_db():
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_sub TEXT NOT NULL,
        device_id TEXT NOT NULL,
        device_name TEXT,
        created_at INTEGER,
        last_seen INTEGER,
        revoked INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

def get_user_sub_from_token(token: str):
    # WARNING: This is a DEMO helper. In production you MUST verify signature using Auth0 JWKS and verify issuer/audience.
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
        return payload.get("sub"), payload
    except Exception:
        return None, None

@app.on_event("startup")
def startup():
    init_db()

@app.post("/api/register")
async def register_session(req: Request, body: RegisterRequest):
    auth = req.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split()[1]
    user_sub, payload = get_user_sub_from_token(token)
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid token")

    # configurable N via query param ?limit=3
    limit = int(req.query_params.get("limit", str(N_DEFAULT)))

    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # cleanup old revoked sessions older than 30 days (optional)
    cur.execute("DELETE FROM sessions WHERE revoked=1 AND last_seen < ?", (int(time.time()) - 30*24*3600,))
    conn.commit()

    # check if device already registered
    cur.execute("SELECT id, revoked FROM sessions WHERE user_sub=? AND device_id=?", (user_sub, body.device_id))
    row = cur.fetchone()
    if row:
        # update last_seen
        cur.execute("UPDATE sessions SET last_seen=? WHERE id=?", (int(time.time()), row[0]))
        conn.commit()
        conn.close()
        return {"status":"ok","action":"already_registered"}

    # count active (not revoked) sessions
    cur.execute("SELECT id, device_id, device_name, created_at FROM sessions WHERE user_sub=? AND revoked=0 ORDER BY created_at ASC", (user_sub,))
    active = cur.fetchall()
    if len(active) < limit:
        cur.execute("INSERT INTO sessions(user_sub, device_id, device_name, created_at, last_seen) VALUES (?,?,?,?,?)",
                    (user_sub, body.device_id, body.device_name, int(time.time()), int(time.time())))
        conn.commit()
        conn.close()
        return {"status":"ok","action":"registered"}

    # else exceed limit - return the list of active sessions so frontend can prompt user
    sessions = [{"id":r[0],"device_id":r[1],"device_name":r[2],"created_at":r[3]} for r in active]
    conn.close()
    return JSONResponse(status_code=409, content={"status":"limit_reached","sessions":sessions})

@app.post("/api/force_logout")
async def force_logout(req: Request, payload: dict):
    # payload: {"logout_session_id": 5}
    auth = req.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split()[1]
    user_sub, _ = get_user_sub_from_token(token)
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid token")
    sid = payload.get("logout_session_id")
    if not sid:
        raise HTTPException(status_code=400, detail="logout_session_id required")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    # mark as revoked if it belongs to this user
    cur.execute("UPDATE sessions SET revoked=1 WHERE id=? AND user_sub=?", (sid, user_sub))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="session not found")
    conn.commit()
    conn.close()
    return {"status":"ok","message":"session revoked"}

@app.get("/api/sessions")
async def list_sessions(req: Request):
    auth = req.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split()[1]
    user_sub, _ = get_user_sub_from_token(token)
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid token")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT id, device_id, device_name, created_at, last_seen, revoked FROM sessions WHERE user_sub=? ORDER BY created_at ASC", (user_sub,))
    rows = cur.fetchall()
    conn.close()
    sessions = [{"id":r[0],"device_id":r[1],"device_name":r[2],"created_at":r[3],"last_seen":r[4],"revoked":bool(r[5])} for r in rows]
    return {"status":"ok","sessions":sessions}

@app.get("/api/private")
async def private(req: Request):
    auth = req.headers.get("authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    token = auth.split()[1]
    user_sub, payload = get_user_sub_from_token(token)
    if not user_sub:
        raise HTTPException(status_code=401, detail="Invalid token")
    # check if this device's session was revoked
    # expecting a custom header X-Device-Id
    device_id = req.headers.get("x-device-id")
    conn = sqlite3.connect(DB)
    cur = conn.cursor()
    cur.execute("SELECT revoked FROM sessions WHERE user_sub=? AND device_id=?", (user_sub, device_id))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="session not registered")
    if row[0] == 1:
        conn.close()
        # inform client that it was force logged out
        raise HTTPException(status_code=401, detail="logged_out_by_another_device")
    # return user info (name and phone) from token claims (for demo)
    name = payload.get("name", "Demo User")
    phone = payload.get("phone_number", "N/A")
    conn.close()
    return {"full_name": name, "phone": phone}
