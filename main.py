"""
MyPass Cloud API
Deploy free on: Render.com / Railway.app / Vercel (serverless)
"""

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
from typing import Optional
import uuid
import json
import os
import random
import string

app = FastAPI(title="MyPass Cloud API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── IN-MEMORY STORE (replace with Redis or SQLite for production) ────────────
# Structure: { license_key: { "passes": [...], "pending_commands": [...] } }
DB: dict = {}

MASTER_KEYS = {
    # license_key → owner info
    "MYPASS-HOME-001": {"owner": "admin", "plan": "pro"},
}

def get_db(license_key: str):
    if license_key not in DB:
        DB[license_key] = {"passes": [], "pending_commands": []}
    return DB[license_key]

def verify_key(x_license_key: str = Header(...)):
    if x_license_key not in MASTER_KEYS:
        raise HTTPException(status_code=401, detail="Invalid license key")
    return x_license_key


# ── MODELS ───────────────────────────────────────────────────────────────────
class CreatePassRequest(BaseModel):
    ssid: str = "MyPass-Guest"
    duration_minutes: int = 60
    password_style: str = "pronounceable"  # pronounceable | random | words

class PassResponse(BaseModel):
    id: str
    ssid: str
    password: str
    expires_at: str
    qr_data: str
    pronounceable_hint: str


# ── PASSWORD GENERATION ──────────────────────────────────────────────────────
VOWELS = "aeiou"
CONSONANTS = "bcdfghjklmnprstvwxz"
WORD_LIST = ["sun","moon","cat","fox","oak","bay","sea","sky","fire","ice",
             "gem","bolt","wave","pine","mist","storm","cliff","dawn","dusk","arch"]
NATO = {"A":"alpha","B":"bravo","C":"charlie","D":"delta","E":"echo","F":"foxtrot",
        "G":"golf","H":"hotel","I":"india","J":"juliet","K":"kilo","L":"lima",
        "M":"mike","N":"november","O":"oscar","P":"papa","Q":"quebec","R":"romeo",
        "S":"sierra","T":"tango","U":"uniform","V":"victor","W":"whiskey",
        "X":"x-ray","Y":"yankee","Z":"zulu"}

def gen_pronounceable(length=10):
    pwd = ""
    for _ in range(length // 2):
        pwd += random.choice(CONSONANTS).upper() + random.choice(VOWELS)
    pwd += str(random.randint(10, 99))
    return pwd[:length + 2]

def gen_random(length=12):
    chars = string.ascii_letters + string.digits + "!@#"
    return "".join(random.choices(chars, k=length))

def gen_words():
    return f"{random.choice(WORD_LIST)}-{random.choice(WORD_LIST)}-{random.randint(10,99)}"

def make_password(style: str) -> str:
    if style == "random":
        return gen_random()
    elif style == "words":
        return gen_words()
    return gen_pronounceable()

def nato_hint(password: str) -> str:
    result = []
    for c in password:
        if c.upper() in NATO:
            result.append(NATO[c.upper()])
        elif c.isdigit():
            result.append(c)
        else:
            result.append(c)
    return "-".join(result)


# ── ROUTES ───────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"service": "MyPass Cloud API", "status": "online"}


@app.post("/api/passes", response_model=PassResponse)
def create_pass(req: CreatePassRequest, key: str = Depends(verify_key)):
    """Create a new temporary WiFi pass and queue a command for the Bridge Agent."""
    db = get_db(key)

    password = make_password(req.password_style)
    pass_id = str(uuid.uuid4())[:8].upper()
    expires_at = datetime.utcnow() + timedelta(minutes=req.duration_minutes)

    new_pass = {
        "id": pass_id,
        "ssid": req.ssid,
        "password": password,
        "style": req.password_style,
        "created_at": datetime.utcnow().isoformat(),
        "expires_at": expires_at.isoformat(),
        "duration_minutes": req.duration_minutes,
        "status": "active",
    }
    db["passes"].append(new_pass)

    # Queue command for Bridge Agent
    db["pending_commands"].append({
        "id": str(uuid.uuid4()),
        "action": "set_password",
        "ssid": req.ssid,
        "password": password,
        "expires_at": expires_at.isoformat(),
        "pass_id": pass_id,
        "acked": False,
    })

    # Also queue an expire command for when the time runs out
    db["pending_commands"].append({
        "id": str(uuid.uuid4()),
        "action": "expire",
        "ssid": req.ssid,
        "execute_at": expires_at.isoformat(),
        "pass_id": pass_id,
        "acked": False,
    })

    qr_data = f"WIFI:T:WPA;S:{req.ssid};P:{password};;"

    return PassResponse(
        id=pass_id,
        ssid=req.ssid,
        password=password,
        expires_at=expires_at.isoformat() + "Z",
        qr_data=qr_data,
        pronounceable_hint=nato_hint(password),
    )


@app.get("/api/passes")
def list_passes(key: str = Depends(verify_key)):
    """List all passes (active + expired)."""
    db = get_db(key)
    now = datetime.utcnow()
    passes = db["passes"]
    for p in passes:
        exp = datetime.fromisoformat(p["expires_at"])
        p["status"] = "active" if exp > now else "expired"
    return {"passes": sorted(passes, key=lambda x: x["created_at"], reverse=True)}


@app.delete("/api/passes/{pass_id}")
def revoke_pass(pass_id: str, key: str = Depends(verify_key)):
    """Immediately revoke a pass (queues expire command)."""
    db = get_db(key)
    for p in db["passes"]:
        if p["id"] == pass_id:
            p["status"] = "revoked"
            db["pending_commands"].append({
                "id": str(uuid.uuid4()),
                "action": "expire",
                "ssid": p["ssid"],
                "execute_at": datetime.utcnow().isoformat(),
                "pass_id": pass_id,
                "acked": False,
            })
            return {"ok": True, "message": f"Pass {pass_id} revoked"}
    raise HTTPException(status_code=404, detail="Pass not found")


# ── AGENT ENDPOINTS ───────────────────────────────────────────────────────────
@app.get("/api/agent/commands")
def get_commands(key: str = Depends(verify_key)):
    """Bridge Agent polls this. Returns next pending command or 204."""
    db = get_db(key)
    now = datetime.utcnow()

    for cmd in db["pending_commands"]:
        if cmd.get("acked"):
            continue
        # Check if it's time to execute
        execute_at = cmd.get("execute_at")
        if execute_at:
            if datetime.fromisoformat(execute_at) > now:
                continue  # Not yet
        return cmd  # Return first ready command

    from fastapi.responses import Response
    return Response(status_code=204)


@app.post("/api/agent/ack")
def ack_command(body: dict, key: str = Depends(verify_key)):
    """Bridge Agent calls this after executing a command."""
    db = get_db(key)
    command_id = body.get("command_id")
    for cmd in db["pending_commands"]:
        if cmd["id"] == command_id:
            cmd["acked"] = True
            cmd["acked_at"] = datetime.utcnow().isoformat()
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Command not found")


@app.get("/api/stats")
def get_stats(key: str = Depends(verify_key)):
    db = get_db(key)
    now = datetime.utcnow()
    passes = db["passes"]
    active = sum(1 for p in passes if datetime.fromisoformat(p["expires_at"]) > now)
    return {
        "total_passes": len(passes),
        "active_passes": active,
        "expired_passes": len(passes) - active,
        "pending_commands": sum(1 for c in db["pending_commands"] if not c.get("acked")),
    }
