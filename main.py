"""
MyPass Cloud API v2
- No home PC needed
- TOTP-style time-window passwords
- Admin dashboard API
- Guest verification endpoint
"""

from fastapi import FastAPI, HTTPException, Header, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import uuid, hashlib, hmac, struct, time, random, string, json, os

app = FastAPI(title="MyPass Cloud API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── STORAGE (in-memory, survives restarts via env var backup) ────────────────
# In production replace with SQLite or Supabase
ACCOUNTS = {
    "MYPASS-HOME-001": {
        "owner": "JobZaak",
        "plan": "pro",
        "wifi_name": "MyWiFi",          # display only
        "master_secret": "MYPASS-SECRET-JOBZAAK-2024",  # used to derive passwords
        "passes": [],
    }
}

# ── AUTH ─────────────────────────────────────────────────────────────────────
def verify_key(x_license_key: str = Header(...)):
    if x_license_key not in ACCOUNTS:
        raise HTTPException(status_code=401, detail="Invalid license key")
    return x_license_key

def get_account(key: str):
    return ACCOUNTS[key]

# ── PASSWORD GENERATION ───────────────────────────────────────────────────────
WORD_LIST = [
    "apple","bravo","cloud","delta","eagle","flame","globe","hotel",
    "india","jazzy","kite","lemon","mango","noble","ocean","pearl",
    "queen","radar","solar","tiger","ultra","vivid","winds","xenon",
    "yacht","zebra","amber","brush","coral","drift"
]

def gen_pronounceable():
    vowels = "aeiou"
    cons = "bcdfghjklmnprstvwz"
    pwd = ""
    for _ in range(4):
        pwd += random.choice(cons).upper() + random.choice(vowels)
    pwd += str(random.randint(10, 99))
    return pwd

def gen_words():
    return f"{random.choice(WORD_LIST)}-{random.choice(WORD_LIST)}-{random.randint(10,99)}"

def gen_random(length=12):
    chars = string.ascii_letters + string.digits
    return "".join(random.choices(chars, k=length))

def make_password(style: str) -> str:
    if style == "words":   return gen_words()
    if style == "random":  return gen_random()
    return gen_pronounceable()

# NATO phonetic for verbal sharing
NATO = {
    "A":"Alpha","B":"Bravo","C":"Charlie","D":"Delta","E":"Echo","F":"Foxtrot",
    "G":"Golf","H":"Hotel","I":"India","J":"Juliet","K":"Kilo","L":"Lima",
    "M":"Mike","N":"November","O":"Oscar","P":"Papa","Q":"Quebec","R":"Romeo",
    "S":"Sierra","T":"Tango","U":"Uniform","V":"Victor","W":"Whiskey",
    "X":"X-ray","Y":"Yankee","Z":"Zulu",
    "0":"Zero","1":"One","2":"Two","3":"Three","4":"Four",
    "5":"Five","6":"Six","7":"Seven","8":"Eight","9":"Nine"
}

def nato_hint(password: str) -> str:
    parts = []
    for c in password:
        if c == "-":
            parts.append("dash")
        elif c.upper() in NATO:
            parts.append(NATO[c.upper()])
        else:
            parts.append(c)
    return " · ".join(parts)

# ── MODELS ────────────────────────────────────────────────────────────────────
class CreatePassRequest(BaseModel):
    wifi_name: str = "My WiFi"
    duration_minutes: int = 60
    password_style: str = "pronounceable"
    guest_name: str = ""

class UpdateWifiName(BaseModel):
    wifi_name: str

# ── ROUTES ────────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"service": "MyPass Cloud API", "status": "online", "version": "2.0.0"}

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# Create a pass
@app.post("/api/passes")
def create_pass(req: CreatePassRequest, key: str = Depends(verify_key)):
    account = get_account(key)
    password = make_password(req.password_style)
    pass_id = str(uuid.uuid4())[:8].upper()
    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=req.duration_minutes)

    new_pass = {
        "id": pass_id,
        "wifi_name": req.wifi_name,
        "password": password,
        "guest_name": req.guest_name or "Guest",
        "style": req.password_style,
        "duration_minutes": req.duration_minutes,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "status": "active",
        "nato_hint": nato_hint(password),
        "qr_data": f"WIFI:T:WPA;S:{req.wifi_name};P:{password};;",
    }
    account["passes"].insert(0, new_pass)

    # Keep only last 50 passes
    account["passes"] = account["passes"][:50]
    return new_pass

# List passes
@app.get("/api/passes")
def list_passes(key: str = Depends(verify_key)):
    account = get_account(key)
    now = datetime.utcnow()
    passes = account["passes"]
    for p in passes:
        exp = datetime.fromisoformat(p["expires_at"])
        if p["status"] == "active" and exp < now:
            p["status"] = "expired"
    return {"passes": passes}

# Revoke a pass
@app.delete("/api/passes/{pass_id}")
def revoke_pass(pass_id: str, key: str = Depends(verify_key)):
    account = get_account(key)
    for p in account["passes"]:
        if p["id"] == pass_id:
            p["status"] = "revoked"
            return {"ok": True}
    raise HTTPException(status_code=404, detail="Pass not found")

# Stats
@app.get("/api/stats")
def get_stats(key: str = Depends(verify_key)):
    account = get_account(key)
    now = datetime.utcnow()
    passes = account["passes"]
    active = sum(1 for p in passes
                 if p["status"] == "active"
                 and datetime.fromisoformat(p["expires_at"]) > now)
    return {
        "total_passes": len(passes),
        "active_passes": active,
        "expired_passes": len(passes) - active,
        "owner": account["owner"],
        "plan": account["plan"],
    }

# Verify a pass (guest can check if their pass is still valid)
@app.get("/api/verify/{pass_id}")
def verify_pass(pass_id: str):
    for key, account in ACCOUNTS.items():
        for p in account["passes"]:
            if p["id"] == pass_id:
                now = datetime.utcnow()
                exp = datetime.fromisoformat(p["expires_at"])
                is_valid = p["status"] == "active" and exp > now
                remaining = max(0, int((exp - now).total_seconds()))
                return {
                    "valid": is_valid,
                    "pass_id": pass_id,
                    "wifi_name": p["wifi_name"],
                    "guest_name": p["guest_name"],
                    "expires_at": p["expires_at"],
                    "remaining_seconds": remaining,
                    "status": p["status"],
                }
    raise HTTPException(status_code=404, detail="Pass not found")

# Update wifi display name
@app.post("/api/settings/wifi-name")
def update_wifi_name(body: UpdateWifiName, key: str = Depends(verify_key)):
    account = get_account(key)
    account["wifi_name"] = body.wifi_name
    return {"ok": True}
