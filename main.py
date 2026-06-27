"""
MyPass Cloud API v3
- Generates time-limited passes
- Pushes commands to GL.iNet router via Node-RED webhook
- No home PC needed — router runs 24/7
"""

from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timedelta
import uuid, random, string, asyncio, httpx, os

app = FastAPI(title="MyPass Cloud API", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── ACCOUNTS ──────────────────────────────────────────────────────────────────
ACCOUNTS = {
    "MYPASS-HOME-001": {
        "owner": "JobZaak",
        "plan": "pro",
        "passes": [],
        # Node-RED webhook on the GL.iNet router
        # Set this after router setup: http://YOUR-ROUTER-IP:1880/mypass
        "router_webhook": os.environ.get("ROUTER_WEBHOOK", ""),
        "router_secret": os.environ.get("ROUTER_SECRET", "mypass-secret-2024"),
    }
}

# ── AUTH ──────────────────────────────────────────────────────────────────────
def verify_key(x_license_key: str = Header(...)):
    if x_license_key not in ACCOUNTS:
        raise HTTPException(status_code=401, detail="Invalid license key")
    return x_license_key

# ── PASSWORD GENERATORS ───────────────────────────────────────────────────────
WORD_LIST = [
    "apple","bravo","cloud","delta","eagle","flame","globe","hotel",
    "india","jazzy","kite","lemon","mango","noble","ocean","pearl",
    "queen","radar","solar","tiger","ultra","vivid","winds","xenon",
    "yacht","zebra","amber","brush","coral","drift"
]
NATO = {
    "A":"Alpha","B":"Bravo","C":"Charlie","D":"Delta","E":"Echo","F":"Foxtrot",
    "G":"Golf","H":"Hotel","I":"India","J":"Juliet","K":"Kilo","L":"Lima",
    "M":"Mike","N":"November","O":"Oscar","P":"Papa","Q":"Quebec","R":"Romeo",
    "S":"Sierra","T":"Tango","U":"Uniform","V":"Victor","W":"Whiskey",
    "X":"X-ray","Y":"Yankee","Z":"Zulu",
    "0":"Zero","1":"One","2":"Two","3":"Three","4":"Four",
    "5":"Five","6":"Six","7":"Seven","8":"Eight","9":"Nine",
    "-":"dash"
}

def gen_pronounceable():
    vowels, cons = "aeiou", "bcdfghjklmnprstvwz"
    pwd = ""
    for _ in range(4):
        pwd += random.choice(cons).upper() + random.choice(vowels)
    pwd += str(random.randint(10, 99))
    return pwd

def gen_words():
    return f"{random.choice(WORD_LIST)}-{random.choice(WORD_LIST)}-{random.randint(10,99)}"

def gen_random(length=12):
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))

def make_password(style):
    if style == "words":  return gen_words()
    if style == "random": return gen_random()
    return gen_pronounceable()

def nato_hint(pwd):
    return " · ".join(NATO.get(c.upper(), c) for c in pwd)

# ── ROUTER PUSH (async, non-blocking) ─────────────────────────────────────────
async def push_to_router(account: dict, action: str, payload: dict):
    """
    Sends a command to Node-RED running on the GL.iNet router.
    Node-RED then calls the OpenWrt UCI API to change WiFi password.
    """
    webhook = account.get("router_webhook", "")
    if not webhook:
        print("No router webhook configured — skipping push")
        return

    data = {
        "action": action,
        "secret": account["router_secret"],
        **payload
    }
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook, json=data)
            print(f"Router push: {action} → {r.status_code}")
    except Exception as e:
        print(f"Router push failed (router may be offline): {e}")

# ── MODELS ───────────────────────────────────────────────────────────────────
class CreatePassRequest(BaseModel):
    ssid: str = "MyPass-Guest"
    duration_minutes: int = 60
    password_style: str = "pronounceable"
    guest_name: str = ""

class RouterWebhookUpdate(BaseModel):
    webhook_url: str

# ── ROUTES ───────────────────────────────────────────────────────────────────
@app.get("/")
def root():
    return {"service": "MyPass Cloud API", "status": "online", "version": "3.0.0"}

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow().isoformat()}

# Create pass → auto-pushes to router
@app.post("/api/passes")
async def create_pass(
    req: CreatePassRequest,
    background_tasks: BackgroundTasks,
    key: str = Depends(verify_key)
):
    account = ACCOUNTS[key]
    password = make_password(req.password_style)
    pass_id  = str(uuid.uuid4())[:8].upper()
    now      = datetime.utcnow()
    expires  = now + timedelta(minutes=req.duration_minutes)

    new_pass = {
        "id":               pass_id,
        "ssid":             req.ssid,
        "password":         password,
        "guest_name":       req.guest_name or "Guest",
        "style":            req.password_style,
        "duration_minutes": req.duration_minutes,
        "created_at":       now.isoformat(),
        "expires_at":       expires.isoformat(),
        "status":           "active",
        "nato_hint":        nato_hint(password),
        "qr_data":          f"WIFI:T:WPA;S:{req.ssid};P:{password};;",
    }
    account["passes"].insert(0, new_pass)
    account["passes"] = account["passes"][:50]

    # Push to router in background (doesn't block the API response)
    background_tasks.add_task(push_to_router, account, "set_password", {
        "ssid":       req.ssid,
        "password":   password,
        "expires_at": expires.isoformat(),
        "pass_id":    pass_id,
        "duration_minutes": req.duration_minutes,
    })

    return new_pass

# List passes (auto-updates statuses)
@app.get("/api/passes")
def list_passes(key: str = Depends(verify_key)):
    account = ACCOUNTS[key]
    now = datetime.utcnow()
    for p in account["passes"]:
        if p["status"] == "active" and datetime.fromisoformat(p["expires_at"]) < now:
            p["status"] = "expired"
    return {"passes": account["passes"]}

# Revoke a pass → auto-pushes expire to router
@app.delete("/api/passes/{pass_id}")
async def revoke_pass(
    pass_id: str,
    background_tasks: BackgroundTasks,
    key: str = Depends(verify_key)
):
    account = ACCOUNTS[key]
    for p in account["passes"]:
        if p["id"] == pass_id:
            p["status"] = "revoked"
            background_tasks.add_task(push_to_router, account, "expire", {
                "ssid":    p["ssid"],
                "pass_id": pass_id,
            })
            return {"ok": True, "message": "Pass revoked — router will disable guest WiFi"}
    raise HTTPException(status_code=404, detail="Pass not found")

# Stats
@app.get("/api/stats")
def get_stats(key: str = Depends(verify_key)):
    account = ACCOUNTS[key]
    now     = datetime.utcnow()
    passes  = account["passes"]
    active  = sum(1 for p in passes
                  if p["status"] == "active"
                  and datetime.fromisoformat(p["expires_at"]) > now)
    webhook = account.get("router_webhook", "")
    return {
        "total_passes":    len(passes),
        "active_passes":   active,
        "expired_passes":  len(passes) - active,
        "owner":           account["owner"],
        "plan":            account["plan"],
        "router_linked":   bool(webhook),
        "router_webhook":  webhook[:30] + "…" if webhook else "Not set",
    }

# Update router webhook URL (called from web app after router setup)
@app.post("/api/settings/router-webhook")
def update_webhook(body: RouterWebhookUpdate, key: str = Depends(verify_key)):
    ACCOUNTS[key]["router_webhook"] = body.webhook_url.strip()
    return {"ok": True, "webhook": body.webhook_url}

# Verify a pass (public endpoint — guest can check)
@app.get("/api/verify/{pass_id}")
def verify_pass(pass_id: str):
    for account in ACCOUNTS.values():
        for p in account["passes"]:
            if p["id"] == pass_id:
                now   = datetime.utcnow()
                exp   = datetime.fromisoformat(p["expires_at"])
                valid = p["status"] == "active" and exp > now
                return {
                    "valid":             valid,
                    "pass_id":           pass_id,
                    "ssid":              p["ssid"],
                    "guest_name":        p["guest_name"],
                    "remaining_seconds": max(0, int((exp - now).total_seconds())),
                    "status":            p["status"],
                }
    raise HTTPException(status_code=404, detail="Pass not found")

# Node-RED polls this to check for pending expiry jobs
@app.get("/api/router/pending-expiry")
def pending_expiry(key: str = Depends(verify_key)):
    account = ACCOUNTS[key]
    now     = datetime.utcnow()
    expired = [
        p for p in account["passes"]
        if p["status"] == "active"
        and datetime.fromisoformat(p["expires_at"]) <= now
    ]
    for p in expired:
        p["status"] = "expired"
    return {"expired_passes": expired}
