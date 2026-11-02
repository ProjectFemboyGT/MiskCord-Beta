import hashlib, hmac, json, logging, os, re, secrets, sqlite3, string, threading, time
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel

ROOT = Path(__file__).parent
DB_PATH = os.environ.get("MISKCORD_DB", str(ROOT / "miskcord.db"))
OWNER = os.environ.get("MISKCORD_OWNER", "bruter").lower()
NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-]{2,32}$")
INVITE_RE = re.compile(r"^[A-Za-z0-9]{6,12}$")
log = logging.getLogger("uvicorn.error")

DATABASE_URL = os.environ.get("DATABASE_URL")

class DB:
    """Tiny wrapper so the same queries run on SQLite (local) or Postgres (DATABASE_URL)."""
    def __init__(self):
        self.lock = threading.Lock()
        self.pg = bool(DATABASE_URL)
        self.connect()
        ident = "SERIAL PRIMARY KEY" if self.pg else "INTEGER PRIMARY KEY"
        num = "DOUBLE PRECISION" if self.pg else "REAL"
        for stmt in [
            f"CREATE TABLE IF NOT EXISTS users(id {ident}, username TEXT UNIQUE, pw TEXT, created {num})",
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_lower ON users(LOWER(username))",
            f"CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER, created {num})",
            "CREATE TABLE IF NOT EXISTS friends(a INTEGER, b INTEGER, status TEXT, PRIMARY KEY(a,b))",
            f"CREATE TABLE IF NOT EXISTS messages(id {ident}, room TEXT, user_id INTEGER, text TEXT, t {num})",
            "CREATE INDEX IF NOT EXISTS idx_room ON messages(room, id)",
            f"CREATE TABLE IF NOT EXISTS servers(id {ident}, name TEXT, owner_id INTEGER, created {num})",
            f"CREATE TABLE IF NOT EXISTS server_members(server_id INTEGER, user_id INTEGER, joined {num}, PRIMARY KEY(server_id, user_id))",
            f"CREATE TABLE IF NOT EXISTS channels(id {ident}, server_id INTEGER, name TEXT, kind TEXT, pos INTEGER)",
            f"CREATE TABLE IF NOT EXISTS invites(code TEXT PRIMARY KEY, server_id INTEGER, creator_id INTEGER, created {num}, uses INTEGER)",
            f"CREATE TABLE IF NOT EXISTS gchats(id {ident}, name TEXT, owner_id INTEGER, created {num})",
            "CREATE TABLE IF NOT EXISTS gchat_members(gchat_id INTEGER, user_id INTEGER, PRIMARY KEY(gchat_id, user_id))",
        ]:
            self.run(stmt)

    def connect(self):
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row
            self.conn = psycopg.connect(DATABASE_URL, autocommit=True, row_factory=dict_row)
        else:
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False, isolation_level=None)
            self.conn.row_factory = sqlite3.Row

    def _exec(self, sql, params):
        if self.pg: sql = sql.replace("?", "%s")
        with self.lock:
            try:
                return self.conn.execute(sql, params)
            except Exception:
                if not self.pg or not self.conn.closed: raise
                self.connect()
                return self.conn.execute(sql, params)

    def run(self, sql, params=()):
        self._exec(sql, params)

    def all(self, sql, params=()):
        return self._exec(sql, params).fetchall()

    def one(self, sql, params=()):
        return self._exec(sql, params).fetchone()

    def insert(self, sql, params=()):
        if self.pg: return self._exec(sql + " RETURNING id", params).fetchone()["id"]
        return self._exec(sql, params).lastrowid

    def count(self, table):
        return self.one(f"SELECT COUNT(*) AS n FROM {table}")["n"]

db = DB()

def hash_pw(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.scrypt(pw.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
    return f"{salt}${h}"

def check_pw(pw, stored):
    salt, _ = stored.split("$", 1)
    return hmac.compare_digest(hash_pw(pw, salt), stored)

def user_json(row):
    return {"id": row["id"], "username": row["username"], "owner": row["username"].lower() == OWNER,
            "online": row["id"] in sockets}

def get_user(token):
    if not token: return None
    return db.one("SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=?", (token,))

def require(request: Request):
    u = get_user(request.cookies.get("misk_token"))
    if not u: raise HTTPException(401, "Not logged in")
    return u

def relation(a, b):
    r = db.one("SELECT status FROM friends WHERE a=? AND b=?", (a, b))
    return r["status"] if r else None

def dm_room(a, b):
    x, y = sorted((a, b))
    return f"dm:{x}:{y}"

def msg_json(row):
    return {"id": row["id"], "room": row["room"], "text": row["text"], "t": row["t"],
            "user": user_json(db.one("SELECT * FROM users WHERE id=?", (row["user_id"],)))}

sockets: dict[int, set] = {}

async def push(user_id, event):
    for ws in list(sockets.get(user_id, ())):
        try: await ws.send_text(json.dumps(event))
        except Exception: pass

async def push_all(event):
    for uid in list(sockets): await push(uid, event)

def server_row(sid):
    s = db.one("SELECT * FROM servers WHERE id=?", (sid,))
    if not s: raise HTTPException(404, "Server not found")
    return s

def is_member(sid, uid):
    return bool(db.one("SELECT 1 FROM server_members WHERE server_id=? AND user_id=?", (sid, uid)))

def require_member(u, sid):
    s = server_row(sid)
    if not is_member(sid, u["id"]): raise HTTPException(403, "You're not in this server")
    return s

def require_server_owner(u, sid):
    s = require_member(u, sid)
    if s["owner_id"] != u["id"]: raise HTTPException(403, "Only the server owner can do that")
    return s

def member_ids(sid):
    return [r["user_id"] for r in db.all("SELECT user_id FROM server_members WHERE server_id=?", (sid,))]

async def push_server(sid, event):
    for uid in member_ids(sid): await push(uid, event)

def server_json(s):
    return {"id": s["id"], "name": s["name"], "owner_id": s["owner_id"]}

voice: dict[int, dict[int, bool]] = {}  # voice channel id -> {user id: muted}
voice_ws: dict[int, tuple] = {}        # user id -> (websocket, channel id, server id)

def voice_state(sid):
    cids = [r["id"] for r in db.all("SELECT id FROM channels WHERE server_id=? AND kind='voice'", (sid,))]
    return {str(c): [{"id": uid, "muted": m} for uid, m in voice[c].items()] for c in cids if voice.get(c)}

async def push_voice(sid):
    await push_server(sid, {"type": "voice", "server": sid, "voice": voice_state(sid)})

async def voice_leave(uid):
    cur = voice_ws.pop(uid, None)
    if not cur: return
    _, cid, sid = cur
    voice.get(cid, {}).pop(uid, None)
    if not voice.get(cid): voice.pop(cid, None)
    await push_voice(sid)

def to_int(v):
    try: return int(v)
    except (TypeError, ValueError): raise HTTPException(404, "Not found")

app = FastAPI()

class Creds(BaseModel):
    username: str
    password: str

class Text(BaseModel):
    text: str

class Name(BaseModel):
    username: str

class ServerIn(BaseModel):
    name: str

class ChannelIn(BaseModel):
    name: str
    kind: str = "text"

class GroupIn(BaseModel):
    usernames: list[str]
    name: str = ""

class GroupAdd(BaseModel):
    usernames: list[str]

class GroupName(BaseModel):
    name: str

GROUP_MAX = 10

def login_response(resp: Response, user_id):
    token = secrets.token_urlsafe(32)
    db.run("INSERT INTO sessions VALUES(?,?,?)", (token, user_id, time.time()))
    resp.set_cookie("misk_token", token, httponly=True, samesite="lax", max_age=60*60*24*90)

@app.post("/api/register")
def register(c: Creds, resp: Response):
    c.username = c.username.strip()
    def fail(msg):
        log.info("register rejected (%r): %s", c.username, msg)
        raise HTTPException(400, msg)
    if not NAME_RE.match(c.username): fail("Usernames can only use letters, numbers, _ . or - (no spaces), 2-32 characters")
    if len(c.password) < 4: fail("Password must be at least 4 characters")
    if len(c.password) > 128: fail("Password is too long (max 128 characters)")
    if db.one("SELECT 1 FROM users WHERE LOWER(username)=LOWER(?)", (c.username,)):
        fail("That username is taken. Try logging in instead")
    uid = db.insert("INSERT INTO users(username,pw,created) VALUES(?,?,?)", (c.username, hash_pw(c.password), time.time()))
    login_response(resp, uid)
    return {"ok": True}

@app.post("/api/login")
def login(c: Creds, resp: Response):
    u = db.one("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (c.username.strip(),))
    if not u or not check_pw(c.password, u["pw"]): raise HTTPException(400, "Wrong username or password")
    login_response(resp, u["id"])
    return {"ok": True}

@app.post("/api/logout")
def logout(request: Request, resp: Response):
    db.run("DELETE FROM sessions WHERE token=?", (request.cookies.get("misk_token"),))
    resp.delete_cookie("misk_token")
    return {"ok": True}

@app.get("/api/me")
def me(request: Request):
    u = require(request)
    out = user_json(u)
    if out["owner"]:
        out["stats"] = {"users": db.count("users"), "messages": db.count("messages"), "servers": db.count("servers")}
    return out

@app.get("/api/friends")
def friends(request: Request):
    u = require(request)
    rows = db.all("SELECT f.status, x.* FROM friends f JOIN users x ON x.id=f.b WHERE f.a=? ORDER BY LOWER(x.username)", (u["id"],))
    out = {"friends": [], "incoming": [], "outgoing": []}
    for r in rows: out[{"accepted": "friends", "incoming": "incoming", "outgoing": "outgoing"}[r["status"]]].append(user_json(r))
    return out

async def notify_friends_changed(*ids):
    for i in ids: await push(i, {"type": "friends"})

@app.post("/api/friends/request")
async def friend_request(n: Name, request: Request):
    u = require(request)
    t = db.one("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (n.username.strip(),))
    if not t: raise HTTPException(404, "No user with that username")
    if t["id"] == u["id"]: raise HTTPException(400, "You can't add yourself")
    rel = relation(u["id"], t["id"])
    if rel == "accepted": raise HTTPException(400, "You're already friends")
    if rel == "outgoing": raise HTTPException(400, "Request already sent")
    if rel == "incoming":
        return await friend_accept(Name(username=t["username"]), request)
    db.run("INSERT INTO friends VALUES(?,?,'outgoing')", (u["id"], t["id"]))
    db.run("INSERT INTO friends VALUES(?,?,'incoming')", (t["id"], u["id"]))
    await notify_friends_changed(u["id"], t["id"])
    return {"ok": True, "message": f"Friend request sent to {t['username']}"}

@app.post("/api/friends/accept")
async def friend_accept(n: Name, request: Request):
    u = require(request)
    t = db.one("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (n.username,))
    if not t or relation(u["id"], t["id"]) != "incoming": raise HTTPException(400, "No request from that user")
    db.run("UPDATE friends SET status='accepted' WHERE (a=? AND b=?) OR (a=? AND b=?)", (u["id"], t["id"], t["id"], u["id"]))
    await notify_friends_changed(u["id"], t["id"])
    return {"ok": True, "message": f"You and {t['username']} are now friends"}

@app.post("/api/friends/remove")
async def friend_remove(n: Name, request: Request):
    u = require(request)
    t = db.one("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (n.username,))
    if not t: raise HTTPException(404, "No such user")
    db.run("DELETE FROM friends WHERE (a=? AND b=?) OR (a=? AND b=?)", (u["id"], t["id"], t["id"], u["id"]))
    await notify_friends_changed(u["id"], t["id"])
    return {"ok": True}

def room_for(u, room):
    if room == "hq": return "hq", None
    if room.startswith("dm:"):
        other = db.one("SELECT * FROM users WHERE id=?", (to_int(room[3:]),))
        if not other or relation(u["id"], other["id"]) != "accepted": raise HTTPException(403, "You can only DM friends")
        return dm_room(u["id"], other["id"]), other
    if room.startswith("ch:"):
        c = db.one("SELECT * FROM channels WHERE id=?", (to_int(room[3:]),))
        if not c or c["kind"] != "text": raise HTTPException(404, "Channel not found")
        require_member(u, c["server_id"])
        return room, c
    if room.startswith("gc:"):
        g = require_group(u, to_int(room[3:]))
        return room, g
    raise HTTPException(404, "Unknown room")

@app.get("/api/rooms/{room}")
def history(room: str, request: Request):
    u = require(request)
    key, _ = room_for(u, room)
    rows = db.all("SELECT * FROM (SELECT * FROM messages WHERE room=? ORDER BY id DESC LIMIT 200) AS recent ORDER BY id", (key,))
    return [msg_json(r) for r in rows]

@app.post("/api/rooms/{room}")
async def send(room: str, body: Text, request: Request):
    u = require(request)
    text = body.text.strip()[:2000]
    if not text: raise HTTPException(400, "Empty message")
    key, other = room_for(u, room)
    mid = db.insert("INSERT INTO messages(room,user_id,text,t) VALUES(?,?,?,?)", (key, u["id"], text, time.time()))
    msg = msg_json(db.one("SELECT * FROM messages WHERE id=?", (mid,)))
    if key.startswith("ch:"):
        await push_server(other["server_id"], {"type": "message", "room": key, "server": other["server_id"], "chan": other["name"], "msg": msg})
    elif key.startswith("gc:"):
        for uid in group_member_ids(other["id"]): await push(uid, {"type": "message", "room": key, "msg": msg})
    elif other:
        await push(u["id"], {"type": "message", "room": f"dm:{other['id']}", "msg": msg})
        await push(other["id"], {"type": "message", "room": f"dm:{u['id']}", "msg": msg})
    else:
        await push_all({"type": "message", "room": "hq", "msg": msg})
    return msg

@app.delete("/api/messages/{mid}")
async def delete_msg(mid: int, request: Request):
    u = require(request)
    m = db.one("SELECT * FROM messages WHERE id=?", (mid,))
    if not m: raise HTTPException(404, "Not found")
    allowed = m["user_id"] == u["id"] or (u["username"].lower() == OWNER and m["room"] == "hq")
    chan = db.one("SELECT * FROM channels WHERE id=?", (to_int(m["room"][3:]),)) if m["room"].startswith("ch:") else None
    if chan and server_row(chan["server_id"])["owner_id"] == u["id"]: allowed = True
    if not allowed: raise HTTPException(403, "Not allowed")
    db.run("DELETE FROM messages WHERE id=?", (mid,))
    if m["room"] == "hq": await push_all({"type": "deleted", "id": mid})
    elif chan: await push_server(chan["server_id"], {"type": "deleted", "id": mid})
    elif m["room"].startswith("gc:"):
        for uid in group_member_ids(to_int(m["room"][3:])): await push(uid, {"type": "deleted", "id": mid})
    else:
        for uid in map(int, m["room"].split(":")[1:]): await push(uid, {"type": "deleted", "id": mid})
    return {"ok": True}

def clean_name(n, maxlen):
    n = " ".join(n.split())[:maxlen]
    if not n: raise HTTPException(400, "Name can't be empty")
    return n

@app.get("/api/servers")
def list_servers(request: Request):
    u = require(request)
    rows = db.all("SELECT s.* FROM servers s JOIN server_members m ON m.server_id=s.id WHERE m.user_id=? ORDER BY m.joined", (u["id"],))
    return [server_json(r) for r in rows]

@app.post("/api/servers")
def create_server(body: ServerIn, request: Request):
    u = require(request)
    name = clean_name(body.name, 50)
    sid = db.insert("INSERT INTO servers(name,owner_id,created) VALUES(?,?,?)", (name, u["id"], time.time()))
    db.run("INSERT INTO server_members VALUES(?,?,?)", (sid, u["id"], time.time()))
    db.insert("INSERT INTO channels(server_id,name,kind,pos) VALUES(?,?,?,?)", (sid, "general", "text", 0))
    db.insert("INSERT INTO channels(server_id,name,kind,pos) VALUES(?,?,?,?)", (sid, "Lounge", "voice", 1))
    return server_json(server_row(sid))

@app.get("/api/servers/{sid}")
def server_detail(sid: int, request: Request):
    u = require(request)
    s = require_member(u, sid)
    chans = db.all("SELECT * FROM channels WHERE server_id=? ORDER BY pos, id", (sid,))
    mems = db.all("SELECT u.* FROM server_members m JOIN users u ON u.id=m.user_id WHERE m.server_id=? ORDER BY LOWER(u.username)", (sid,))
    return {**server_json(s), "is_owner": s["owner_id"] == u["id"],
            "channels": [{"id": c["id"], "name": c["name"], "kind": c["kind"]} for c in chans],
            "members": [user_json(m) for m in mems], "voice": voice_state(sid)}

@app.delete("/api/servers/{sid}")
async def delete_server(sid: int, request: Request):
    u = require(request)
    require_server_owner(u, sid)
    ids = member_ids(sid)
    for c in db.all("SELECT id FROM channels WHERE server_id=?", (sid,)):
        for uid in list(voice.get(c["id"], {})): await voice_leave(uid)
        db.run("DELETE FROM messages WHERE room=?", (f"ch:{c['id']}",))
    for table, col in (("channels", "server_id"), ("server_members", "server_id"), ("invites", "server_id"), ("servers", "id")):
        db.run(f"DELETE FROM {table} WHERE {col}=?", (sid,))
    for uid in ids: await push(uid, {"type": "servers"})
    return {"ok": True}

@app.post("/api/servers/{sid}/leave")
async def leave_server(sid: int, request: Request):
    u = require(request)
    s = require_member(u, sid)
    if s["owner_id"] == u["id"]: raise HTTPException(400, "You own this server. Delete it instead")
    if voice_ws.get(u["id"]) and voice_ws[u["id"]][2] == sid: await voice_leave(u["id"])
    db.run("DELETE FROM server_members WHERE server_id=? AND user_id=?", (sid, u["id"]))
    await push(u["id"], {"type": "servers"})
    await push_server(sid, {"type": "server", "id": sid})
    return {"ok": True}

@app.post("/api/servers/{sid}/channels")
async def create_channel(sid: int, body: ChannelIn, request: Request):
    u = require(request)
    require_server_owner(u, sid)
    if body.kind not in ("text", "voice"): raise HTTPException(400, "Channel type must be text or voice")
    name = clean_name(body.name, 32)
    if body.kind == "text":
        name = re.sub(r"[^a-z0-9_\-]", "", name.lower().replace(" ", "-"))
        if not name: raise HTTPException(400, "Text channel names can use letters, numbers, - and _")
    pos = (db.one("SELECT MAX(pos) AS p FROM channels WHERE server_id=?", (sid,))["p"] or 0) + 1
    cid = db.insert("INSERT INTO channels(server_id,name,kind,pos) VALUES(?,?,?,?)", (sid, name, body.kind, pos))
    await push_server(sid, {"type": "server", "id": sid})
    return {"id": cid, "name": name, "kind": body.kind}

@app.delete("/api/channels/{cid}")
async def delete_channel(cid: int, request: Request):
    u = require(request)
    c = db.one("SELECT * FROM channels WHERE id=?", (cid,))
    if not c: raise HTTPException(404, "Channel not found")
    require_server_owner(u, c["server_id"])
    for uid in list(voice.get(cid, {})): await voice_leave(uid)
    db.run("DELETE FROM messages WHERE room=?", (f"ch:{cid}",))
    db.run("DELETE FROM channels WHERE id=?", (cid,))
    await push_server(c["server_id"], {"type": "server", "id": c["server_id"]})
    return {"ok": True}

@app.post("/api/servers/{sid}/invites")
def create_invite(sid: int, request: Request):
    u = require(request)
    require_member(u, sid)
    existing = db.one("SELECT code FROM invites WHERE server_id=? AND creator_id=?", (sid, u["id"]))
    if existing: return {"code": existing["code"]}
    code = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(8))
    db.run("INSERT INTO invites VALUES(?,?,?,?,0)", (code, sid, u["id"], time.time()))
    return {"code": code}

def invite_row(code):
    inv = db.one("SELECT * FROM invites WHERE code=?", (code,))
    if not inv: raise HTTPException(404, "This invite is invalid or has expired")
    return inv

@app.get("/api/invites/{code}")
def invite_info(code: str, request: Request):
    inv = invite_row(code)
    s = server_row(inv["server_id"])
    u = get_user(request.cookies.get("misk_token"))
    inviter = db.one("SELECT username FROM users WHERE id=?", (inv["creator_id"],))
    n = db.one("SELECT COUNT(*) AS n FROM server_members WHERE server_id=?", (s["id"],))["n"]
    return {"code": code, "server": server_json(s), "members": n,
            "inviter": inviter["username"] if inviter else None, "joined": bool(u and is_member(s["id"], u["id"]))}

@app.post("/api/invites/{code}/join")
async def join_invite(code: str, request: Request):
    u = require(request)
    inv = invite_row(code)
    sid = server_row(inv["server_id"])["id"]
    if not is_member(sid, u["id"]):
        db.run("INSERT INTO server_members VALUES(?,?,?)", (sid, u["id"], time.time()))
        db.run("UPDATE invites SET uses=uses+1 WHERE code=?", (code,))
        await push(u["id"], {"type": "servers"})
        await push_server(sid, {"type": "server", "id": sid})
    return {"server_id": sid}

def group_member_ids(gid):
    return [r["user_id"] for r in db.all("SELECT user_id FROM gchat_members WHERE gchat_id=?", (gid,))]

def require_group(u, gid):
    g = db.one("SELECT * FROM gchats WHERE id=?", (gid,))
    if not g or u["id"] not in group_member_ids(gid): raise HTTPException(404, "Group chat not found")
    return g

def friends_by_name(u, names):
    out = []
    for n in names:
        t = db.one("SELECT * FROM users WHERE LOWER(username)=LOWER(?)", (n.strip(),))
        if not t: raise HTTPException(404, f"No user named {n}")
        if t["id"] == u["id"]: continue
        if relation(u["id"], t["id"]) != "accepted": raise HTTPException(403, f"You can only add friends ({t['username']} isn't your friend)")
        if t["id"] not in [x["id"] for x in out]: out.append(t)
    return out

def group_json(g):
    mems = db.all("SELECT u.* FROM gchat_members m JOIN users u ON u.id=m.user_id WHERE m.gchat_id=? ORDER BY LOWER(u.username)", (g["id"],))
    return {"id": g["id"], "name": g["name"] or "", "owner_id": g["owner_id"], "members": [user_json(m) for m in mems]}

async def push_groups(ids):
    for uid in ids: await push(uid, {"type": "groups"})

@app.get("/api/groups")
def list_groups(request: Request):
    u = require(request)
    rows = db.all("SELECT g.* FROM gchats g JOIN gchat_members m ON m.gchat_id=g.id WHERE m.user_id=? ORDER BY g.id DESC", (u["id"],))
    return [group_json(g) for g in rows]

@app.post("/api/groups")
async def create_group(body: GroupIn, request: Request):
    u = require(request)
    people = friends_by_name(u, body.usernames)
    if not people: raise HTTPException(400, "Pick at least one friend")
    if len(people) + 1 > GROUP_MAX: raise HTTPException(400, f"Group chats can have up to {GROUP_MAX} people")
    name = " ".join(body.name.split())[:50]
    gid = db.insert("INSERT INTO gchats(name,owner_id,created) VALUES(?,?,?)", (name, u["id"], time.time()))
    for t in [u, *people]: db.run("INSERT INTO gchat_members VALUES(?,?)", (gid, t["id"]))
    await push_groups(group_member_ids(gid))
    return group_json(db.one("SELECT * FROM gchats WHERE id=?", (gid,)))

@app.post("/api/groups/{gid}/members")
async def group_add(gid: int, body: GroupAdd, request: Request):
    u = require(request)
    g = require_group(u, gid)
    cur = group_member_ids(gid)
    people = [t for t in friends_by_name(u, body.usernames) if t["id"] not in cur]
    if len(cur) + len(people) > GROUP_MAX: raise HTTPException(400, f"Group chats can have up to {GROUP_MAX} people")
    for t in people: db.run("INSERT INTO gchat_members VALUES(?,?)", (gid, t["id"]))
    await push_groups(group_member_ids(gid))
    return group_json(g)

@app.post("/api/groups/{gid}/name")
async def group_rename(gid: int, body: GroupName, request: Request):
    u = require(request)
    require_group(u, gid)
    db.run("UPDATE gchats SET name=? WHERE id=?", (" ".join(body.name.split())[:50], gid))
    await push_groups(group_member_ids(gid))
    return group_json(db.one("SELECT * FROM gchats WHERE id=?", (gid,)))

@app.post("/api/groups/{gid}/leave")
async def group_leave(gid: int, request: Request):
    u = require(request)
    g = require_group(u, gid)
    db.run("DELETE FROM gchat_members WHERE gchat_id=? AND user_id=?", (gid, u["id"]))
    left = group_member_ids(gid)
    if not left:
        db.run("DELETE FROM messages WHERE room=?", (f"gc:{gid}",))
        db.run("DELETE FROM gchats WHERE id=?", (gid,))
    elif g["owner_id"] == u["id"]:
        db.run("UPDATE gchats SET owner_id=? WHERE id=?", (left[0], gid))
    await push_groups([u["id"], *left])
    return {"ok": True}

@app.get("/api/members")
def members(request: Request):
    require(request)
    return [user_json(r) for r in db.all("SELECT * FROM users ORDER BY LOWER(username)")]

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    u = get_user(ws.cookies.get("misk_token"))
    if not u: return await ws.close(code=4401)
    await ws.accept()
    first = u["id"] not in sockets
    sockets.setdefault(u["id"], set()).add(ws)
    if first: await push_all({"type": "presence"})
    try:
        while True:
            data = json.loads(await ws.receive_text())
            if data.get("type") == "typing" and str(data.get("room", "")).startswith("dm:"):
                other = int(data["room"][3:])
                if relation(u["id"], other) == "accepted":
                    await push(other, {"type": "typing", "room": f"dm:{u['id']}", "user": u["username"]})
            elif data.get("type") == "typing" and str(data.get("room", "")).startswith("ch:"):
                c = db.one("SELECT * FROM channels WHERE id=?", (to_int(data["room"][3:]),))
                if c and is_member(c["server_id"], u["id"]):
                    for uid in member_ids(c["server_id"]):
                        if uid != u["id"]: await push(uid, {"type": "typing", "room": data["room"], "user": u["username"]})
            elif data.get("type") == "typing" and str(data.get("room", "")).startswith("gc:"):
                gid = to_int(data["room"][3:])
                ids = group_member_ids(gid)
                if u["id"] in ids:
                    for uid in ids:
                        if uid != u["id"]: await push(uid, {"type": "typing", "room": data["room"], "user": u["username"]})
            elif data.get("type") == "voice_join":
                c = db.one("SELECT * FROM channels WHERE id=?", (to_int(data.get("channel")),))
                if c and c["kind"] == "voice" and is_member(c["server_id"], u["id"]):
                    await voice_leave(u["id"])
                    peers = list(voice.get(c["id"], {}))
                    voice.setdefault(c["id"], {})[u["id"]] = False
                    voice_ws[u["id"]] = (ws, c["id"], c["server_id"])
                    await ws.send_text(json.dumps({"type": "voice_joined", "channel": c["id"], "peers": peers}))
                    await push_voice(c["server_id"])
            elif data.get("type") == "voice_leave":
                if voice_ws.get(u["id"], (None,))[0] is ws: await voice_leave(u["id"])
            elif data.get("type") == "voice_mute":
                cur = voice_ws.get(u["id"])
                if cur and cur[0] is ws:
                    voice[cur[1]][u["id"]] = bool(data.get("muted"))
                    await push_voice(cur[2])
            elif data.get("type") == "rtc":
                mine, theirs = voice_ws.get(u["id"]), voice_ws.get(to_int(data.get("to")))
                if mine and theirs and mine[0] is ws and mine[1] == theirs[1]:
                    try: await theirs[0].send_text(json.dumps({"type": "rtc", "from": u["id"], "data": data.get("data")}))
                    except Exception: pass
            elif data.get("type") == "typing" and data.get("room") == "hq":
                for uid in list(sockets):
                    if uid != u["id"]: await push(uid, {"type": "typing", "room": "hq", "user": u["username"]})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        if voice_ws.get(u["id"], (None,))[0] is ws: await voice_leave(u["id"])
        sockets.get(u["id"], set()).discard(ws)
        if not sockets.get(u["id"]):
            sockets.pop(u["id"], None); await push_all({"type": "presence"})

for name in ("index.html", "app.html", "logo.svg"):
    app.add_api_route(f"/{name}", (lambda n: lambda: FileResponse(ROOT / n))(name), methods=["GET"])
app.add_api_route("/", lambda: FileResponse(ROOT / "index.html"), methods=["GET"])

@app.get("/invite/{code}")
def invite_page(code: str):
    return FileResponse(ROOT / "app.html")

@app.get("/{code}")
def short_invite(code: str):
    if INVITE_RE.match(code) and db.one("SELECT 1 FROM invites WHERE code=?", (code,)):
        return FileResponse(ROOT / "app.html")
    raise HTTPException(404, "Not found")
