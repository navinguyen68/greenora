#!/usr/bin/env python3
"""GREENORA prototype server: Python stdlib, SQLite, cookie sessions, role checks."""
import os, json, time, sqlite3, secrets, hashlib, hmac, mimetypes, re, urllib.request, base64, binascii
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

ROOT=Path(__file__).resolve().parent
DB=Path(os.environ.get("GREENORA_DB",str(ROOT/"data"/"greenora.sqlite")))
DB.parent.mkdir(parents=True,exist_ok=True)
HOST=os.environ.get("GREENORA_HOST","0.0.0.0")
PORT=int(os.environ.get("PORT",os.environ.get("GREENORA_PORT","8765")))
SECURE=os.environ.get("GREENORA_SECURE_COOKIE","0")=="1"
MAX=9_000_000
def connect():
 c=sqlite3.connect(DB,timeout=15);c.row_factory=sqlite3.Row
 c.execute("PRAGMA journal_mode=WAL")
 c.execute("PRAGMA foreign_keys=ON")
 return c
def init():
 with connect() as c:
  c.executescript("""
  CREATE TABLE IF NOT EXISTS site_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL,updated_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,passhash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('admin','reception','viewer')),active INTEGER NOT NULL DEFAULT 1);
  CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id),expires INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY,client_ref TEXT UNIQUE,source TEXT,service TEXT NOT NULL,name TEXT NOT NULL,contact TEXT NOT NULL,building TEXT,room TEXT,requested_date TEXT,requested_time TEXT,notes TEXT,details_json TEXT,estimated_total INTEGER,quoted_total INTEGER,status TEXT NOT NULL DEFAULT 'pending',payment_status TEXT NOT NULL DEFAULT 'unpaid',admin_note TEXT DEFAULT '',created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY,request_id INTEGER REFERENCES requests(id),event TEXT NOT NULL,created_at INTEGER NOT NULL,read_at INTEGER);
  CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,user_id INTEGER,action TEXT NOT NULL,object_id INTEGER,created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS partners(id INTEGER PRIMARY KEY,name TEXT NOT NULL,contact TEXT,kind TEXT NOT NULL DEFAULT 'owner',status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS contracts(id INTEGER PRIMARY KEY,partner_id INTEGER NOT NULL REFERENCES partners(id),reference TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'draft',signed_at TEXT,expires_at TEXT,notes TEXT,created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS apartments(id INTEGER PRIMARY KEY,partner_id INTEGER NOT NULL REFERENCES partners(id),contract_id INTEGER REFERENCES contracts(id),title TEXT NOT NULL,place TEXT NOT NULL,building TEXT,area REAL NOT NULL DEFAULT 0,bed_type TEXT,bedrooms INTEGER NOT NULL DEFAULT 1,capacity INTEGER NOT NULL DEFAULT 2,night_price INTEGER NOT NULL DEFAULT 0,amenities_json TEXT NOT NULL DEFAULT '[]',photos_json TEXT NOT NULL DEFAULT '[]',quality_approved INTEGER NOT NULL DEFAULT 0,status TEXT NOT NULL DEFAULT 'draft',created_at INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS reservations(id INTEGER PRIMARY KEY,apartment_id INTEGER NOT NULL REFERENCES apartments(id),guest_name TEXT NOT NULL,guest_phone TEXT NOT NULL,check_in TEXT NOT NULL,check_out TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'hold',amount INTEGER NOT NULL DEFAULT 0,created_at INTEGER NOT NULL, CHECK(check_out>check_in));
  CREATE INDEX IF NOT EXISTS ix_reservations_dates ON reservations(apartment_id,check_in,check_out,status);
  CREATE TABLE IF NOT EXISTS payments(id INTEGER PRIMARY KEY,request_id INTEGER REFERENCES requests(id),reservation_id INTEGER REFERENCES reservations(id),amount INTEGER NOT NULL,currency TEXT NOT NULL DEFAULT 'VND',method TEXT NOT NULL DEFAULT 'manual',status TEXT NOT NULL DEFAULT 'pending',reference TEXT,created_at INTEGER NOT NULL, CHECK ((request_id IS NOT NULL AND reservation_id IS NULL) OR (request_id IS NULL AND reservation_id IS NOT NULL)));
  CREATE INDEX IF NOT EXISTS ix_requests_status ON requests(status,created_at);
  """)
def password_hash(p):
 salt=secrets.token_bytes(16)
 return salt.hex()+":"+hashlib.scrypt(p.encode(),salt=salt,n=2**14,r=8,p=1).hex()
def password_ok(p,s):
 try:
  salt,digest=s.split(":")
  return hmac.compare_digest(hashlib.scrypt(p.encode(),salt=bytes.fromhex(salt),n=2**14,r=8,p=1),bytes.fromhex(digest))
 except Exception:return False
def bootstrap():
 user=os.environ.get("GREENORA_ADMIN_USER")
 password=os.environ.get("GREENORA_ADMIN_PASSWORD")
 if not user or not password or len(password)<12:
  print("ADMIN SETUP: set GREENORA_ADMIN_USER and GREENORA_ADMIN_PASSWORD (>=12 chars) before first start.")
  return
 with connect() as c:
  if c.execute("SELECT count(*) FROM users").fetchone()[0]==0:
   c.execute("INSERT INTO users(username,passhash,role) VALUES(?,?,'admin')",(user,password_hash(password)))
   print("Admin account created.")
def now():return int(time.time())
def clean(s,n=500):return str(s or "").strip()[:n]
def record(r):return dict(r)
class Handler(BaseHTTPRequestHandler):
 def log_message(self,fmt,*args):print("%s %s"%(self.address_string(),fmt%args))
 def json(self,code,data,extra=None):
  body=json.dumps(data,ensure_ascii=False).encode()
  self.send_response(code);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Cache-Control","no-store");self.send_header("X-Content-Type-Options","nosniff")
  for k,v in (extra or {}).items():self.send_header(k,v)
  self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
 def payload(self):
  n=int(self.headers.get("Content-Length","0"))
  if n>MAX:raise ValueError("Payload too large")
  data=json.loads(self.rfile.read(n))
  if not isinstance(data,dict):raise ValueError("JSON object required")
  return data
 def session(self):
  cookie=SimpleCookie()
  try:cookie.load(self.headers.get("Cookie",""))
  except Exception:return None
  token=cookie.get("greenora_sid")
  if not token:return None
  hashed=hashlib.sha256(token.value.encode()).hexdigest()
  with connect() as c:
   r=c.execute("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>? AND u.active=1",(hashed,now())).fetchone()
   return record(r) if r else None
 def allowed(self,roles=None):
  u=self.session()
  if not u:self.json(401,{"error":"Authentication required"});return None
  if roles and u["role"] not in roles:self.json(403,{"error":"Insufficient role"});return None
  return u
 def cookie_header(self,value,age):
  return "greenora_sid="+value+"; Path=/; HttpOnly; SameSite=Lax; Max-Age="+str(age)+("; Secure" if SECURE else "")
 def origin_ok(self):
  origin=self.headers.get("Origin")
  if not origin:return True
  expected=self.headers.get("Host","")
  return urlsplit(origin).netloc==expected
 def audit(self,u,action,obj):
  with connect() as c:c.execute("INSERT INTO audit(user_id,action,object_id,created_at) VALUES(?,?,?,?)",(u["id"],action,obj,now()))
 def do_GET(self):
  path=urlsplit(self.path).path
  if path=="/api/public/hero":
   with connect() as c:r=c.execute("SELECT value,updated_at FROM site_settings WHERE key='hero_image'").fetchone()
   return self.json(200,{"url":r["value"] if r else None,"updated_at":r["updated_at"] if r else None})
  if path=="/api/public/apartments":
   with connect() as c:
    rows=c.execute("SELECT a.id,a.title,a.place,a.building,a.area,a.bed_type,a.bedrooms,a.capacity,a.night_price,a.amenities_json,a.photos_json FROM apartments a JOIN contracts co ON co.id=a.contract_id WHERE a.status='published' AND a.quality_approved=1 AND co.status='signed'").fetchall()
   return self.json(200,{"items":[record(r) for r in rows]})
  if path in ("/api/partners","/api/contracts","/api/apartments","/api/reservations","/api/payments"):
   if not self.allowed():return
   table=path.split('/')[-1]
   with connect() as c:rows=c.execute("SELECT * FROM "+table+" ORDER BY id DESC LIMIT 300").fetchall()
   return self.json(200,{"items":[record(r) for r in rows]})
  if path=="/api/health":return self.json(200,{"ok":True,"mode":"starter"})
  if path=="/api/me":
   u=self.session();return self.json(200,{"user":u})
  if path=="/api/requests":
   if not self.allowed():return
   with connect() as c:rows=c.execute("SELECT * FROM requests ORDER BY created_at DESC LIMIT 300").fetchall()
   return self.json(200,{"items":[record(r) for r in rows]})
  if path=="/api/notifications":
   if not self.allowed():return
   with connect() as c:rows=c.execute("SELECT * FROM notifications WHERE read_at IS NULL ORDER BY id DESC LIMIT 50").fetchall()
   return self.json(200,{"items":[record(r) for r in rows]})
  if path.startswith("/api/"):return self.json(404,{"error":"Not found"})
  if path=="/admin":path="/admin.html"
  if path=="/":path="/index.html"
  file=(ROOT/"public"/path.lstrip("/")).resolve()
  if not file.is_relative_to((ROOT/"public").resolve()) or not file.is_file():self.send_error(404);return
  content=file.read_bytes();self.send_response(200);self.send_header("Content-Type",(mimetypes.guess_type(file)[0] or "text/html")+("; charset=utf-8" if file.suffix in (".html",".css",".js") else ""))
  self.send_header("Content-Security-Policy","frame-ancestors 'none'")
  self.send_header("X-Content-Type-Options","nosniff")
  self.send_header("Content-Length",str(len(content)));self.end_headers();self.wfile.write(content)
 def do_POST(self):
  path=urlsplit(self.path).path
  if not self.origin_ok():return self.json(403,{"error":"Invalid origin"})
  try:d=self.payload()
  except Exception as e:return self.json(400,{"error":str(e)})
  if path in ("/api/partners","/api/contracts","/api/apartments","/api/reservations","/api/payments"):
   u=self.allowed(["admin","reception"] if path in ("/api/reservations","/api/payments") else ["admin"])
   if not u:return
   table=path.split('/')[-1]
   try:
    with connect() as c:
     t=now()
     if table=="partners":
      name=clean(d.get("name"),150)
      if not name:raise ValueError('Partner name required')
      if d.get('kind','owner') not in ('owner','homestay'):raise ValueError('Invalid partner type')
      cur=c.execute("INSERT INTO partners(name,contact,kind,created_at) VALUES(?,?,?,?)",(name,clean(d.get('contact'),100),d.get('kind','owner'),t))
     elif table=="contracts":
      partner=int(d['partner_id']);ref=clean(d.get('reference'),100)
      if not ref:raise ValueError('Contract reference required')
      cur=c.execute("INSERT INTO contracts(partner_id,reference,notes,created_at) VALUES(?,?,?,?)",(partner,ref,clean(d.get('notes'),1000),t))
     elif table=="apartments":
      partner=int(d['partner_id']);title=clean(d.get('title'),150);place=clean(d.get('place'),100)
      if not title or not place:raise ValueError('Apartment title and place required')
      contract=int(d['contract_id']) if d.get('contract_id') else None
      if contract and not c.execute('SELECT id FROM contracts WHERE id=? AND partner_id=?',(contract,partner)).fetchone():raise ValueError('Contract belongs to another partner')
      area=float(d.get('area') or 0);capacity=int(d.get('capacity') or 2);bedrooms=int(d.get('bedrooms') or 1);price=int(d.get('night_price') or 0)
      if area<=0 or capacity<1 or bedrooms<0 or price<0:raise ValueError('Invalid apartment details')
      amenities=d.get('amenities',[]);photos=d.get('photos',[])
      if not isinstance(amenities,list) or not isinstance(photos,list):raise ValueError('Amenities and photos must be arrays')
      cur=c.execute("INSERT INTO apartments(partner_id,contract_id,title,place,building,area,bed_type,bedrooms,capacity,night_price,amenities_json,photos_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(partner,contract,title,place,clean(d.get('building'),100),area,clean(d.get('bed_type'),40),bedrooms,capacity,price,json.dumps(amenities[:40]),json.dumps(photos[:30]),t))
     elif table=="reservations":
      aid=int(d['apartment_id']);start=clean(d.get('check_in'),10);end=clean(d.get('check_out'),10)
      import datetime
      try:
       a=datetime.date.fromisoformat(start);b=datetime.date.fromisoformat(end)
      except Exception:raise ValueError('Use YYYY-MM-DD dates')
      if a>=b:raise ValueError('Check-out must be after check-in')
      apartment=c.execute("SELECT a.*,co.status AS contract_status FROM apartments a LEFT JOIN contracts co ON co.id=a.contract_id WHERE a.id=?",(aid,)).fetchone()
      if not apartment or apartment['status']!='published' or not apartment['quality_approved'] or apartment['contract_status']!='signed':raise ValueError('Apartment is not bookable')
      overlap=c.execute("SELECT id FROM reservations WHERE apartment_id=? AND status IN ('hold','confirmed') AND check_in<? AND check_out>?",(aid,end,start)).fetchone()
      if overlap:raise ValueError('Dates already reserved')
      name=clean(d.get('guest_name'),120);phone=clean(d.get('guest_phone'),30)
      if not name or not re.fullmatch(r'[+0-9() .-]{8,30}',phone):raise ValueError('Guest name and phone required')
      amount=(b-a).days*apartment['night_price']
      cur=c.execute("INSERT INTO reservations(apartment_id,guest_name,guest_phone,check_in,check_out,amount,created_at) VALUES(?,?,?,?,?,?,?)",(aid,name,phone,start,end,amount,t))
     elif table=="payments":
      reqid=int(d['request_id']) if d.get('request_id') else None
      resid=int(d['reservation_id']) if d.get('reservation_id') else None
      if bool(reqid)==bool(resid):raise ValueError('Choose one request or reservation')
      amount=int(d.get('amount') or 0)
      if amount<=0:raise ValueError('Amount must be positive')
      cur=c.execute("INSERT INTO payments(request_id,reservation_id,amount,created_at) VALUES(?,?,?,?)",(reqid,resid,amount,t))
     rid=cur.lastrowid
    self.audit(u,table+'.create',rid)
    return self.json(201,{"id":rid,"status":"created"})
   except (ValueError,KeyError,sqlite3.IntegrityError,TypeError) as e:return self.json(400,{"error":str(e)})
  if path.startswith('/api/contracts/') and path.endswith('/sign'):
   u=self.allowed(['admin'])
   if not u:return
   try:rid=int(path.split('/')[3])
   except Exception:return self.json(400,{"error":"Bad id"})
   with connect() as c:
    row=c.execute('SELECT id FROM contracts WHERE id=?',(rid,)).fetchone()
    if not row:return self.json(404,{"error":"Not found"})
    c.execute("UPDATE contracts SET status='signed',signed_at=? WHERE id=?",(clean(d.get('signed_at'),10) or time.strftime('%Y-%m-%d'),rid))
   self.audit(u,'contract.sign',rid)
   return self.json(200,{"ok":True,"note":"Manual confirmation; upload and legal verification not implemented"})
  if path.startswith('/api/apartments/') and path.endswith('/publish'):
   u=self.allowed(['admin'])
   if not u:return
   try:rid=int(path.split('/')[3])
   except Exception:return self.json(400,{"error":"Bad id"})
   with connect() as c:
    a=c.execute('SELECT a.*,co.status AS contract_status FROM apartments a LEFT JOIN contracts co ON co.id=a.contract_id WHERE a.id=?',(rid,)).fetchone()
    if not a:return self.json(404,{"error":"Not found"})
    if a['contract_status']!='signed':return self.json(409,{"error":"Signed partner contract required"})
    if not d.get('quality_approved'):return self.json(409,{"error":"Quality approval required"})
    c.execute("UPDATE apartments SET quality_approved=1,status='published' WHERE id=?",(rid,))
   self.audit(u,'apartment.publish',rid)
   return self.json(200,{"ok":True})
  if path.startswith('/api/reservations/') and path.endswith('/status'):
   u=self.allowed(['admin','reception'])
   if not u:return
   try:rid=int(path.split('/')[3])
   except Exception:return self.json(400,{"error":"Bad id"})
   status=d.get('status')
   if status not in ('hold','confirmed','cancelled','completed'):return self.json(400,{"error":"Invalid status"})
   with connect() as c:
    row=c.execute('SELECT * FROM reservations WHERE id=?',(rid,)).fetchone()
    if not row:return self.json(404,{"error":"Not found"})
    if status in ('hold','confirmed') and c.execute("SELECT id FROM reservations WHERE id<>? AND apartment_id=? AND status IN ('hold','confirmed') AND check_in<? AND check_out>?",(rid,row['apartment_id'],row['check_out'],row['check_in'])).fetchone():return self.json(409,{"error":"Conflicting reservation"})
    c.execute('UPDATE reservations SET status=? WHERE id=?',(status,rid))
   self.audit(u,'reservation.status',rid)
   return self.json(200,{"ok":True})
  if path.startswith('/api/payments/') and path.endswith('/status'):
   u=self.allowed(['admin'])
   if not u:return
   try:rid=int(path.split('/')[3])
   except Exception:return self.json(400,{"error":"Bad id"})
   if d.get('status') not in ('pending','paid','failed','refunded'):return self.json(400,{"error":"Invalid status"})
   with connect() as c:
    row=c.execute('SELECT id FROM payments WHERE id=?',(rid,)).fetchone()
    if not row:return self.json(404,{"error":"Not found"})
    c.execute('UPDATE payments SET status=?,reference=? WHERE id=?',(d['status'],clean(d.get('reference'),100),rid))
   self.audit(u,'payment.manual_status',rid)
   return self.json(200,{"ok":True,"note":"Manual status only; no payment provider verification"})
  if path=="/api/login":
   user=clean(d.get("username"),100)
   with connect() as c:r=c.execute("SELECT * FROM users WHERE username=? AND active=1",(user,)).fetchone()
   if not r or not password_ok(str(d.get("password","")),r["passhash"]):return self.json(401,{"error":"Invalid credentials"})
   token=secrets.token_urlsafe(40);hashed=hashlib.sha256(token.encode()).hexdigest()
   with connect() as c:c.execute("INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)",(hashed,r["id"],now()+8*3600))
   return self.json(200,{"user":{"id":r["id"],"username":r["username"],"role":r["role"]}},{"Set-Cookie":self.cookie_header(token,8*3600)})
  if path=="/api/logout":
   cookie=SimpleCookie()
   try:cookie.load(self.headers.get("Cookie",""))
   except Exception:pass
   token=cookie.get("greenora_sid")
   if token:
    with connect() as c:c.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(token.value.encode()).hexdigest(),))
   return self.json(200,{"ok":True},{"Set-Cookie":self.cookie_header("",0)})
  if path=="/api/requests":
   service=clean(d.get("service"),90);name=clean(d.get("name"),100);contact=clean(d.get("contact"),30)
   if not d.get("consent") or not service or not name or not re.fullmatch(r"[+0-9() .-]{8,30}",contact):return self.json(400,{"error":"Service, name, phone and consent are required"})
   ref=clean(d.get("client_ref"),100) or None
   try:est=int(d.get("estimated_total") or 0)
   except Exception:est=0
   t=now()
   with connect() as c:
    if ref:
     existing=c.execute("SELECT id FROM requests WHERE client_ref=?",(ref,)).fetchone()
     if existing:return self.json(200,{"id":existing["id"],"duplicate":True})
    cur=c.execute("INSERT INTO requests(client_ref,source,service,name,contact,building,room,requested_date,requested_time,notes,details_json,estimated_total,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",(ref,clean(d.get("source"),90),service,name,contact,clean(d.get("building"),100),clean(d.get("room"),50),clean(d.get("date"),30),clean(d.get("time"),30),clean(d.get("notes"),2000),json.dumps(d.get("details",{}),ensure_ascii=False)[:6000],max(0,est),t,t))
    c.execute("INSERT INTO notifications(request_id,event,created_at) VALUES(?,?,?)",(cur.lastrowid,"new_request",t))
    rid=cur.lastrowid
   return self.json(201,{"id":rid,"status":"pending"})
  if path=="/api/chat":
   message=clean(d.get("message"),1200)
   if not message:return self.json(400,{"error":"Empty message"})
   key=os.environ.get("OPENAI_API_KEY")
   if not key:return self.json(200,{"reply":"GREENORA Concierge: Tôi có thể hỗ trợ đặt phòng, dọn dẹp, đón sân bay, đặt món, giặt ủi và hướng dẫn viên. Vui lòng chọn dịch vụ trên cửa sổ chatbot để gửi yêu cầu. Giá và lịch cần nhân viên xác nhận.","ai_enabled":False})
   prompt="You are GREENORA Concierge. Answer in the user's language. Help with stays, housekeeping, airport pickup, food delivery, laundry and private guides. Never invent live availability, prices, payment confirmations or claim an order was placed. Ask customers to use the service request form. Be concise. Never request card numbers or passwords."
   try:
    req=urllib.request.Request("https://api.openai.com/v1/responses",data=json.dumps({"model":os.environ.get("OPENAI_MODEL","gpt-4.1-mini"),"instructions":prompt,"input":message,"max_output_tokens":220}).encode(),headers={"Authorization":"Bearer "+key,"Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=15) as resp:result=json.load(resp)
    reply=" ".join(x.get("text","") for o in result.get("output",[]) for x in o.get("content",[]) if x.get("type")=="output_text")
    return self.json(200,{"reply":reply or "Vui lòng chọn dịch vụ để gửi yêu cầu.","ai_enabled":True})
   except Exception:return self.json(503,{"error":"AI temporarily unavailable"})
  if path.startswith("/api/requests/") and path.endswith("/update"):
   u=self.allowed(["admin","reception"])
   if not u:return
   try:rid=int(path.split("/")[3])
   except Exception:return self.json(400,{"error":"Bad id"})
   status=clean(d.get("status"),20)
   if status not in ("pending","processing","confirmed","completed","cancelled"):return self.json(400,{"error":"Bad status"})
   try:quote=int(d.get("quoted_total") or 0)
   except Exception:return self.json(400,{"error":"Bad quote"})
   if quote<0:return self.json(400,{"error":"Bad quote"})
   with connect() as c:
    result=c.execute("UPDATE requests SET status=?,quoted_total=?,admin_note=?,updated_at=? WHERE id=?",(status,quote,clean(d.get("admin_note"),700),now(),rid))
    if not result.rowcount:return self.json(404,{"error":"Not found"})
    c.execute("INSERT INTO audit(user_id,action,object_id,created_at) VALUES(?,?,?,?)",(u["id"],"request.update",rid,now()))
   return self.json(200,{"ok":True})
  if path=="/api/admin/hero":
   u=self.allowed(["admin"])
   if not u:return
   raw=d.get("image")
   if not isinstance(raw,str) or not raw.startswith("data:image/") or ";base64," not in raw:
    return self.json(400,{"error":"Vui lòng chọn ảnh JPG, PNG hoặc WebP."})
   header,encoded=raw.split(";base64,",1)
   if header not in ("data:image/jpeg","data:image/png","data:image/webp"):
    return self.json(400,{"error":"Chỉ hỗ trợ JPG, PNG, WebP."})
   try:blob=base64.b64decode(encoded,validate=True)
   except (ValueError,binascii.Error):return self.json(400,{"error":"Dữ liệu ảnh không hợp lệ."})
   if not (100<=len(blob)<=5_000_000):return self.json(400,{"error":"Ảnh phải nhỏ hơn 5 MB."})
   ext=None
   if blob.startswith(b"\xff\xd8\xff"):ext=".jpg"
   elif blob.startswith(b"\x89PNG\r\n\x1a\n"):ext=".png"
   elif blob.startswith(b"RIFF") and blob[8:12]==b"WEBP":ext=".webp"
   if not ext or {"data:image/jpeg":".jpg","data:image/png":".png","data:image/webp":".webp"}[header]!=ext:
    return self.json(400,{"error":"Định dạng tệp không khớp nội dung."})
   folder=ROOT/"public"/"uploads";folder.mkdir(exist_ok=True)
   filename="hero-"+secrets.token_hex(12)+ext
   target=folder/filename
   target.write_bytes(blob)
   url="/uploads/"+filename
   with connect() as c:
    old=c.execute("SELECT value FROM site_settings WHERE key='hero_image'").fetchone()
    c.execute("INSERT INTO site_settings(key,value,updated_at) VALUES('hero_image',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",(url,now()))
   self.audit(u,"update_hero",None)
   return self.json(200,{"ok":True,"url":url})
  if path=="/api/admin/hero/reset":
   u=self.allowed(["admin"])
   if not u:return
   with connect() as c:c.execute("DELETE FROM site_settings WHERE key='hero_image'")
   self.audit(u,"reset_hero",None)
   return self.json(200,{"ok":True})
  if path=="/api/notifications/read":
   u=self.allowed(["admin","reception"]); 
   if not u:return
   with connect() as c:c.execute("UPDATE notifications SET read_at=? WHERE read_at IS NULL",(now(),))
   return self.json(200,{"ok":True})
  if path=="/api/users":
   u=self.allowed(["admin"])
   if not u:return
   username=clean(d.get("username"),100);role=clean(d.get("role"),20);password=str(d.get("password",""))
   if not re.fullmatch(r"[A-Za-z0-9_.-]{3,100}",username) or role not in ("admin","reception","viewer") or len(password)<12:return self.json(400,{"error":"Invalid username, role or password (minimum 12 characters)"})
   try:
    with connect() as c:c.execute("INSERT INTO users(username,passhash,role) VALUES(?,?,?)",(username,password_hash(password),role))
   except sqlite3.IntegrityError:return self.json(409,{"error":"Username exists"})
   return self.json(201,{"ok":True})
  return self.json(404,{"error":"Not found"})
if __name__=="__main__":
 init();bootstrap()
 print("GREENORA server: http://%s:%s/ | admin: /admin"%(HOST,PORT))
 ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
