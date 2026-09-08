const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = Number(process.env.PORT || 3000);
const root = __dirname;
const dataDir = path.join(root, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, 'lingospark.db'));
db.exec(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, password_salt TEXT NOT NULL, role TEXT NOT NULL,
  level TEXT NOT NULL DEFAULT 'A1', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
); CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);`);

function send(res, status, body, type='application/json') { res.writeHead(status, { 'Content-Type': `${type}; charset=utf-8`, 'Cache-Control':'no-store' }); res.end(type === 'application/json' ? JSON.stringify(body) : body); }
function publicUser(user) { return { id:user.id, name:user.name, email:user.email, role:user.role, level:user.level }; }
function hash(password, salt=crypto.randomBytes(16).toString('hex')) { return { salt, hash:crypto.scryptSync(password, salt, 64).toString('hex') }; }
function getToken(req) { const value=req.headers.authorization||''; return value.startsWith('Bearer ')?value.slice(7):null; }
function currentUser(req) { const token=getToken(req); if (!token) return null; const row=db.prepare('SELECT u.id,u.name,u.email,u.role,u.level FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires_at>?').get(token, Date.now()); return row||null; }
function readBody(req) { return new Promise((resolve,reject)=>{let body='';req.on('data',c=>{body+=c;if(body.length>100000)reject(new Error('Слишком большой запрос'))});req.on('end',()=>{try{resolve(body?JSON.parse(body):{})}catch{reject(new Error('Неверный JSON'))}});}); }
function auth(req,res,admin=false) { const user=currentUser(req); if (!user || (admin && user.role!=='admin')) { send(res,403,{error:'Недостаточно прав'}); return null; } return user; }

async function api(req,res,url) {
  if(req.method==='POST' && url.pathname==='/api/register') { const body=await readBody(req); const name=(body.name||'').trim(), email=(body.email||'').trim().toLowerCase(), password=body.password||''; if(!name||!/^\S+@\S+\.\S+$/.test(email)||password.length<8)return send(res,400,{error:'Укажите имя, корректный email и пароль минимум из 8 символов'}); const total=db.prepare('SELECT COUNT(*) AS count FROM users').get().count; const creator=currentUser(req); if(total>0 && creator && creator.role!=='admin')return send(res,403,{error:'Недостаточно прав'}); if(total>0 && !creator) { /* public student registration */ } const secured=hash(password); try { const role=total===0?'admin':'student'; const result=db.prepare('INSERT INTO users(name,email,password_hash,password_salt,role,level) VALUES(?,?,?,?,?,?)').run(name,email,secured.hash,secured.salt,role,role==='admin'?'—':'A1'); const user=db.prepare('SELECT id,name,email,role,level FROM users WHERE id=?').get(result.lastInsertRowid); const token=crypto.randomBytes(32).toString('hex'); db.prepare('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)').run(token,user.id,Date.now()+1000*60*60*24*7); return send(res,201,{token,user:publicUser(user)}); } catch { return send(res,409,{error:'Пользователь с таким email уже существует'}); } }
  if(req.method==='POST' && url.pathname==='/api/login') { const body=await readBody(req); const user=db.prepare('SELECT * FROM users WHERE email=?').get((body.email||'').trim().toLowerCase()); if(!user)return send(res,401,{error:'Неверный email или пароль'}); const actual=hash(body.password||'',user.password_salt).hash; if(!crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(user.password_hash,'hex')))return send(res,401,{error:'Неверный email или пароль'}); const token=crypto.randomBytes(32).toString('hex'); db.prepare('INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)').run(token,user.id,Date.now()+1000*60*60*24*7); return send(res,200,{token,user:publicUser(user)}); }
  if(req.method==='GET' && url.pathname==='/api/bootstrap') return send(res,200,{hasUsers:db.prepare('SELECT COUNT(*) AS count FROM users').get().count>0});
  if(req.method==='GET' && url.pathname==='/api/me') { const user=auth(req,res); if(user)send(res,200,{user:publicUser(user)}); return; }
  if(req.method==='GET' && url.pathname==='/api/users') { if(!auth(req,res,true))return; const list=db.prepare('SELECT id,name,email,role,level FROM users ORDER BY id').all(); return send(res,200,{users:list.map(publicUser)}); }
  const match=url.pathname.match(/^\/api\/users\/(\d+)$/); if(req.method==='DELETE' && match) { const user=auth(req,res,true); if(!user)return; if(Number(match[1])===user.id)return send(res,400,{error:'Нельзя удалить свой аккаунт'}); db.prepare('DELETE FROM users WHERE id=?').run(Number(match[1])); return send(res,200,{ok:true}); }
  send(res,404,{error:'Не найдено'});
}
function serveFile(req,res,url) { let file=url.pathname==='/'?'index.html':decodeURIComponent(url.pathname).replace(/^\/+/,''); file=path.normalize(file); const target=path.join(root,file); if(!target.startsWith(root) || !fs.existsSync(target) || fs.statSync(target).isDirectory())return send(res,404,'Не найдено','text/plain'); const types={'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml'}; send(res,200,fs.readFileSync(target),types[path.extname(target)]||'application/octet-stream'); }
http.createServer((req,res)=>{const url=new URL(req.url,`http://${req.headers.host}`);if(url.pathname.startsWith('/api/'))api(req,res,url).catch(e=>send(res,400,{error:e.message||'Ошибка запроса'}));else serveFile(req,res,url)}).listen(PORT,()=>console.log(`LingoSpark: http://localhost:${PORT}`));
