"""The server's own admin dashboard at /admin - a small, self-contained, password-protected web page.

It shows everything about THIS Bridge server (clients, realms, messages, friends, trusted servers, backup,
settings, activity). It is reachable over the server's public URL, so an admin can look at a server from anywhere
with just the admin password - Bridge needs no extra app for this.

Self-contained on purpose: the HTML/CSS/JS is inline (brand colours as values, system fonts), so the page has no
outside dependency and works even when Bridge runs completely on its own.
"""
from fastapi import APIRouter
from fastapi.responses import HTMLResponse

Router = APIRouter()

_PAGE = r"""<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bridge – Server-Dashboard</title>
<style>
  :root{
    --blue:#3369FF; --blue-text:#2152E6; --blue-50:#EDF2FF; --bg:#F7F8FB; --surface:#FFFFFF;
    --text:#0E1A33; --text2:#36435C; --muted:#56657F; --line:#E4E9F2; --ink:#13203B;
    --ok:#0B7A54; --ok-bg:#E3F5EC; --warn:#8A5A00; --warn-bg:#FBEFD6; --err:#A8242E; --err-bg:#F7E0E1;
    color-scheme: light;
  }
  *{box-sizing:border-box;}
  body{margin:0;background:var(--bg);color:var(--text);
       font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;font-size:15px;}
  .mono{font-family:ui-monospace,"IBM Plex Mono",Consolas,monospace;}
  a{color:var(--blue-text);}
  .wrap{max-width:1080px;margin:0 auto;padding:22px 18px 60px;}

  /* login */
  #login{min-height:100vh;display:grid;place-items:center;padding:20px;}
  .login-card{width:100%;max-width:360px;background:var(--surface);border:1px solid var(--line);
    border-radius:18px;padding:30px 26px;box-shadow:0 18px 50px rgba(14,26,51,.10);text-align:center;}
  .mark{font-weight:800;font-size:40px;letter-spacing:-.03em;color:var(--blue);}
  .mark b{color:var(--text);}
  .login-card p{color:var(--muted);font-size:13.5px;margin:6px 0 20px;}
  input[type=password],input[type=text]{width:100%;height:46px;border:1px solid var(--line);border-radius:12px;
    padding:0 14px;font-size:15px;background:var(--surface);color:var(--text);outline:none;}
  input:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(51,105,255,.16);}
  button{font-family:inherit;cursor:pointer;}
  .btn{height:44px;padding:0 18px;border-radius:12px;border:1px solid transparent;background:var(--blue);
    color:#fff;font-size:15px;font-weight:600;display:inline-flex;align-items:center;gap:8px;justify-content:center;}
  .btn:hover{background:#2a5be6;}
  .btn--ghost{background:transparent;border-color:var(--line);color:var(--text2);}
  .btn--ghost:hover{background:var(--blue-50);color:var(--blue-text);border-color:var(--blue);}
  .btn--full{width:100%;margin-top:16px;}
  .err{color:var(--err);font-size:13.5px;margin-top:12px;min-height:18px;}

  /* topbar */
  .top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding-bottom:18px;border-bottom:1px solid var(--line);margin-bottom:22px;}
  .top .mark{font-size:30px;}
  .top .sub{color:var(--muted);font-size:13px;}
  .grow{flex:1 1 auto;}
  .pill{display:inline-flex;align-items:center;gap:7px;height:28px;padding:0 11px;border-radius:999px;font-size:13px;font-weight:600;}
  .pill--ok{background:var(--ok-bg);color:var(--ok);} .pill--info{background:var(--blue-50);color:var(--blue-text);}
  .pill--warn{background:var(--warn-bg);color:var(--warn);} .pill--neutral{background:#EEF1F6;color:var(--text2);}
  .dot{width:8px;height:8px;border-radius:50%;background:currentColor;}

  /* tiles */
  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:26px;}
  .tile{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px;}
  .tile .v{font-size:28px;font-weight:700;letter-spacing:-.02em;}
  .tile .l{font-size:12.5px;color:var(--muted);margin-top:2px;}

  section{margin-bottom:28px;}
  h2{font-size:17px;font-weight:700;letter-spacing:-.01em;margin:0 0 12px;display:flex;align-items:center;gap:10px;}
  h2 .c{font-size:12.5px;font-weight:600;color:var(--muted);background:#EEF1F6;border-radius:999px;padding:2px 9px;}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden;}
  table{width:100%;border-collapse:collapse;font-size:13.5px;}
  th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);white-space:nowrap;}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em;}
  tr:last-child td{border-bottom:0;}
  td.mono{color:var(--text2);}
  .empty{padding:18px 16px;color:var(--muted);font-size:13.5px;}
  .kv{display:flex;flex-wrap:wrap;gap:8px;}
  .kv span{display:inline-flex;gap:6px;align-items:center;background:#F1F4F9;border:1px solid var(--line);
    border-radius:8px;padding:5px 10px;font-size:13px;}
  .kv b{font-weight:600;color:var(--text2);}
  .muted{color:var(--muted);}
  @media(max-width:620px){th,td{padding:9px 10px;} .wrap{padding:16px 12px 50px;}}
</style>
</head>
<body>

<div id="login">
  <form class="login-card" id="loginForm">
    <div class="mark">br<b>.</b></div>
    <p>Server-Dashboard · Admin-Passwort eingeben</p>
    <input type="password" id="pw" placeholder="Admin-Passwort" autocomplete="current-password" autofocus>
    <button class="btn btn--full" type="submit">Anmelden</button>
    <div class="err" id="loginErr"></div>
  </form>
</div>

<div class="wrap" id="app" hidden>
  <div class="top">
    <span class="mark">br<b>.</b></span>
    <div>
      <div id="srvState"></div>
      <div class="sub mono" id="srvUrl"></div>
    </div>
    <span class="grow"></span>
    <button class="btn btn--ghost" id="refreshBtn" type="button">Aktualisieren</button>
    <button class="btn btn--ghost" id="logoutBtn" type="button">Abmelden</button>
  </div>

  <div class="tiles" id="tiles"></div>

  <section><h2>Clients <span class="c" id="cCount">0</span></h2><div class="card" id="clients"></div></section>
  <section><h2>Realms <span class="c" id="rCount">0</span></h2><div class="card" id="realms"></div></section>
  <section><h2>Vertraute Server <span class="c" id="tCount">0</span></h2><div class="card" id="trusted"></div></section>
  <section><h2>Freunde</h2><div class="card" id="friends"></div></section>
  <section><h2>Backup</h2><div class="card" id="backup"></div></section>
  <section><h2>Einstellungen</h2><div class="card" id="settings" style="padding:14px 16px"></div></section>
  <section><h2>Aktivität</h2><div class="card" id="activity" style="padding:14px 16px"></div></section>

  <p class="muted" style="font-size:12.5px">Bridge <span id="ver" class="mono"></span> · aktualisiert <span id="when"></span> · Auto-Aktualisierung alle 5 s</p>
</div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let PW=sessionStorage.getItem("bridge-admin-pw")||"";
let timer=null;

function fmtTime(iso){ if(!iso) return "–"; try{const d=new Date(iso);return d.toLocaleString("de-DE");}catch(e){return iso;} }
function ago(iso){ if(!iso) return "–"; const s=(Date.now()-new Date(iso).getTime())/1000;
  if(s<60) return Math.max(0,Math.round(s))+" s"; if(s<3600) return Math.round(s/60)+" min";
  if(s<86400) return Math.round(s/3600)+" h"; return Math.round(s/86400)+" d"; }
function uptime(sec){ sec=sec||0; const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);
  if(d) return d+" d "+h+" h"; if(h) return h+" h "+m+" min"; if(m) return m+" min"; return sec+" s"; }

async function load(){
  if(!PW){ showLogin(); return; }
  let r;
  try{ r=await fetch("/admin/overview",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({password:PW})}); }
  catch(e){ $("srvState").innerHTML='<span class="pill pill--warn"><span class="dot"></span>Server nicht erreichbar</span>'; return; }
  if(r.status===403||r.status===401){ PW=""; sessionStorage.removeItem("bridge-admin-pw"); showLogin("Falsches Passwort."); return; }
  if(!r.ok){ $("srvState").innerHTML='<span class="pill pill--warn"><span class="dot"></span>Fehler '+r.status+'</span>'; return; }
  render(await r.json());
}

function showLogin(msg){ if(timer){clearInterval(timer);timer=null;} $("app").hidden=true; $("login").style.display="grid";
  $("loginErr").textContent=msg||""; $("pw").value=""; $("pw").focus(); }
function showApp(){ $("login").style.display="none"; $("app").hidden=false;
  if(!timer) timer=setInterval(load,5000); }

function tile(v,l){ return '<div class="tile"><div class="v">'+v+'</div><div class="l">'+esc(l)+'</div></div>'; }
function rows(head,body){ return '<table><thead><tr>'+head.map(h=>'<th>'+esc(h)+'</th>').join("")+'</tr></thead><tbody>'+body+'</tbody></table>'; }

function render(d){
  showApp();
  const s=d.status||{};
  const ready=!!(s.backup?s.backup.ready:true);
  const stateReady = (s.backup && s.backup.ready===false) ? false : true;
  $("srvState").innerHTML = stateReady
    ? '<span class="pill pill--ok"><span class="dot"></span>Läuft</span>'
    : '<span class="pill pill--info"><span class="dot"></span>Startet / stellt wieder her …</span>';
  $("srvUrl").textContent=s.url||"";
  $("ver").textContent="Protokoll "+(s.protocol_version||"?");
  $("when").textContent=new Date().toLocaleTimeString("de-DE");

  $("tiles").innerHTML =
    tile(s.clients??0,"Clients")+tile((d.realms||[]).length,"Realms")+tile(s.sessions??0,"Sessions")+
    tile(s.open_tasks??0,"Offene Tasks")+tile(s.conversations??0,"Konversationen")+
    tile(s.scheduled_messages??0,"Geplante Nachr.")+tile((s.trusted_servers||[]).length,"Vertraute")+
    tile("↑ "+uptime(s.uptime_seconds),"Laufzeit");

  // Clients
  const cl=d.clients||[]; $("cCount").textContent=cl.length;
  $("clients").innerHTML = cl.length ? rows(["Client-IP","Name","Realms","Wartend","Erstellt","Letztes Signal"],
    cl.map(c=>'<tr><td class="mono">'+esc(c.client_ip)+'</td><td>'+esc(c.name||"–")+'</td><td>'+((c.realms||[]).length)+
    '</td><td>'+(c.waiting_messages||0)+'</td><td class="mono">'+fmtTime(c.created_at)+'</td><td class="mono">vor '+ago(c.last_signal)+'</td></tr>').join(""))
    : '<div class="empty">Noch keine Clients angemeldet.</div>';

  // Realms
  const rl=d.realms||[]; $("rCount").textContent=rl.length;
  $("realms").innerHTML = rl.length ? rows(["Name","Typ","Mitglieder","Commands","Topics",""],
    rl.map(r=>'<tr><td>'+esc(r.name)+'</td><td>'+esc(r.realm_type)+'</td><td>'+(r.member_count||0)+'</td><td>'+
    (r.commands||0)+'</td><td>'+(r.topics||0)+'</td><td>'+(r.is_public?'<span class="pill pill--info">öffentlich</span>':'')+'</td></tr>').join(""))
    : '<div class="empty">Keine Realms.</div>';

  // Trusted
  const ts=s.trusted_servers||[]; $("tCount").textContent=ts.length;
  $("trusted").innerHTML = ts.length ? rows(["Server","Status","Version","Commit","Verbunden seit"],
    ts.map(t=>{const ok=t.status==="connected";const pill=ok?'pill--ok':(t.status==="pending"?'pill--warn':'pill--neutral');
    return '<tr><td class="mono">'+esc(t.url)+'</td><td><span class="pill '+pill+'"><span class="dot"></span>'+esc(t.status)+
    '</span></td><td class="mono">'+esc(t.protocol_version||"–")+'</td><td class="mono">'+esc(t.commit||"–")+
    '</td><td class="mono">'+(t.connected_at?fmtTime(t.connected_at):"–")+'</td></tr>';}).join(""))
    : '<div class="empty">Keine vertrauten Server eingetragen.</div>';

  // Friends
  const f=s.friends||{};
  $("friends").innerHTML='<div class="empty"><div class="kv">'+
    '<span><b>Modus</b> '+esc(f.mode??"?")+'</span>'+
    Object.keys(f).filter(k=>k!=="mode"&&typeof f[k]!=="object").map(k=>'<span><b>'+esc(k)+'</b> '+esc(f[k])+'</span>').join("")+
    '</div></div>';

  // Backup
  const b=s.backup||{};
  $("backup").innerHTML='<div class="empty"><div class="kv">'+
    '<span><b>Modus</b> '+esc(b.mode??"?")+'</span>'+
    '<span><b>Bereit</b> '+(b.ready?"ja":"nein")+'</span>'+
    (b.last_backup_at?'<span><b>Letztes Backup</b> vor '+ago(b.last_backup_at)+'</span>':'')+
    '<span><b>Für andere gelagert</b> '+(s.stored_backups??0)+'</span>'+
    '</div></div>';

  // Settings
  const set=s.settings||{};
  $("settings").innerHTML='<div class="kv">'+Object.keys(set).map(k=>'<span><b>'+esc(k)+'</b> '+esc(set[k])+'</span>').join("")+'</div>';

  // Activity / errors
  const errs=s.errors||{}; const ek=Object.keys(errs);
  $("activity").innerHTML = ek.length
    ? '<div class="kv">'+ek.map(k=>'<span><b>'+esc(k)+'</b> '+esc(errs[k])+'</span>').join("")+'</div>'
    : '<span class="muted">Keine Fehler erfasst.</span>';
}

$("loginForm").addEventListener("submit",e=>{e.preventDefault();PW=$("pw").value;sessionStorage.setItem("bridge-admin-pw",PW);load();});
$("refreshBtn").addEventListener("click",load);
$("logoutBtn").addEventListener("click",()=>{PW="";sessionStorage.removeItem("bridge-admin-pw");showLogin();});
if(PW) load(); else showLogin();
</script>
</body>
</html>"""


@Router.get("/admin", response_class=HTMLResponse, include_in_schema=False)
async def admin_dashboard() -> str:
    return _PAGE
