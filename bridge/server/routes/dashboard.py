"""The server's own admin dashboard at /admin - a small, self-contained, password-protected control panel.

It shows everything about THIS Bridge server AND lets the admin control it: add/remove/reconnect trusted servers
(server-to-server "friendships" by URL), change the settings, block/unblock servers, back up now or restore, change
the admin password, and reset the server. Reachable over the server's public URL, so an admin can run a server from
anywhere with just the admin password - Bridge needs no extra app for this.

Self-contained on purpose: the HTML/CSS/JS is inline (brand colours as values, system fonts), so the page has no
outside dependency and works even when Bridge runs completely on its own. Every control calls the existing
password-protected /admin/* endpoints.
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
  .wrap{max-width:1080px;margin:0 auto;padding:22px 18px 70px;}

  #login{min-height:100vh;display:grid;place-items:center;padding:20px;}
  .login-card{width:100%;max-width:360px;background:var(--surface);border:1px solid var(--line);
    border-radius:18px;padding:30px 26px;box-shadow:0 18px 50px rgba(14,26,51,.10);text-align:center;}
  .mark{font-weight:800;font-size:40px;letter-spacing:-.03em;color:var(--blue);}
  .mark b{color:var(--text);}
  .login-card p{color:var(--muted);font-size:13.5px;margin:6px 0 20px;}
  input,select{font-family:inherit;}
  input[type=password],input[type=text],input.in,select{width:100%;height:44px;border:1px solid var(--line);
    border-radius:11px;padding:0 13px;font-size:14.5px;background:var(--surface);color:var(--text);outline:none;}
  input:focus,select:focus{border-color:var(--blue);box-shadow:0 0 0 4px rgba(51,105,255,.16);}
  button{font-family:inherit;cursor:pointer;}
  .btn{height:44px;padding:0 18px;border-radius:11px;border:1px solid transparent;background:var(--blue);
    color:#fff;font-size:14.5px;font-weight:600;display:inline-flex;align-items:center;gap:8px;justify-content:center;white-space:nowrap;}
  .btn:hover{background:#2a5be6;}
  .btn--ghost{background:transparent;border-color:var(--line);color:var(--text2);}
  .btn--ghost:hover{background:var(--blue-50);color:var(--blue-text);border-color:var(--blue);}
  .btn--danger{background:var(--err);} .btn--danger:hover{background:#8C1C25;}
  .btn--sm{height:36px;padding:0 12px;font-size:13px;border-radius:9px;}
  .btn--full{width:100%;margin-top:16px;}
  .err{color:var(--err);font-size:13.5px;margin-top:12px;min-height:18px;}

  .top{display:flex;align-items:center;gap:14px;flex-wrap:wrap;padding-bottom:18px;border-bottom:1px solid var(--line);margin-bottom:22px;}
  .top .mark{font-size:30px;}
  .top .sub{color:var(--muted);font-size:13px;}
  .grow{flex:1 1 auto;}
  .pill{display:inline-flex;align-items:center;gap:7px;height:26px;padding:0 10px;border-radius:999px;font-size:12.5px;font-weight:600;}
  .pill--ok{background:var(--ok-bg);color:var(--ok);} .pill--info{background:var(--blue-50);color:var(--blue-text);}
  .pill--warn{background:var(--warn-bg);color:var(--warn);} .pill--neutral{background:#EEF1F6;color:var(--text2);}
  .dot{width:8px;height:8px;border-radius:50%;background:currentColor;}

  .tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:26px;}
  .tile{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px 16px;}
  .tile .v{font-size:28px;font-weight:700;letter-spacing:-.02em;}
  .tile .l{font-size:12.5px;color:var(--muted);margin-top:2px;}

  section{margin-bottom:26px;}
  h2{font-size:17px;font-weight:700;letter-spacing:-.01em;margin:0 0 12px;display:flex;align-items:center;gap:10px;}
  h2 .c{font-size:12.5px;font-weight:600;color:var(--muted);background:#EEF1F6;border-radius:999px;padding:2px 9px;}
  .card{background:var(--surface);border:1px solid var(--line);border-radius:14px;overflow:hidden;}
  .card--danger{border-color:#EDC3C7;}
  table{width:100%;border-collapse:collapse;font-size:13.5px;}
  th,td{text-align:left;padding:10px 14px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:middle;}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em;}
  tr:last-child td{border-bottom:0;}
  td.mono{color:var(--text2);}
  td.act{text-align:right;}
  .empty{padding:16px;color:var(--muted);font-size:13.5px;}
  .addrow{display:flex;gap:8px;padding:14px;border-top:1px solid var(--line);flex-wrap:wrap;}
  .addrow input{flex:1;min-width:200px;}
  .kv{display:flex;flex-wrap:wrap;gap:8px;}
  .kv span{display:inline-flex;gap:6px;align-items:center;background:#F1F4F9;border:1px solid var(--line);
    border-radius:8px;padding:5px 10px;font-size:13px;}
  .kv b{font-weight:600;color:var(--text2);}
  .muted{color:var(--muted);}
  .setgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px;padding:16px;}
  .setfield{display:flex;flex-direction:column;gap:5px;}
  .setfield label{font-size:12.5px;color:var(--muted);font-weight:600;}
  .barrow{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:14px 16px;}
  .hint{font-size:12.5px;color:var(--muted);padding:0 16px 14px;}
  .msgs{position:fixed;right:16px;bottom:16px;display:flex;flex-direction:column;gap:8px;z-index:60;width:min(340px,calc(100vw - 32px));}
  .msg{padding:12px 14px;border-radius:12px;background:var(--surface);border:1px solid var(--line);
    box-shadow:0 12px 30px rgba(14,26,51,.16);font-size:14px;}
  .msg--ok{border-left:4px solid var(--ok);} .msg--err{border-left:4px solid var(--err);color:var(--err);}
  .msg--info{border-left:4px solid var(--blue);}
  @media(max-width:620px){th,td{padding:9px 10px;} .wrap{padding:16px 12px 60px;}}
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

  <section>
    <h2>Adresse dieses Servers</h2>
    <div class="card">
      <div class="barrow">
        <code class="mono" id="selfUrl" style="font-size:15px;word-break:break-all;flex:1 1 260px"></code>
        <button class="btn btn--sm" data-act="copy-self" type="button">Kopieren</button>
      </div>
      <p class="hint">Genau diese Adresse beim anderen Server unter „Vertraute Server" eintragen (ohne /admin).</p>
    </div>
  </section>

  <section>
    <h2>Vertraute Server <span class="c" id="tCount">0</span></h2>
    <div class="card" id="trusted"></div>
    <p class="muted" style="font-size:12.5px;margin:8px 2px 0">
      Zwei Server werden „Freunde", wenn <b>beide</b> die Adresse des anderen eintragen. „Wartet" heißt: der andere
      Server hat dich noch nicht eingetragen oder ist gerade nicht erreichbar – der Grund steht darunter.</p>
  </section>

  <section>
    <h2>Blockierte Server <span class="c" id="bCount">0</span></h2>
    <div class="card" id="blocked"></div>
  </section>

  <section><h2>Clients <span class="c" id="cCount">0</span></h2><div class="card" id="clients"></div></section>
  <section><h2>Realms <span class="c" id="rCount">0</span></h2><div class="card" id="realms"></div></section>

  <section>
    <h2>Backup</h2>
    <div class="card">
      <div id="backup"></div>
      <div class="barrow" style="border-top:1px solid var(--line)">
        <button class="btn btn--sm" data-act="backup-now" type="button">Jetzt sichern</button>
        <button class="btn btn--sm btn--ghost" data-act="backup-restore" type="button">Von Partnern wiederherstellen</button>
      </div>
    </div>
  </section>

  <section>
    <h2>Einstellungen</h2>
    <div class="card">
      <div class="setgrid" id="settings"></div>
      <div class="barrow" style="border-top:1px solid var(--line)">
        <button class="btn btn--sm" data-act="settings-save" type="button">Einstellungen speichern</button>
      </div>
    </div>
  </section>

  <section>
    <h2>Verwaltung</h2>
    <div class="card card--danger">
      <div class="barrow">
        <input class="in" id="pw-new" type="text" placeholder="Neues Admin-Passwort" style="max-width:280px">
        <button class="btn btn--sm" data-act="pw-change" type="button">Passwort ändern</button>
      </div>
      <div class="barrow" style="border-top:1px solid var(--line)">
        <button class="btn btn--sm btn--ghost" data-act="agent-reset" type="button">Agent zurücksetzen</button>
        <button class="btn btn--sm btn--danger" data-act="reset" type="button">Server zurücksetzen</button>
        <span class="muted" style="font-size:12.5px">„Zurücksetzen" löscht Clients, Nachrichten und Realms. Vertraute Server bleiben.</span>
      </div>
    </div>
  </section>

  <section><h2>Aktivität</h2><div class="card" id="activity" style="padding:14px 16px"></div></section>

  <p class="muted" style="font-size:12.5px">Bridge <span id="ver" class="mono"></span> · aktualisiert <span id="when"></span></p>
</div>

<div class="msgs" id="msgs"></div>

<script>
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let PW=sessionStorage.getItem("bridge-admin-pw")||"";
let timer=null, busy=false;

function fmtTime(iso){ if(!iso) return "–"; try{return new Date(iso).toLocaleString("de-DE");}catch(e){return iso;} }
function ago(iso){ if(!iso) return "–"; const s=(Date.now()-new Date(iso).getTime())/1000;
  if(s<60) return Math.max(0,Math.round(s))+" s"; if(s<3600) return Math.round(s/60)+" min";
  if(s<86400) return Math.round(s/3600)+" h"; return Math.round(s/86400)+" d"; }
function uptime(sec){ sec=sec||0; const d=Math.floor(sec/86400),h=Math.floor(sec%86400/3600),m=Math.floor(sec%3600/60);
  if(d) return d+" d "+h+" h"; if(h) return h+" h "+m+" min"; if(m) return m+" min"; return sec+" s"; }

function msg(kind, text){
  const el=document.createElement("div"); el.className="msg msg--"+kind; el.textContent=text;
  $("msgs").appendChild(el); setTimeout(()=>{ el.style.opacity="0"; el.style.transition="opacity .3s"; setTimeout(()=>el.remove(),300); }, 4200);
}

async function admin(path, body){
  const r=await fetch("/admin/"+path,{method:"POST",headers:{"content-type":"application/json"},
    body:JSON.stringify(Object.assign({password:PW}, body||{}))});
  if(r.status===403||r.status===401){ PW=""; sessionStorage.removeItem("bridge-admin-pw"); showLogin("Falsches Passwort oder Sitzung abgelaufen."); throw new Error("auth"); }
  let data=null; try{ data=await r.json(); }catch(e){}
  if(!r.ok){
    let m="Fehler "+r.status; const d=data&&data.detail;
    if(d) m = (typeof d==="string") ? d : (d.message||d.name||JSON.stringify(d));
    throw new Error(m);
  }
  return data||{};
}

async function load(){
  if(!PW){ showLogin(); return; }
  let ov, blocked=[];
  try{ ov=await admin("overview"); }
  catch(e){ if(e.message==="auth") return; $("srvState").innerHTML='<span class="pill pill--warn"><span class="dot"></span>nicht erreichbar</span>'; return; }
  try{ blocked=(await admin("blocked/list")).blocked_servers||[]; }catch(e){}
  render(ov, blocked);
}

function showLogin(m){ if(timer){clearInterval(timer);timer=null;} $("app").hidden=true; $("login").style.display="grid";
  $("loginErr").textContent=m||""; $("pw").value=""; $("pw").focus(); }
function showApp(){ $("login").style.display="none"; $("app").hidden=false; if(!timer) timer=setInterval(load,6000); }

function tile(v,l){ return '<div class="tile"><div class="v">'+v+'</div><div class="l">'+esc(l)+'</div></div>'; }
function rows(head,body){ return '<table><thead><tr>'+head.map(h=>'<th>'+esc(h)+'</th>').join("")+'</tr></thead><tbody>'+body+'</tbody></table>'; }

const SET=[
  ["friends_mode","Freunde-Modus",["open","trusted","local","off"]],
  ["relay_mode","Weiterleiten (Relay)",["off","trusted"]],
  ["accept_relayed","Weitergeleitetes annehmen",["ja","nein"]],
  ["backup_mode","Backup",["peers","off"]],
  ["routing","Routing",["direct","agent"]],
  ["agent_mode","Agent",["learn","frozen","off"]],
  ["conversation_mode","Konversationen",["all","started","off"]],
];

function render(d, blocked){
  showApp();
  const s=d.status||{};
  const starting = (s.backup && s.backup.ready===false);
  $("srvState").innerHTML = starting
    ? '<span class="pill pill--info"><span class="dot"></span>Startet / stellt wieder her …</span>'
    : '<span class="pill pill--ok"><span class="dot"></span>Läuft</span>';
  $("srvUrl").textContent=s.url||"";
  $("selfUrl").textContent=s.url||"";
  $("ver").textContent="Protokoll "+(s.protocol_version||"?");
  $("when").textContent=new Date().toLocaleTimeString("de-DE");

  $("tiles").innerHTML =
    tile(s.clients??0,"Clients")+tile((d.realms||[]).length,"Realms")+tile(s.sessions??0,"Sessions")+
    tile(s.open_tasks??0,"Offene Tasks")+tile(s.conversations??0,"Konversationen")+
    tile((s.trusted_servers||[]).length,"Vertraute")+tile(s.stored_backups??0,"Backups gelagert")+
    tile("↑ "+uptime(s.uptime_seconds),"Laufzeit");

  // Vertraute Server (mit Steuerung)
  const ts=s.trusted_servers||[]; $("tCount").textContent=ts.length;
  const trows = ts.map(t=>{
    const ok=t.status==="connected", wait=(t.status==="waiting"||t.status==="pending");
    const pill=ok?'pill--ok':(wait?'pill--warn':'pill--neutral');
    const label=ok?"Verbunden":(wait?"Wartet":esc(t.status));
    const why=(!ok && t.last_error) ? '<div class="muted" style="font-size:12px;white-space:normal;max-width:340px;margin-top:4px">'+esc(t.last_error)+'</div>' : '';
    return '<tr><td class="mono">'+esc(t.url)+'</td>'+
      '<td><span class="pill '+pill+'"><span class="dot"></span>'+label+'</span>'+why+'</td>'+
      '<td class="mono">'+esc(t.protocol_version||"–")+'</td><td class="mono">'+esc(t.commit||"–")+'</td>'+
      '<td class="act"><button class="btn btn--sm btn--ghost" data-act="trusted-connect" data-url="'+esc(t.url)+'">Neu verbinden</button> '+
      '<button class="btn btn--sm btn--ghost" data-act="trusted-remove" data-url="'+esc(t.url)+'">Entfernen</button></td></tr>';
  }).join("");
  $("trusted").innerHTML =
    (ts.length ? rows(["Server-URL","Status","Version","Commit",""], trows) : '<div class="empty">Noch keine vertrauten Server.</div>')
    + '<div class="addrow"><input class="in mono" id="t-add" placeholder="Adresse des anderen Servers, z. B. https://pc.ts.net:8443" autocomplete="off">'
    + '<button class="btn" data-act="trusted-add" type="button">Hinzufügen</button></div>';

  // Blockierte Server
  blocked=blocked||[]; $("bCount").textContent=blocked.length;
  const brows=blocked.map(u=>'<tr><td class="mono">'+esc(u)+'</td><td class="act">'+
    '<button class="btn btn--sm btn--ghost" data-act="blocked-remove" data-url="'+esc(u)+'">Entsperren</button></td></tr>').join("");
  $("blocked").innerHTML =
    (blocked.length ? rows(["Server-URL",""], brows) : '<div class="empty">Keine blockierten Server.</div>')
    + '<div class="addrow"><input class="in mono" id="b-add" placeholder="https://zu-blockierender-server.ts.net" autocomplete="off">'
    + '<button class="btn btn--ghost" data-act="blocked-add" type="button">Blockieren</button></div>';

  // Clients
  const cl=d.clients||[]; $("cCount").textContent=cl.length;
  $("clients").innerHTML = cl.length ? rows(["Client-IP","Name","Realms","Wartend","Letztes Signal"],
    cl.map(c=>'<tr><td class="mono">'+esc(c.client_ip)+'</td><td>'+esc(c.name||"–")+'</td><td>'+((c.realms||[]).length)+
    '</td><td>'+(c.waiting_messages||0)+'</td><td class="mono">vor '+ago(c.last_signal)+'</td></tr>').join(""))
    : '<div class="empty">Noch keine Clients angemeldet.</div>';

  // Realms
  const rl=d.realms||[]; $("rCount").textContent=rl.length;
  $("realms").innerHTML = rl.length ? rows(["Name","Typ","Mitglieder","Commands","Topics",""],
    rl.map(r=>'<tr><td>'+esc(r.name)+'</td><td>'+esc(r.realm_type)+'</td><td>'+(r.member_count||0)+'</td><td>'+
    (r.commands||0)+'</td><td>'+(r.topics||0)+'</td><td>'+(r.is_public?'<span class="pill pill--info">öffentlich</span>':'')+'</td></tr>').join(""))
    : '<div class="empty">Keine Realms.</div>';

  // Backup
  const b=s.backup||{};
  $("backup").innerHTML='<div class="barrow"><div class="kv">'+
    '<span><b>Modus</b> '+esc(b.mode??"?")+'</span>'+
    '<span><b>Bereit</b> '+(b.ready?"ja":"nein")+'</span>'+
    (b.last_backup_at?'<span><b>Letztes Backup</b> vor '+ago(b.last_backup_at)+'</span>':'')+
    '<span><b>Für andere gelagert</b> '+(s.stored_backups??0)+'</span>'+
    '</div></div>';

  // Einstellungen (editierbar) - nur neu aufbauen, wenn nicht gerade im Fokus
  if(document.activeElement===document.body || !$("settings").querySelector("select")){
    const set=s.settings||{};
    $("settings").innerHTML = SET.map(([key,lbl,opts])=>{
      let cur = set[key];
      if(key==="accept_relayed") cur = cur ? "ja":"nein";
      return '<div class="setfield"><label>'+esc(lbl)+'</label><select class="in" data-set="'+key+'">'+
        opts.map(o=>'<option'+(String(o)===String(cur)?' selected':'')+'>'+esc(o)+'</option>').join("")+'</select></div>';
    }).join("");
  }

  // Aktivität
  const errs=s.errors||{}; const ek=Object.keys(errs);
  $("activity").innerHTML = ek.length
    ? '<div class="kv">'+ek.map(k=>'<span><b>'+esc(k)+'</b> '+esc(errs[k])+'</span>').join("")+'</div>'
    : '<span class="muted">Keine Fehler erfasst.</span>';
}

function fallbackCopy(text, done){
  const ta=document.createElement("textarea"); ta.value=text; ta.style.position="fixed"; ta.style.opacity="0";
  document.body.appendChild(ta); ta.select();
  try{ document.execCommand("copy"); done(); }catch(e){ msg("err","Kopieren ging nicht – bitte von Hand markieren."); }
  ta.remove();
}

async function act(fn, okText){
  if(busy) return; busy=true;
  try{ const r=await fn(); if(okText) msg("ok", okText); await load(); }
  catch(e){ if(e.message!=="auth") msg("err", e.message); }
  finally{ busy=false; }
}

document.addEventListener("click", ev=>{
  const btn=ev.target.closest("[data-act]"); if(!btn) return;
  const a=btn.dataset.act, url=btn.dataset.url;
  if(a==="copy-self"){ const u=$("selfUrl").textContent||"";
    const done=()=>msg("ok","Adresse kopiert: "+u);
    if(navigator.clipboard&&window.isSecureContext){ navigator.clipboard.writeText(u).then(done,()=>fallbackCopy(u,done)); }
    else fallbackCopy(u,done);
    return; }
  if(a==="trusted-add"){ let v=($("t-add").value||"").trim();
    v=v.replace(/\/(admin|server|s2s)(\/.*)?$/i,"").replace(/\/+$/,"");   // aus der Adresszeile kopiertes /admin weg
    if(!v){msg("err","Bitte die Adresse des anderen Servers eingeben.");return;}
    act(()=>admin("trusted/add",{url:v}), "Eingetragen: "+v+" – verbindet, sobald der andere Server dich auch eingetragen hat."); }
  else if(a==="trusted-remove"){ act(()=>admin("trusted/remove",{url}), "Entfernt."); }
  else if(a==="trusted-connect"){ act(()=>admin("trusted/connect",{url}), "Verbindung wird neu aufgebaut."); }
  else if(a==="blocked-add"){ const v=($("b-add").value||"").trim(); if(!v){msg("err","Bitte eine URL eingeben.");return;}
    act(()=>admin("blocked/add",{url:v}), "Server blockiert."); }
  else if(a==="blocked-remove"){ act(()=>admin("blocked/remove",{url}), "Entsperrt."); }
  else if(a==="backup-now"){ act(()=>admin("backup/now"), "Backup ausgelöst."); }
  else if(a==="backup-restore"){ if(confirm("Alles im Arbeitsspeicher mit dem neuesten Backup der Partner ersetzen?"))
    act(()=>admin("backup/restore"), "Wiederherstellung gestartet."); }
  else if(a==="settings-save"){ const body={};
    $("settings").querySelectorAll("select[data-set]").forEach(sel=>{ let v=sel.value;
      if(sel.dataset.set==="accept_relayed") v=(v==="ja"); body[sel.dataset.set]=v; });
    act(()=>admin("settings",body), "Einstellungen gespeichert."); }
  else if(a==="pw-change"){ const np=($("pw-new").value||"").trim(); if(np.length<4){msg("err","Neues Passwort ist zu kurz.");return;}
    if(confirm("Admin-Passwort wirklich ändern?")) act(async()=>{ await admin("password/change",{new_password:np});
      PW=np; sessionStorage.setItem("bridge-admin-pw",np); $("pw-new").value=""; }, "Passwort geändert."); }
  else if(a==="agent-reset"){ if(confirm("BridgeAgent auf die Grundwerte zurücksetzen?"))
    act(()=>admin("agent",{action:"reset"}), "Agent zurückgesetzt."); }
  else if(a==="reset"){ if(confirm("Server wirklich zurücksetzen? Clients, Nachrichten und Realms werden gelöscht (vertraute Server bleiben)."))
    act(()=>admin("reset"), "Server zurückgesetzt."); }
});

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
