const quickToken = new URLSearchParams(location.hash.slice(1)).get('connect');
if(location.hash) history.replaceState(null, '', location.pathname + location.search);
const $ = id => document.getElementById(id);
let remoteCursor = null;
let ws, url, sending = false, generation = 0, latestMove = null;
const status = text => $('status').textContent = text;
function send(data) { if (ws?.readyState === 1) ws.send(JSON.stringify(data)); }
function release() { $('remoteCursor').classList.remove('pressed'); send({type:'release'}); }
function active() { return $('control').checked && ws?.readyState === 1; }
async function disconnect() {
  generation++; release(); ws?.close(); ws = null;
  if (url) URL.revokeObjectURL(url); url = null;
  remoteCursor = null; $('remoteCursor').hidden = true; $('screen').style.cursor = ''; $('screen').removeAttribute('src'); $('remote').hidden = true; $('login').hidden = false;
  $('control').checked = false; $('stage').classList.remove('active');
  await fetch('/logout', {method:'POST'}).catch(() => {});
  status('Доступ отключён');
}
async function connect(endpoint, payload) {
  const button = $('form').querySelector('button'); button.disabled = true;
  try {
    const response = await fetch(endpoint, {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload)});
    if (!response.ok) throw new Error(await response.text());
    $('password').value = ''; const current = ++generation;
    ws = new WebSocket(`wss://${location.host}/stream`); ws.binaryType = 'blob';
    ws.onopen = () => { $('login').hidden = true; $('remote').hidden = false; status('Подключено · просмотр экрана'); send({type:'quality',profile:$('quality').value}); };
    ws.onmessage = async e => {
      if (typeof e.data === 'string') { const data = JSON.parse(e.data); if(data.type === 'cursor'){remoteCursor=data;drawCursor();}else if(data.type === 'quality'){$('quality').value=data.profile;}else if(data.error){status(data.error);} return; }
      if (sending) return; sending = true;
      const next = URL.createObjectURL(e.data), image = new Image(); image.src = next;
      try {
        await image.decode();
        if (generation !== current) { URL.revokeObjectURL(next); return; }
        if (url) URL.revokeObjectURL(url); url = next; $('screen').src = next; drawCursor();
      } catch { URL.revokeObjectURL(next); } finally { sending = false; }
    };
    ws.onclose = () => { if (generation === current) { disconnect(); status('Соединение закрыто. Подключитесь снова.'); } };
    ws.onerror = () => status('Не удалось подключиться. Проверьте, включён ли доступ.');
  } catch(error) { status(error.message); } finally { button.disabled = false; }
};
$('form').onsubmit = e => { e.preventDefault(); connect('/login', {password:$('password').value}); };
async function quickConnect(token) {
  if(ws) await disconnect();
  status('Выполняю быстрый вход…');
  await connect('/quick-login', {token});
}
if(quickToken) quickConnect(quickToken);
window.addEventListener('hashchange', () => {
  const token = new URLSearchParams(location.hash.slice(1)).get('connect');
  if(location.hash) history.replaceState(null, '', location.pathname + location.search);
  if(token) quickConnect(token);
});
$('disconnect').onclick = disconnect;
$('fullscreen').onclick = () => $('stage').requestFullscreen().catch(error => status(error.message));
$('control').onchange = () => { release(); $('stage').classList.toggle('active', active()); drawCursor(); status(active() ? 'Подключено · управление включено' : 'Подключено · просмотр экрана'); };
function position(e) {
  const r = $('screen').getBoundingClientRect();
  if (!r.width || !r.height) return null;
  return {type:'move',x:Math.max(0,Math.min(1,(e.clientX-r.left)/r.width)),y:Math.max(0,Math.min(1,(e.clientY-r.top)/r.height))};
}
$('screen').onpointermove = e => { if(active()) latestMove = position(e); };
setInterval(() => { if (latestMove && active()) send(latestMove); latestMove = null; }, 30);
$('screen').onpointerdown = e => {
  $('remoteCursor').classList.add('pressed');
  if(!active() || e.button > 2) return; e.preventDefault(); $('stage').focus();
  latestMove = null; const p = position(e); if(p) send(p);
  $('screen').setPointerCapture(e.pointerId); send({type:'button',button:e.button,down:true});
};
$('screen').onpointerup = e => { $('remoteCursor').classList.remove('pressed'); if(active() && e.button <= 2) { const p=position(e); if(p) send(p); send({type:'button',button:e.button,down:false}); } };
$('screen').onpointercancel = release;
$('screen').oncontextmenu = e => e.preventDefault();
$('screen').addEventListener('wheel', e => { if(active()){e.preventDefault();send({type:'wheel',delta:e.deltaY > 0 ? -120 : 120});} }, {passive:false});
const keys = {Backspace:8,Tab:9,Enter:13,ShiftLeft:16,ShiftRight:16,ControlLeft:17,ControlRight:17,AltLeft:18,AltRight:18,Pause:19,CapsLock:20,Escape:27,Space:32,PageUp:33,PageDown:34,End:35,Home:36,ArrowLeft:37,ArrowUp:38,ArrowRight:39,ArrowDown:40,Insert:45,Delete:46,MetaLeft:91,MetaRight:92,Semicolon:186,Equal:187,Comma:188,Minus:189,Period:190,Slash:191,Backquote:192,BracketLeft:219,Backslash:220,BracketRight:221,Quote:222};
function keycode(code) { if(/^Key[A-Z]$/.test(code)) return code.charCodeAt(3); if(/^Digit[0-9]$/.test(code)) return code.charCodeAt(5); if(/^F([1-9]|1[0-2])$/.test(code)) return 111+Number(code.slice(1)); return keys[code]; }
for(const name of ['keydown','keyup']) $('stage').addEventListener(name, e => {
  if(!active()) return; if(e.code === 'Escape'){release();$('stage').blur();return;}
  const code=keycode(e.code); if(code){e.preventDefault();send({type:'key',code,down:name==='keydown'});}
});
$('stage').addEventListener('blur', release);
window.addEventListener('blur', release);
document.addEventListener('visibilitychange', () => {if(document.hidden) release();});
$('sendtext').onclick = () => { if(active()){send({type:'text',text:$('text').value});$('text').value='';}else status('Сначала включите мышь и клавиатуру'); };

$('quality').onchange = () => send({type:'quality',profile:$('quality').value});
function drawCursor() {
  const marker = $('remoteCursor'), c = remoteCursor;
  if(!c?.visible || c.x<0 || c.x>1 || c.y<0 || c.y>1){marker.hidden=true;return;}
  const screen=$('screen').getBoundingClientRect(), stage=$('stage').getBoundingClientRect();
  marker.hidden=false;
  marker.style.left=`${screen.left-stage.left+$('stage').scrollLeft+c.x*screen.width}px`;
  marker.style.top=`${screen.top-stage.top+$('stage').scrollTop+c.y*screen.height}px`;
  const shapes=['default','text','wait','pointer','ew-resize','ns-resize','nwse-resize','nesw-resize','move','not-allowed','progress','crosshair'];
  $('screen').style.cursor=active() && shapes.includes(c.shape) ? c.shape : 'default';
}
new ResizeObserver(drawCursor).observe($('stage'));
$('screen').addEventListener('load', drawCursor);
document.addEventListener('fullscreenchange', drawCursor);

$('zoom').onclick = () => {
  const pixel = $('stage').classList.toggle('pixel');
  $('zoom').setAttribute('aria-pressed', String(pixel));
  $('zoom').textContent = pixel ? 'Вписать в окно' : 'Масштаб 100%';
  drawCursor();
};
