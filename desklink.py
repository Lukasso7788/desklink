"""DeskLink: visible, manually enabled Windows remote desktop host."""
import asyncio
import ctypes as C
from ctypes import wintypes as W
import datetime as dt
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import ssl
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk

from aiohttp import web, WSMsgType
from PIL import ImageGrab
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

PORT = 47831
VERSION = '0.2.0'
PROFILES = {'balanced': (1920, 1200, 80), 'sharp': (2560, 1600, 92), 'native': (0, 0, 96)}
ROOT = Path(getattr(sys, '_MEIPASS', Path(__file__).parent))


class Mouse(C.Structure):
    _fields_ = [('dx', W.LONG), ('dy', W.LONG), ('mouseData', W.DWORD),
                ('dwFlags', W.DWORD), ('time', W.DWORD), ('dwExtraInfo', C.c_size_t)]


class Keyboard(C.Structure):
    _fields_ = [('wVk', W.WORD), ('wScan', W.WORD), ('dwFlags', W.DWORD),
                ('time', W.DWORD), ('dwExtraInfo', C.c_size_t)]


class Payload(C.Union):
    _fields_ = [('mi', Mouse), ('ki', Keyboard)]


class Input(C.Structure):
    _anonymous_ = ('data',)
    _fields_ = [('type', W.DWORD), ('data', Payload)]


class Desktop:
    def __init__(self):
        self.user = C.WinDLL('user32', use_last_error=True)
        self.user.SendInput.argtypes = (W.UINT, C.POINTER(Input), C.c_int)
        self.keys, self.buttons = set(), set()

    def send(self, item):
        if self.user.SendInput(1, C.byref(item), C.sizeof(Input)) != 1:
            raise RuntimeError('Windows заблокировала ввод (возможно, окно администратора).')

    def key(self, code, down):
        extended = code in (33, 34, 35, 36, 37, 38, 39, 40, 45, 46, 91, 92)
        self.send(Input(type=1, ki=Keyboard(wVk=code, dwFlags=(1 if extended else 0) | (0 if down else 2))))
        (self.keys.add if down else self.keys.discard)(code)

    def release(self):
        for code in list(self.keys):
            try:
                self.key(code, False)
            except RuntimeError:
                self.keys.discard(code)
        for button in list(self.buttons):
            try:
                self.button(button, False)
            except RuntimeError:
                self.buttons.discard(button)

    def button(self, button, down):
        flags = {0: (2, 4), 1: (32, 64), 2: (8, 16)}
        self.send(Input(type=0, mi=Mouse(dwFlags=flags[button][0 if down else 1])))
        (self.buttons.add if down else self.buttons.discard)(button)

    def cursor(self):
        class CursorInfo(C.Structure):
            _fields_ = [('cbSize', W.DWORD), ('flags', W.DWORD), ('hCursor', W.HANDLE), ('ptScreenPos', W.POINT)]
        info = CursorInfo(cbSize=C.sizeof(CursorInfo))
        if not self.user.GetCursorInfo(C.byref(info)):
            return {'type': 'cursor', 'visible': False}
        self.user.LoadCursorW.restype = W.HANDLE
        self.user.LoadCursorW.argtypes = (W.HINSTANCE, C.c_void_p)
        shapes = {32512:'default',32513:'text',32514:'wait',32649:'pointer',32644:'ew-resize',32645:'ns-resize',32642:'nwse-resize',32643:'nesw-resize',32646:'move',32648:'not-allowed',32650:'progress',32515:'crosshair'}
        shape = next((name for resource, name in shapes.items() if self.user.LoadCursorW(None, resource) == info.hCursor), 'default')
        return {'type':'cursor', 'visible':bool(info.flags & 1), 'shape':shape,
                'x':info.ptScreenPos.x / max(1, self.user.GetSystemMetrics(0)-1),
                'y':info.ptScreenPos.y / max(1, self.user.GetSystemMetrics(1)-1)}

    def capture(self, profile='sharp'):
        im = ImageGrab.grab()  # Primary display; DPI awareness set before UI creation.
        width, height, quality = PROFILES[profile]
        if width:
            im.thumbnail((width, height))
        out = io.BytesIO()
        im.convert('RGB').save(out, 'JPEG', quality=quality, subsampling=0)
        return out.getvalue()

    def event(self, event):
        kind = event.get('type')
        if kind == 'release':
            self.release()
        elif kind == 'move':
            x, y = float(event['x']), float(event['y'])
            if not (0 <= x <= 1 and 0 <= y <= 1):
                raise ValueError('Invalid position')
            self.user.SetCursorPos(round(x * (self.user.GetSystemMetrics(0) - 1)),
                                   round(y * (self.user.GetSystemMetrics(1) - 1)))
        elif kind == 'button' and event.get('button') in (0, 1, 2):
            self.button(event['button'], event.get('down') is True)
        elif kind == 'wheel':
            delta = max(-1200, min(1200, int(event['delta'])))
            self.send(Input(type=0, mi=Mouse(mouseData=delta & 0xffffffff, dwFlags=0x800)))
        elif kind == 'key':
            code = event.get('code')
            if type(code) is not int or not 8 <= code <= 254:
                raise ValueError('Invalid key')
            self.key(code, event.get('down') is True)
        elif kind == 'text':
            text = event.get('text', '')
            if not isinstance(text, str) or len(text) > 2000:
                raise ValueError('Text too long')
            raw = text.encode('utf-16-le')
            for i in range(0, len(raw), 2):
                unit = int.from_bytes(raw[i:i+2], 'little')
                self.send(Input(type=1, ki=Keyboard(wScan=unit, dwFlags=4)))
                self.send(Input(type=1, ki=Keyboard(wScan=unit, dwFlags=6)))
        else:
            raise ValueError('Unknown event')


def addresses():
    found = {'127.0.0.1'}
    try:
        found.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return sorted(found)


def certificate(folder, ips):
    """Persistent identity; private key encrypted with Windows DPAPI via CryptProtectData."""
    certfile, keyfile = folder / 'identity.pem', folder / 'identity.key'
    # DPAPI local-user protection keeps the persistent key off disk in plaintext.
    class Blob(C.Structure):
        _fields_ = [('size', W.DWORD), ('data', C.POINTER(C.c_ubyte))]

    def protect(raw, decrypt=False):
        buf = C.create_string_buffer(raw)
        src = Blob(len(raw), C.cast(buf, C.POINTER(C.c_ubyte)))
        dest = Blob()
        crypt = C.WinDLL('crypt32', use_last_error=True)
        fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
        if not fn(C.byref(src), None, None, None, None, 1, C.byref(dest)):
            raise C.WinError(C.get_last_error())
        try:
            return C.string_at(dest.data, dest.size)
        finally:
            kernel = C.WinDLL('kernel32')
            kernel.LocalFree.argtypes = [C.c_void_p]
            kernel.LocalFree(dest.data)

    if not certfile.exists() or not keyfile.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DeskLink')])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=365))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                    x509.DNSName(socket.gethostname())] + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]), False)
                .sign(key, hashes.SHA256()))
        certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        keyfile.write_bytes(protect(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))
    pem = protect(keyfile.read_bytes(), True)
    # SSLContext requires a filename. The temporary key is encrypted with a random password.
    key = serialization.load_pem_private_key(pem, password=None)
    password = secrets.token_urlsafe(32).encode()
    temporary = folder / ('tls-' + secrets.token_hex(8) + '.tmp')
    try:
        temporary.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(password)))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile, temporary, password)
    finally:
        temporary.unlink(missing_ok=True)
    cert = x509.load_pem_x509_certificate(certfile.read_bytes())
    return ctx, cert.fingerprint(hashes.SHA256()).hex(':').upper()


class Host:
    def __init__(self, password, report, desktop=None):
        self.password, self.report = password, report
        self.desktop = desktop or Desktop()
        self.sessions = {}
        self.failures = []
        self.ws = None
        self.ws_token = None
        self.runner = None
        self.loop = None

    def valid(self, request):
        token = request.cookies.get('desklink', '')
        return self.sessions.get(token, 0) > time.monotonic()

    @staticmethod
    def same_origin(request):
        return request.headers.get('Origin') == f'https://{request.host}'

    def app(self):
        @web.middleware
        async def guard(request, handler):
            try:
                response = await handler(request)
            except web.HTTPException as error:
                response = web.Response(status=error.status, text=error.text, headers=error.headers)
            response.headers.update({'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
                'Content-Security-Policy': "default-src 'self'; img-src 'self' blob:; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'"})
            return response
        app = web.Application(middlewares=[guard], client_max_size=16384)
        async def asset(request):
            name = request.match_info.get('asset', 'index.html')
            if name not in ('index.html', 'app.js', 'style.css'):
                raise web.HTTPNotFound()
            return web.FileResponse(ROOT / 'web' / name)
        app.router.add_get('/', asset)
        app.router.add_post('/login', self.login)
        app.router.add_post('/logout', self.logout)
        app.router.add_get('/stream', self.stream)
        app.router.add_get('/{asset}', asset)
        return app

    async def login(self, request):
        if not self.same_origin(request):
            raise web.HTTPForbidden()
        now = time.monotonic()
        self.failures = [t for t in self.failures if now - t < 60]
        if len(self.failures) >= 5:
            raise web.HTTPTooManyRequests(text='Подождите минуту перед следующей попыткой.')
        try:
            data = await request.json()
        except (ValueError, UnicodeDecodeError):
            raise web.HTTPBadRequest(text='Некорректный запрос')
        supplied = data.get('password', '') if isinstance(data, dict) else ''
        if not isinstance(supplied, str) or not secrets.compare_digest(supplied.encode(), self.password.encode()):
            self.failures.append(now)
            raise web.HTTPUnauthorized(text='Неверный пароль')
        self.sessions = {t: expiry for t, expiry in self.sessions.items() if expiry > now}
        if len(self.sessions) >= 8:
            raise web.HTTPTooManyRequests(text='Слишком много сеансов')
        token = secrets.token_urlsafe(32)
        self.sessions[token] = now + 3600
        response = web.json_response({'ok': True})
        response.set_cookie('desklink', token, secure=True, httponly=True, samesite='Strict', max_age=3600)
        return response

    async def logout(self, request):
        if not self.same_origin(request):
            raise web.HTTPForbidden()
        token = request.cookies.get('desklink', '')
        self.sessions.pop(token, None)
        if self.ws is not None and self.ws_token == token:
            self.desktop.release()
            await self.ws.close(code=1000, message=b'Logged out')
        response = web.json_response({'ok': True})
        response.del_cookie('desklink')
        return response

    async def stream(self, request):
        if not self.same_origin(request) or not self.valid(request):
            raise web.HTTPUnauthorized()
        if self.ws is not None:
            raise web.HTTPConflict(text='Компьютером уже управляет другой сеанс')
        ws = web.WebSocketResponse(heartbeat=15, max_msg_size=16384, compress=False)
        self.ws = ws  # Reserve before prepare awaits: only one controller can acquire input.
        self.ws_token = request.cookies.get('desklink')
        sender = None
        try:
            await ws.prepare(request)
            self.report('Подключён: ' + (request.remote or 'unknown'))
            settings = {'profile':'sharp'}
            async def frames():
                while not ws.closed and self.valid(request):
                    frame = await asyncio.to_thread(self.desktop.capture, settings['profile'])
                    if hasattr(self.desktop, 'cursor'):
                        await ws.send_json(self.desktop.cursor())
                    await asyncio.wait_for(ws.send_bytes(frame), timeout=5)
                    await asyncio.sleep(0.16)
                self.desktop.release()
                await ws.close()
            async def guarded_frames():
                try:
                    await frames()
                except Exception:
                    await ws.close(code=1011, message=b'Screen capture unavailable')
            sender = asyncio.create_task(guarded_frames())
            window, count = time.monotonic(), 0
            async for msg in ws:
                if not self.valid(request):
                    break
                if msg.type == WSMsgType.TEXT:
                    now = time.monotonic()
                    if now - window >= 1:
                        window, count = now, 0
                    count += 1
                    if count > 250:
                        break
                    try:
                        event = json.loads(msg.data)
                        if not isinstance(event, dict):
                            raise ValueError('Invalid event')
                        if event.get('type') == 'quality':
                            if event.get('profile') not in PROFILES:
                                raise ValueError('Unknown quality profile')
                            settings['profile'] = event['profile']
                            await ws.send_json({'type':'quality','profile':settings['profile']})
                        else:
                            self.desktop.event(event)
                    except (ValueError, KeyError, TypeError, OverflowError, RuntimeError) as error:
                        await ws.send_json({'error': str(error)})
        finally:
            if sender:
                sender.cancel()
                await asyncio.gather(sender, return_exceptions=True)
            self.desktop.release()
            await ws.close()
            self.ws = None
            self.ws_token = None
            self.report('Доступ включён. Ожидание подключения.')
        return ws

    async def start(self, ctx, bind='0.0.0.0', port=PORT):
        self.loop = asyncio.get_running_loop()
        self.runner = web.AppRunner(self.app(), access_log=None, shutdown_timeout=2)
        await self.runner.setup()
        try:
            await web.TCPSite(self.runner, bind, port, ssl_context=ctx).start()
        except Exception:
            await self.runner.cleanup()
            raise

    async def stop(self):
        self.sessions.clear()
        self.desktop.release()
        if self.ws is not None:
            await self.ws.close(code=1001, message=b'Host stopped')
        if self.runner:
            await self.runner.cleanup()
        self.desktop.release()


class Window:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('DeskLink ' + VERSION + ' — удалённый доступ')
        self.root.geometry('720x660')
        self.root.minsize(680, 520)
        self.events = queue.Queue()
        self.host = None
        self.thread = None
        self.closing = False
        self.password = tk.StringVar(value=secrets.token_urlsafe(12))
        self.status = tk.StringVar(value='Доступ выключен')
        frame = ttk.Frame(self.root, padding=24)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='DeskLink', font=('Segoe UI', 26, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Ваш компьютер. Ваш доступ.', font=('Segoe UI', 12)).pack(anchor='w', pady=(0, 18))
        ttk.Label(frame, text='1. Включите доступ на этом компьютере.\n2. Откройте адрес ниже в браузере ноутбука.\n3. Проверьте сертификат и введите пароль.', justify='left').pack(anchor='w')
        ttk.Label(frame, text='Пароль (новый при каждом запуске):').pack(anchor='w', pady=(16, 4))
        self.entry = ttk.Entry(frame, textvariable=self.password, font=('Consolas', 14), state='readonly')
        self.entry.pack(fill='x')
        self.info = tk.Text(frame, height=8, wrap='word', font=('Consolas', 10), state='disabled', takefocus=False)
        self.info.pack(fill='both', expand=True, pady=12)
        row = ttk.Frame(frame)
        row.pack(fill='x')
        self.start_button = ttk.Button(row, text='Включить доступ', command=self.start)
        self.start_button.pack(side='left')
        self.stop_button = ttk.Button(row, text='Остановить доступ', command=self.stop, state='disabled')
        self.stop_button.pack(side='left', padx=10)
        ttk.Label(frame, textvariable=self.status, font=('Segoe UI', 11, 'bold')).pack(anchor='w', pady=14)
        ttk.Label(frame, text='Закрытие окна отключает доступ. Экран: основной монитор.').pack(anchor='w')
        ttk.Label(frame, text='Обновления: HTTPS-адрес файла release.json').pack(anchor='w', pady=(12, 3))
        self.update_url = ttk.Entry(frame)
        self.update_url.insert(0, 'https://github.com/lukasso7788/desklink/releases/latest/download/release.json')
        self.update_url.pack(fill='x')
        self.update_button = ttk.Button(frame, text='Проверить и скачать обновление', command=self.update)
        self.update_button.pack(anchor='w', pady=6)
        self.root.protocol('WM_DELETE_WINDOW', self.close)
        self.root.after(100, self.poll)

    def update(self):
        from updater import download_update
        url = self.update_url.get().strip()
        self.update_button['state'] = 'disabled'
        self.status.set('Проверяю обновление…')
        def worker():
            try:
                result = download_update(url, VERSION, Path.home() / 'Downloads')
                self.events.put(('update', 'Установлена последняя версия.' if result is None else 'Скачано: ' + str(result)))
            except Exception as error:
                self.events.put(('update', 'Обновление: ' + str(error)))
        threading.Thread(target=worker, daemon=True).start()

    def start(self):
        self.start_button['state'] = 'disabled'
        password = self.password.get()
        self.status.set('Запускаю защищённое подключение…')
        def worker():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                folder = Path(os.environ['LOCALAPPDATA']) / 'DeskLink'
                folder.mkdir(parents=True, exist_ok=True)
                ips = addresses()
                ctx, fingerprint = certificate(folder, ips)
                host = Host(password, lambda message: self.events.put(('status', message)))
                loop.run_until_complete(host.start(ctx))
                self.host = host
                self.events.put(('ready', '\n'.join(f'https://{ip}:{PORT}' for ip in ips)
                    + '\n\nSHA-256 сертификата:\n' + fingerprint))
                loop.run_forever()
            except Exception as error:
                self.events.put(('error', str(error)))
            finally:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.run_until_complete(loop.shutdown_default_executor())
                loop.close()
                self.events.put(('stopped', ''))
        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_button['state'] = 'disabled'
        self.status.set('Отключаю доступ…')
        host = self.host
        if host and host.loop and host.loop.is_running():
            future = asyncio.run_coroutine_threadsafe(host.stop(), host.loop)
            future.add_done_callback(lambda _: host.loop.call_soon_threadsafe(host.loop.stop))

    def close(self):
        self.closing = True
        if self.thread and self.thread.is_alive():
            self.stop()
        else:
            self.root.destroy()

    def poll(self):
        while not self.events.empty():
            kind, text = self.events.get()
            if kind == 'ready':
                self.info['state'] = 'normal'
                self.info.delete('1.0', 'end')
                self.info.insert('1.0', text)
                self.info['state'] = 'disabled'
                self.stop_button['state'] = 'normal'
                self.status.set('Доступ включён. Ожидание подключения.')
                if self.closing:
                    self.stop()
            elif kind == 'status':
                self.status.set(text)
            elif kind == 'update':
                self.update_button['state'] = 'normal'
                self.status.set(text)
            elif kind == 'error':
                self.status.set('Ошибка: ' + text)
            elif kind == 'stopped':
                self.host = None
                self.start_button['state'] = 'normal'
                self.stop_button['state'] = 'disabled'
                if not self.status.get().startswith('Ошибка'):
                    self.status.set('Доступ выключен')
                self.password.set(secrets.token_urlsafe(12))
                if self.closing:
                    self.root.destroy()
                    return
        self.root.after(100, self.poll)


if __name__ == '__main__':
    try:
        C.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        C.windll.user32.SetProcessDPIAware()
    Window().root.mainloop()
