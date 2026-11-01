"""DeskLink Client: remember paired hosts and open short-lived browser sign-in links."""
import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import queue
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse
import webbrowser

import aiohttp
from device_store import protect

VERSION = '0.3.0'


def normalize_address(value):
    value = value.strip()
    if '://' not in value:
        value = 'https://' + value
    parsed = urlparse(value)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('Введите только HTTPS-адрес компьютера, например https://192.168.1.10:47831')
    port = parsed.port or 47831
    hostname = '[' + parsed.hostname + ']' if ':' in parsed.hostname else parsed.hostname
    return f'https://{hostname}:{port}'


def fingerprint(address):
    parsed = urlparse(address)
    pem = ssl.get_server_certificate((parsed.hostname, parsed.port), timeout=10)
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()


async def browser_access(address, pinned, password=None, token=None):
    """Pin the host certificate; never disable certificate checks for later API calls."""
    pin = aiohttp.Fingerprint(bytes.fromhex(pinned))
    async with aiohttp.ClientSession(cookie_jar=aiohttp.CookieJar(unsafe=True),
            timeout=aiohttp.ClientTimeout(total=20), headers={'Origin':address}) as client:
        async def post(endpoint, payload=None):
            async with client.post(address+endpoint, json=payload, ssl=pin) as response:
                if response.status != 200:
                    if response.status == 404:
                        raise RuntimeError('Обновите DeskLink на компьютере до версии 0.3.0 или новее.')
                    raise RuntimeError((await response.text())[:300])
                return await response.json()
        await post('/login' if password is not None else '/device-login',
                   {'password':password} if password is not None else {'token':token})
        try:
            if password is not None:
                result = await post('/pair')
                return {'address':address, 'fingerprint':pinned, 'token':result['token']}
            return (await post('/browser-link'))['url']
        finally:
            await post('/logout')


class Client:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title('DeskLink Client ' + VERSION + ' — мои компьютеры')
        self.root.geometry('720x650')
        self.root.minsize(680, 600)
        self.folder = Path(os.environ['LOCALAPPDATA']) / 'DeskLinkClient'
        self.file = self.folder / 'computers.dat'
        self.events = queue.Queue()
        self.busy = False
        self.devices = []
        load_error = None
        try:
            if self.file.exists():
                self.devices = json.loads(protect(self.file.read_bytes(), True))
                if not isinstance(self.devices, list):
                    raise ValueError('Некорректный список компьютеров')
        except Exception:
            load_error = 'Не удалось прочитать привязки этого профиля Windows. Файл не изменён.'
        self.load_error = load_error
        frame = ttk.Frame(self.root, padding=24)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Мои компьютеры', font=('Segoe UI', 24, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Один раз привяжите компьютер. Затем открывайте экран одной кнопкой.').pack(anchor='w', pady=12)
        self.list = tk.Listbox(frame, height=6, font=('Segoe UI', 12), exportselection=False)
        self.list.pack(fill='both', expand=True)
        self.list.bind('<Double-Button-1>', lambda _: self.open())
        row = ttk.Frame(frame)
        row.pack(fill='x', pady=10)
        self.open_button = ttk.Button(row, text='Открыть экран в браузере', command=self.open)
        self.open_button.pack(side='left')
        ttk.Button(row, text='Скопировать ссылку', command=lambda: self.open(copy_only=True)).pack(side='left', padx=8)
        ttk.Button(row, text='Забыть на этом ноутбуке', command=self.forget).pack(side='left', padx=8)
        ttk.Separator(frame).pack(fill='x', pady=8)
        ttk.Label(frame, text='Добавить компьютер', font=('Segoe UI', 13, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Адрес из окна DeskLink на компьютере:').pack(anchor='w', pady=(8, 3))
        self.address = ttk.Entry(frame)
        self.address.pack(fill='x')
        ttk.Label(frame, text='Пароль из того же окна — только для первой привязки:').pack(anchor='w', pady=(8, 3))
        self.password = ttk.Entry(frame, show='●')
        self.password.pack(fill='x')
        self.add_button = ttk.Button(frame, text='Привязать компьютер', command=self.add)
        self.add_button.pack(anchor='w', pady=8)
        self.status = tk.StringVar(value=load_error or 'На компьютере должен быть включён доступ в DeskLink 0.3.0 или новее.')
        ttk.Label(frame, textvariable=self.status, wraplength=650).pack(anchor='w', pady=10)
        ttk.Button(frame, text='Установить клиент на этот ноутбук', command=self.install).pack(anchor='w')
        self.refresh()
        self.root.after(100, self.poll)

    def save(self):
        self.folder.mkdir(parents=True, exist_ok=True)
        temporary = self.file.with_suffix('.tmp')
        temporary.write_bytes(protect(json.dumps(self.devices).encode()))
        temporary.replace(self.file)

    def refresh(self):
        self.list.delete(0, 'end')
        for device in self.devices:
            self.list.insert('end', device['address'])
        if self.devices:
            self.list.selection_set(0)

    def worker(self, function, kind):
        if self.busy:
            return
        self.busy = True
        self.open_button['state'] = self.add_button['state'] = 'disabled'
        def run():
            try:
                self.events.put((kind, function()))
            except Exception as error:
                self.events.put(('error', str(error)))
        threading.Thread(target=run, daemon=True).start()

    def add(self):
        if self.busy:
            return
        if self.load_error:
            messagebox.showerror('Привязки', self.load_error, parent=self.root)
            return
        try:
            address = normalize_address(self.address.get())
            if not self.password.get():
                raise ValueError('Введите пароль из окна DeskLink на компьютере.')
        except ValueError as error:
            self.status.set(str(error))
            return
        self.status.set('Получаю отпечаток сертификата компьютера…')
        self.worker(lambda: (address, fingerprint(address)), 'fingerprint')

    def open(self, copy_only=False):
        if self.busy:
            return
        selected = self.list.curselection()
        if not selected:
            self.status.set('Сначала добавьте или выберите компьютер.')
            return
        device = dict(self.devices[selected[0]])
        self.status.set('Получаю ссылку и открываю браузер…')
        self.worker(lambda: asyncio.run(browser_access(device['address'], device['fingerprint'], token=device['token'])), 'copy' if copy_only else 'open')

    def forget(self):
        if self.busy or self.load_error:
            return
        selected = self.list.curselection()
        if selected:
            device = self.devices.pop(selected[0])
            try:
                self.save()
            except Exception as error:
                self.devices.insert(selected[0], device)
                self.status.set('Не удалось сохранить: ' + str(error))
                return
            self.refresh()
            self.status.set('Компьютер удалён с этого ноутбука. Полный отзыв доступа — кнопкой «Сбросить привязки» на компьютере.')

    def install(self):
        if not getattr(sys, 'frozen', False):
            self.status.set('Установка доступна в собранном DeskLinkClient.exe.')
            return
        try:
            destination = Path(os.environ['LOCALAPPDATA']) / 'Programs' / 'DeskLink'
            destination.mkdir(parents=True, exist_ok=True)
            target = destination / 'DeskLinkClient.exe'
            if Path(sys.executable).resolve() != target.resolve():
                shutil.copy2(sys.executable, target)
            script = "$shortcutPath=Join-Path ([Environment]::GetFolderPath('Programs')) 'DeskLink Client.lnk'; $taskShell=New-Object -ComObject WScript.Shell; $taskShortcut=$taskShell.CreateShortcut($shortcutPath); $taskShortcut.TargetPath=$env:DESKLINK_CLIENT_TARGET; $taskShortcut.Save()"
            subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-WindowStyle','Hidden','-Command',script],
                env={**os.environ, 'DESKLINK_CLIENT_TARGET':str(target)}, creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True, check=True, timeout=20)
            self.status.set('Клиент установлен. Открывайте «DeskLink Client» через меню Пуск.')
        except Exception as error:
            self.status.set('Не удалось установить: ' + str(error))

    def poll(self):
        while not self.events.empty():
            kind, value = self.events.get()
            self.busy = False
            self.open_button['state'] = self.add_button['state'] = 'normal'
            if kind == 'fingerprint':
                address, pin = value
                shown = ':'.join(pin[i:i+2] for i in range(0,len(pin),2)).upper()
                if messagebox.askyesno('Проверка компьютера', 'Сравните SHA-256 с окном DeskLink на компьютере:\n\n'+shown+'\n\nОтпечатки полностью совпадают?', parent=self.root):
                    password = self.password.get()
                    self.password.delete(0, 'end')
                    self.status.set('Привязываю ноутбук…')
                    self.worker(lambda: asyncio.run(browser_access(address, pin, password=password)), 'paired')
                else:
                    self.password.delete(0, 'end')
                    self.status.set('Привязка отменена.')
            elif kind == 'paired':
                previous = list(self.devices)
                self.devices = [device for device in self.devices if device['address'] != value['address']] + [value]
                try:
                    self.save()
                    self.refresh()
                    self.status.set('Компьютер сохранён. Выберите его и нажмите «Открыть экран в браузере».')
                except Exception as error:
                    self.devices = previous
                    self.status.set('Не удалось сохранить привязку: ' + str(error))
            elif kind == 'open':
                if webbrowser.open(value):
                    self.status.set('Экран открыт в браузере. При первом входе проверьте сертификат браузера.')
                else:
                    self.status.set('Не удалось запустить браузер. Проверьте браузер по умолчанию.')
            elif kind == 'copy':
                self.root.clipboard_clear()
                self.root.clipboard_append(value)
                self.status.set('Одноразовая ссылка скопирована. Действует 5 минут.')
            else:
                self.status.set('Не удалось подключиться: ' + value)
        self.root.after(100, self.poll)


if __name__ == '__main__':
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass
    Client().root.mainloop()
