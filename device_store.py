"""Revocable device credentials: host stores hashes; client secrets use Windows DPAPI."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
from pathlib import Path
import secrets
import time


def protect(raw, decrypt=False):
    class Blob(C.Structure):
        _fields_ = [('size', W.DWORD), ('data', C.POINTER(C.c_ubyte))]
    buffer = C.create_string_buffer(raw)
    source = Blob(len(raw), C.cast(buffer, C.POINTER(C.c_ubyte)))
    target = Blob()
    crypt = C.WinDLL('crypt32', use_last_error=True)
    fn = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    if not fn(C.byref(source), None, None, None, None, 1, C.byref(target)):
        raise C.WinError(C.get_last_error())
    try:
        return C.string_at(target.data, target.size)
    finally:
        kernel = C.WinDLL('kernel32')
        kernel.LocalFree.argtypes = [C.c_void_p]
        kernel.LocalFree(target.data)


class DeviceStore:
    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.devices = {}
        if self.path and self.path.exists():
            data = json.loads(self.path.read_text(encoding='utf-8'))
            if not isinstance(data, dict):
                raise ValueError('Invalid device store')
            self.devices = data

    def save(self):
        self.devices = {key:expiry for key, expiry in self.devices.items()
                        if expiry is None or expiry > time.time()}
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.path.with_suffix('.tmp')
            temporary.write_text(json.dumps(self.devices), encoding='utf-8')
            temporary.replace(self.path)

    def issue(self):
        self.save()
        if len(self.devices) >= 10:
            raise ValueError('Слишком много привязанных ноутбуков. Сбросьте привязки на компьютере.')
        token = secrets.token_urlsafe(32)
        self.devices[hashlib.sha256(token.encode()).hexdigest()] = None
        self.save()
        return token

    def valid(self, token):
        if not isinstance(token, str) or not 20 <= len(token) <= 128:
            return False
        key = hashlib.sha256(token.encode()).hexdigest()
        expiry = self.devices.get(key, 0)
        if expiry is None:
            return True
        if expiry <= time.time():
            return False
        self.devices[key] = None
        try:
            self.save()
        except OSError:
            self.devices[key] = expiry
            raise
        return True

    def revoke(self):
        self.devices.clear()
        self.save()
