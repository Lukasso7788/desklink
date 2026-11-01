"""Explicit HTTPS update download. Never executes or overwrites the running host."""
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, build_opener


class HTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        secure_url(newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r'\d{1,5}\.\d{1,5}\.\d{1,5}', value):
        raise ValueError('Некорректная версия')
    return tuple(map(int, value.split('.')))


def secure_url(url):
    parsed = urlparse(url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Нужен доверенный HTTPS-адрес публикации обновлений')
    return url


def open_https(url):
    response = build_opener(HTTPSRedirects()).open(secure_url(url), timeout=20)
    try:
        secure_url(response.url)
    except Exception:
        response.close()
        raise
    return response


def download_update(manifest_url, current, destination):
    with open_https(manifest_url) as response:
        data = response.read(16385)
    if len(data) > 16384:
        raise ValueError('Слишком большой файл версии')
    manifest = json.loads(data)
    if not isinstance(manifest, dict):
        raise ValueError('Некорректный файл версии')
    latest = manifest.get('version')
    if version(latest) <= version(current):
        return None
    expected = manifest.get('sha256', '')
    if not isinstance(expected, str) or not re.fullmatch('[a-fA-F0-9]{64}', expected):
        raise ValueError('В файле версии отсутствует SHA-256')
    folder = Path(destination)
    folder.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        digest = hashlib.sha256()
        total = 0
        started = time.monotonic()
        with open_https(manifest.get('download_url', '')) as response, tempfile.NamedTemporaryFile(dir=folder, suffix='.part', delete=False) as output:
            temporary = Path(output.name)
            while block := response.read(256 * 1024):
                total += len(block)
                if total > 100 * 1024 * 1024 or time.monotonic() - started > 180:
                    raise ValueError('Превышен размер или время скачивания обновления')
                digest.update(block)
                output.write(block)
        if digest.hexdigest() != expected.lower():
            raise ValueError('SHA-256 не совпадает. Файл не сохранён.')
        with temporary.open('rb') as downloaded:
            if downloaded.read(2) != b'MZ':
                raise ValueError('Получен не EXE-файл')
        target = folder / ('DeskLink-' + latest + '.exe')
        if target.exists():
            raise ValueError('Файл этой версии уже существует в Downloads')
        temporary.rename(target)
        return target
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)
