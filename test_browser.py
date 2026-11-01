"""Headless browser contract test against a real HTTPS host with synthetic desktop."""
import asyncio
import os
from pathlib import Path
import queue
import tempfile
import threading
import time
from playwright.sync_api import sync_playwright
from desklink import Host, certificate
from test_host import FakeDesktop


def main():
    ready = queue.Queue()
    desktop = FakeDesktop()
    desktop.cursor = lambda: {'type':'cursor','visible':True,'x':0.5,'y':0.5,'shape':'pointer'}
    temporary = tempfile.TemporaryDirectory()
    def server():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        ctx, _ = certificate(Path(temporary.name), ['127.0.0.1'])
        host = Host('browser-test-only', lambda _: None, desktop)
        loop.run_until_complete(host.start(ctx, '127.0.0.1', 0))
        port = next(iter(host.runner.sites))._server.sockets[0].getsockname()[1]
        ready.put((host, loop, port))
        loop.run_forever()
        loop.run_until_complete(loop.shutdown_default_executor())
        loop.close()
    thread = threading.Thread(target=server)
    thread.start()
    host, loop, port = ready.get(timeout=15)
    evidence = Path('evidence')
    evidence.mkdir(exist_ok=True)
    try:
        with sync_playwright() as p:
            executable = Path(os.environ['LOCALAPPDATA']) / 'ms-playwright/chromium-1200/chrome-win64/chrome.exe'
            browser = p.chromium.launch(executable_path=str(executable), headless=True)
            context = browser.new_context(ignore_https_errors=True, viewport={'width':1280,'height':800})
            page = context.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.goto(f'https://127.0.0.1:{port}')
            page.screenshot(path=str(evidence/'browser-login.png'))
            page.locator('#password').fill('wrong')
            page.locator('form button').click()
            page.wait_for_function("() => document.querySelector('#status').textContent.includes('Неверный')")
            page.locator('#password').fill('browser-test-only')
            page.locator('form button').click()
            page.locator('#remote').wait_for(state='visible')
            page.wait_for_function("() => document.querySelector('#screen').naturalWidth === 80")
            assert not page.locator('#control').is_checked()
            page.locator('#control').check()
            page.locator('#remoteCursor').wait_for(state='visible')
            assert page.locator('#screen').evaluate("el => getComputedStyle(el).cursor") == 'pointer'
            page.locator('#quality').select_option('native')
            page.wait_for_timeout(200)
            assert page.locator('#quality').input_value() == 'native'
            page.locator('#zoom').click()
            assert page.locator('#zoom').get_attribute('aria-pressed') == 'true'
            page.locator('#zoom').click()
            assert page.locator('#zoom').get_attribute('aria-pressed') == 'false'
            page.locator('#screen').click()
            page.locator('#stage').press('a')
            page.locator('#text').fill('Привет, Windows!')
            page.locator('#sendtext').click()
            page.screenshot(path=str(evidence/'browser-remote.png'))
            page.wait_for_timeout(200)
            kinds = {event['type'] for event in desktop.events}
            assert {'move', 'button', 'key', 'text', 'release'} <= kinds, kinds
            assert any(e.get('text') == 'Привет, Windows!' for e in desktop.events)
            assert any(e.get('code') == 65 and e.get('down') for e in desktop.events)
            page.locator('#disconnect').click()
            page.locator('#login').wait_for(state='visible')
            page.wait_for_function("() => document.querySelector('#status').textContent === 'Доступ отключён'")
            from companion import browser_access
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes
            pin = x509.load_pem_x509_certificate((Path(temporary.name)/'identity.pem').read_bytes()).fingerprint(hashes.SHA256()).hex()
            device = asyncio.run_coroutine_threadsafe(browser_access(f'https://127.0.0.1:{port}', pin, password='browser-test-only'), loop).result(timeout=10)
            quick_url = asyncio.run_coroutine_threadsafe(browser_access(device['address'], pin, token=device['token']), loop).result(timeout=10)
            page.goto(quick_url)
            page.locator('#remote').wait_for(state='visible')
            assert not page.evaluate('location.hash')
            assert not page.locator('#control').is_checked()
            page.locator('#disconnect').click()
            page.wait_for_function("() => document.querySelector('#status').textContent === 'Доступ отключён'")
            page.goto(quick_url)
            page.wait_for_function("() => document.querySelector('#status').textContent.includes('Ссылка истекла')")
            assert page.locator('#login').is_visible()
            assert not page.evaluate('location.hash')
            page.set_viewport_size({'width':390,'height':844})
            page.screenshot(path=str(evidence/'browser-mobile.png'))
            assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
            assert not errors, errors
            assert desktop.releases > 0
            browser.close()
        print('PASS: Chromium login, wrong password, JPEG decode, view-only default, pointer/key/Unicode protocol, logout, mobile overflow, no JS errors')
    finally:
        asyncio.run_coroutine_threadsafe(host.stop(), loop).result(timeout=10)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=10)
        temporary.cleanup()


if __name__ == '__main__':
    main()
