"""Real TLS/network tests; simulated input avoids touching the user's desktop."""
import asyncio
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
from aiohttp import ClientSession, CookieJar, WSServerHandshakeError
from PIL import Image
from desklink import Host, Desktop, certificate, Input, C


class FakeDesktop:
    def __init__(self):
        self.events = []
        self.releases = 0
    def capture(self, profile="sharp"):
        out = io.BytesIO()
        Image.new('RGB', (80, 50), 'green').save(out, 'JPEG')
        return out.getvalue()
    def event(self, event):
        self.events.append(event)
    def release(self):
        self.releases += 1


class Integration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ctx, self.fingerprint = certificate(Path(self.temp.name), ['127.0.0.1'])
        self.desktop = FakeDesktop()
        self.host = Host('test-password', lambda _: None, self.desktop)
        await self.host.start(self.ctx, '127.0.0.1', 0)
        port = next(iter(self.host.runner.sites))._server.sockets[0].getsockname()[1]
        self.url = f'https://127.0.0.1:{port}'
        self.origin = {'Origin': self.url}
        self.client = ClientSession(cookie_jar=CookieJar(unsafe=True))
    async def asyncTearDown(self):
        await self.client.close()
        await self.host.stop()
        self.temp.cleanup()
    async def login(self):
        return await self.client.post(self.url+'/login', json={'password':'test-password'}, headers=self.origin, ssl=False)
    async def test_tls_auth_stream_and_logout(self):
        async with self.client.get(self.url+'/', ssl=False) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers['X-Frame-Options'], 'DENY')
            self.assertIn('DeskLink', await r.text())
        with self.assertRaises(WSServerHandshakeError):
            await self.client.ws_connect(self.url+'/stream', headers=self.origin, ssl=False)
        r = await self.client.post(self.url+'/login', json={'password':'test-password'}, ssl=False)
        self.assertEqual(r.status, 403)
        self.assertEqual((await self.login()).status, 200)
        cookie = self.client.cookie_jar.filter_cookies(__import__('yarl').URL(self.url))
        self.assertIn('desklink', cookie)
        with self.assertRaises(WSServerHandshakeError):
            await self.client.ws_connect(self.url+'/stream', headers={'Origin':'https://evil.example'}, ssl=False)
        ws = await self.client.ws_connect(self.url+'/stream', headers=self.origin, ssl=False)
        frame = await ws.receive(timeout=5)
        self.assertEqual(Image.open(io.BytesIO(frame.data)).size, (80, 50))
        with self.assertRaises(WSServerHandshakeError) as error:
            await self.client.ws_connect(self.url+'/stream', headers=self.origin, ssl=False)
        self.assertEqual(error.exception.status, 409)
        await ws.send_json({'type':'key', 'code':65, 'down':True})
        for _ in range(20):
            if self.desktop.events:
                break
            await asyncio.sleep(.02)
        self.assertEqual(self.desktop.events[0]['code'], 65)
        await ws.send_str('not json')
        for _ in range(20):
            msg = await ws.receive(timeout=5)
            if isinstance(msg.data, str):
                self.assertIn('error', json.loads(msg.data))
                break
        else:
            self.fail('Malformed input did not yield error')
        self.assertEqual((await self.client.post(self.url+'/logout', headers=self.origin, ssl=False)).status, 200)
        for _ in range(20):
            msg = await ws.receive(timeout=5)
            if msg.type in (__import__('aiohttp').WSMsgType.CLOSE, __import__('aiohttp').WSMsgType.CLOSED):
                break
        else:
            self.fail('Logout did not close the stream')
        await ws.close()
        self.assertGreater(self.desktop.releases, 0)
    async def test_bruteforce_limited(self):
        for _ in range(5):
            r = await self.client.post(self.url+'/login', json={'password':'wrong'}, headers=self.origin, ssl=False)
            self.assertEqual(r.status, 401)
        self.assertEqual((await self.login()).status, 429)
    async def test_stop_closes_active_session(self):
        await self.login()
        ws = await self.client.ws_connect(self.url+'/stream', headers=self.origin, ssl=False)
        await ws.receive(timeout=5)
        await self.host.stop()
        self.assertFalse(self.host.sessions)
        self.assertGreater(self.desktop.releases, 0)
        await ws.close()
    async def test_certificate_persists(self):
        _, second = certificate(Path(self.temp.name), ['127.0.0.1'])
        self.assertEqual(self.fingerprint, second)
        self.assertNotIn(b'PRIVATE KEY', (Path(self.temp.name)/'identity.key').read_bytes())


class WindowsCapture(unittest.TestCase):
    def test_real_screen_and_input_layout(self):
        self.assertEqual(C.sizeof(Input), 40)
        frame = Desktop().capture()
        image = Image.open(io.BytesIO(frame))
        self.assertEqual(image.format, 'JPEG')
        self.assertGreater(image.width, 0)
        self.assertLessEqual(image.width, 2560)
        self.assertLessEqual(image.height, 1600)


if __name__ == '__main__':
    unittest.main(verbosity=2)
