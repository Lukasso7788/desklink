import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from updater import download_update, secure_url, version
from desklink import Desktop
from PIL import Image, JpegImagePlugin


class UpdateTests(unittest.TestCase):
    def test_https_and_versions(self):
        for url in ['http://example.org/a', 'file:///x', 'https://user:password@example.org/a', '']:
            with self.assertRaises(ValueError):
                secure_url(url)
        self.assertGreater(version('0.10.0'), version('0.2.0'))
        with self.assertRaises(ValueError):
            version('../../0.3.0')

    def test_verified_download_and_corruption_cleanup(self):
        payload = b'MZtest executable'
        manifest = {'version':'0.3.0','download_url':'https://example.org/DeskLink.exe','sha256':hashlib.sha256(payload).hexdigest()}
        with tempfile.TemporaryDirectory() as folder:
            with patch('updater.open_https', side_effect=[io.BytesIO(json.dumps(manifest).encode()), io.BytesIO(payload)]):
                target = download_update('https://example.org/release.json', '0.2.0', folder)
                self.assertEqual(target.read_bytes(), payload)
            manifest['version'] = '0.4.0'
            with patch('updater.open_https', side_effect=[io.BytesIO(json.dumps(manifest).encode()), io.BytesIO(b'MZbad')]):
                with self.assertRaisesRegex(ValueError, 'SHA-256'):
                    download_update('https://example.org/release.json', '0.2.0', folder)
            self.assertEqual([p.name for p in Path(folder).iterdir()], ['DeskLink-0.3.0.exe'])
            with patch('updater.open_https', return_value=io.BytesIO(json.dumps(manifest).encode())):
                self.assertIsNone(download_update('https://example.org/release.json', '0.4.0', folder))


class QualityTests(unittest.TestCase):
    def test_profiles_and_real_cursor(self):
        desktop = Desktop()
        for profile, expected in [('balanced',(1920,1080)),('sharp',(2560,1440)),('native',(3840,2160))]:
            with patch('desklink.ImageGrab.grab', return_value=Image.new('RGB',(3840,2160),'white')):
                image = Image.open(io.BytesIO(desktop.capture(profile)))
                self.assertEqual(image.size, expected)
                self.assertEqual(JpegImagePlugin.get_sampling(image), 0)
        cursor = desktop.cursor()
        self.assertEqual(cursor['type'], 'cursor')
        self.assertIn('visible', cursor)


if __name__ == '__main__':
    unittest.main(verbosity=2)
