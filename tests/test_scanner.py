import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import scanner


class TestScanner(unittest.TestCase):
    def test_ioc_hashes_are_valid(self):
        data = json.loads((Path(scanner.__file__).parent / 'iocs.json').read_text())
        self.assertEqual(len(data['packages']), 6)
        self.assertEqual(len({x['package'] for x in data['packages']}), 6)
        self.assertTrue(all(len(x['sha256']) == 64 and int(x['sha256'], 16) >= 0 for x in data['packages']))

    def test_sha256_local_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'sample.bin'
            p.write_bytes(b'test data')
            self.assertEqual(scanner.sha256(p), hashlib.sha256(b'test data').hexdigest())

    @patch('scanner.shutil.which', return_value=None)
    def test_cert_tool_absent(self, _mock):
        self.assertEqual(scanner.certificate_info(Path('missing.apk'))['status'], 'not_checked')

    @patch('scanner.cmd')
    def test_adb_connected_device_parser(self, mock_cmd):
        mock_cmd.return_value.returncode = 0
        mock_cmd.return_value.stdout = 'List of devices attached\nabc device usb:1-2\ndef unauthorized\n'
        self.assertEqual(scanner.serials(), ['abc'])


if __name__ == '__main__':
    unittest.main()
