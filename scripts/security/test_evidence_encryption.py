import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from run_zap import encrypt


class PrivateEvidenceTest(unittest.TestCase):
    def test_alert_evidence_is_authenticated_ciphertext_and_decryptable_only_with_the_recipient_key(self):
        with tempfile.TemporaryDirectory(prefix='asvs-crypto-test-') as directory:
            root = Path(directory)
            key, certificate = root/'key.pem', root/'recipient.crt'
            result = subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
                '-subj','/CN=Disposable ASVS encryption fixture','-keyout',str(key),'-out',str(certificate)],capture_output=True)
            self.assertEqual(0, result.returncode)
            raw = root/'raw.json'; raw.write_bytes(b'{"private_fixture":"never upload raw findings"}')
            ciphertext = root/'evidence.cms'; encrypt(raw, ciphertext, certificate)
            self.assertNotIn(b'never upload raw findings', ciphertext.read_bytes())
            args=['openssl','cms','-decrypt','-binary','-inform','DER','-in',str(ciphertext),'-inkey',str(key)]
            decoded=subprocess.run(args,capture_output=True)
            self.assertEqual(0,decoded.returncode)
            self.assertEqual(raw.read_bytes(),decoded.stdout)
            altered=bytearray(ciphertext.read_bytes()); altered[-1]^=1; ciphertext.write_bytes(altered)
            self.assertNotEqual(0,subprocess.run(args,capture_output=True).returncode)


if __name__=='__main__': unittest.main()
