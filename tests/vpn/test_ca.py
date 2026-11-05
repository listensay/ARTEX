import ssl
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/vpn"))
from runtime import ca_bundle


class VPNCATests(unittest.TestCase):
    def test_adds_ca_without_disabling_verification(self):
        system = Path("/etc/ssl/cert.pem")
        if not system.is_file():
            system = Path(ssl.get_default_verify_paths().openssl_cafile)
        pem = system.read_bytes()
        cert = pem[pem.index(b"-----BEGIN CERTIFICATE-----"):]
        cert = cert[:cert.index(b"-----END CERTIFICATE-----") + len(b"-----END CERTIFICATE-----")]
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "trusted.crt").write_bytes(cert)
            merged = ca_bundle(tmp, system_bundle=pem)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=merged.decode("ascii"))
            self.assertGreater(len(context.get_ca_certs()), 0)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertTrue(context.check_hostname)

    def test_private_key_and_invalid_ca_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "invalid.crt")
            for data in [b"-----BEGIN PRIVATE KEY-----\nsecret", b"invalid certificate"]:
                path.write_bytes(data)
                with self.assertRaises((ValueError, ssl.SSLError)):
                    ca_bundle(tmp, system_bundle=b"")
