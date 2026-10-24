import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("init_secrets", Path(__file__).with_name("init-secrets.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class SecretInitializationTest(unittest.TestCase):
    def test_generated_secrets_are_stable_and_private(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "secrets"
            module.initialize(root)
            before = {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()}
            module.initialize(root)
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in root.rglob("*") if p.is_file()})
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            for name in before:
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o600)
            self.assertRegex(before[Path("api-key")].decode(), r"^ssk_[a-f0-9]{40}$")
            self.assertNotEqual(before[Path("mongo-password")], before[Path("redis-password")])

    def test_invalid_existing_secret_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "mongo-password").write_text("")
            with self.assertRaises(ValueError):
                module.initialize(root)
            self.assertEqual((root / "mongo-password").read_text(), "")

    def test_symlink_is_rejected_without_changing_target(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / "secrets"
            root.mkdir()
            target = Path(folder) / "target"
            target.write_text("keep")
            (root / "mongo-password").symlink_to(target)
            with self.assertRaises(ValueError):
                module.initialize(root)
            self.assertEqual(target.read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
