from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from postlogin_mail_config import load


class MailConfigTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "mail.env"
        self.valid = "APP_MAIL_USERNAME=owned@gmail.com\nAPP_MAIL_FROM=owned@gmail.com\nAPP_MAIL_PASSWORD='abcdefghijklmnop'\n"

    def write(self, value):
        self.path.write_text(value); self.path.chmod(0o600)

    def test_literal_private_config_uses_only_fixed_gmail_endpoint(self):
        self.write(self.valid)
        settings = load(self.path)
        self.assertEqual(settings["SPRING_MAIL_HOST"], "smtp.gmail.com")
        self.assertEqual(settings["SPRING_MAIL_PORT"], "587")
        self.assertEqual(settings["APP_MAIL_PASSWORD"], "abcdefghijklmnop")

    def test_unsafe_permissions_symlink_and_duplicates_are_rejected(self):
        self.write(self.valid); self.path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "OWNER_PRIVATE"): load(self.path)
        self.path.chmod(0o600)
        link = self.path.with_name("link.env"); link.symlink_to(self.path)
        with self.assertRaisesRegex(ValueError, "SYMLINK"): load(link)
        self.write(self.valid + "APP_MAIL_USERNAME=other@gmail.com\n")
        with self.assertRaisesRegex(ValueError, "UNIQUE_ALLOWLISTED"): load(self.path)

    def test_no_shell_expansion_unknown_keys_or_external_endpoint(self):
        for extra in ("UNRELATED_SECRET=unused\n", "SPRING_MAIL_HOST=untrusted.example\n",
                      "SPRING_MAIL_PORT=25\n", "APP_MAIL_PASSWORD=$(touch forbidden)\n"):
            self.write(self.valid + extra)
            with self.assertRaises(ValueError): load(self.path)
        self.write(self.valid.replace("abcdefghijklmnop", "$(touch forbidden)"))
        with self.assertRaisesRegex(ValueError, "LITERAL_NONEMPTY"): load(self.path)


if __name__ == "__main__":
    unittest.main()
