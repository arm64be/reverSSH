from pathlib import Path
import tempfile
import unittest

from reverssh.sftp import normalize_sftp_path


class SFTPTests(unittest.TestCase):
    def test_normalize_sftp_path_relative(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            self.assertEqual(normalize_sftp_path(tmp_path, "a/../b"), tmp_path / "b")

    def test_normalize_sftp_path_rejects_nul(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "NUL"):
                normalize_sftp_path(Path(tmp), "bad\x00path")


if __name__ == "__main__":
    unittest.main()
