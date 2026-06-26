import base64
import tempfile
import unittest
from pathlib import Path

from reverssh.client import OPERATOR_KEYS_ENV, KnownOperators, OperatorApproval
from reverssh.keys import ed25519_key_blob


PUBLIC_ONE = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
PUBLIC_TWO = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")


def authorized_line(public: bytes) -> tuple[str, bytes]:
    blob = ed25519_key_blob(public)
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " test", blob


class OperatorApprovalTests(unittest.TestCase):
    def known(self, tmp: str) -> KnownOperators:
        return KnownOperators(Path(tmp) / "known_operators")

    def test_env_allowlist_approves_matching_public_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            line, blob = authorized_line(PUBLIC_ONE)
            approval = OperatorApproval.from_env(self.known(tmp), line)

            self.assertTrue(approval.strict)
            self.assertEqual(approval.approve("host", "SHA256:test", blob), (True, False))

    def test_env_allowlist_rejects_unknown_public_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            line, _blob = authorized_line(PUBLIC_ONE)
            _other_line, other_blob = authorized_line(PUBLIC_TWO)
            approval = OperatorApproval.from_env(self.known(tmp), line)

            self.assertEqual(approval.approve("host", "SHA256:other", other_blob), (False, False))

    def test_env_allowlist_accepts_colon_separated_public_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            line_one, _blob_one = authorized_line(PUBLIC_ONE)
            line_two, blob_two = authorized_line(PUBLIC_TWO)
            approval = OperatorApproval.from_env(self.known(tmp), line_one + ":" + line_two)

            self.assertEqual(approval.approve("host", "SHA256:test", blob_two), (True, False))

    def test_env_allowlist_invalid_public_key_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, OPERATOR_KEYS_ENV):
                OperatorApproval.from_env(self.known(tmp), "not-a-key")


if __name__ == "__main__":
    unittest.main()
