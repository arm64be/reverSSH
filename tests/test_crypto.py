import unittest

from reverssh.crypto import curve25519, ed25519
from reverssh.crypto.poly1305 import poly1305_mac
from reverssh.ssh_packet import OpenSSHChaCha20Poly1305, PacketStream


class CryptoTests(unittest.TestCase):
    def test_ed25519_rfc8032_test_vector_1(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        self.assertEqual(ed25519.public_from_seed(seed), public)
        self.assertEqual(ed25519.sign(seed, b""), signature)
        self.assertTrue(ed25519.verify(public, b"", signature))
        self.assertFalse(ed25519.verify(public, b"x", signature))


    def test_x25519_rfc7748_test_vector(self):
        scalar = bytes.fromhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        u = bytes.fromhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        expected = bytes.fromhex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        self.assertEqual(curve25519.x25519(scalar, u), expected)


    def test_poly1305_rfc8439_vector(self):
        key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        msg = b"Cryptographic Forum Research Group"
        self.assertEqual(poly1305_mac(msg, key), bytes.fromhex("a8061dc1305136c6c22b8baf0c0127a9"))


    def test_openssh_chacha_packet_roundtrip(self):
        key = bytes(range(64))
        cipher = OpenSSHChaCha20Poly1305(key)
        packet = PacketStream._build_plain_packet(b"\x05hello")
        encrypted = cipher.encrypt_packet(7, packet)
        self.assertNotEqual(encrypted, packet)
        self.assertEqual(cipher.decrypt_packet(7, encrypted), packet)


if __name__ == "__main__":
    unittest.main()
