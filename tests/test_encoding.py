import unittest

from reverssh.ssh_encoding import Reader, boolean, mpint, name_list, string, uint32


class EncodingTests(unittest.TestCase):
    def test_ssh_binary_roundtrip(self):
        payload = uint32(7) + boolean(True) + string("hello") + name_list(["a", "b"]) + mpint(0x80)
        reader = Reader(payload)
        self.assertEqual(reader.uint32(), 7)
        self.assertIs(reader.boolean(), True)
        self.assertEqual(reader.text(), "hello")
        self.assertEqual(reader.name_list(), ["a", "b"])
        self.assertEqual(reader.mpint(), 0x80)
        reader.eof()

    def test_mpint_zero_is_empty_string(self):
        self.assertEqual(mpint(0), b"\x00\x00\x00\x00")


if __name__ == "__main__":
    unittest.main()
