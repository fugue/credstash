import unittest
from credstash import paddedInt


class TestPadLeft(unittest.TestCase):
    def test_zero(self):
        i = 0
        self.assertEqual(paddedInt(i), "0" * 19)

    def test_ten(self):
        i = 10
        self.assertEqual(paddedInt(i), str(i).zfill(19))

    def test_arbitrary_number(self):
        i = 98218329123
        self.assertEqual(paddedInt(i), str(i).zfill(19))

    def test_huge_number(self):
        i = 12345678901234567890123
        self.assertEqual(paddedInt(i), str(i).zfill(19))
