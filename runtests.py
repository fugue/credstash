import unittest
import argparse
from credstash import key_value_pair
from credstash import expand_wildcard
from credstash import paddedInt


class TestKeyValuePairExtraction(unittest.TestCase):

    def test_key_value_pair_has_two_equals(self):
        self.assertRaises(argparse.ArgumentTypeError, key_value_pair , "==")

    def test_key_value_pair_has_zero_equals(self):
        self.assertRaises(argparse.ArgumentTypeError, key_value_pair, "")

    def test_key_value_pair_has_one_equals(self):
        self.assertEqual(key_value_pair("="), ["",""])
            
    def test_key_value_pair_has_one_equals_with_values(self):
        self.assertEqual(key_value_pair("key1=value1"), ["key1","value1"])

    def test_key_value_pair_has_one_equals_with_values(self):
        self.assertEqual(key_value_pair("key1=value1"), ["key1","value1"])


class TestExpandingWildcard(unittest.TestCase):
    secrets_set = ["a", "b", "ab", " a", " b", "ba", "abc", "a[anyvalue]z", "a b", "aabb"]
    secrets_set2 = ["QQQ", "QVQQ", "QVQVQ", "QQ", "Q", "QQVQ", "QrEQrE", "QErQE"]

    def test_start_regex(self):
        self.assertEqual(expand_wildcard("a", self.secrets_set), ["a"])

    def test_end_regex(self):
        self.assertEqual(expand_wildcard("ba", self.secrets_set), ["ba"])
                        
    def test_exact_match_regex(self):
        self.assertEqual(expand_wildcard("abc", self.secrets_set), ["abc"])

    def test_one_wild_card_with_one_match(self):
        self.assertEqual(expand_wildcard("a*z", self.secrets_set), ["a[anyvalue]z"])

    def test_one_wild_card_with_many_matches(self):
        self.assertEqual(expand_wildcard("a*b", self.secrets_set), ["ab", "a b", "aabb"])

    def test_two_wild_cards_with_many_matches(self):
        self.assertEqual(expand_wildcard("Q*Q*Q", self.secrets_set2), ["QQQ", "QVQQ", "QVQVQ", "QQVQ"])

    def test_three_wild_card_with_many_matches(self):
        self.assertEqual(expand_wildcard("Q*E*Q*E", self.secrets_set2), ["QrEQrE", "QErQE"])


class TestPadLeft(unittest.TestCase):
    def test_zero(self):
        i = 0
        self.assertEqual(paddedInt(i), "0"*19)

    def test_ten(self):
        i = 10
        self.assertEqual(paddedInt(i), str(i).zfill(19))

    def test_arbitrary_number(self):
        i = 98218329123
        self.assertEqual(paddedInt(i), str(i).zfill(19))

    def test_huge_number(self):
        i = 12345678901234567890123
        self.assertEqual(paddedInt(i), str(i).zfill(19))


if __name__ == '__main__':
    unittest.main()