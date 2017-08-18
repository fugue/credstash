import unittest
from credstash import expand_wildcard


class TestExpandingWildcard(unittest.TestCase):
    secrets_set = ["a", "b", "ab", " a", " b",
                   "ba", "abc", "a[anyvalue]z", "a b", "aabb"]
    secrets_set2 = ["QQQ", "QVQQ", "QVQVQ",
                    "QQ", "Q", "QQVQ", "QrEQrE", "QErQE"]

    def test_start_regex(self):
        self.assertEqual(expand_wildcard("a", self.secrets_set), ["a"])

    def test_end_regex(self):
        self.assertEqual(expand_wildcard("ba", self.secrets_set), ["ba"])

    def test_exact_match_regex(self):
        self.assertEqual(expand_wildcard("abc", self.secrets_set), ["abc"])

    def test_one_wild_card_with_one_match(self):
        self.assertEqual(expand_wildcard(
            "a*z", self.secrets_set), ["a[anyvalue]z"])

    def test_one_wild_card_with_many_matches(self):
        self.assertEqual(expand_wildcard(
            "a*b", self.secrets_set), ["ab", "a b", "aabb"])

    def test_two_wild_cards_with_many_matches(self):
        self.assertEqual(expand_wildcard(
            "Q*Q*Q", self.secrets_set2), ["QQQ", "QVQQ", "QVQVQ", "QQVQ"])

    def test_three_wild_card_with_many_matches(self):
        self.assertEqual(expand_wildcard(
            "Q*E*Q*E", self.secrets_set2), ["QrEQrE", "QErQE"])
