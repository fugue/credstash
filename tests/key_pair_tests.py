import unittest
import argparse
from credstash import key_value_pair


class TestKeyValuePairExtraction(unittest.TestCase):

    def test_key_value_pair_has_two_equals_test(self):
        self.assertRaises(argparse.ArgumentTypeError, key_value_pair, "==")

    def test_key_value_pair_has_zero_equals(self):
        self.assertRaises(argparse.ArgumentTypeError, key_value_pair, "")

    def test_key_value_pair_has_one_equals(self):
        self.assertEqual(key_value_pair("="), ["", ""])

    def test_key_value_pair_has_one_equals_with_values(self):
        self.assertEqual(key_value_pair("key1=value1"), ["key1", "value1"])
