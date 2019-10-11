import unittest
from credstash import keep_highest_version


class TestKeepHighestVersion(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(keep_highest_version(None), None)
        self.assertEqual(keep_highest_version([]), [])

    def test_singleton(self):
        s1 = [
                {"version": "00000", "name": "a"},
                {"version": "00001", "name": "a"},
                {"version": "00002", "name": "a"},
                {"version": "00003", "name": "a"},
                {"version": "00004", "name": "a"}
                ]
        e1 = [
                {"version": "00004", "name": "a"},
                ]
        self.assertEqual(keep_highest_version(s1), e1)
        s2 = [
                {"version": "00003", "name": "a"}
                ]
        e2 = [
                {"version": "00003", "name": "a"}
                ]
        self.assertEqual(keep_highest_version(s2), e2)

    def test_multiples(self):
        s1 = [
                {"version": "00000", "name": "a"},
                {"version": "00001", "name": "a"},
                {"version": "00002", "name": "a"},
                {"version": "00003", "name": "a"},
                {"version": "00004", "name": "a"},
                {"version": "00000", "name": "b"},
                {"version": "00001", "name": "b"},
                {"version": "00002", "name": "b"},
                {"version": "00003", "name": "b"},
                {"version": "00004", "name": "b"},
                {"version": "00005", "name": "b"},
                {"version": "00006", "name": "b"},
                {"version": "00007", "name": "b"}
                ]
        e1 = [
                {"version": "00004", "name": "a"},
                {"version": "00007", "name": "b"}
                ]
        self.assertEqual(keep_highest_version(s1), e1)
        s1 = [
                {"version": "00004", "name": "b"},
                {"version": "00007", "name": "b"},
                {"version": "00000", "name": "a"},
                {"version": "00001", "name": "a"},
                {"version": "00002", "name": "a"},
                {"version": "00003", "name": "a"},
                {"version": "00000", "name": "b"},
                {"version": "00001", "name": "b"},
                {"version": "00002", "name": "b"},
                {"version": "00003", "name": "b"},
                {"version": "00004", "name": "a"},
                {"version": "00005", "name": "b"},
                {"version": "00006", "name": "b"}
                ]
        e1 = [
                {"version": "00004", "name": "a"},
                {"version": "00007", "name": "b"}
                ]
