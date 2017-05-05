import httplib2
# TODO: remove unittest classes, convert to plain test functions
import unittest


class CredentialsTest(unittest.TestCase):
    def test(self):
        c = httplib2.Credentials()
        c.add("joe", "password")
        self.assertEqual(("joe", "password"), list(c.iter("bitworking.org"))[0])
        self.assertEqual(("joe", "password"), list(c.iter(""))[0])
        c.add("fred", "password2", "wellformedweb.org")
        self.assertEqual(("joe", "password"), list(c.iter("bitworking.org"))[0])
        self.assertEqual(1, len(list(c.iter("bitworking.org"))))
        self.assertEqual(2, len(list(c.iter("wellformedweb.org"))))
        self.assertTrue(("fred", "password2") in list(c.iter("wellformedweb.org")))
        c.clear()
        self.assertEqual(0, len(list(c.iter("bitworking.org"))))
        c.add("fred", "password2", "wellformedweb.org")
        self.assertTrue(("fred", "password2") in list(c.iter("wellformedweb.org")))
        self.assertEqual(0, len(list(c.iter("bitworking.org"))))
        self.assertEqual(0, len(list(c.iter(""))))
