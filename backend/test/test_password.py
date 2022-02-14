import unittest
from app import app, api, bcrypt
import os

"""
    Class for testing passwords
"""


class PasswordTest(unittest.TestCase):

    def test_same_password(self):
        """
        Ensuring same password hashed twice does not give same hash.
        """
        password = "password321"
        hashed_1 = bcrypt.generate_password_hash(password)
        hashed_2 = bcrypt.generate_password_hash(password)
        self.assertNotEqual(hashed_1, hashed_2)

    def test_hashed_password(self):
        """
        Comparing hashed and non-hashed password
        """
        password = "password123"
        hashed = bcrypt.generate_password_hash(password)
        test = bcrypt.check_password_hash(hashed, password)
        self.assertEqual(True, test)




