from mongoengine import disconnect, connect
from application.user_model import User
from application import user_model
import unittest


"""
    Class containing test for user models
"""


class ModelsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        disconnect()
        # Creating mock db and establishing connectivity
        connect("mongoenginetest", host="mongomock://localhost")

    @classmethod
    def tearDownClass(cls):
        disconnect()

    def setUp(self):
        """
        Creating mock data for mock db
        """
        self.user_1 = user_model.User(**{'_id': '6065b71f2b7edc50cdf2211b',
                                         'email': 'dan@email.com', 'password': 'qwerty'})
        self.user_2 = user_model.User(**{'_id': '6065b71f2b7edc50cdf531b',
                                         'email': 'mick@email.com', 'password': 'qwerty123'})

    def test_models(self):
        """
        Testing the if mock data is correct
        """
        self.assertEqual(self.user_1['_id'], user_model.ObjectId('6065b71f2b7edc50cdf2211b'))
        self.assertEqual(self.user_1['email'], 'dan@email.com')
        self.assertEqual(self.user_1['password'], 'qwerty')
        self.assertEqual(self.user_2['email'], 'mick@email.com')

    def test_new_user(self):
        """
        Testing if new added users are successful
        :return:
        """
        user = self.user_1
        new_user = User(_id=user._id, email=user.email, password=user.password).save()
        self.assertEqual(User.objects.first().email, 'dan@email.com')



