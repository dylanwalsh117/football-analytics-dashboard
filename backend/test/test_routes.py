import unittest
import json
from application.user_model import User
from mongoengine import connect, disconnect
from application import user_model, routes
import app
from flask import jsonify
from app import app, api, bcrypt

app.testing = True


# class ApiMockResponse(object):
#
#     def __init__(self, status_code, response):
#         self.status_code = status_code
#         self.response = response
#         self.text = str((json.dumps(response)))


class TestApi(unittest.TestCase):
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
        User(email='renan@email.com', password=bcrypt.generate_password_hash('qwerty123')).save()
        User(email='dovy@email.com', password=bcrypt.generate_password_hash('qwerty321')).save()

        self.userAll = routes.UserAll()
        self.userByEmail = routes.UserByEmail()

    def test_post_user_by_email(self):
        """
        Testing POST request to determine if login is successful.
        """
        with app.test_client() as client:
            sent = {'email': 'renan@email.com', 'password': 'qwerty123'}
            result = client.post(
                '/auth',
                data=json.dumps(sent),
                content_type='application/json'
            )
            self.assertTrue(result.json['login'])

    def test_get_all(self):
        """
        Testing GET request to ensure API payload and db data are a match.
        """
        with app.app_context():
            test_response = jsonify(User.objects.all()).json
            payload = routes.UserAll.get(self.userAll).json

            self.assertEqual(test_response, payload)

    def test_get_all_fail(self):
        """
        Testing API payload against new user which has been created after response. Which should not be equal.
        """
        with app.app_context():
            payload = routes.UserAll.get(self.userAll).json
            User(email='user5@dell.com', password=bcrypt.generate_password_hash('ireland')).save()
            test_response = jsonify(User.objects.all()).json

            self.assertNotEqual(payload, test_response)

    def test_post_incorrect_user_by_email(self):
        """
        Testing POST without all of the required data for successful login
        """
        with app.test_client() as client:
            sent = {'password': 'qwerty123'}
            result = client.post(
                '/auth',
                data=json.dumps(sent),
                content_type='application/json'
            )
            self.assertFalse(result.json['login'])

    def test_routes_user_all_post_success(self):
        """
        Testing if register of new user is successful through the API, new registered user is then checked in the
        database to see if the names match.
        """
        with app.test_client() as client:
            # Send data as POST form to endpoint
            user = {

                'email': 'sammy@mail.com',
                # Converting byte hash to str for formatting as json
                'password': str(bcrypt.generate_password_hash('sammypwd'))
            }
            result = client.post(
                '/user',
                data=json.dumps(user),
                content_type='application/json'
            )
            # check result from server response.
            api_response = json.loads(result.data.decode())['response']

            self.assertEqual('Successfully Registered', api_response)
            # Testing if last object registered has the same name as the one just added to it.
            self.assertEqual(list(User.objects.all())[-1].email, 'sammy@mail.com')



