from flask import jsonify
from flask_restplus import Resource
from app import app, api, bcrypt
from application.user_model import User
from flask_jwt_extended import jwt_required, create_access_token

"""
    Class to create required routes for API
"""


@api.route('/user')
class UserAll(Resource):
    def get(self):
        """
        Method to get every user in the db
        :return: Returns users from the db in JSON format
        """
        try:
            return jsonify(User.objects.all())
        except:
            return jsonify({'response': 'Error'})

    def post(self):
        """
        Method to create a new user

        """
        # Declaring variable for api payload
        data = api.payload

        print(data)

        try:
            # Using bcrypt to encrypt password
            data['password'] = bcrypt.generate_password_hash(data['password'])
        except TypeError:
            return "Password must be a string"
        # Creating new user using data variable
        User(email=data['email'], password=data['password']).save()


@api.route('/auth')
class UserByEmail(Resource):
    def post(self):
        """
        Method to see if login was successful or not and returns a boolean.
        :return: Boolean
        """
        try:
            data = api.payload
            if User.objects(email=data['email']):
                # Compares password with encrypted password in db
                if bcrypt.check_password_hash(User.objects(email=data['email'])[0].password, data['password']):
                    # if the password matches a token will be created for user
                    token = create_access_token(identity=data['email'])
                    print(token)
                    return jsonify({'response': 'Login Successful!', 'login': True, 'token': token})
                else:
                    # Returns error if passwords do not match
                    return jsonify({'response': 'Login Unsuccessful!', 'login': False}), 401
            else:
                return jsonify({'response': 'Invalid! Please Try again', 'login': False}), 401
        except Exception as e:
            print(e)
            return jsonify({'response': "Backend Error", 'login': False}), 500


@app.route('/token', methods=["GET"])
# Ensures that a valid JWT is required.
@jwt_required()
def login():
    return jsonify({"response": "Token Authenticated"})
