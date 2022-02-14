from flask import Flask, jsonify, request
from flask_restplus import Api, Resource, fields
from flask_mongoengine import MongoEngine
from flask_cors import CORS
from config import Config
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, jwt_required, create_access_token


# Declaring flask application
app = Flask(__name__)
# Passing config file
app.config.from_object(Config)
# Declaring rest plus api
api = Api(app=app, doc="/", title="Soccer_Dashboard-WebApp")
CORS(app)
# Creating instance of bcrypt
bcrypt = Bcrypt(app)
# Creating instance of JWT
jwt = JWTManager(app)
# Creating instance of MongoEngine
db = MongoEngine(app=app)

# Importing declared routes from routes.py
from application import routes


if __name__ == '__main__':
    app.run()
