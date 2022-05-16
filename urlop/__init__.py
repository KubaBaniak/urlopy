import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_bcrypt import Bcrypt


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.getcwd()
app.config['SECRET_KEY'] = 'xddd'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xddd.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)

from urlop import routes

