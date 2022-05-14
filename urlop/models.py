from flask_login import UserMixin
from urlop import db, login_manager

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False)
    email = db.Column(db.String(40), unique=True, nullable=False)
    role = db.Column(db.String(20), default='user')
    password = db.Column(db.String(60), nullable=False)
    leave = db.relationship('Leave', backref='user', lazy=True)
    days_left = db.Column(db.Integer, default=26)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.role}')"


class Leave(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    start_day = db.Column(db.DateTime, nullable=False)
    end_day = db.Column(db.DateTime, nullable=False)
    accepted = db.Column(db.Boolean, unique=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
