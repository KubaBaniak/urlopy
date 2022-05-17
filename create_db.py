from urlop import db, bcrypt
from urlop.forms import User

db.drop_all()

db.create_all()
admin = User(username='Admin', email='pymailxd@gmail.com', role='Admin', password=bcrypt.generate_password_hash("Admin123").decode())
test = User(username='est123', email='test123@gmail.com', password=bcrypt.generate_password_hash("test123").decode())

db.session.add(admin)
db.session.add(test)

db.session.commit()