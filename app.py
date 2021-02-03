import os
from flask import Flask, session, redirect, url_for, request, render_template, make_response, flash
from markupsafe import escape
import pyrebase
from flask_sqlalchemy import SQLAlchemy
from flask_security import Security, SQLAlchemyUserDatastore, \
    UserMixin, RoleMixin, login_required
from flask_security.utils import encrypt_password
from flask_login import logout_user
from werkzeug.utils import secure_filename
from hashlib import md5


app = Flask(__name__)   
app.secret_key = "Joseph@2005!"
app.config['DEBUG'] = True
app.config['SECRET_KEY'] = 'super-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///auth.db'
app.config['SECURITY_PASSWORD_HASH'] = 'bcrypt'
app.config['SECURITY_PASSWORD_SALT'] = '$2a$16$PnnIgfMwkOjGX4SkHqSOPO'
UPLOAD_FOLDER = 'C:\\Users\\1595187\\Desktop'
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)


roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def avatar(self, size):
        digest = md5(self.email.lower().encode('utf-8')).hexdigest()
        return 'https://www.gravatar.com/avatar/{}?d=identicon&s={}'.format(
            digest, size)

# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)
db.create_all()

@app.route('/signup/', methods=['GET', 'POST'])
def signup():
    if 'user' in session:
        return render_template('userProfile.html', signedIn = True)
    else:
        if request.method == 'POST':
            email_Signup = request.form['email']
            password_Signup = request.form['password']
            user_datastore.create_user(email= email_Signup,password=encrypt_password(password_Signup))
            db.session.commit()
            session['user'] = email_Signup
            return render_template('userProfile.html', signedIn = True)
    return render_template('signup.html')


@app.route('/uploader', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        if 'file1' not in request.files:
            return 'there is no file1 in form!'
        file1 = request.files['file1']
        path = os.path.join(app.config['UPLOAD_FOLDER'], file1.filename)
        file1.save(path)
        return path

        return 'ok'
    return '''
    <h1>Upload new File</h1>
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="file1">
      <input type="submit">
    </form>
    '''

# Views
@app.route('/')
@login_required
def home():
    return render_template('userProfile.html', signedIn = True)

@app.route('/logout')
def logout():
    if 'user' in session:
        logout_user()
        session.pop('user', None)
    else:
        return render_template('login.html')
    return render_template('login.html')

if __name__ == "__main__":
     app.run(debug=True)