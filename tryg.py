from flask import Flask, render_template, flash, redirect, render_template, request, url_for
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy

tryg = Flask(__name__)
tryg.config["SECRET_KEY"] = b'U\x12"\xb7P\xc9\x9f\x9da3lZlb\xc7\x95\xe4W\xd2o\xf2\xbb\xdfg<\xd9\x0f\x87\x1en\xc0;'
tryg.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tryg_db.sqlite3'
tryg.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

bcrypt = Bcrypt(tryg)

login_manager = LoginManager(tryg)
login_manager.login_view = 'login'

tryg_db = SQLAlchemy(tryg)


class User(tryg_db.Model):
    """An admin user capable of viewing reports.

    :param str username: username of user
    :param str password: encrypted password for the user

    """
    __tablename__ = 'user'

    username = tryg_db.Column(tryg_db.String, primary_key=True)
    password = tryg_db.Column(tryg_db.String)
    authenticated = tryg_db.Column(tryg_db.Boolean, default=False)

    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the username to satisfy Flask-Login's requirements."""
        return self.username

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

@login_manager.user_loader
def load_user(user_id):
    """Given *user_id*, return the associated User object.

    :param unicode user_id: user_id (username) user to retrieve

    """
    return User.query.get(user_id)

@tryg.route('/')
def index():
    return render_template('index.html')

@tryg.route('/add')
@login_required
def add():
    return render_template('add.html')

@tryg.route('/listing')
@login_required
def listing():
    return render_template('listing.html')

@tryg.route('/login', methods=["GET"])
def login():
    """For GET requests, display the login form. 
    For POSTS, login the current user by processing the form.

    """
    return render_template('login.html')

@tryg.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    # check if user actually exists
    # take the user supplied password, hash it, and compare it to the hashed password in database
    if not user or not check_password_hash(user.password, password): 
        flash('Please check your login details and try again.')
        return redirect(url_for('login')) # if user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('index'))


@tryg.route("/logout", methods=["GET"])
@login_required
def logout():
    """Logout the current user."""
    user = current_user
    user.authenticated = False
    tryg_db.session.add(user)
    tryg_db.session.commit()
    logout_user()
    return render_template("index.html")

if __name__ == "__main__":
    tryg.run(debug=True)