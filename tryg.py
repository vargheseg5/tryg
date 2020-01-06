from datetime import datetime

from flask import Flask, flash, redirect, render_template, request, url_for
from flask_bcrypt import Bcrypt, check_password_hash
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)
from flask_sqlalchemy import SQLAlchemy

from utils import str_to_date, get_uuid

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

class Journal(tryg_db.Model):
    jid = tryg_db.Column(tryg_db.String, primary_key=True)
    title = tryg_db.Column(tryg_db.String, nullable=False)
    content = tryg_db.Column(tryg_db.String, nullable=False)
    journal_date = tryg_db.Column(tryg_db.Date, default=datetime.utcnow)
    date_created = tryg_db.Column(tryg_db.DateTime, default=datetime.utcnow)
    author = tryg_db.Column(tryg_db.String, nullable=False)

    def __repr__(self):
        return "<Journal #%r>" % self.jid

@tryg.route('/')
def index():
    return render_template('index.html')

@tryg.route('/add', methods=['GET'])
@login_required
def add():
    return render_template('add.html')

@tryg.route('/add', methods=['POST'])
@login_required
def add_post():
    jid = request.form.get('jid', get_uuid())
    journal_date = request.form.get('journal-date')
    journal_title = request.form.get('journal-title')
    journal_content = request.form.get('journal-content')
    journal_entry = Journal(jid=jid, title=journal_title, content=journal_content, journal_date=str_to_date(journal_date), author=current_user.username)
    try:
        tryg_db.session.add(journal_entry)
        tryg_db.session.commit()
        return redirect(url_for('listing'))
    except Exception as e:
        print(e)
        flash("Could not save Journal Entry!")
        context = {
            "jid": jid,
            "journal_date": journal_date,
            "journal_title": journal_title,
            "journal_content": journal_content
        }
        return render_template('add.html', context=context)

@tryg.route('/listing')
@login_required
def listing():
    context = {
    }
    entries = [{"jid": i.jid, "journal_date": i.journal_date, "journal_title": i.title, "date_created": i.date_created} for i in Journal.query.filter_by(author=current_user.username).all()]
    print(entries)
    if len(entries) != 0:
        context["entries"] = entries
    return render_template('listing.html', context=context)

@tryg.route('/view/<jid>')
@login_required
def view(jid):
    journal_entry = Journal.query.filter_by(jid=jid).first()
    if not journal_entry:
        flash("Sorry, the requested Journal Entry does not exist. Please select one from below.")
        return redirect(url_for('listing'))
    else:
        context = {
            "jid": journal_entry.jid,
            "journal_date": journal_entry.journal_date,
            "journal_title": journal_entry.title,
            "journal_content": journal_entry.content
        }
        return render_template('view.html', context=context)

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
    with  tryg.app_context():
        tryg_db.metadata.create_all(tryg_db.engine)
    tryg.run(debug=True)
