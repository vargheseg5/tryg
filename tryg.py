from flask import Flask, render_template

tryg = Flask(__name__)
tryg.config["SECRET_KEY"] = b'U\x12"\xb7P\xc9\x9f\x9da3lZlb\xc7\x95\xe4W\xd2o\xf2\xbb\xdfg<\xd9\x0f\x87\x1en\xc0;'

@tryg.route('/')
def index():
    return render_template('index.html')

@tryg.route('/add')
def add():
    return render_template('add.html')

@tryg.route('/listing')
def listing():
    return render_template('listing.html')

@tryg.route('/login')
def login():
    return render_template('login.html')

@tryg.route('/logout')
def logout():
    return render_template('logout.html')

if __name__ == "__main__":
    tryg.run(debug=True)