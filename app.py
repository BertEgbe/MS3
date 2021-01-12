import os 
from bson_objectid import ObjectId
from flask import Flask, render_template, redirect, url_for, request, session, g
from flask_pymongo  import PyMongo, pymongo 
from passlib.hash import pbkdf2_sha256
from functools import wraps

app = Flask(__name__) 
app.secret_key = os.urandom(24)

app.config["MONGO_DBNAME"] = "chefdiary"
app.config["MONGO_URI"] = os.getenv('MONGO_URI', 'mongodb://localhost')

client = pymongo.MongoClient(os.getenv('MONGO_URI'))
db = client.chefdiary

placeholder_image = '#'
# Manage session user
@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']
# Check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash('Unauthorized, Please log in', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function
        
@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        
        # Retrieve users from database and check that username exists
        username_entered = request.form.get('username')
        this_user_in_db = db.users.find_one({'username': username_entered})
        if not this_user_in_db:
            flash('Username does not exist', 'error')
            return render_template('login.html')
        
        # once username exists in database confirm password entered and that both fields are populated
        password_entered = request.form.get('password')
        if not username_entered or not password_entered:
            flash('Please enter a valid username and password', 'error')
            return render_template('login.html')
        
        # check password against this username's user record in database
        if pbkdf2_sha256.verify(password_entered, this_user_in_db['password']):
            # once verified with user record in database, start a new session and redirect to main recipelist
            session['user'] = username_entered
            flash('You have successfully logged in', 'success')
            return redirect(url_for('recipelist'))
        else:
            # else if password does not match, flash error message
            flash('The password did not match the user profile', 'error')
            return render_template('login.html')

    if g.user:
        return redirect(url_for('recipelist'))

    return render_template('login.html')

@app.route('/logout')
