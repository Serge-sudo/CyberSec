from flask import Flask, render_template, redirect, url_for, request, session, flash
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import os
import re

app = Flask(__name__)
app.secret_key = 'CyberSec123+#!'

DATABASE = 'users.db'

PASSWORDRESETMIN = 2
FAILEDATTEMPTCNT = 3
FAILEDATTEMPTBLOCKMIN = 1

def getDBConnection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def initDB():
    conn = getDBConnection()
    with app.open_resource('schema.sql') as f:
        conn.executescript(f.read().decode('utf8'))
    conn.close()

def loginRequired(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('You need to be signed in for that page.')
            return redirect(url_for('signin'))
        return f(*args, **kwargs)
    return decorated_function

def validateUsername(username):
    errors = []
    if len(username) < 5:
        errors.append('Username must be at least 5 characters long.')
    if not re.match(r'^[A-Za-z][A-Za-z0-9_.]+$', username):
        errors.append('Username must start with a letter and contain only letters, digits, underscores, or periods.')
    return errors

def validatePassword(password):
    errors = []
    if len(password) < 8:
        errors.append('Password must be at least 8 characters long.')
    if not re.search(r'[A-Z]', password):
        errors.append('Password must contain at least one uppercase letter.')
    if not re.search(r'[a-z]', password):
        errors.append('Password must contain at least one lowercase letter.')
    if not re.search(r'\d', password):
        errors.append('Password must contain at least one digit.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        errors.append('Password must contain at least one special character.')
    return errors

def validateSecretPhrase(secret_phrase):
    errors = []
    if len(secret_phrase) < 6:
        errors.append('Secret phrase must be at least 6 characters long.')
    return errors

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=('GET', 'POST'))
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        secret_phrase = request.form['secret_phrase']
        created_at = datetime.now()

        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('signup'))

        username_errors = validateUsername(username)
        if username_errors:
            for error in username_errors:
                flash(error)
            return redirect(url_for('signup'))

        password_errors = validatePassword(password)
        secret_phrase_errors = validateSecretPhrase(secret_phrase)
        if password_errors or secret_phrase_errors:
            for error in password_errors + secret_phrase_errors:
                flash(error)
            return redirect(url_for('signup'))

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        hashed_secret_phrase = bcrypt.hashpw(secret_phrase.encode('utf-8'), bcrypt.gensalt())

        conn = getDBConnection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            flash('Username already exists.')
            conn.close()
            return redirect(url_for('signup'))

        conn.execute('INSERT INTO users (username, password, secret_phrase, password_set_time) VALUES (?, ?, ?, ?)',
                     (username, hashed_password, hashed_secret_phrase, created_at))
        conn.commit()
        conn.close()
        flash('Account created successfully! Please sign in.')
        return redirect(url_for('signin'))

    return render_template('signup.html')

@app.route('/signin', methods=('GET', 'POST'))
def signin():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = getDBConnection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            lockout_time = user['lockout_time']
            if lockout_time:
                lockout_time = datetime.strptime(lockout_time, '%Y-%m-%d %H:%M:%S.%f')
                if datetime.now() < lockout_time:
                    flash('Account is locked. Please try again later.')
                    conn.close()
                    return redirect(url_for('signin'))
                else:
                    conn.execute('UPDATE users SET failed_attempts = 0, lockout_time = NULL WHERE username = ?', (username,))
                    conn.commit()

            password_set_time = datetime.strptime(user['password_set_time'], '%Y-%m-%d %H:%M:%S.%f')

            if bcrypt.checkpw(password.encode('utf-8'), user['password']):
                if datetime.now() - password_set_time > timedelta(minutes=PASSWORDRESETMIN):
                    flash('Password has expired. Please reset your password.')
                    conn.close()
                    return redirect(url_for('reset_password'))

                session['username'] = username
                conn.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', (username,))
                conn.commit()
                conn.close()
                flash('Signed in successfully!')
                return redirect(url_for('dashboard'))
            else:
                failed_attempts = user['failed_attempts'] + 1
                if failed_attempts >= FAILEDATTEMPTCNT:
                    lockout_until = datetime.now() + timedelta(minutes=FAILEDATTEMPTBLOCKMIN)
                    conn.execute('UPDATE users SET failed_attempts = ?, lockout_time = ? WHERE username = ?',
                                 (failed_attempts, lockout_until, username))
                    flash(f'Too many failed attempts. Account locked for {FAILEDATTEMPTBLOCKMIN} minute.')
                else:
                    conn.execute('UPDATE users SET failed_attempts = ? WHERE username = ?', (failed_attempts, username))
                    flash('Incorrect password.')
                conn.commit()
                conn.close()
                return redirect(url_for('signin'))
        else:
            flash('Username does not exist.')
            conn.close()
            return redirect(url_for('signin'))

    return render_template('signin.html')

@app.route('/dashboard')
@loginRequired
def dashboard():
    return render_template('dashboard.html')

@app.route('/reset_password', methods=('GET', 'POST'))
def reset_password():
    if request.method == 'POST':
        username = request.form['username']
        old_password = request.form['old_password']
        secret_phrase = request.form['secret_phrase']
        new_password = request.form['new_password']

        password_errors = validatePassword(new_password)
        if password_errors:
            for error in password_errors:
                flash(error)
            return redirect(url_for('reset_password'))

        conn = getDBConnection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user:
            if bcrypt.checkpw(old_password.encode('utf-8'), user['password']) and \
               bcrypt.checkpw(secret_phrase.encode('utf-8'), user['secret_phrase']):
                if bcrypt.checkpw(new_password.encode('utf-8'), user['password']):
                    flash('New password must be different from the current password.')
                    conn.close()
                    return redirect(url_for('reset_password'))

                hashed_new_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                conn.execute('UPDATE users SET failed_attempts = 0, lockout_time = NULL, password = ?, password_set_time = ? WHERE username = ?',
                             (hashed_new_password, datetime.now(), username))
                conn.commit()
                conn.close()
                flash('Password reset successful. Please sign in.')
                return redirect(url_for('signin'))
            else:
                flash('Incorrect credentials. Please try again.')
                conn.close()
                return redirect(url_for('reset_password'))
        else:
            flash('Username does not exist.')
            conn.close()
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been signed out.')
    return redirect(url_for('signin'))

if __name__ == '__main__':
    # initDB()
    app.run(debug=True)
