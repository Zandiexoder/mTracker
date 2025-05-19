from flask import Flask, render_template, flash, request, send_file, redirect, url_for, session
from wtforms import Form, StringField, TextAreaField, RadioField, validators, SubmitField, PasswordField
import logging
import time
import db
import os
from flask_mail import Mail, Message
import threading
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config.from_object(__name__)
app.config['SECRET_KEY'] = '7d441f27d441f27567d441f2b6176a'

app.config.update(
    DEBUG=True,
    #EMAIL SETTINGS
    MAIL_SERVER='smtp.mail.yahoo.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = 'YOUR_EMAIL',
    MAIL_PASSWORD = 'YOUR_PASSWORD'
)
mail = Mail(app)

ii = {1234:['prashantsengar5@gmail.com','abc@ptg.com']}

DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def init_user_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')
    # Add a default admin user if not exists
    c.execute('SELECT * FROM users WHERE username=?', ('admin',))
    if not c.fetchone():
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                  ('admin', generate_password_hash('password123')))
    conn.commit()
    conn.close()

def get_user(username):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT username, password_hash FROM users WHERE username=?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def add_user(username, password):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                  (username, generate_password_hash(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def get_my_ip():
    return request.remote_addr

def maill(sender, receiver, ip):
    try:
        msg = Message(f"{receiver} has opened the email",
          sender="prashantsgig@yahoo.com",
          recipients=[sender])
        msg.body = f"{receiver} opened the email just now from IP: {ip}\n\n'Sent by mTrack'"           
        mail.send(msg)
        app.logger.warning('Mail sent!')
    except Exception as e:
        app.logger.warning(e)

@app.route("/image", methods=["GET"])
def render_image():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    app.logger.warning('Called')
    mailID = int(request.args.get('type'))
    app.logger.warning(mailID)
    if mailID in ii:
        ip = get_my_ip()
        app.logger.warning(ip)
        maill(ii[mailID][0], ii[mailID][1], ip)
    return send_file('pi.png', mimetype='image/gif')

def create_id():
    return str(int(time.time()%99999))

class LoginForm(Form):
    username = StringField('Username', validators=[validators.DataRequired()])
    password = PasswordField('Password', validators=[validators.DataRequired()])

class ReusableForm(Form):
    def validate_amazon(form, field):
        logging.warning(field.data)
        
    sender = StringField('Sender\'s email:', validators=[validators.DataRequired()])
    receiver = StringField('Receiver\'s email:', validators=[validators.Email('Please enter a valid email address')])
    # url = StringField('URL:', validators=[validators.DataRequired(), validators.URL('Enter URL with http:// or https://'), validate_amazon])
    # label = RadioField('Label', choices=[('PayPal','PayPal'),('Amazon','Amazon Gift Card'),('ptm', 'PayTM')])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/", methods=['GET', 'POST'])
@login_required
def hello():
    form = ReusableForm(request.form)
    print(form.errors)
    if request.method == 'POST':
        sender = str(request.form['sender'])
        receiver = str(request.form['receiver'])
        if form.validate():
            mail_id = create_id()
            flash('SUCCESS: Thanks for registration ')
            logging.warning(f'{sender}, {receiver}')
            flash(f'Paste this HTML code in the email: ')
            url = request.url_root
            html_code = f'<img src={url}image?type={mail_id}></img>'
            flash(f'{html_code}')
            db.write_data(sender, receiver, mail_id)
            ii[int(mail_id)] = [sender, receiver]
            app.logger.warning(ii)
        else:
            msg = ''
            ers = form.errors
            for key in ers.keys():
                for l in ers[key]:
                    msg += l
                    msg += '. '
            print(msg)
            flash(f'Error: {msg}')
    return render_template('hello.html', form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = get_user(username)
        if user and check_password_hash(user[1], password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("hello"))
        else:
            flash("Invalid username or password.")
    return render_template("login.html", form=form)

@app.cli.command("logout-all")
def logout_all():
    """Deauthenticate all users by clearing all sessions (requires server restart for full effect)."""
    print("All users will be logged out on next request (session cookies will be invalidated if server restarts).")
    # For Flask's default session, clearing all sessions requires a server restart or changing the SECRET_KEY.
    # Here, we rotate the SECRET_KEY to force logout for all users:
    import secrets
    new_key = secrets.token_hex(24)
    app.config['SECRET_KEY'] = new_key
    print(f"SECRET_KEY rotated. All users will be logged out. New SECRET_KEY: {new_key}")

# Usage in terminal:
# flask logout-all

if __name__ == "__main__":
    init_user_db()
    try:
        port = int(os.environ.get('PORT', 5000))
        app.run(host='0.0.0.0', port=port)
    except:
        logging.exception('error')
