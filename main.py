from flask import Flask, render_template, request, redirect, url_for, session
from flask_limiter import Limiter
from user_agents import parse
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length
import sqlite3
import hashlib
from contextlib import closing
import os
import time
from dotenv import load_dotenv
from flask_mail import Mail, Message
from twilio.rest import Client

load_dotenv()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
RECIPIENT_PHONE_NUMBERS = ["+33781112061"]

def send_sms(message):
    try:
        account_sid = 'AC5f96edca010690c516e71d288429427e'
        auth_token = '90ac3ac29d096508c5833c03cb0d9e7d'
        client = Client(account_sid, auth_token)

        message = client.messages.create(
        from_='+12542683434',
        body=message,
        to='+33781112061'
        )

        print(message.sid)

        print("erreur")
    except Exception as e:
        print(e.message)

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])

class AuthServer:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'my_secret_key'
        self.limiter = Limiter(
            app=self.app, key_func=lambda: request.remote_addr, default_limits=["1000 per second"])

        self.failed_attempts = {}

        def add_ip_to_blocklist(ip):
            with open("blocked_ips.txt", "a") as file:
                file.write(ip + "\n")

        def send_intrusion_alert(ip):
            alert_message = f"Intrusion detected from IP address {ip}. The IP has been blocked."
            send_sms(alert_message)
        
        def is_ip_blocked(ip):
            with open("blocked_ips.txt", "r") as file:
                blocked_ips = [line.strip() for line in file.readlines()]
                return ip in blocked_ips
            
        @self.app.errorhandler(429)
        def ratelimit_handler(e):
            send_intrusion_alert("127.0.0.1")
            return render_template('429.html'), 429
    
        @self.app.route('/')
        def home():
            return render_template('home.html')

        @self.app.route('/logout', endpoint='logout')
        def logout():
            if 'username' in session:
                session.pop('username', None)
            return redirect(url_for('login'))

        def is_unknown_agent(user_agent):
            user_agent_obj = parse(user_agent)
            return user_agent_obj.is_bot or user_agent_obj.is_touch_capable

        @self.app.route('/profile')
        def profile():
            return render_template('profile.html')

        @self.app.route('/login', methods=['GET', 'POST'])
        @self.limiter.limit("5 per minute")
        def login():
            form = LoginForm()
            if form.validate_on_submit():
                username = form.username.data
                password = hashlib.sha256(form.password.data.encode()).hexdigest()

                with closing(sqlite3.connect('db.db')) as conn:
                    c = conn.cursor()
                    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
                    user = c.fetchone()

                if user:
                    session['username'] = username
                    return redirect(url_for('welcome'))  
                else:
                    error = 'Invalid username or password'
                    remote_addr = request.remote_addr
                    user_agent = request.headers.get('User-Agent')

                    if is_unknown_agent(user_agent):
                        current_time = int(time.time())
                        failed_attempts_key = f"failed_attempts_{remote_addr}"

                        if failed_attempts_key not in self.failed_attempts:
                            self.failed_attempts[failed_attempts_key] = {"count": 0, "timestamp": current_time}

                        if current_time - self.failed_attempts[failed_attempts_key]["timestamp"] > 60:
                            self.failed_attempts[failed_attempts_key] = {"count": 1, "timestamp": current_time}
                        else:
                            self.failed_attempts[failed_attempts_key]["count"] += 1

                        if self.failed_attempts[failed_attempts_key]["count"] >= 5:
                            add_ip_to_blocklist(remote_addr)

                    return render_template('login.html', error=error, form=form)
            else:
                return render_template('login.html', form=form)

        @self.app.route('/register', methods=['GET', 'POST'])
        def register():
            form = RegistrationForm()
            if form.validate_on_submit():
                username = form.username.data
                password = hashlib.sha256(form.password.data.encode()).hexdigest()

                with closing(sqlite3.connect('db.db')) as conn:
                    c = conn.cursor()
                    c.execute("SELECT * FROM users WHERE username=?", (username,))
                    existing_user = c.fetchone()

                    if existing_user:
                        error = 'Username already exists'
                        return render_template('register.html', error=error, form=form)

                    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                    conn.commit()

                session['username'] = username
                return redirect(url_for('home'))
            else:
                return render_template('register.html', form=form)

        @self.app.route('/welcome')
        def welcome():
            if 'username' in session:
                return render_template('welcome.html', username=session['username'])
            else:
                return redirect(url_for('login'))

        self.app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
        self.app.config['MAIL_PORT'] = 2525
        self.app.config['MAIL_USERNAME'] = '8c179c53a81c32'
        self.app.config['MAIL_PASSWORD'] = 'a8491b9a1affa3'
        self.app.config['MAIL_USE_TLS'] = True
        self.app.config['MAIL_USE_SSL'] = False
        
        self.mail = Mail(self.app)

if __name__ == '__main__':
    app = AuthServer()
    app.app.run(debug=True)
