from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from routes.saltverifier import generate_srp6_verifier
from db import get_db_connection
import random
import requests
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import os

register_bp = Blueprint('register', __name__)

# Generate 6-digit OTP
def generate_otp():
    return f"{random.randint(100000, 999999)}"

# Send OTP (one time password) via email
def send_otp_email(recipient_email, otp):
    body = f"Your verification code is: {otp}" # Uses f-string "variables into strings, so otp"
    msg = MIMEText(body) # MIME(Multipurpose Internet Mail Extensions) = standard that allows emails to include text(plain or HTML) and attachments.
    msg['Subject'] = "Verify Your Email"
    msg['From'] = os.environ.get('EMAIL_FROM')
    msg['To'] = recipient_email

    with smtplib.SMTP_SSL(os.environ.get('SMTP_SERVER'), int(os.environ.get('SMTP_PORT'))) as server: # smtplib = Python library used to send emails using the SMTP protocol
        server.login(os.environ.get('SMTP_USER'), os.environ.get('SMTP_PASSWORD')) # Authenticates with email server with Gmail and App Password.
        server.send_message(msg) # Sends MIME message

@register_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        ip_address = request.remote_addr
        username = request.form['username'].upper()
        password = request.form['password']
        email = request.form.get('email')
        recaptcha_response = request.form.get('g-recaptcha-response')
        secret_key = os.getenv("RECAPTCHA_SECRET_KEY")

        verify_response = requests.post(
            'https://www.google.com/recaptcha/api/siteverify',
            data={'secret': secret_key, 'response': recaptcha_response}
        )

        captcha_result = verify_response.json()
        
        # Validate required fields
        if not username:
            flash("Username is required.")
            return redirect(url_for('register.register'))
        if not password:
            flash("Password is required.")
            return redirect(url_for('register.register'))
        if not email:
            flash("Email is required.")
            return redirect(url_for('register.register'))
        if not captcha_result.get('success'):
            flash("CAPTCHA verification failed. Please try again.")
            return redirect(url_for('register.register'))


        salt, verifier = generate_srp6_verifier(username, password) # Calls SRP6 utility to generate 'salt' and 'verifier' in db
        otp_code = generate_otp() # Current generated OTP code 
        otp_expires_at = datetime.now() + timedelta(minutes=5) # Experation time of OTP in db
        

        conn = get_db_connection()
        try: # To ensure db closes properly
            with conn.cursor() as cur: # Cursor to execute SQL commands
                # Check for existing Username
                cur.execute("SELECT id FROM account WHERE username = %s", (username,))
                if cur.fetchone(): # Retreives the next available row, if row is returned...
                    flash("Username already exists.")
                    return redirect(url_for('register.register'))

                # Check for existing Email
                cur.execute("SELECT id FROM account WHERE email = %s", (email,))
                if cur.fetchone():
                    flash("An account with that email already exists.")
                    return redirect(url_for('register.register'))
                
                cur.execute("""SELECT 1 FROM account WHERE registration_ip = %s AND registration_time >= NOW() - INTERVAL 1 DAY
                            """, (ip_address,))
                recent_reg = cur.fetchone()

                if recent_reg:
                    flash("An account has already been registered from this IP in the last 24 hours.")
                    return redirect(url_for('register.register'))
                
                # Send email before inserting into DB
                send_otp_email(email, otp_code)

                cur.execute(
                    "INSERT INTO account (username, salt, verifier, email, otp_code, otp_expires_at, registration_ip, registration_time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                    (username, salt, verifier, email, otp_code, otp_expires_at, ip_address, datetime.now())
                )
                conn.commit()

                 # Fetch the inserted user ID
                cur.execute("SELECT id FROM account WHERE username = %s", (username,))
                user = cur.fetchone()

                # Automatically log the user in
                session['user_id'] = user['id']
                session['username'] = username
                session['logged_in'] = True

                flash("Check your email and verify your account.")
                return redirect(url_for('verify.verify'))
        finally:
            conn.close()
            
    return render_template('register.html', recaptcha_site_key=os.environ.get('RECAPTCHA_SITE_KEY')) #allows use of env in register.html

