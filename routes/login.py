from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from routes.saltverifier import sha1_binary, int_to_le_bytes, le_bytes_to_int
from routes.register import generate_otp, send_otp_email
from db import get_db_connection
from datetime import datetime, timedelta

login_bp = Blueprint('auth', __name__)

MAX_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=60)

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_input = request.form['username'].upper()
        password_input = request.form['password'].upper()

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM account WHERE username = %s", (username_input,))
                user = cur.fetchone()

                if not user:
                    flash("Invalid username or password.")
                    return redirect(url_for('auth.login'))

                # ⛔ Check lockout
                lockout_until = user.get('lockout_until')
                if lockout_until and datetime.now() < lockout_until:
                    remaining = int((lockout_until - datetime.now()).total_seconds() / 60)
                    flash(f"Account is temporarily locked. Try again in {remaining} minute(s).")
                    return redirect(url_for('auth.login'))

                salt = user['salt']
                verifier_db = user['verifier']

                h1 = sha1_binary(f"{username_input}:{password_input}".encode())
                h2 = sha1_binary(salt + h1)
                h2_int = le_bytes_to_int(h2)

                G = 7
                N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
                verifier_int = pow(G, h2_int, N)
                verifier_calc = int_to_le_bytes(verifier_int, 32)

                if verifier_calc == verifier_db:
                    # ✅ Reset failed attempts on successful login
                    cur.execute("""
                        UPDATE account SET failed_logins = 0, lockout_until = NULL WHERE id = %s
                    """, (user['id'],))
                    conn.commit()

                    session['username'] = username_input
                    session['logged_in'] = True
                    session['user_id'] = user['id']

                    otp_verified = user['otp_verified']
                    otp_verified_at = user['otp_verified_at'] or datetime.min

                    # 🔄 Expire verification after 1 day
                    if (datetime.now() - otp_verified_at).days >= 1 and otp_verified:
                        cur.execute("UPDATE account SET otp_verified = 0 WHERE id = %s", (user['id'],))
                        conn.commit()

                    if not otp_verified:
                        expires_at = user['otp_expires_at']
                        if not expires_at or datetime.now() > expires_at:
                            otp_code = generate_otp()
                            new_expires = datetime.now() + timedelta(minutes=5)

                            send_otp_email(user['email'], otp_code)
                            cur.execute("""
                                UPDATE account SET otp_code = %s, otp_expires_at = %s WHERE id = %s
                            """, (otp_code, new_expires, user['id']))
                            conn.commit()

                            flash("Your verification code has expired. A new code has been sent to your email.")
                        else:
                            flash("Please verify your email.")

                        return redirect(url_for('verify.verify'))

                    flash("Welcome to Redemption!")
                    return redirect(url_for('home'))

                else:
                    # ❌ Wrong password — increment failed attempts
                    new_attempts = user.get('failed_logins', 0) + 1
                    lockout_until = None

                    if new_attempts >= MAX_ATTEMPTS:
                        lockout_until = datetime.now() + LOCKOUT_DURATION
                        flash(f"Too many failed attempts. Account locked for {LOCKOUT_DURATION.seconds // 60} minutes.")
                    else:
                        flash("Invalid username or password.")

                    cur.execute("""
                        UPDATE account SET failed_logins = %s, lockout_until = %s WHERE id = %s
                    """, (new_attempts, lockout_until, user['id']))
                    conn.commit()

                    return redirect(url_for('auth.login'))

        finally:
            conn.close()

    return render_template('login.html')

@login_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('home'))
