from flask import Blueprint, request, render_template, redirect, url_for, flash, session
from db import get_db_connection
from datetime import datetime

verify_bp = Blueprint('verify', __name__)

@verify_bp.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'user_id' not in session:
        flash("You must be logged in to verify your account.")
        return redirect(url_for('auth.login'))

    user_id = session['user_id']

    if request.method == 'POST':
        input_code = request.form['otp_code']

        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT otp_code, otp_expires_at FROM account WHERE id = %s", (user_id,))
                user = cur.fetchone()

                if not user:
                    flash("User not found.")
                    return redirect(url_for('auth.login'))

                stored_code = user['otp_code']
                expires_at = user['otp_expires_at']

                if datetime.now() > expires_at:
                    flash("Verification code has expired.")
                    return redirect(url_for('verify.verify'))

                if input_code == stored_code:
                    cur.execute("""
                        UPDATE account
                        SET otp_verified = 1, otp_verified_at = %s
                        WHERE id = %s
                    """, (datetime.now(), user_id))
                    
                    cur.execute("""
                        DELETE FROM account_banned
                         WHERE id = %s
                        AND banreason = 'unverified'
                        AND active = 1
                    """, (user_id,))

                    conn.commit()

                    flash("Email verified successfully!")
                    return redirect(url_for('home'))
                else:
                    flash("Invalid verification code.")
        finally:
            conn.close()

    return render_template('verify.html')

