from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from routes.saltverifier import sha1_binary, int_to_le_bytes, le_bytes_to_int
from db import get_db_connection

login_bp = Blueprint('auth', __name__)

@login_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_input = request.form['username'].upper() #grab username and password input converted to uppercase
        password_input = request.form['password'].upper()

        conn = get_db_connection() #Start db connection (conn).
        try:
            with conn.cursor() as cur: #DB cursor named cur with proper cleanup (with).
                cur.execute("SELECT * FROM account WHERE username = %s", (username_input,))
                user = cur.fetchone() #Fetch operation to get a single row from the results of your SQL query (line above).

                if not user:
                    flash("Invalid username or password.")
                    return redirect(url_for('auth.login'))

                if user.get('locked'):
                    flash("Account is Banned. Sorry foo...")
                    return redirect(url_for('auth.login'))

                salt = user['salt']
                verifier_db = user['verifier']

                # Calculate verifier from input password and stored salt
                h1 = sha1_binary(f"{username_input}:{password_input}".encode()) #SRP6 step 1: binary digest
                h2 = sha1_binary(salt + h1)
                h2_int = le_bytes_to_int(h2)

                G = 7
                N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
                verifier_int = pow(G, h2_int, N)
                verifier_calc = int_to_le_bytes(verifier_int, 32)

                if verifier_calc == verifier_db:
                    session['logged_in'] = True
                    session['username'] = username_input #temporary storage space per user (session) with a key storing the current user's username.
                    flash("Welcome to Redemption!")
                    return redirect(url_for('home'))
                else:
                    flash("Invalid username or password.")
                    return redirect(url_for('auth.login'))
        finally:
            conn.close()

    return render_template('login.html')

@login_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('home'))