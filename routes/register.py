from flask import Blueprint, request, render_template, redirect, url_for, flash
from routes.saltverifier import generate_srp6_verifier
from db import get_db_connection

register_bp = Blueprint('register', __name__)

@register_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].upper()
        password = request.form['password']
        email = request.form.get('email', '') #optional for now

        salt, verifier = generate_srp6_verifier(username, password) #calls SRP6 utility to generate 'salt' and 'verifier' in db

        conn = get_db_connection() #connection establish with db
        try: #to ensure db closes properly
            with conn.cursor() as cur: #cursor to execute SQL commands

                cur.execute("SELECT id FROM account WHERE username = %s", (username,))#grab id where username = (username)
                if cur.fetchone(): #retreives the next available row, if row is returned...
                    flash("Username already exists.")
                    return redirect(url_for('register.register'))

                cur.execute( #insert account with columns (username, salt, verifier, email)
                    "INSERT INTO account (username, salt, verifier, email) VALUES (%s, %s, %s, %s)",
                    (username, salt, verifier, email)
                )
                conn.commit()
        finally:
            conn.close()

        return redirect(url_for('auth.login'))

    return render_template('register.html')
