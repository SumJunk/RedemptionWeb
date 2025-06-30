from flask import Flask, render_template, session
from dotenv import load_dotenv
from routes.register import register_bp
from routes.login import login_bp
import os

load_dotenv(dotenv_path="security.env") # Loads environment variables from .env
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY') # Secret key Flask uses to sign session cookies.
#If someone tampers with the cookie, Flask can tell, and it will reject the session.
app.register_blueprint(register_bp) #links to route blueprints.
app.register_blueprint(login_bp)


@app.route('/')
def home():
    return render_template('index.html', logged_in=session.get('logged_in'), username=session.get('username'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5500))  #dynamic set, if not set 5500 otherwise.
    app.run(debug=False, host='0.0.0.0', port=port) #binds to all public ip addresses, reachable from outside, debug=False turns off debug mode for safety internals/ reloader issues. 