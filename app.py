import os
from flask import Flask, render_template

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
 port = int(os.environ.get('PORT', 5500))  #dynamic set, if not set 5500 otherwise.
 app.run(debug=False, host='0.0.0.0', port=port) #binds to all public ip addresses, reachable from outside, debug=False turns off debug mode for safety internals/ reloader issues. 
