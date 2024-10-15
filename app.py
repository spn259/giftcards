

from flask import (Flask, json, jsonify, redirect, render_template, request,
                   session, url_for, render_template_string, current_app)

app = Flask(__name__)

@app.route('/')
def landing():
    return render_template("base.html")

local = False
if local:
    app.run(debug=True, host="0.0.0.0", port=8080, threaded=True, use_reloader=True)

