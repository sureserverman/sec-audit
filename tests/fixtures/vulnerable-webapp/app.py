# Synthetic vulnerable Django/Flask snippet — bearer-detectable SQL injection.
import sqlite3
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route("/users")
def users():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    rows = conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()
    return str(rows)

@app.route("/redirect")
def open_redirect():
    next_url = request.args.get("next")
    return redirect(next_url)
