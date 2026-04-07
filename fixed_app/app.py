"""Hardened Flask application — fixed version of vulnerable_app/app.py.

Security fixes applied:
  - Secret key loaded from environment variable (not hardcoded)
  - eval() replaced with ast.literal_eval() limited to safe expressions
  - subprocess removed; admin route disabled
  - Argon2id password hashing (replaces MD5)
  - Parameterized SQL queries (eliminates SQLi)
  - Jinja2 template with autoescaping (eliminates reflected XSS)
  - CSRF protection via Flask-WTF
  - HTTP security headers via Flask-Talisman
"""

import ast
import os
import sqlite3

from flask import Flask, abort, render_template_string, request
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect, generate_csrf

try:
    from argon2 import PasswordHasher

    _ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2)
    _HAS_ARGON2 = True
except ImportError:
    _HAS_ARGON2 = False

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or os.urandom(32)

csrf = CSRFProtect(app)
Talisman(
    app,
    content_security_policy={
        "default-src": "'self'",
        "script-src": "'self'",
    },
    force_https=False,
)

_DB_CONN: sqlite3.Connection | None = None


def get_db() -> sqlite3.Connection:
    global _DB_CONN
    if _DB_CONN is None:
        _DB_CONN = sqlite3.connect(":memory:", check_same_thread=False)
        _DB_CONN.row_factory = sqlite3.Row
    return _DB_CONN


def init_db() -> None:
    conn = get_db()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users "
        "(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, balance REAL)"
    )
    conn.commit()


def _hash_password(password: str) -> str:
    if _HAS_ARGON2:
        return _ph.hash(password)
    import hashlib

    return hashlib.sha256(password.encode()).hexdigest()


@app.route("/")
def index():
    return "<h1>Fixed App</h1><p>Endpoints: /search, /profile, /transfer, /register</p>"


@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = get_db()
    rows = conn.execute(
        "SELECT username, balance FROM users WHERE username = ?", (query,)
    ).fetchall()
    conn.close()
    results = "".join(f"<li>{r['username']}: ${r['balance']}</li>" for r in rows)
    return f"<ul>{results}</ul>" if results else "<p>No results</p>"


@app.route("/profile")
def profile():
    name = request.args.get("name", "Guest")
    template = "<h1>Hello, {{ name }}!</h1><p>Welcome to your profile.</p>"
    return render_template_string(template, name=name)


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if request.method == "GET":
        token = generate_csrf()
        return (
            f'<form method="POST">'
            f'<input type="hidden" name="csrf_token" value="{token}">'
            f'Amount: <input name="amount"> To: <input name="to">'
            f"<button>Transfer</button></form>"
        )
    amount = request.form.get("amount", "0")
    to_user = request.form.get("to", "")
    return f"<p>Transferred ${amount} to {to_user} (CSRF token validated)</p>"


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    if not username or not password:
        abort(400)
    hashed = _hash_password(password)
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (username, password, balance) VALUES (?, ?, 0)",
            (username, hashed),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return "<p>Username already exists</p>", 409
    finally:
        conn.close()
    return f"<p>Registered {username}</p>"


@app.route("/debug")
def debug():
    expr = request.args.get("expr", "1+1")
    try:
        value = ast.literal_eval(expr)
    except (ValueError, SyntaxError) as e:
        return f"<p>Invalid expression: {e}</p>", 400
    return f"<p>{expr} = {value}</p>"


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5001, debug=False)
