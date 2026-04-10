"""Deliberately vulnerable Flask application for Experiment 3.

This file contains intentional security flaws for educational scanning.
DO NOT deploy this application in any production or Internet-facing environment.

Intentional flaws (for static and dynamic scanning exercises):
  - Hardcoded secret key (bandit B105)
  - Use of eval() (bandit B307)
  - Insecure subprocess with shell=True (bandit B602)
  - MD5 password hashing (bandit B324)
  - SQL injection on /search (no parameterization)
  - Reflected XSS on /profile (render_template_string without escaping)
  - Missing CSRF protection on /transfer
  - Missing HTTP security headers
"""

import hashlib
import sqlite3
import subprocess  # noqa: S404

from flask import Flask, request

app = Flask(__name__)
app.secret_key = "supersecret123"  # noqa: S105  # B105: hardcoded secret

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
        "(id INTEGER PRIMARY KEY, username TEXT, password TEXT, balance REAL)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, balance) VALUES "
        "(1, 'alice', 'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f', 100.0)"
    )
    conn.execute(
        "INSERT OR IGNORE INTO users (id, username, password, balance) VALUES "
        "(2, 'admin', '5f4dcc3b5aa765d61d8327deb882cf99', 9999.0)"
    )
    conn.commit()


@app.route("/")
def index():
    return (
        "<h1>Vulnerable App</h1><p>Endpoints: /search, /profile, /transfer, /register, /admin</p>"
    )


@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = get_db()
    # B608 / SQLi: raw string concatenation
    sql = "SELECT username, balance FROM users WHERE username = '" + query + "'"
    try:
        rows = conn.execute(sql).fetchall()  # noqa: S608
    except Exception as e:
        return f"<p>Error: {e}</p>", 500
    results = "".join(f"<li>{r['username']}: ${r['balance']}</li>" for r in rows)
    return f"<ul>{results}</ul>" if results else "<p>No results</p>"


@app.route("/profile")
def profile():
    from flask import render_template_string

    name = request.args.get("name", "Guest")
    # XSS: unsanitized user input in render_template_string
    template = f"<h1>Hello, {name}!</h1><p>Welcome to your profile.</p>"
    return render_template_string(template)  # noqa: S701


@app.route("/transfer", methods=["POST"])
def transfer():
    # Missing CSRF token check
    amount = request.form.get("amount", "0")
    to_user = request.form.get("to", "")
    return f"<p>Transferred ${amount} to {to_user} (no CSRF check performed)</p>"


@app.route("/register", methods=["POST"])
def register():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # B324: MD5 password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()  # noqa: S324
    conn = get_db()
    conn.execute(
        "INSERT INTO users (username, password, balance) VALUES (?, ?, 0)", (username, hashed)
    )
    conn.commit()
    return f"<p>Registered {username}</p>"


@app.route("/admin")
def admin():
    cmd = request.args.get("cmd", "echo hello")
    # B602 + B605: shell=True subprocess injection
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)  # noqa: S602 S605
    return f"<pre>{result.stdout}</pre>"


@app.route("/debug")
def debug():
    expr = request.args.get("expr", "1+1")
    # B307: eval of user-controlled input
    try:
        value = eval(expr)  # noqa: S307 PGH001
    except Exception as e:
        value = f"Error: {e}"
    return f"<p>{expr} = {value}</p>"


init_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
