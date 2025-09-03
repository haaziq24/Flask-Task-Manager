from __future__ import annotations

# Flask Task Manager — single-file app
# - User registration & login (hashed passwords via passlib.bcrypt)
# - SQLite persistence (users, tasks)
# - Task CRUD + filters (all/active/completed), search, categories, due dates
# - Inline Jinja templates using a DictLoader (no separate template files)
#
# Python 3.9+ compatible
# Run:
#   pip install flask passlib
#   python app.py
# Then open http://127.0.0.1:5000

import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Optional

from flask import (
    Flask, request, redirect, url_for, session, abort,
    render_template_string, flash
)
from passlib.hash import bcrypt
from jinja2 import DictLoader

# ----------------------------------------------------------------------------
# 1) Flask app + DB path
# ----------------------------------------------------------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-change-me"  # change for production
DB_PATH = Path(__file__).with_name("taskmanager.db")


# ----------------------------------------------------------------------------
# 2) Database helpers
# ----------------------------------------------------------------------------

def get_db() -> sqlite3.Connection:
    """Return a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            category TEXT DEFAULT '',
            due_date TEXT DEFAULT NULL,
            is_done INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        """
    )

    conn.commit()
    conn.close()


init_db()


# ----------------------------------------------------------------------------
# 3) Auth helpers
# ----------------------------------------------------------------------------

def current_user_id() -> Optional[int]:
    return session.get("user_id")


def login_required(fn):
    from functools import wraps

    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


# ----------------------------------------------------------------------------
# 4) Routes: register/login/logout
# ----------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        pw_hash = bcrypt.hash(password)
        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, pw_hash, datetime.utcnow().isoformat()),
            )
            conn.commit()
            conn.close()
        except sqlite3.IntegrityError:
            flash("Username already taken. Choose another.", "danger")
            return redirect(url_for("register"))

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for("login"))

    return render_template_string(TPL_REGISTER, **common_template_ctx())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if not row or not bcrypt.verify(password, row["password_hash"]):
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))

        session["user_id"] = int(row["id"])  # persist login in secure cookie
        session["username"] = row["username"]
        flash("Logged in successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template_string(TPL_LOGIN, **common_template_ctx())


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ----------------------------------------------------------------------------
# 5) Routes: dashboard + task CRUD
# ----------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    uid = current_user_id()

    show = request.args.get("show", "all")  # all | active | completed
    q = request.args.get("search", "").strip()
    category = request.args.get("category", "").strip()

    where = ["user_id = ?"]
    params = [uid]

    if show == "active":
        where.append("is_done = 0")
    elif show == "completed":
        where.append("is_done = 1")

    if q:
        where.append("title LIKE ?")
        params.append(f"%{q}%")

    if category:
        where.append("category = ?")
        params.append(category)

    where_sql = " AND ".join(where)

    conn = get_db()
    rows = conn.execute(
        f"""
        SELECT id, title, category, due_date, is_done, created_at
        FROM tasks
        WHERE {where_sql}
        ORDER BY is_done ASC, due_date IS NULL, due_date ASC, created_at DESC
        """,
        params,
    ).fetchall()

    cats = conn.execute(
        "SELECT DISTINCT category FROM tasks WHERE user_id = ? AND category != '' ORDER BY category",
        (uid,),
    ).fetchall()
    conn.close()

    return render_template_string(
        TPL_DASHBOARD,
        **common_template_ctx(),
        tasks=rows,
        filter_show=show,
        search_text=q,
        categories=[r["category"] for r in cats],
        active_category=category,
    )


@app.route("/task/new", methods=["POST"])
@login_required
def task_new():
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    due = request.form.get("due_date") or None

    if not title:
        flash("Task title is required.", "danger")
        return redirect(url_for("dashboard"))

    conn = get_db()
    conn.execute(
        "INSERT INTO tasks (user_id, title, category, due_date, is_done, created_at) VALUES (?, ?, ?, ?, 0, ?)",
        (current_user_id(), title, category, due, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()

    flash("Task added!", "success")
    return redirect(url_for("dashboard"))


@app.route("/task/<int:task_id>/toggle", methods=["POST"])
@login_required
def task_toggle(task_id: int):
    uid = current_user_id()
    conn = get_db()
    row = conn.execute("SELECT is_done FROM tasks WHERE id = ? AND user_id = ?", (task_id, uid)).fetchone()
    if not row:
        conn.close()
        abort(404)

    new_val = 0 if row["is_done"] else 1
    conn.execute("UPDATE tasks SET is_done = ? WHERE id = ? AND user_id = ?", (new_val, task_id, uid))
    conn.commit()
    conn.close()

    return redirect(url_for("dashboard"))


@app.route("/task/<int:task_id>/delete", methods=["POST"])
@login_required
def task_delete(task_id: int):
    uid = current_user_id()
    conn = get_db()
    conn.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, uid))
    conn.commit()
    conn.close()
    flash("Task deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/task/<int:task_id>/edit", methods=["POST"])
@login_required
def task_edit(task_id: int):
    uid = current_user_id()
    title = request.form.get("title", "").strip()
    category = request.form.get("category", "").strip()
    due = request.form.get("due_date") or None

    conn = get_db()
    conn.execute(
        """
        UPDATE tasks SET title = ?, category = ?, due_date = ?
        WHERE id = ? AND user_id = ?
        """,
        (title, category, due, task_id, uid),
    )
    conn.commit()
    conn.close()
    flash("Task updated.", "success")
    return redirect(url_for("dashboard"))


# ----------------------------------------------------------------------------
# 6) Inline templates (DictLoader)
# ----------------------------------------------------------------------------
BASE_HTML = """
<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>{{ app_title }}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 0; background:#0f172a; color:#e2e8f0; }
    a { color: #93c5fd; text-decoration: none; }
    .container { max-width: 980px; margin: 0 auto; padding: 24px; }
    header { display:flex; justify-content: space-between; align-items:center; margin-bottom: 16px; }
    .card { background:#111827; border:1px solid #1f2937; border-radius: 12px; padding: 16px; box-shadow: 0 10px 20px rgba(0,0,0,.2); }
    input, select { padding:10px; border-radius:8px; border:1px solid #334155; background:#0b1220; color:#e2e8f0; }
    button { padding:10px 14px; border-radius:10px; border:1px solid #334155; background:#1e40af; color:#e2e8f0; cursor:pointer; }
    button.secondary { background:#0b1220; }
    .grid { display:grid; grid-template-columns: 240px 1fr; gap: 16px; }
    .task { display:flex; align-items:center; gap:12px; padding:10px; border-bottom:1px solid #1f2937; }
    .task.done .title { text-decoration: line-through; color:#9ca3af; }
    .badges { display:flex; gap:8px; font-size:12px; }
    .badge { background:#0b1220; border:1px solid #334155; padding:4px 8px; border-radius:999px; }
    .flash { padding:10px 12px; border-radius:10px; margin-bottom:10px; }
    .flash.success { background:#065f46; }
    .flash.info { background:#1e40af; }
    .flash.warning, .flash.danger { background:#7c2d12; }
    form.inline { display:inline; }
    .muted { color:#9ca3af; }
  </style>
</head>
<body>
  <div class=\"container\">
    <header>
      <h2>{{ app_title }}</h2>
      {% if username %}
        <div>Hi, <strong>{{ username }}</strong> • <a href=\"{{ url_for('logout') }}\">Logout</a></div>
      {% endif %}
    </header>

    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class=\"flash {{ cat }}\">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    {% block content %}{% endblock %}
  </div>
</body>
</html>
"""

# Register the base template under a real name so Jinja can extend it
app.jinja_loader = DictLoader({
    "base.html": BASE_HTML
})


def common_template_ctx():
    return {
        "app_title": "Task Manager",
        "username": session.get("username"),
    }

# --- Register page ---
TPL_REGISTER = (
    "{% extends 'base.html' %}{% block content %}"
    "<div class='card'>"
    "  <h3>Create account</h3>"
    "  <form method='post'>"
    "    <p><input name='username' placeholder='Username' required></p>"
    "    <p><input type='password' name='password' placeholder='Password' required></p>"
    "    <button type='submit'>Register</button>"
    "    <a class='muted' style='margin-left:10px' href='{{ url_for('login') }}'>Have an account? Log in</a>"
    "  </form>"
    "</div>"
    "{% endblock %}"
)

# --- Login page ---
TPL_LOGIN = (
    "{% extends 'base.html' %}{% block content %}"
    "<div class='card'>"
    "  <h3>Log in</h3>"
    "  <form method='post'>"
    "    <p><input name='username' placeholder='Username' required></p>"
    "    <p><input type='password' name='password' placeholder='Password' required></p>"
    "    <button type='submit'>Log in</button>"
    "    <a class='muted' style='margin-left:10px' href='{{ url_for('register') }}'>Create account</a>"
    "  </form>"
    "</div>"
    "{% endblock %}"
)

# --- Dashboard page ---
TPL_DASHBOARD = (
    "{% extends 'base.html' %}{% block content %}"
    "<div class='grid'>"
    "  <aside class='card'>"
    "    <h3>Add task</h3>"
    "    <form method='post' action='{{ url_for('task_new') }}'>"
    "      <p><input name='title' placeholder='Task title' required></p>"
    "      <p><input name='category' placeholder='Category (optional)'></p>"
    "      <p><input type='date' name='due_date' placeholder='Due date (optional)'></p>"
    "      <button type='submit'>Add</button>"
    "    </form>"
    "    <hr style='border-color:#1f2937'>"
    "    <h3>Filters</h3>"
    "    <div class='badges'>"
    "      <a class='badge' href='{{ url_for('dashboard', show='all') }}'>All</a>"
    "      <a class='badge' href='{{ url_for('dashboard', show='active') }}'>Active</a>"
    "      <a class='badge' href='{{ url_for('dashboard', show='completed') }}'>Completed</a>"
    "    </div>"
    "    <form method='get' action='{{ url_for('dashboard') }}' style='margin-top:10px'>"
    "      <p><input name='search' value='{{ search_text }}' placeholder='Search title'></p>"
    "      <p>Category:</p>"
    "      <select name='category'>"
    "        <option value='' {% if not active_category %}selected{% endif %}>Any</option>"
    "        {% for c in categories %}"
    "          <option value='{{ c }}' {% if active_category==c %}selected{% endif %}>{{ c }}</option>"
    "        {% endfor %}"
    "      </select>"
    "      <p><button class='secondary' type='submit'>Apply</button></p>"
    "    </form>"
    "  </aside>"

    "  <main class='card'>"
    "    <h3>Your tasks</h3>"
    "    {% if not tasks %}<p class='muted'>No tasks yet. Add one on the left.</p>{% endif %}"
    "    {% for t in tasks %}"
    "      <div class='task {% if t['is_done'] %}done{% endif %}'>"
    "        <form class='inline' method='post' action='{{ url_for('task_toggle', task_id=t['id']) }}'>"
    "          <button type='submit'>{% if t['is_done'] %}↩ Undo{% else %}✓ Done{% endif %}</button>"
    "        </form>"
    "        <div class='title' style='flex:1'>"
    "          <strong>{{ t['title'] }}</strong><br>"
    "          <span class='badges'>"
    "            {% if t['category'] %}<span class='badge'>#{{ t['category'] }}</span>{% endif %}"
    "            {% if t['due_date'] %}<span class='badge'>Due {{ t['due_date'] }}</span>{% endif %}"
    "          </span>"
    "        </div>"
    "        <form class='inline' method='post' action='{{ url_for('task_delete', task_id=t['id']) }}' onsubmit='return confirm(\"Delete this task?\")'>"
    "          <button class='secondary' type='submit'>Delete</button>"
    "        </form>"
    "      </div>"
    "      <details class='muted' style='margin:4px 0 14px 48px'>"
    "        <summary>Edit</summary>"
    "        <form method='post' action='{{ url_for('task_edit', task_id=t['id']) }}'>"
    "          <input name='title' value='{{ t['title'] }}' placeholder='Title'>"
    "          <input name='category' value='{{ t['category'] }}' placeholder='Category'>"
    "          <input type='date' name='due_date' value='{{ t['due_date'] or \"\" }}'>"
    "          <button type='submit'>Save</button>"
    "        </form>"
    "      </details>"
    "    {% endfor %}"
    "  </main>"
    "</div>"
    "{% endblock %}"
)


# ----------------------------------------------------------------------------
# 7) Run
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)