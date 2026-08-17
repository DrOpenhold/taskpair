
from flask import Flask, request, redirect, url_for, render_template, session, jsonify, flash
import sqlite3
from pathlib import Path
from functools import wraps
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash

BASE = Path(__file__).resolve().parent
DB = BASE / "app.db"

app = Flask(__name__)
app.secret_key = "CHANGE_THIS_SECRET_KEY_BEFORE_INTERNET_DEPLOYMENT"

TASK_TYPES = {
    "instant": "Моментальное (до 5 минут)",
    "normal": "Обычное (30 минут — несколько часов)",
    "long": "Долгосрочное с дедлайном",
    "complex": "Сложное",
}

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('giver','executor'))
    );
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT DEFAULT '',
        type TEXT NOT NULL CHECK(type IN ('instant','normal','long','complex')),
        created_by INTEGER NOT NULL,
        assigned_to INTEGER NOT NULL,
        due_date TEXT,
        planned_date TEXT,
        requires_review INTEGER NOT NULL DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'open'
            CHECK(status IN ('open','submitted','completed','rejected')),
        rejection_reason TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        completed_at TEXT,
        FOREIGN KEY(created_by) REFERENCES users(id),
        FOREIGN KEY(assigned_to) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        task_id INTEGER,
        is_read INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(task_id) REFERENCES tasks(id)
    );
    CREATE TABLE IF NOT EXISTS activity (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        task_id INTEGER,
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(task_id) REFERENCES tasks(id)
    );
    """)
    if conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
        conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                     ("giver", generate_password_hash("giver123"), "giver"))
        conn.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
                     ("executor", generate_password_hash("executor123"), "executor"))
    conn.commit()
    conn.close()

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return user

def render(name, **context):
    # Always provide user to all templates.
    context.setdefault("user", current_user())
    return render_template(name, **context)

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def role_required(role):
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            u = current_user()
            if not u or u["role"] != role:
                flash("Недостаточно прав.", "error")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return wrapper
    return deco

def notify(conn, user_id, text, task_id=None):
    conn.execute(
        "INSERT INTO notifications(user_id,text,task_id,created_at) VALUES(?,?,?,?)",
        (user_id, text, task_id, now())
    )

def log(conn, user_id, action, task_id=None):
    conn.execute(
        "INSERT INTO activity(user_id,action,task_id,created_at) VALUES(?,?,?,?)",
        (user_id, action, task_id, now())
    )

@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Неверный логин или пароль.", "error")
    return render("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    conn = get_db()
    if user["role"] == "giver":
        tasks = conn.execute("""
            SELECT t.*, u.username AS executor
            FROM tasks t JOIN users u ON u.id=t.assigned_to
            ORDER BY
              CASE t.status WHEN 'open' THEN 0 WHEN 'submitted' THEN 1
                   WHEN 'rejected' THEN 2 ELSE 3 END,
              COALESCE(t.due_date,t.planned_date,'9999-12-31'), t.id DESC
        """).fetchall()
    else:
        tasks = conn.execute("""
            SELECT t.*, u.username AS giver
            FROM tasks t JOIN users u ON u.id=t.created_by
            WHERE t.assigned_to=?
            ORDER BY
              CASE t.status WHEN 'open' THEN 0 WHEN 'rejected' THEN 1
                   WHEN 'submitted' THEN 2 ELSE 3 END,
              COALESCE(t.due_date,t.planned_date,'9999-12-31'), t.id DESC
        """, (user["id"],)).fetchall()

    notifications = conn.execute("""
        SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 20
    """, (user["id"],)).fetchall()

    activity = conn.execute("""
        SELECT a.*, u.username, t.title
        FROM activity a
        JOIN users u ON u.id=a.user_id
        LEFT JOIN tasks t ON t.id=a.task_id
        ORDER BY a.id DESC LIMIT 50
    """).fetchall()
    conn.close()

    return render("dashboard.html", tasks=tasks, notifications=notifications,
                  activity=activity, types=TASK_TYPES,
                  today=date.today().isoformat())

@app.route("/task/new", methods=["GET","POST"])
@login_required
@role_required("giver")
def new_task():
    if request.method == "POST":
        title = request.form.get("title","").strip()
        description = request.form.get("description","").strip()
        task_type = request.form.get("type","")
        due_date = request.form.get("due_date") or None
        planned_date = request.form.get("planned_date") or None
        requires_review = 1 if request.form.get("requires_review") else 0

        if not title or task_type not in TASK_TYPES:
            flash("Заполните название и выберите тип задания.", "error")
            return render("new_task.html", types=TASK_TYPES,
                          today=date.today().isoformat())

        conn = get_db()
        executor = conn.execute(
            "SELECT * FROM users WHERE role='executor' LIMIT 1"
        ).fetchone()

        if task_type == "long":
            active_long = conn.execute("""
                SELECT COUNT(*) AS c FROM tasks
                WHERE assigned_to=? AND type='long'
                AND status IN ('open','submitted','rejected')
            """, (executor["id"],)).fetchone()["c"]
            if active_long >= 2:
                conn.close()
                flash("Нельзя создать третье активное долгосрочное задание.", "error")
                return render("new_task.html", types=TASK_TYPES,
                              today=date.today().isoformat())
            if not due_date:
                conn.close()
                flash("Для долгосрочного задания нужен дедлайн.", "error")
                return render("new_task.html", types=TASK_TYPES,
                              today=date.today().isoformat())
            if due_date < date.today().isoformat():
                conn.close()
                flash("Дедлайн не может быть в прошлом.", "error")
                return render("new_task.html", types=TASK_TYPES,
                              today=date.today().isoformat())

        if task_type == "normal":
            if not planned_date:
                conn.close()
                flash("Для обычного задания укажите плановую дату.", "error")
                return render("new_task.html", types=TASK_TYPES,
                              today=date.today().isoformat())
            if planned_date <= date.today().isoformat():
                conn.close()
                flash("Обычное задание нельзя назначить на сегодня или прошедшую дату.", "error")
                return render("new_task.html", types=TASK_TYPES,
                              today=date.today().isoformat())
            existing = conn.execute("""
                SELECT COUNT(*) AS c FROM tasks
                WHERE assigned_to=? AND type='normal'
                AND planned_date=?
                AND status IN ('open','submitted','rejected')
            """, (executor["id"], planned_date)).fetchone()["c"]
            if existing:
                conn.close()
                flash("На эту дату уже есть обычное задание.", "error")
                return render("new_task.html", types=TASK_TYPES,
                              today=date.today().isoformat())

        conn.execute("""
            INSERT INTO tasks(title,description,type,created_by,assigned_to,
                              due_date,planned_date,requires_review,status,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
        """, (title, description, task_type, current_user()["id"], executor["id"],
              due_date, planned_date, requires_review, "open", now()))
        task_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]

        notify(conn, executor["id"], f"Новое задание: {title}", task_id)
        log(conn, current_user()["id"], f"Создано задание «{title}»", task_id)
        conn.commit()
        conn.close()
        flash("Задание создано.", "success")
        return redirect(url_for("dashboard"))

    return render("new_task.html", types=TASK_TYPES,
                  today=date.today().isoformat())

@app.post("/task/<int:task_id>/complete")
@login_required
@role_required("executor")
def complete_task(task_id):
    conn = get_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
    if not task or task["assigned_to"] != current_user()["id"]:
        conn.close()
        flash("Задание не найдено.", "error")
        return redirect(url_for("dashboard"))

    if task["status"] == "completed":
        conn.close()
        return redirect(url_for("dashboard"))

    giver = conn.execute("SELECT * FROM users WHERE id=?", (task["created_by"],)).fetchone()

    if task["requires_review"]:
        conn.execute("UPDATE tasks SET status='submitted' WHERE id=?", (task_id,))
        notify(conn, giver["id"], f"Задание «{task['title']}» отправлено на проверку.", task_id)
        log(conn, current_user()["id"], f"Отправлено на проверку: «{task['title']}»", task_id)
    else:
        conn.execute(
            "UPDATE tasks SET status='completed', completed_at=? WHERE id=?",
            (now(), task_id)
        )
        notify(conn, giver["id"], f"Задание «{task['title']}» выполнено.", task_id)
        log(conn, current_user()["id"], f"Выполнено: «{task['title']}»", task_id)

    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))

@app.post("/task/<int:task_id>/review")
@login_required
@role_required("giver")
def review_task(task_id):
    decision = request.form.get("decision")
    reason = request.form.get("reason","").strip()
    conn = get_db()
    task = conn.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()

    if not task or task["created_by"] != current_user()["id"] or task["status"] != "submitted":
        conn.close()
        flash("Задание не найдено или не ожидает проверки.", "error")
        return redirect(url_for("dashboard"))

    executor = conn.execute("SELECT * FROM users WHERE id=?", (task["assigned_to"],)).fetchone()

    if decision == "approve":
        conn.execute(
            "UPDATE tasks SET status='completed', completed_at=? WHERE id=?",
            (now(), task_id)
        )
        notify(conn, executor["id"], f"Выполнение «{task['title']}» подтверждено.", task_id)
        log(conn, current_user()["id"], f"Подтверждено: «{task['title']}»", task_id)
    elif decision == "reject":
        if not reason:
            conn.close()
            flash("Укажите причину отклонения.", "error")
            return redirect(url_for("dashboard"))
        conn.execute(
            "UPDATE tasks SET status='rejected', rejection_reason=? WHERE id=?",
            (reason, task_id)
        )
        notify(conn, executor["id"],
               f"Задание «{task['title']}» отклонено. {reason}", task_id)
        log(conn, current_user()["id"], f"Отклонено: «{task['title']}»", task_id)

    conn.commit()
    conn.close()
    return redirect(url_for("dashboard"))

@app.post("/notifications/read")
@login_required
def read_notifications():
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read=1 WHERE user_id=?",
                 (current_user()["id"],))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})

@app.get("/api/notifications")
@login_required
def api_notifications():
    conn = get_db()
    rows = conn.execute("""
        SELECT id,text,is_read,created_at
        FROM notifications
        WHERE user_id=? ORDER BY id DESC LIMIT 20
    """, (current_user()["id"],)).fetchall()
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.get("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
