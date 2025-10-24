from flask import Flask, render_template, request, redirect, session, url_for
import pymysql
from datetime import datetime
import os
from dotenv import load_dotenv

# --------------------------------------------------
# INITIAL SETUP
# --------------------------------------------------
load_dotenv()

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

# --------------------------------------------------
# CONTEXT (inject current time globally)
# --------------------------------------------------
@app.context_processor
def inject_now():
    return {'now': datetime.now()}

# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------
def get_db():
    try:
        return pymysql.connect(
            host=os.getenv("DB_HOST", "mysql.railway.internal"),
            user=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD"),
            database=os.getenv("DB_NAME", "railway"),
            port=int(os.getenv("DB_PORT", 3306)),
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception as e:
        print("❌ Database connection error:", e)
        raise

# --------------------------------------------------
# STATIC USER LOGIN DATA
# --------------------------------------------------
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "staff": {"password": "staff123", "role": "staff"},
}

# --------------------------------------------------
# LOGGING FUNCTION
# --------------------------------------------------
def log_action(username, action, issue_id=None):
    try:
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_log (username, action, issue_id, timestamp) VALUES (%s, %s, %s, %s)",
                (username, action, issue_id, datetime.now()),
            )
        db.commit()
    except Exception as e:
        print("⚠️ Log action error:", e)
    finally:
        db.close()

# --------------------------------------------------
# LOGIN & LOGOUT
# --------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        user = USERS.get(username)

        if user and user["password"] == password:
            session["username"] = username
            session["role"] = user["role"]
            log_action(username, "Login to system")
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")

@app.route("/logout")
def logout():
    if "username" in session:
        log_action(session["username"], "Logout")
    session.clear()
    return redirect(url_for("login"))

# --------------------------------------------------
# DASHBOARD PAGE
# --------------------------------------------------
@app.route("/")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) AS total FROM issues")
            total = cursor.fetchone()["total"]

            cursor.execute("SELECT COUNT(*) AS open_issues FROM issues WHERE status='Open'")
            open_issues = cursor.fetchone()["open_issues"]

            cursor.execute("SELECT COUNT(*) AS in_progress FROM issues WHERE status='In Progress'")
            in_progress = cursor.fetchone()["in_progress"]

            cursor.execute("SELECT COUNT(*) AS closed_issues FROM issues WHERE status='Closed'")
            closed_issues = cursor.fetchone()["closed_issues"]

            cursor.execute("""
                SELECT 
                    SUM(CASE WHEN priority='Low' THEN 1 ELSE 0 END) AS priority_low,
                    SUM(CASE WHEN priority='Medium' THEN 1 ELSE 0 END) AS priority_medium,
                    SUM(CASE WHEN priority='High' THEN 1 ELSE 0 END) AS priority_high,
                    SUM(CASE WHEN priority='Critical' THEN 1 ELSE 0 END) AS priority_critical
                FROM issues
            """)
            priority_data = cursor.fetchone()
    except Exception as e:
        print("❌ Dashboard DB error:", e)
        return f"Database connection failed: {e}"
    finally:
        db.close()

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        total=total,
        open_issues=open_issues,
        in_progress=in_progress,
        closed_issues=closed_issues,
        priority_low=priority_data.get("priority_low", 0),
        priority_medium=priority_data.get("priority_medium", 0),
        priority_high=priority_data.get("priority_high", 0),
        priority_critical=priority_data.get("priority_critical", 0)
    )

# --------------------------------------------------
# ADD ISSUE PAGE
# --------------------------------------------------
@app.route("/add_issue", methods=["GET", "POST"])
def add_issue():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        priority = request.form.get("priority")
        status = request.form.get("status")

        try:
            db = get_db()
            with db.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO issues (title, description, priority, status, created_by, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
                    (title, description, priority, status, session["username"], datetime.now())
                )
            db.commit()
            log_action(session["username"], f"Added new issue: {title}")
        except Exception as e:
            print("❌ Add issue error:", e)
        finally:
            db.close()

        return redirect(url_for("dashboard"))

    return render_template("add_issue.html", username=session["username"], role=session["role"])

# --------------------------------------------------
# EDIT ISSUE PAGE
# --------------------------------------------------
@app.route("/edit/<int:issue_id>", methods=["GET", "POST"])
def edit(issue_id):
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        db = get_db()
        with db.cursor() as cursor:
            if request.method == "POST":
                title = request.form.get("title")
                description = request.form.get("description")
                priority = request.form.get("priority")
                status = request.form.get("status")

                cursor.execute(
                    "UPDATE issues SET title=%s, description=%s, priority=%s, status=%s WHERE id=%s",
                    (title, description, priority, status, issue_id)
                )
                db.commit()
                log_action(session["username"], f"Edited issue ID {issue_id}")
                return redirect(url_for("dashboard"))

            cursor.execute("SELECT * FROM issues WHERE id=%s", (issue_id,))
            issue = cursor.fetchone()
    except Exception as e:
        print("❌ Edit issue DB error:", e)
        issue = None
    finally:
        db.close()

    return render_template("edit.html", issue=issue, username=session["username"], role=session["role"])

# --------------------------------------------------
# RECENT ISSUES PAGE
# --------------------------------------------------
@app.route("/recent")
def recent():
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM issues ORDER BY created_at DESC LIMIT 20")
            issues = cursor.fetchall()
    except Exception as e:
        print("❌ Recent issues DB error:", e)
        issues = []
    finally:
        db.close()

    return render_template("recent.html", issues=issues, username=session["username"], role=session["role"])

# --------------------------------------------------
# AUDIT LOG PAGE
# --------------------------------------------------
@app.route("/audit_log")
def audit_log():
    if "username" not in session:
        return redirect(url_for("login"))

    try:
        db = get_db()
        with db.cursor() as cursor:
            cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100")
            logs = cursor.fetchall()
    except Exception as e:
        print("❌ Audit log DB error:", e)
        logs = []
    finally:
        db.close()

    return render_template("audit_log.html", logs=logs, username=session["username"], role=session["role"])

# --------------------------------------------------
# EXPORT PAGE
# --------------------------------------------------
@app.route("/export")
def export():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("export.html", username=session["username"], role=session["role"])

# --------------------------------------------------
# SERVER STARTUP
# --------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Server running on port {port}")
    app.run(host="0.0.0.0", port=port)
