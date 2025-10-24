from flask import Flask, render_template, request, redirect, session
import pymysql
from datetime import datetime
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "supersecretkey")

@app.context_processor
def inject_now():
    return {'now': datetime.now}

# --------------------------------------------------
# Database Connection
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
# User Login Data
# --------------------------------------------------
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "staff": {"password": "staff123", "role": "staff"},
}

# --------------------------------------------------
# Logging Function
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
        db.close()
    except Exception as e:
        print("⚠️ Log action error:", e)

# --------------------------------------------------
# LOGIN PAGE
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
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid username or password", now=datetime.now)

    return render_template("login.html", now=datetime.now)

@app.route("/logout")
def logout():
    if "username" in session:
        log_action(session["username"], "Logout")
    session.clear()
    return redirect("/login")

# --------------------------------------------------
# DASHBOARD PAGE
# --------------------------------------------------
@app.route("/")
def dashboard():
    if "username" not in session:
        return redirect("/login")

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
        db.close()
    except Exception as e:
        print("❌ Dashboard DB error:", e)
        return f"Database connection failed: {e}"

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
# RUN SERVER (for Railway)
# --------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Server running on port {port}")
    app.run(host="0.0.0.0", port=port)
