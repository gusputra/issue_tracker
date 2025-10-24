from flask import Flask, render_template, request, redirect, session, send_file
import pymysql
from datetime import datetime
import pandas as pd
import io
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Image, Spacer
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet

app = Flask(__name__)
app.secret_key = "supersecretkey"

@app.context_processor
def inject_now():
    return {'now': datetime.now}

# --------------------------------------------------
# Database Connection
# --------------------------------------------------
def get_db():
    return pymysql.connect(
        host="localhost",
        user="root",
        password="Um@nis97",
        database="db_tracker",
        cursorclass=pymysql.cursors.DictCursor
    )

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
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(
            "INSERT INTO audit_log (username, action, issue_id, timestamp) VALUES (%s, %s, %s, %s)",
            (username, action, issue_id, datetime.now()),
        )
    db.commit()
    db.close()

# --------------------------------------------------
# LOGIN PAGE
# --------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
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

    db = get_db()
    with db.cursor() as cursor:
        # --- Total Issue Counts ---
        cursor.execute("SELECT COUNT(*) AS total FROM issues")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) AS open_issues FROM issues WHERE status='Open'")
        open_issues = cursor.fetchone()["open_issues"]

        cursor.execute("SELECT COUNT(*) AS in_progress FROM issues WHERE status='In Progress'")
        in_progress = cursor.fetchone()["in_progress"]

        cursor.execute("SELECT COUNT(*) AS closed_issues FROM issues WHERE status='Closed'")
        closed_issues = cursor.fetchone()["closed_issues"]

        # --- Priority Counts ---
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

    return render_template(
        "dashboard.html",
        username=session["username"],
        role=session["role"],
        total=total,
        open_issues=open_issues,
        in_progress=in_progress,
        closed_issues=closed_issues,
        priority_low=priority_data["priority_low"] or 0,
        priority_medium=priority_data["priority_medium"] or 0,
        priority_high=priority_data["priority_high"] or 0,
        priority_critical=priority_data["priority_critical"] or 0
    )

# --------------------------------------------------
# ADD ISSUE
# --------------------------------------------------
@app.route("/add_issue", methods=["GET", "POST"])
def add_issue():
    if "username" not in session:
        return redirect("/login")

    if request.method == "POST":
        property_name = request.form["property_name"]
        description = request.form["description"]
        status = request.form["status"]
        priority = request.form["priority"]
        notes = request.form["notes"]
        handled_by = session["username"]

        db = get_db()
        with db.cursor() as cursor:
            cursor.execute(
                "INSERT INTO issues (property_name, description, status, handled_by, priority, notes, created_at) VALUES (%s,%s,%s,%s,%s,%s,%s)",
                (property_name, description, status, handled_by, priority, notes, datetime.now()),
            )
        db.commit()
        db.close()
        return redirect("/recent")

    return render_template("add_issue.html", username=session["username"], role=session["role"])

# --------------------------------------------------
# RECENT ISSUES
# --------------------------------------------------
@app.route("/recent", methods=["GET", "POST"])
def recent():
    if "username" not in session:
        return redirect("/login")

    db = get_db()
    query = "SELECT * FROM issues WHERE 1=1"
    params = []

    if request.method == "POST":
        property_name = request.form.get("property_name")
        status = request.form.get("status")
        priority = request.form.get("priority")

        if property_name:
            query += " AND property_name LIKE %s"
            params.append(f"%{property_name}%")
        if status:
            query += " AND status = %s"
            params.append(status)
        if priority:
            query += " AND priority = %s"
            params.append(priority)

    query += " ORDER BY created_at DESC"

    with db.cursor() as cursor:
        cursor.execute(query, params)
        issues = cursor.fetchall()
    db.close()

    return render_template("recent.html", issues=issues, role=session["role"], username=session["username"])

# --------------------------------------------------
# EDIT ISSUE
# --------------------------------------------------
@app.route("/edit/<int:issue_id>", methods=["GET", "POST"])
def edit_issue(issue_id):
    if "username" not in session:
        return redirect("/login")

    db = get_db()
    if request.method == "POST":
        property_name = request.form["property_name"]
        description = request.form["description"]
        status = request.form["status"]
        priority = request.form["priority"]
        notes = request.form["notes"]

        with db.cursor() as cursor:
            cursor.execute(
                "UPDATE issues SET property_name=%s, description=%s, status=%s, priority=%s, notes=%s WHERE id=%s",
                (property_name, description, status, priority, notes, issue_id),
            )
        db.commit()
        db.close()

        log_action(session["username"], "Edited issue", issue_id)
        return redirect("/recent")

    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM issues WHERE id=%s", (issue_id,))
        issue = cursor.fetchone()
    db.close()
    return render_template("edit.html", issue=issue, role=session["role"])

# --------------------------------------------------
# DELETE ISSUE
# --------------------------------------------------
@app.route("/delete/<int:issue_id>")
def delete_issue(issue_id):
    if "username" not in session or session["role"] != "admin":
        return redirect("/login")

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("DELETE FROM issues WHERE id=%s", (issue_id,))
    db.commit()
    db.close()

    log_action(session["username"], "Deleted issue", issue_id)
    return redirect("/recent")

# --------------------------------------------------
# AUDIT LOG
# --------------------------------------------------
@app.route("/audit_log")
def audit_log():
    if "username" not in session or session["role"] != "admin":
        return redirect("/login")

    db = get_db()
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM audit_log ORDER BY timestamp DESC")
        logs = cursor.fetchall()
    db.close()

    return render_template("audit_log.html", logs=logs, role=session["role"])

# --------------------------------------------------
# EXPORT REPORT (PDF & EXCEL)
# --------------------------------------------------
@app.route("/export", methods=["GET", "POST"])
def export():
    if "username" not in session or session["role"] != "admin":
        return redirect("/login")

    if request.method == "POST":
        date_range = request.form["date_range"]
        export_type = request.form["export_type"]

        # Parsing date range dari flatpickr
        if "→" in date_range:
            start_date, end_date = [d.strip() for d in date_range.split("→")]
        elif "to" in date_range:
            start_date, end_date = [d.strip() for d in date_range.split("to")]
        else:
            return "<h3 style='text-align:center;margin-top:50px;'>❌ Invalid date range format.</h3>"

        db = get_db()
        query = """
            SELECT id, property_name, description, status, handled_by, priority, 
                   created_at, notes 
            FROM issues 
            WHERE DATE(created_at) BETWEEN %s AND %s 
            ORDER BY created_at DESC
        """
        with db.cursor() as cursor:
            cursor.execute(query, (start_date, end_date))
            data = cursor.fetchall()
        db.close()

        if not data:
            return "<h3 style='text-align:center;margin-top:50px;'>❌ No data found for that date range.</h3>"

        # ---------- EXPORT EXCEL ----------
        if export_type == "excel":
            df = pd.DataFrame(data)
            if "created_at" in df.columns:
                df["created_at"] = pd.to_datetime(df["created_at"]).dt.strftime("%Y-%m-%d %H:%M")

            output = io.BytesIO()
            with pd.ExcelWriter(output, engine="xlsxwriter") as writer:
                df.to_excel(writer, index=False, sheet_name="Issues")
                workbook = writer.book
                worksheet = writer.sheets["Issues"]

                header_format = workbook.add_format({
                    "bold": True,
                    "font_color": "white",
                    "bg_color": "#2E75B6",
                    "align": "center",
                    "valign": "vcenter",
                    "border": 1
                })

                for col_num, value in enumerate(df.columns.values):
                    worksheet.write(0, col_num, value, header_format)
                    col_width = max(df[value].astype(str).map(len).max(), len(value)) + 3
                    worksheet.set_column(col_num, col_num, col_width)

                cell_format = workbook.add_format({
                    "text_wrap": True,
                    "valign": "top",
                    "border": 1
                })
                worksheet.set_column(0, len(df.columns) - 1, None, cell_format)

                for row_num in range(1, len(df) + 1):
                    if row_num % 2 == 0:
                        worksheet.set_row(row_num, None, workbook.add_format({"bg_color": "#F2F2F2"}))

            output.seek(0)
            filename = f"Issue_Report_{start_date}_to_{end_date}.xlsx"
            return send_file(output, download_name=filename, as_attachment=True,
                             mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

        # ---------- EXPORT PDF ----------
        elif export_type == "pdf":
            output = io.BytesIO()
            doc = SimpleDocTemplate(output, pagesize=landscape(A4))
            styles = getSampleStyleSheet()

            elements = []

            # Tambahkan logo jika ada
            try:
                logo = Image("static/images/HL_logo.png", width=80, height=40)
                elements.append(logo)
            except Exception:
                pass

            elements.append(Paragraph("<b>📊 Issue Tracker Report</b>", styles["Title"]))
            elements.append(Paragraph(f"Period: {start_date} — {end_date}", styles["Heading3"]))
            elements.append(Paragraph(f"Generated by: {session['username']} on {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]))
            elements.append(Spacer(1, 12))

            data_table = [["ID", "Property", "Description", "Status", "Handled By", "Priority", "Created", "Notes"]]
            for row in data:
                data_table.append([
                    row["id"],
                    row["property_name"],
                    row["description"],
                    row["status"],
                    row["handled_by"],
                    row["priority"],
                    row["created_at"].strftime("%Y-%m-%d %H:%M"),
                    row["notes"]
                ])

            table = Table(data_table, repeatRows=1, hAlign='CENTER')
            table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E75B6")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), 11),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F2F2F2")]),
            ]))

            elements.append(table)
            doc.build(elements)

            output.seek(0)
            filename = f"Issue_Report_{start_date}_to_{end_date}.pdf"
            return send_file(output, download_name=filename, as_attachment=True, mimetype="application/pdf")

    return render_template("export.html", role=session["role"])

# --------------------------------------------------
# RUN SERVER
# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
