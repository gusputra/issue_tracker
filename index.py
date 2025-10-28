from flask import (
    Flask, render_template, request, redirect,
    session, url_for, flash, send_file, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    login_required, logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime, timedelta
from urllib.parse import urlparse, urljoin
import pandas as pd
from io import BytesIO

# ---------------------------------------------------
# APP SETUP
# ---------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'  # ganti ke env var di production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///./issues.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.permanent_session_lifetime = timedelta(days=7)

db = SQLAlchemy(app)

# ---------------------------------------------------
# DATABASE MODELS
# ---------------------------------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='user')


class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='In Progress')
    level = db.Column(db.String(50), nullable=False)
    handled_by = db.Column(db.String(100), nullable=False)
    # gunakan utc time untuk konsistensi (hindari komplikasi timezone saat query)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class LogActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# ---------------------------------------------------
# LOGIN SETUP
# ---------------------------------------------------
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception:
        return None


# helper: check safe redirect
def is_safe_url(target):
    host_url = urlparse(request.host_url)
    redirect_url = urlparse(urljoin(request.host_url, target))
    return (redirect_url.scheme in ('http', 'https') and host_url.netloc == redirect_url.netloc)


# ---------------------------------------------------
# ROLE-BASED ACCESS DECORATOR
# ---------------------------------------------------
def role_required(role):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            if current_user.role != role:
                flash('You do not have permission to access this page.', 'warning')
                # arahkan non-admin ke recent (bukan dashboard admin-only)
                return redirect(url_for('recent'))
            return f(*args, **kwargs)
        return decorated_function
    return wrapper


# ---------------------------------------------------
# ROUTES
# ---------------------------------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))


# ---------- LOGIN ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            # login user
            login_user(user)  # sets Flask-Login session
            # set flask session as well
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session.modified = True

            flash('Login successful!', 'success')

            # handle next param securely
            next_page = request.args.get('next')
            if next_page and is_safe_url(next_page):
                return redirect(next_page)

            if user.role == 'admin':
                return redirect(url_for('dashboard'))
            else:
                return redirect(url_for('recent'))
        else:
            flash('Invalid username or password!', 'danger')

    return render_template('login.html')


# ---------- LOGOUT ----------
@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


# ---------- DASHBOARD ----------
@app.route('/dashboard')
@login_required
def dashboard():
    # hanya admin boleh lihat detail tertentu — template juga harus cek role
    issues = Issue.query.order_by(Issue.created_at.desc()).all()
    total_issues = len(issues)
    in_progress_count = Issue.query.filter_by(status='In Progress').count()
    closed_count = Issue.query.filter_by(status='Closed').count()

    level_counts = (
        db.session.query(Issue.level, db.func.count(Issue.id))
        .group_by(Issue.level)
        .all()
    )
    levels = [lc[0] for lc in level_counts]
    counts = [lc[1] for lc in level_counts]

    return render_template(
        'dashboard.html',
        username=current_user.username,
        role=current_user.role,
        issues=issues,
        total_issues=total_issues,
        in_progress_count=in_progress_count,
        closed_count=closed_count,
        levels=levels,
        counts=counts
    )


# ---------- ADD ISSUE ----------
@app.route('/add_issue', methods=['GET', 'POST'])
@login_required
def add_issue():
    if request.method == 'POST':
        property_name = request.form['property_name']
        description = request.form['description']
        level = request.form['level']
        status = request.form['status']

        new_issue = Issue(
            property_name=property_name,
            description=description,
            level=level,
            status=status,
            handled_by=current_user.username
        )
        db.session.add(new_issue)
        db.session.commit()

        log = LogActivity(username=current_user.username, action=f"Added new issue: {property_name}")
        db.session.add(log)
        db.session.commit()

        flash('Issue added successfully!', 'success')
        return redirect(url_for('recent'))

    return render_template('add_issue.html')


# ---------- RECENT ISSUES ----------
@app.route('/recent')
@login_required
def recent():
    search_query = request.args.get('search', '', type=str)
    status_filter = request.args.get('status', '', type=str)
    level_filter = request.args.get('level', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 10

    query = Issue.query

    if search_query:
        query = query.filter(
            Issue.property_name.ilike(f'%{search_query}%') |
            Issue.description.ilike(f'%{search_query}%')
        )

    if status_filter:
        query = query.filter(Issue.status == status_filter)
    if level_filter:
        query = query.filter(Issue.level == level_filter)

    query = query.order_by(Issue.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    issues = pagination.items

    return render_template(
        'recent.html',
        issues=issues,
        pagination=pagination,
        role=current_user.role,
        search_query=search_query,
        status_filter=status_filter,
        level_filter=level_filter
    )


# ---------- EDIT ISSUE ----------
@app.route('/edit_issue/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_issue(id):
    issue = Issue.query.get_or_404(id)
    if request.method == 'POST':
        issue.property_name = request.form['property_name']
        issue.description = request.form['description']
        issue.status = request.form['status']
        issue.level = request.form['level']
        db.session.commit()

        log = LogActivity(username=current_user.username, action=f"Edited issue: {issue.property_name}")
        db.session.add(log)
        db.session.commit()

        flash('Issue updated successfully!', 'success')
        return redirect(url_for('recent'))

    return render_template('edit_issue.html', issue=issue)


# ---------- DELETE ISSUE (ADMIN ONLY) ----------
@app.route('/delete/<int:id>', methods=['POST'])
@login_required
def delete(id):
    if current_user.role != 'admin':
        flash('You do not have permission to delete issues.', 'danger')
        return redirect(url_for('recent'))

    issue = Issue.query.get_or_404(id)
    db.session.delete(issue)
    db.session.commit()

    log = LogActivity(username=current_user.username, action=f"Deleted issue: {issue.property_name}")
    db.session.add(log)
    db.session.commit()

    flash('Issue deleted successfully.', 'info')
    return redirect(url_for('recent'))


# ---------- LOG ACTIVITY ----------
@app.route('/log_activity')
@login_required
def log_activity():
    logs = LogActivity.query.order_by(LogActivity.timestamp.desc()).all()
    return render_template('log_activity.html', logs=logs)


# ---------- EXPORT REPORT ----------
@app.route('/export', methods=['GET', 'POST'])
@login_required
def export():
    issues = []
    start_date = end_date = None

    if request.method == 'POST':
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')

        if not start_date or not end_date:
            flash("Please select both start and end dates.", "warning")
            return render_template('export.html', issues=[], start_date=start_date, end_date=end_date)

        start_dt = datetime.strptime(start_date, '%Y-%m-%d')
        end_dt = datetime.strptime(end_date, '%Y-%m-%d') + timedelta(days=1)

        issues = Issue.query.filter(
            Issue.created_at >= start_dt,
            Issue.created_at < end_dt
        ).order_by(Issue.created_at.desc()).all()

        if not issues:
            flash("No data found for the selected date range.", "info")

        if 'download' in request.form and issues:
            data = [{
                'Property Name': i.property_name,
                'Description': i.description,
                'Status': i.status,
                'Level': i.level,
                'Handled By': i.handled_by,
                'Created At': i.created_at.strftime('%Y-%m-%d %H:%M:%S')
            } for i in issues]

            df = pd.DataFrame(data)
            output = BytesIO()

            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, index=False, sheet_name='Issues')
                worksheet = writer.sheets['Issues']
                for col in worksheet.columns:
                    max_length = 0
                    col_letter = col[0].column_letter
                    for cell in col:
                        if cell.value:
                            max_length = max(max_length, len(str(cell.value)))
                    worksheet.column_dimensions[col_letter].width = max_length + 2

            output.seek(0)
            filename = f"Issue_Report_{start_date}_to_{end_date}.xlsx"
            return send_file(output, as_attachment=True, download_name=filename)

    return render_template('export.html', issues=issues, start_date=start_date, end_date=end_date)


# ---------- MANAGE USERS ----------
@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_users():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for('manage_users'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already exists!", "warning")
            return redirect(url_for('manage_users'))

        new_user = User(
            username=username,
            password=generate_password_hash(password, method='pbkdf2:sha256'),
            role=role
        )
        db.session.add(new_user)
        db.session.commit()
        flash(f"User '{username}' added successfully!", "success")
        return redirect(url_for('manage_users'))

    users = User.query.all()
    return render_template('manage_users.html', users=users)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == 'admin':
        flash("Cannot delete admin user.", "warning")
        return redirect(url_for('manage_users'))

    db.session.delete(user)
    db.session.commit()
    flash(f"User '{user.username}' deleted successfully!", "success")
    return redirect(url_for('manage_users'))


# ---------------------------------------------------
# MAIN
# ---------------------------------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database and tables created or already exist.")

        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("👑 Default admin user created: admin / admin123")

    print("🚀 Flask app running... Open http://127.0.0.1:5000")
    app.run(debug=True)
