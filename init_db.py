from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from datetime import datetime
import pytz

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///issues.db'
db = SQLAlchemy(app)

# Model untuk tabel issue
class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    property_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='In Progress')
    level = db.Column(db.String(50), nullable=False)
    handled_by = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: 
datetime.now(pytz.timezone('Asia/Makassar')))

# Model untuk log aktivitas user
class LogActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False)
    action = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: 
datetime.now(pytz.timezone('Asia/Makassar')))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Database berhasil dibuat: issues.db")

