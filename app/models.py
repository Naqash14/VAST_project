from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import random

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_2fa_enabled = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)  # ✅ Admin flag
    profile_pic = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    login_attempts = db.Column(db.Integer, default=0)
    
    projects = db.relationship('Project', backref='owner', lazy=True, cascade='all, delete-orphan')
    otps = db.relationship('OTP', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

class OTP(db.Model):
    __tablename__ = 'otp'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)
    
    def __init__(self, email, user_id=None):
        self.email = email
        self.user_id = user_id
        self.otp_code = self.generate_otp()
        self.expires_at = datetime.utcnow() + timedelta(minutes=10)
    
    def generate_otp(self):
        return ''.join([str(random.randint(0, 9)) for _ in range(6)])
    
    def is_valid(self):
        return (not self.is_used and 
                datetime.utcnow() < self.expires_at and
                self.attempts < 3)
    
    def increment_attempts(self):
        self.attempts += 1
        db.session.commit()
    
    def __repr__(self):
        return f'<OTP for {self.email}>'

class Project(db.Model):
    __tablename__ = 'project'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    project_name = db.Column(db.String(200), nullable=False)
    code_content = db.Column(db.Text)
    filename = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    scan_results = db.relationship('ScanResult', backref='project', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Project {self.project_name}>'

class ScanResult(db.Model):
    __tablename__ = 'scan_result'
    
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    tool_name = db.Column(db.String(50), nullable=False)
    findings = db.Column(db.Text)
    severity = db.Column(db.String(20), default='info')
    ai_analysis = db.Column(db.Text, nullable=True)
    ai_status = db.Column(db.String(20), default='none')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<ScanResult for Project {self.project_id}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Add is_admin field if not exists
# In User class, add:
# is_admin = db.Column(db.Boolean, default=False)
