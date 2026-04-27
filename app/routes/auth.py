from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from app import db
from app.models import User, OTP
from app.utils.security import check_password_strength
from app.utils.email_service import send_otp_email
from app.utils.otp_manager import OTPManager
import os
import re
from datetime import datetime

bp = Blueprint('auth', __name__, url_prefix='/auth')
print("🟢 Auth blueprint created")

# ========== SIGNUP ==========
@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm_password]):
            flash('All fields are required', 'error')
            return redirect(url_for('auth.signup'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('auth.signup'))
        
        strength, msg, _ = check_password_strength(password)
        if strength == 'weak':
            flash('Password too weak. Use a stronger password.', 'error')
            return redirect(url_for('auth.signup'))
        
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email format', 'error')
            return redirect(url_for('auth.signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return redirect(url_for('auth.signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return redirect(url_for('auth.signup'))
        
        session['pending_user'] = {
            'username': username,
            'email': email,
            'password': password
        }
        session.permanent = True
        
        otp_code = OTPManager.create_otp(email)
        
        if otp_code:
            send_otp_email(email, otp_code)
            flash('OTP sent to your email. Please verify.', 'success')
            return redirect(url_for('auth.verify_otp', email=email))
        else:
            flash('Failed to generate OTP. Try again.', 'error')
            return redirect(url_for('auth.signup'))
    
    return render_template('auth/signup.html')

# ========== VERIFY OTP ==========
@bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or request.form.get('email')
    
    if not email:
        return redirect(url_for('auth.signup'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp')
        email = request.form.get('email')
        
        if not otp_code or len(otp_code) != 6:
            flash('Please enter 6-digit OTP', 'error')
            return redirect(url_for('auth.verify_otp', email=email))
        
        valid, message = OTPManager.verify_otp(email, otp_code)
        
        if valid:
            pending = session.get('pending_user')
            
            if pending and pending['email'] == email:
                try:
                    user = User(
                        username=pending['username'],
                        email=pending['email'],
                        is_verified=True
                    )
                    user.set_password(pending['password'])
                    
                    db.session.add(user)
                    db.session.commit()
                    
                    session.pop('pending_user', None)
                    
                    flash('Email verified! Please login to continue.', 'success')
                    return redirect(url_for('auth.login'))
                    
                except Exception as e:
                    print(f"Error creating user: {e}")
                    db.session.rollback()
                    flash('Error creating account. Try again.', 'error')
                    return redirect(url_for('auth.signup'))
            else:
                flash('Session expired. Please register again.', 'error')
                return redirect(url_for('auth.signup'))
        else:
            flash(message, 'error')
            return redirect(url_for('auth.verify_otp', email=email))
    
    return render_template('auth/verify_otp.html', email=email)

# ========== RESEND OTP ==========
@bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = request.form.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email required'}), 400
    
    otp_code = OTPManager.create_otp(email)
    
    if otp_code:
        send_otp_email(email, otp_code)
        return jsonify({'success': True, 'message': 'New OTP sent'})
    else:
        return jsonify({'success': False, 'message': 'Failed to generate OTP'}), 500

# ========== LOGIN ==========
@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Email not registered. Please sign up first.', 'error')
            return redirect(url_for('auth.login'))
        
        if not user.check_password(password):
            flash('Incorrect password. Please try again.', 'error')
            return redirect(url_for('auth.login'))
        
        if not user.is_verified:
            flash('Please verify your email first.', 'warning')
            return redirect(url_for('auth.verify_otp', email=email))
        
        login_user(user, remember=bool(remember))
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard.index'))
    
    return render_template('auth/login.html')

# ========== UPDATE PROFILE ==========
@bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    username = request.form.get('username')
    
    if not username:
        flash('Username is required', 'error')
        return redirect(url_for('dashboard.index'))
    
    existing = User.query.filter(User.id != current_user.id, User.username == username).first()
    if existing:
        flash('Username already taken', 'error')
        return redirect(url_for('dashboard.index'))
    
    current_user.username = username
    
    if 'profile_pic' in request.files:
        file = request.files['profile_pic']
        if file and file.filename != '':
            filename = secure_filename(f"{current_user.id}_{file.filename}")
            upload_folder = os.path.join('app', 'static', 'uploads')
            os.makedirs(upload_folder, exist_ok=True)
            filepath = os.path.join(upload_folder, filename)
            file.save(filepath)
            current_user.profile_pic = filename
    
    db.session.commit()
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('dashboard.index'))

# ========== CHANGE PASSWORD ==========
@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_pwd = request.form.get('current_password')
    new_pwd = request.form.get('new_password')
    confirm_pwd = request.form.get('confirm_password')
    
    if not current_user.check_password(current_pwd):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('dashboard.index'))
    
    if new_pwd != confirm_pwd:
        flash('New passwords do not match', 'error')
        return redirect(url_for('dashboard.index'))
    
    strength, msg, _ = check_password_strength(new_pwd)
    if strength == 'weak':
        flash('Password too weak. Use a stronger password.', 'error')
        return redirect(url_for('dashboard.index'))
    
    current_user.set_password(new_pwd)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('dashboard.index'))

# ========== LOGOUT ==========
@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))
