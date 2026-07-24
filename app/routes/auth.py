from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app import db
from app.models import User, OTP
from app.utils.security import check_password_strength
from app.utils.email_service import send_otp_email
from app.utils.otp_manager import OTPManager
import re
from datetime import datetime

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')
        
        if not all([username, email, password, confirm]):
            flash('All fields required', 'error')
            return redirect(url_for('auth.signup'))
        
        if password != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('auth.signup'))
        
        strength, _, _ = check_password_strength(password)
        if strength == 'weak':
            flash('Password too weak', 'error')
            return redirect(url_for('auth.signup'))
        
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email', 'error')
            return redirect(url_for('auth.signup'))
        
        if User.query.filter_by(username=username).first():
            flash('Username exists', 'error')
            return redirect(url_for('auth.signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email exists', 'error')
            return redirect(url_for('auth.signup'))
        
        session['pending_user'] = {
            'username': username,
            'email': email,
            'password': password
        }
        
        otp_code = OTPManager.create_otp(email)
        
        if otp_code:
            # Send email asynchronously - don't wait
            send_otp_email(email, otp_code)
            flash('OTP sent to your email', 'success')
            return redirect(url_for('auth.verify_otp', email=email))
        else:
            flash('Failed to generate OTP', 'error')
            return redirect(url_for('auth.signup'))
    
    return render_template('auth/signup.html')

@bp.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    email = request.args.get('email') or request.form.get('email')
    
    if not email:
        return redirect(url_for('auth.signup'))
    
    if request.method == 'POST':
        otp_code = request.form.get('otp')
        email = request.form.get('email')
        
        if not otp_code or len(otp_code) != 6:
            flash('Enter 6-digit OTP', 'error')
            return redirect(url_for('auth.verify_otp', email=email))
        
        valid, message = OTPManager.verify_otp(email, otp_code)
        
        if valid:
            pending = session.get('pending_user')
            if pending and pending['email'] == email:
                user = User(
                    username=pending['username'],
                    email=pending['email'],
                    is_verified=True
                )
                user.set_password(pending['password'])
                
                db.session.add(user)
                db.session.commit()
                
                session.pop('pending_user', None)
                
                flash('Account created! Please login.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Session expired', 'error')
                return redirect(url_for('auth.signup'))
        else:
            flash(message, 'error')
            return redirect(url_for('auth.verify_otp', email=email))
    
    return render_template('auth/verify_otp.html', email=email)

@bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    email = request.form.get('email')
    
    if not email:
        return jsonify({'success': False, 'message': 'Email required'})
    
    otp_code = OTPManager.create_otp(email)
    
    if otp_code:
        send_otp_email(email, otp_code)
        return jsonify({'success': True, 'message': 'OTP sent'})
    else:
        return jsonify({'success': False, 'message': 'Failed'})

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.index'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = request.form.get('remember', False)
        
        user = User.query.filter_by(email=email).first()
        
        if not user or not user.check_password(password):
            flash('Invalid credentials', 'error')
            return redirect(url_for('auth.login'))
        
        if not user.is_verified:
            flash('Verify email first', 'warning')
            return redirect(url_for('auth.verify_otp', email=email))
        
        login_user(user, remember=bool(remember))
        flash(f'Welcome {user.username}!', 'success')
        return redirect(url_for('dashboard.index'))
    
    return render_template('auth/login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'info')
    return redirect(url_for('auth.login'))
