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
        
        print(f"\n🔵 SIGNUP - Session set: {session.get('pending_user')}")
        
        otp_code = OTPManager.create_otp(email)
        
        if otp_code:
            # Try to send email
            email_sent = send_otp_email(email, otp_code)
            
            if email_sent:
                flash('OTP sent to your email. Please verify.', 'success')
            else:
                flash(f'OTP: {otp_code} (Check console - Email failed)', 'warning')
            
            return redirect(url_for('auth.verify_otp', email=email))
        else:
            flash('Failed to generate OTP. Try again.', 'error')
            return redirect(url_for('auth.signup'))
    
    return render_template('auth/signup.html')

# ... rest of auth.py (verify_otp, resend_otp, login, logout)
