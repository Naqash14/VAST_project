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
        
        print(f"\n🔵 SIGNUP - Session set: {session.get('pending_user')}")
        
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
    print("\n" + "="*60)
    print("🔍 VERIFY_OTP FUNCTION CALLED")
    print(f"Method: {request.method}")
    print(f"Form data: {dict(request.form)}")
    print(f"Args: {request.args}")
    print("="*60)
    
    # 🔴 FIX: Get email from both URL args and form data
    email = request.args.get('email') or request.form.get('email')
    
    if not email:
        print("❌ No email found in request!")
        flash('Email required', 'error')
        return redirect(url_for('auth.signup'))
    
    print(f"📧 Email found: {email}")
    
    # Check session
    pending = session.get('pending_user')
    print(f"\n🟡 Session pending_user: {pending}")
    print(f"🟡 Email from request: {email}")
    
    if not pending:
        print("❌ No pending user in session!")
        flash('Session expired. Please register again.', 'error')
        return redirect(url_for('auth.signup'))
    
    if pending['email'] != email:
        print(f"❌ Email mismatch! Session: {pending['email']}, Request: {email}")
        flash('Session error. Please register again.', 'error')
        return redirect(url_for('auth.signup'))
    
    if request.method == 'POST':
        print("\n🔴 VERIFY POST REQUEST PROCESSING")
        otp_code = request.form.get('otp')
        
        print(f"🔴 OTP from form: {otp_code}")
        print(f"🔴 Session before verification: {session.get('pending_user')}")
        
        if not otp_code or len(otp_code) != 6:
            print("❌ Invalid OTP format")
            flash('Please enter 6-digit OTP', 'error')
            return redirect(url_for('auth.verify_otp', email=email))
        
        # Verify OTP
        print("🔍 Calling OTPManager.verify_otp...")
        valid, message = OTPManager.verify_otp(email, otp_code)
        print(f"📝 Verification result - Valid: {valid}, Message: {message}")
        
        if valid:
            print("✅ OTP verified successfully")
            
            # Get pending user
            pending = session.get('pending_user')
            print(f"📝 Pending user after verification: {pending}")
            
            if pending and pending['email'] == email:
                try:
                    # Create user
                    user = User(
                        username=pending['username'],
                        email=pending['email'],
                        is_verified=True
                    )
                    user.set_password(pending['password'])
                    
                    db.session.add(user)
                    db.session.commit()
                    
                    print(f"✅ User created in database: {user.username} ({user.email})")
                    
                    # Clear session
                    session.pop('pending_user', None)
                    
                    flash('Email verified! You can now login.', 'success')
                    print("✅ Redirecting to login page")
                    return redirect(url_for('auth.login'))
                    
                except Exception as e:
                    print(f"❌ Error creating user: {e}")
                    import traceback
                    traceback.print_exc()
                    db.session.rollback()
                    flash('Error creating account. Try again.', 'error')
                    return redirect(url_for('auth.signup'))
            else:
                print(f"❌ Session lost or mismatched")
                print(f"   Pending: {pending}")
                print(f"   Email: {email}")
                flash('Session expired. Please register again.', 'error')
                return redirect(url_for('auth.signup'))
        else:
            print(f"❌ OTP verification failed: {message}")
            flash(message, 'error')
            return redirect(url_for('auth.verify_otp', email=email))
    
    # GET request
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
        
        if not user or not user.check_password(password):
            flash('Invalid email or password', 'error')
            return redirect(url_for('auth.login'))
        
        if not user.is_verified:
            flash('Please verify your email first', 'warning')
            return redirect(url_for('auth.verify_otp', email=email))
        
        login_user(user, remember=bool(remember))
        flash(f'Welcome back, {user.username}!', 'success')
        return redirect(url_for('dashboard.index'))
    
    return render_template('auth/login.html')


# ========== LOGOUT ==========
@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'info')
    return redirect(url_for('auth.login'))


# ========== TOGGLE 2FA ==========
@bp.route('/toggle-2fa', methods=['POST'])
@login_required
def toggle_2fa():
    """Toggle 2FA setting for user"""
    try:
        current_user.is_2fa_enabled = not current_user.is_2fa_enabled
        db.session.commit()
        
        status = 'enabled' if current_user.is_2fa_enabled else 'disabled'
        flash(f'Two-factor authentication {status} successfully!', 'success')
        
    except Exception as e:
        flash('Error toggling 2FA. Please try again.', 'error')
        print(f"Error toggling 2FA: {e}")
    
    return redirect(url_for('dashboard.index'))
