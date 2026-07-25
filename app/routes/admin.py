from flask import Blueprint, render_template, request, flash, redirect, url_for, current_app
from flask_login import login_required, current_user
from app import db
from app.models import User, Project, ScanResult
from werkzeug.utils import secure_filename
import os
from datetime import datetime

bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    """Decorator to check if user is admin"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('dashboard.index'))
        return f(*args, **kwargs)
    return decorated_function

@bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Admin Dashboard"""
    # Statistics
    total_users = User.query.count()
    total_projects = Project.query.count()
    total_scans = ScanResult.query.count()
    
    # Recent activity
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_projects = Project.query.order_by(Project.created_at.desc()).limit(10).all()
    recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    
    # User statistics
    verified_users = User.query.filter_by(is_verified=True).count()
    admin_users = User.query.filter_by(is_admin=True).count()
    
    # Scan statistics by tool
    scan_tools = db.session.query(
        ScanResult.tool_name, 
        db.func.count(ScanResult.id)
    ).group_by(ScanResult.tool_name).all()
    
    # Severity statistics
    severity_stats = db.session.query(
        ScanResult.severity,
        db.func.count(ScanResult.id)
    ).group_by(ScanResult.severity).all()
    
    return render_template('admin/dashboard.html',
        total_users=total_users,
        total_projects=total_projects,
        total_scans=total_scans,
        verified_users=verified_users,
        admin_users=admin_users,
        recent_users=recent_users,
        recent_projects=recent_projects,
        recent_scans=recent_scans,
        scan_tools=scan_tools,
        severity_stats=severity_stats,
        now=datetime.now()
    )

@bp.route('/users')
@login_required
@admin_required
def users():
    """Manage users"""
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users, now=datetime.now())

@bp.route('/user/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin(user_id):
    """Toggle admin status for a user"""
    user = User.query.get_or_404(user_id)
    
    # Prevent self-demotion
    if user.id == current_user.id:
        flash('Cannot change your own admin status', 'error')
        return redirect(url_for('admin.users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = 'enabled' if user.is_admin else 'disabled'
    flash(f'Admin status {status} for {user.username}', 'success')
    return redirect(url_for('admin.users'))

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user"""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin.users'))
    
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {user.username} deleted', 'success')
    return redirect(url_for('admin.users'))

@bp.route('/projects')
@login_required
@admin_required
def projects():
    """View all projects"""
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('admin/projects.html', projects=projects, now=datetime.now())

@bp.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_project(project_id):
    """Delete a project"""
    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    
    flash(f'Project {project.project_name} deleted', 'success')
    return redirect(url_for('admin.projects'))

@bp.route('/scans')
@login_required
@admin_required
def scans():
    """View all scans"""
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).all()
    return render_template('admin/scans.html', scans=scans, now=datetime.now())

@bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_scan(scan_id):
    """Delete a scan"""
    scan = ScanResult.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    
    flash('Scan deleted', 'success')
    return redirect(url_for('admin.scans'))

@bp.route('/settings')
@login_required
@admin_required
def settings():
    """Admin settings"""
    return render_template('admin/settings.html', now=datetime.now())

@bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile - works for all users"""
    username = request.form.get('username')
    
    if not username:
        flash('Username is required', 'error')
        return redirect(url_for('dashboard.index'))
    
    # Check if username already taken by another user
    existing = User.query.filter(User.id != current_user.id, User.username == username).first()
    if existing:
        flash('Username already taken', 'error')
        return redirect(url_for('dashboard.index'))
    
    current_user.username = username
    
    # Handle profile picture upload
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

@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    from app.utils.security import check_password_strength
    
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
