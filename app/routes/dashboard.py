from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, send_file
from flask_login import login_required, current_user
from app import db
from app.models import User, Project, ScanResult  # ✅ Added User import
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from app.utils.security import check_password_strength

bp = Blueprint('dashboard', __name__)

@bp.route('/')
@bp.route('/dashboard')
@login_required
def index():
    projects_count = Project.query.filter_by(user_id=current_user.id).count()
    
    recent_scans = ScanResult.query.join(Project).filter(
        Project.user_id == current_user.id
    ).order_by(ScanResult.created_at.desc()).limit(5).all()
    
    stats = {
        'total_projects': projects_count,
        'scans_today': ScanResult.query.join(Project).filter(
            Project.user_id == current_user.id,
            db.func.date(ScanResult.created_at) == db.func.date('now')
        ).count(),
        'critical_findings': ScanResult.query.join(Project).filter(
            Project.user_id == current_user.id,
            ScanResult.severity == 'critical'
        ).count()
    }
    
    return render_template('dashboard/index.html', 
                         stats=stats,
                         recent_scans=recent_scans,
                         now=datetime.now())

@bp.route('/history')
@login_required
def history():
    projects = Project.query.filter_by(
        user_id=current_user.id
    ).order_by(Project.created_at.desc()).all()
    
    return render_template('dashboard/history.html', 
                         projects=projects,
                         now=datetime.now())

@bp.route('/settings')
@login_required
def settings():
    """User settings page"""
    return render_template('dashboard/settings.html', now=datetime.now())

@bp.route('/update-profile', methods=['POST'])
@login_required
def update_profile():
    """Update user profile"""
    username = request.form.get('username')
    
    if not username:
        flash('Username is required', 'error')
        return redirect(url_for('dashboard.settings'))
    
    # Check if username already taken by another user
    existing = User.query.filter(User.id != current_user.id, User.username == username).first()
    if existing:
        flash('Username already taken', 'error')
        return redirect(url_for('dashboard.settings'))
    
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
    return redirect(url_for('dashboard.settings'))

@bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_pwd = request.form.get('current_password')
    new_pwd = request.form.get('new_password')
    confirm_pwd = request.form.get('confirm_password')
    
    if not current_user.check_password(current_pwd):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('dashboard.settings'))
    
    if new_pwd != confirm_pwd:
        flash('New passwords do not match', 'error')
        return redirect(url_for('dashboard.settings'))
    
    strength, msg, _ = check_password_strength(new_pwd)
    if strength == 'weak':
        flash('Password too weak. Use a stronger password.', 'error')
        return redirect(url_for('dashboard.settings'))
    
    current_user.set_password(new_pwd)
    db.session.commit()
    flash('Password changed successfully!', 'success')
    return redirect(url_for('dashboard.settings'))

@bp.route('/delete-project/<int:project_id>', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    if project.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('dashboard.index'))
    
    ScanResult.query.filter_by(project_id=project.id).delete()
    db.session.delete(project)
    db.session.commit()
    
    flash('Project deleted successfully', 'success')
    return redirect(url_for('dashboard.history'))
