"""
Admin Routes - Separate blueprint for admin functionality
Does NOT interfere with existing user routes
"""

from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from flask_login import login_required, current_user
from app import db
from app.models import User, Project, ScanResult
from datetime import datetime

bp = Blueprint('admin', __name__, url_prefix='/admin')

# Admin login check decorator
def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Admin access required', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

# Create default admin user (if not exists)
def create_default_admin():
    admin = User.query.filter_by(email='admin@vast.com').first()
    if not admin:
        admin = User(
            username='admin',
            email='admin@vast.com',
            is_verified=True,
            is_admin=True
        )
        admin.set_password('Admin@123')
        db.session.add(admin)
        db.session.commit()
        print("✅ Default admin created: admin@vast.com / Admin@123")
    else:
        # Ensure existing admin has admin flag
        if not admin.is_admin:
            admin.is_admin = True
            db.session.commit()

# Admin Dashboard
@bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Statistics
    total_users = User.query.count()
    total_projects = Project.query.count()
    total_scans = ScanResult.query.count()
    
    # Recent users
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    
    # Recent scans
    recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(10).all()
    
    # Vulnerability statistics
    vuln_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for scan in ScanResult.query.all():
        try:
            import json
            findings = json.loads(scan.findings) if scan.findings else {}
            for sev, count in findings.get('by_severity', {}).items():
                if sev in vuln_stats:
                    vuln_stats[sev] += count
        except:
            pass
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_projects=total_projects,
                         total_scans=total_scans,
                         recent_users=recent_users,
                         recent_scans=recent_scans,
                         vuln_stats=vuln_stats,
                         now=datetime.now())

# User Management
@bp.route('/users')
@login_required
@admin_required
def users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users, now=datetime.now())

@bp.route('/user/<int:user_id>')
@login_required
@admin_required
def user_detail(user_id):
    user = User.query.get_or_404(user_id)
    projects = Project.query.filter_by(user_id=user.id).all()
    return render_template('admin/user_detail.html', user=user, projects=projects, now=datetime.now())

@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow deleting yourself
    if user.id == current_user.id:
        flash('Cannot delete your own admin account', 'error')
        return redirect(url_for('admin.users'))
    
    # First delete all scan results for user's projects
    projects = Project.query.filter_by(user_id=user.id).all()
    for project in projects:
        # Delete scan results first
        ScanResult.query.filter_by(project_id=project.id).delete()
    
    # Then delete projects
    Project.query.filter_by(user_id=user.id).delete()
    
    # Finally delete user
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User "{user.username}" and all associated data deleted successfully', 'success')
    return redirect(url_for('admin.users'))

# Project Management
@bp.route('/projects')
@login_required
@admin_required
def projects():
    projects = Project.query.order_by(Project.created_at.desc()).all()
    return render_template('admin/projects.html', projects=projects, now=datetime.now())

@bp.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    project_name = project.project_name
    db.session.delete(project)
    db.session.commit()
    
    flash(f'Project "{project_name}" deleted successfully', 'success')
    return redirect(url_for('admin.projects'))

# Scan Results Management
@bp.route('/scans')
@login_required
@admin_required
def scans():
    scans = ScanResult.query.order_by(ScanResult.created_at.desc()).all()
    return render_template('admin/scans.html', scans=scans, now=datetime.now())

@bp.route('/scan/<int:scan_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_scan(scan_id):
    scan = ScanResult.query.get_or_404(scan_id)
    db.session.delete(scan)
    db.session.commit()
    
    flash('Scan result deleted successfully', 'success')
    return redirect(url_for('admin.scans'))

# Make admin available - call this when app starts
def init_admin():
    with db.session.begin_nested():
        create_default_admin()
    db.session.commit()
