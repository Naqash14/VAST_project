from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user
from app import db
from app.models import User, Project, ScanResult
from datetime import datetime

bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
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
    total_users = User.query.count()
    total_projects = Project.query.count()
    total_scans = ScanResult.query.count()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_projects = Project.query.join(User).order_by(Project.created_at.desc()).limit(10).all()
    
    stats = {
        'total_users': total_users,
        'total_projects': total_projects,
        'total_scans': total_scans,
        'recent_users': recent_users,
        'recent_projects': recent_projects
    }
    return render_template('admin/dashboard.html', stats=stats)

@bp.route('/users')
@login_required
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@bp.route('/projects')
@login_required
@admin_required
def manage_projects():
    projects = Project.query.join(User).order_by(Project.created_at.desc()).all()
    return render_template('admin/projects.html', projects=projects)

@bp.route('/view-project/<int:project_id>')
@login_required
@admin_required
def view_project(project_id):
    project = Project.query.get_or_404(project_id)
    user = User.query.get(project.user_id)
    return render_template('admin/view_project.html', project=project, user=user)

@bp.route('/make-admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def make_admin(user_id):
    if user_id == current_user.id:
        flash('Cannot modify your own status', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user = User.query.get_or_404(user_id)
    user.is_admin = True
    db.session.commit()
    flash(f'{user.username} is now an admin', 'success')
    return redirect(url_for('admin.manage_users'))

@bp.route('/revoke-admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def revoke_admin(user_id):
    if user_id == current_user.id:
        flash('Cannot modify your own status', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user = User.query.get_or_404(user_id)
    admin_count = User.query.filter_by(is_admin=True).count()
    if admin_count <= 1 and user.is_admin:
        flash('Cannot revoke the last admin', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user.is_admin = False
    db.session.commit()
    flash(f'{user.username} is no longer an admin', 'success')
    return redirect(url_for('admin.manage_users'))

@bp.route('/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('admin.manage_users'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User {user.username} deleted', 'success')
    return redirect(url_for('admin.manage_users'))

@bp.route('/delete-project/<int:project_id>', methods=['POST'])
@login_required
@admin_required
def delete_project_admin(project_id):
    project = Project.query.get_or_404(project_id)
    ScanResult.query.filter_by(project_id=project.id).delete()
    db.session.delete(project)
    db.session.commit()
    flash(f'Project "{project.project_name}" deleted', 'success')
    return redirect(url_for('admin.manage_projects'))
